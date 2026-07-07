package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

func itoa(n int) string { return strconv.Itoa(n) }

// scanExtensions reads the profile's Preferences / Secure Preferences (the
// authoritative registry — it also lists unpacked, external, and policy
// extensions the Extensions/ folder alone would miss) and returns a Note per
// extension whose permission union is risky.
func scanExtensions(p profile, live bool) []module.Note {
	settings := map[string]map[string]any{}
	for _, f := range []string{"Preferences", "Secure Preferences"} {
		mergeExtSettings(filepath.Join(p.dir, f), settings)
	}
	// stable order for deterministic output/tests
	ids := make([]string, 0, len(settings))
	for id := range settings {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var notes []module.Note
	benign := 0
	for _, id := range ids {
		e := settings[id]
		if state, ok := e["state"].(float64); ok && state == 0 {
			continue // disabled
		}
		mani, _ := e["manifest"].(map[string]any)
		if mani == nil {
			continue
		}
		loc, _ := e["location"].(float64)
		verified := hasVerifiedContents(p.dir, id) || e["from_webstore"] == true
		x := extractManifest(mani, id)
		findings, risky, tr, summary := scoreExtension(x, loc, verified)
		if !risky {
			benign++
			continue
		}
		// Cheap benign-ness check: a "Web Store" extension that's no longer listed
		// (removed/delisted) is a strong IOC. Only under --live (a network call),
		// and only for store-claimed extensions (sideloaded ones have no listing).
		if live && (tr == trustWebstore || tr == trustUnknown) {
			if listed, note := webStoreStatus(id); !listed {
				findings = append(findings, module.Finding{Key: "web store", Value: note + " — but still installed here", Flag: module.FlagWarn})
				summary = "installed extension NOT in the public Web Store — verify"
			}
		}
		locLabel, _ := chromeLocation(loc)
		title := "browser extension: " + x.name + " (" + p.browser + "/" + p.name + " · " + id[:min(8, len(id))] + " · " + locLabel + ")"
		notes = append(notes, module.Note{Title: title, Findings: findings, Summary: summary})
	}
	// A one-line context note so the operator knows the rest were checked.
	if benign > 0 && len(notes) > 0 {
		notes[len(notes)-1].Findings = append(notes[len(notes)-1].Findings, module.Finding{
			Key: "also installed", Value: itoa(benign) + " other extension(s) with narrow/benign permissions (not shown)", Flag: module.FlagInfo})
	}
	return notes
}

func mergeExtSettings(path string, into map[string]map[string]any) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var root struct {
		Extensions struct {
			Settings map[string]map[string]any `json:"settings"`
		} `json:"extensions"`
	}
	if json.Unmarshal(data, &root) != nil {
		return
	}
	for id, e := range root.Extensions.Settings {
		if _, seen := into[id]; !seen {
			into[id] = e
		}
	}
}

func hasVerifiedContents(profileDir, id string) bool {
	// Extensions/<id>/<version>/_metadata/verified_contents.json (Google-signed).
	base := filepath.Join(profileDir, "Extensions", id)
	vers, err := os.ReadDir(base)
	if err != nil {
		return false
	}
	for _, v := range vers {
		if _, err := os.Stat(filepath.Join(base, v.Name(), "_metadata", "verified_contents.json")); err == nil {
			return true
		}
	}
	return false
}

// manifestFacts is the subset of a manifest we score.
type manifestFacts struct {
	name         string
	mv           int
	permissions  []string // API permissions (MV2 also holds host patterns here)
	hostPerms    []string // host_permissions (MV3)
	contentMatch []string // content_scripts[].matches
}

func extractManifest(m map[string]any, id string) manifestFacts {
	x := manifestFacts{name: strOf(m["name"])}
	if x.name == "" {
		x.name = id[:min(16, len(id))]
	}
	if mv, ok := m["manifest_version"].(float64); ok {
		x.mv = int(mv)
	}
	x.permissions = strSlice(m["permissions"])
	x.hostPerms = strSlice(m["host_permissions"])
	for _, cs := range anySlice(m["content_scripts"]) {
		if csm, ok := cs.(map[string]any); ok {
			x.contentMatch = append(x.contentMatch, strSlice(csm["matches"])...)
		}
	}
	return x
}

// dangerous API permissions worth surfacing.
var interceptPerms = set("webRequest", "webRequestBlocking", "declarativeNetRequest", "declarativeNetRequestWithHostAccess")

// trust is the provenance-derived weight. The SAME reach is a force multiplier
// on a sideloaded (unsigned, not content-verified) extension — the actual
// malicious-extension vector — and near-info on a Web-Store-signed one.
type trust int

const (
	trustSideloaded trust = iota // unpacked / command-line / external — unsigned
	trustUnknown                 // claims Web Store origin but no signed hashes
	trustPolicy                  // admin/component — managed
	trustWebstore                // Web Store, content-verified (Google-signed)
)

func trustLevel(loc float64, verified bool) trust {
	switch int(loc) {
	case 4, 8: // unpacked (developer mode) / --load-extension — the prime malicious
		// sideload vector: never content-verified, referenced in place, unsigned.
		return trustSideloaded
	case 5, 7, 9, 10: // component / enterprise policy — admin-managed
		return trustPolicy
	case 1, 2, 3, 6: // Web Store + external mechanisms (which now require a Web Store
		// update_url, so they are content-verified like a normal store install)
		if verified {
			return trustWebstore
		}
		return trustUnknown // store-claimed but no signed hashes on disk → suspicious
	default:
		return trustUnknown
	}
}

func worse(a, b module.FlagLevel) module.FlagLevel {
	if a > b {
		return a
	}
	return b
}

// scoreExtension is the pure capability model: given the manifest facts +
// provenance, return findings, whether it's risky enough to report, the trust
// level, and a one-line summary. Capability severity scales with provenance —
// a sideloaded extension gets the full force-multiplier weight, a content-
// verified Web Store one the same reach at near-info. This is the CursedChrome-
// impact core, unit-tested directly.
func scoreExtension(x manifestFacts, loc float64, verified bool) (findings []module.Finding, risky bool, tr trust, summary string) {
	perms := set(x.permissions...)
	// MV2 folds host patterns into permissions; MV3 uses host_permissions. Also
	// content-script matches count as host reach for warning purposes.
	hosts := append(append([]string{}, x.hostPerms...), x.contentMatch...)
	if x.mv < 3 {
		hosts = append(hosts, x.permissions...)
	}
	broad := broadHost(hosts)

	cookies := perms["cookies"]
	intercept := anyIn(perms, interceptPerms)
	inject := perms["scripting"] || len(x.contentMatch) > 0
	proxy := perms["proxy"]
	native := perms["nativeMessaging"]
	tabs := perms["tabs"]

	tr = trustLevel(loc, verified)
	capFlag := module.FlagInfo // Web Store / policy baseline
	switch tr {
	case trustSideloaded:
		capFlag = module.FlagForceMultiplier
	case trustUnknown:
		capFlag = module.FlagWarn
	}
	emit := func(key, val string, floor module.FlagLevel) {
		findings = append(findings, module.Finding{Key: key, Value: val, Flag: worse(capFlag, floor)})
	}

	findings = append(findings, module.Finding{Key: "manifest", Value: "MV" + itoa(x.mv) + hostSummary(hosts), Flag: module.FlagInfo})

	cursed := false
	if broad && cookies {
		emit("cookies", "reads every site's cookies including httpOnly/Secure session tokens — session theft across all logged-in sites", module.FlagInfo)
		cursed = true
	} else if cookies {
		emit("cookies", "reads cookies (incl. httpOnly) for its host scope", module.FlagInfo)
	}
	if broad && intercept {
		emit("intercept", "observes/rewrites all web requests — Authorization and Cookie headers, on every site", module.FlagInfo)
		cursed = true
	}
	if broad && inject {
		emit("inject", "injects scripts into every page — reads DOM, typed form input, and in-page tokens", module.FlagInfo)
		cursed = true
	}
	if proxy {
		// A proxy permission is unusual and dangerous regardless of store trust.
		emit("proxy", "proxy permission — can route traffic through this browser (CursedChrome-style authenticated pivot)", module.FlagWarn)
		cursed = true
	}
	if native {
		emit("native messaging", "bridges to a local host process — a covert C2 / exfiltration channel", module.FlagWarn)
	}
	if tabs && !inject {
		emit("tabs", "reads URL/title of every tab (cross-site browsing visibility)", module.FlagInfo)
	}

	// Provenance — the finding that carries the weight.
	locLabel, _ := chromeLocation(loc)
	switch tr {
	case trustSideloaded:
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — unsigned, NOT content-verified; sideloading is the primary malicious-extension vector", Flag: module.FlagForceMultiplier})
	case trustUnknown:
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — claims Web Store origin but no signed verified_contents.json; verify provenance", Flag: module.FlagWarn})
	case trustPolicy:
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — admin-managed", Flag: module.FlagInfo})
	case trustWebstore:
		findings = append(findings, module.Finding{Key: "provenance", Value: "Chrome Web Store, content-verified (Google-signed, tamper-detected)", Flag: module.FlagInfo})
	}

	risky = broad || cookies || intercept || proxy || native
	switch {
	case cursed && tr == trustSideloaded:
		summary = "SIDELOADED extension with total-browser reach — prime CursedChrome vector"
	case cursed:
		summary = "extension with broad browser reach — " + trustLabel(tr)
	default:
		summary = "extension with notable browser permissions"
	}
	return findings, risky, tr, summary
}

func trustLabel(tr trust) string {
	switch tr {
	case trustSideloaded:
		return "sideloaded"
	case trustUnknown:
		return "unverified origin"
	case trustPolicy:
		return "admin-managed"
	default:
		return "Web Store, content-verified"
	}
}

// broadHost reports whether any match pattern grants all-sites reach.
func broadHost(patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		switch p {
		case "<all_urls>", "*://*/*", "https://*/*", "http://*/*", "*://*", "*":
			return true
		}
		// *://*/ or scheme://*/... with a bare * host
		if strings.Contains(p, "://*/") {
			return true
		}
	}
	return false
}

func hostSummary(hosts []string) string {
	if broadHost(hosts) {
		return " · host access: ALL sites (<all_urls>)"
	}
	n := 0
	for _, h := range hosts {
		if strings.TrimSpace(h) != "" {
			n++
		}
	}
	if n == 0 {
		return " · host access: none declared"
	}
	return " · host access: " + itoa(n) + " site pattern(s)"
}

// --- small helpers ---

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func anyIn(have map[string]bool, want map[string]bool) bool {
	for k := range want {
		if have[k] {
			return true
		}
	}
	return false
}

func strSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func anySlice(v any) []any {
	arr, _ := v.([]any)
	return arr
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}
