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
func scanExtensions(p profile) []module.Note {
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
		findings, risky, summary := scoreExtension(x, loc, verified)
		if !risky {
			benign++
			continue
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

// scoreExtension is the pure capability model: given the manifest facts +
// provenance, return findings, whether it's risky enough to report, and a
// one-line summary. This is the CursedChrome-impact core, unit-tested directly.
func scoreExtension(x manifestFacts, loc float64, verified bool) (findings []module.Finding, risky bool, summary string) {
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

	mvLabel := "MV" + itoa(x.mv)
	findings = append(findings, module.Finding{Key: "manifest", Value: mvLabel + hostSummary(hosts), Flag: module.FlagInfo})

	// Capability lines — the ones that make an extension CursedChrome-grade.
	cursed := false
	if broad && cookies {
		findings = append(findings, module.Finding{Key: "cookies", Value: "reads every site's cookies including httpOnly/Secure session tokens — session theft across all logged-in sites", Flag: module.FlagForceMultiplier})
		cursed = true
	} else if cookies {
		findings = append(findings, module.Finding{Key: "cookies", Value: "reads cookies (incl. httpOnly) for its host scope", Flag: module.FlagWarn})
	}
	if broad && intercept {
		findings = append(findings, module.Finding{Key: "intercept", Value: "observes/rewrites all web requests — Authorization and Cookie headers, on every site", Flag: module.FlagForceMultiplier})
		cursed = true
	}
	if broad && inject {
		findings = append(findings, module.Finding{Key: "inject", Value: "injects scripts into every page — reads DOM, typed form input, and in-page tokens", Flag: module.FlagForceMultiplier})
		cursed = true
	}
	if proxy {
		findings = append(findings, module.Finding{Key: "proxy", Value: "proxy permission — can route traffic through this browser (CursedChrome-style authenticated pivot)", Flag: module.FlagForceMultiplier})
		cursed = true
	}
	if native {
		findings = append(findings, module.Finding{Key: "native messaging", Value: "bridges to a local host process — a covert C2 / exfiltration channel", Flag: module.FlagWarn})
	}
	if tabs && !inject {
		findings = append(findings, module.Finding{Key: "tabs", Value: "reads URL/title of every tab (cross-site browsing visibility)", Flag: module.FlagWarn})
	}

	// Provenance aggravator — sideloaded/unpacked is unsigned and not content-verified.
	locLabel, sideloaded := chromeLocation(loc)
	if sideloaded {
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — unsigned, not content-verified (Chrome cannot detect tampering)", Flag: module.FlagWarn})
	} else if !verified {
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — no signed verified_contents.json found", Flag: module.FlagInfo})
	}

	risky = broad || cookies || intercept || proxy || native
	switch {
	case cursed && sideloaded:
		summary = "sideloaded extension with total-browser reach — CursedChrome-grade"
	case cursed:
		summary = "extension with total-browser reach (cookies/intercept/inject/proxy)"
	default:
		summary = "extension with notable browser permissions"
	}
	return findings, risky, summary
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
