package browser

import (
	"encoding/json"
	"net/http"
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
func scanExtensions(p profile, live, intrusive bool, cws *http.Client) []module.Note {
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
		loc, _ := e["location"].(float64)
		if int(loc) == 5 {
			continue // component extension — the browser's own built-in code, not a threat vector
		}
		// Webstore/installed extensions embed a manifest copy in Preferences.
		// UNPACKED extensions (location 4/8) do NOT — Chrome references them in
		// place — so read manifest.json from their on-disk path instead. Trust the
		// Google-SIGNED verified_contents.json ONLY (not the spoofable from_webstore
		// flag, not the attacker-controlled manifest update_url).
		mani, _ := e["manifest"].(map[string]any)
		path, _ := e["path"].(string)
		if mani == nil && path != "" {
			mani = readManifestFile(path)
		}
		verified := hasVerifiedContents(p.dir, id)
		tr := trustLevel(loc, verified)

		var findings []module.Finding
		var risky bool
		var summary, name string
		switch {
		case mani != nil:
			x := extractManifest(mani, id)
			if gh, ok := grantedHosts(e); ok {
				// Score the ACTUAL granted reach, not the manifest request: Chrome's
				// per-site "on click / specific sites" control can narrow a
				// <all_urls>-requesting extension to far less at runtime.
				x.hostPerms, x.contentMatch, x.granted = gh, nil, true
			}
			name = x.name
			findings, risky, tr, summary = scoreExtension(x, loc, verified)
		case tr == trustSideloaded:
			// Unpacked but manifest.json unreadable (folder moved/removed) — still an
			// IOC: an unpacked extension is registered but its code isn't where Chrome
			// expects it.
			name = baseName(path, id)
			findings = []module.Finding{{Key: "provenance",
				Value: "unpacked/sideloaded — unsigned, not content-verified; manifest.json not readable (folder moved/removed?)", Flag: module.FlagWarn}}
			risky, summary = true, "unpacked extension, manifest unreadable — verify why it is loaded"
		default:
			continue // no manifest and not sideloaded → nothing to report
		}
		if !risky {
			benign++
			continue
		}
		// Cheap benign-ness check: a "Web Store" extension that's no longer listed
		// (removed/delisted) is a strong IOC. Only under --live (a network call),
		// and only for store-claimed extensions (sideloaded ones have no listing).
		if live && (tr == trustWebstore || tr == trustUnknown) {
			if listed, note := webStoreStatus(id, cws); !listed {
				findings = append(findings, module.Finding{Key: "web store", Value: note + " — but still installed here", Flag: module.FlagWarn})
				summary = "installed extension NOT in the public Web Store — verify"
			}
		}
		// The on-disk source of a sideloaded extension is a key IOC.
		if path != "" && tr == trustSideloaded {
			findings = append(findings, module.Finding{Key: "source", Value: "loaded from " + path, Flag: module.FlagInfo})
		}
		// Responder triage bundle for the ambiguous cases (sideloaded / unknown
		// origin) — provenance context + a low-FP grep for hardcoded remote hosts.
		if tr == trustSideloaded || tr == trustUnknown {
			srcDir, external := path, true
			if srcDir == "" {
				srcDir, external = extensionCodeDir(p.dir, id), false
			}
			findings = append(findings, triageFindings(triageInput{
				profileDir: p.dir, id: id, srcDir: srcDir, external: external,
				manifest: mani, intrusive: intrusive,
			})...)
		}
		locLabel, _ := chromeLocation(loc)
		title := "browser extension: " + name + " (" + p.browser + "/" + p.name + " · " + id[:min(8, len(id))] + " · " + locLabel + ")"
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

// readManifestFile reads an unpacked extension's manifest.json from its on-disk
// directory (unpacked extensions are referenced in place, not copied into
// Preferences).
func readManifestFile(dir string) map[string]any {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return m
}

func baseName(path, id string) string {
	if path != "" {
		return filepath.Base(path)
	}
	return id[:min(16, len(id))]
}

// manifestFacts is the subset of a manifest we score.
type manifestFacts struct {
	name         string
	mv           int
	permissions  []string // API permissions (MV2 also holds host patterns here)
	hostPerms    []string // host_permissions (MV3), or the user-granted host set
	contentMatch []string // content_scripts[].matches
	granted      bool     // hostPerms reflect the runtime-granted set, not the request
}

// grantedHosts returns the user-granted host set (explicit + scriptable) from a
// Preferences entry — the actual runtime reach, which Chrome's per-site access
// control can narrow below the manifest request. ok is true when the entry
// carries a granted_permissions block at all (so an empty result means "granted
// no hosts" — e.g. pinned to on-click — not "unknown").
func grantedHosts(e map[string]any) (hosts []string, ok bool) {
	gp, ok := e["granted_permissions"].(map[string]any)
	if !ok {
		return nil, false
	}
	return append(strSlice(gp["explicit_host"]), strSlice(gp["scriptable_host"])...), true
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
	case 1, 2, 3, 6: // Web Store + external registry/pref mechanisms
		// Only the presence of Google-signed content hashes earns full trust. A
		// store-claimed extension with no signed hashes on disk is NOT trusted
		// (the --live check then confirms whether it's still actually listed).
		if verified {
			return trustWebstore
		}
		return trustUnknown
	default:
		return trustUnknown
	}
}

// scoreExtension returns findings, whether it's worth reporting, the trust
// level, and a one-line summary. Design: the declared CAPABILITIES are
// descriptive context (info) — a broad extension is normal. SEVERITY is driven
// by PROVENANCE: a sideloaded/unverified extension is worth a look (warn); a
// content-verified Web Store one is not (info). The one exception is the proxy
// permission on unsigned code — the literal CursedChrome pivot — which is
// force-multiplier grade. Sessions are handled separately and are always info.
func scoreExtension(x manifestFacts, loc float64, verified bool) (findings []module.Finding, risky bool, tr trust, summary string) {
	perms := set(x.permissions...)
	// MV2 folds host patterns into permissions; MV3 uses host_permissions. Also
	// content-script matches count as host reach.
	hosts := append(append([]string{}, x.hostPerms...), x.contentMatch...)
	if x.mv < 3 && !x.granted {
		// MV2 folds host patterns into permissions — but the granted set already
		// separates hosts from API perms, so don't re-add them there.
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

	findings = append(findings, module.Finding{Key: "manifest", Value: "MV" + itoa(x.mv) + hostSummary(hosts, x.granted), Flag: module.FlagInfo})

	// Capabilities — descriptive context (info). They say what an extension COULD
	// do; on trusted code that's normal, so they never set severity themselves.
	if cookies {
		v := "can read cookies (incl. httpOnly) for its host scope"
		if broad {
			v = "can read every site's cookies incl. httpOnly/Secure session tokens"
		}
		findings = append(findings, module.Finding{Key: "cookies", Value: v, Flag: module.FlagInfo})
	}
	if broad && intercept {
		findings = append(findings, module.Finding{Key: "intercept", Value: "can observe/rewrite web requests (Authorization/Cookie headers) on every site", Flag: module.FlagInfo})
	}
	if broad && inject {
		findings = append(findings, module.Finding{Key: "inject", Value: "can inject scripts into every page (DOM, form input, in-page tokens)", Flag: module.FlagInfo})
	}
	if proxy {
		fl := module.FlagInfo
		if tr != trustSideloaded {
			fl = module.FlagWarn // proxy on a "trusted" store extension is itself unusual
		}
		findings = append(findings, module.Finding{Key: "proxy", Value: "requests the proxy permission — can route traffic through this browser", Flag: fl})
	}
	if native {
		fl := module.FlagInfo
		if tr == trustSideloaded {
			fl = module.FlagWarn
		}
		findings = append(findings, module.Finding{Key: "native messaging", Value: "can bridge to a local host process (potential C2 / exfil channel)", Flag: fl})
	}
	if tabs && !inject {
		findings = append(findings, module.Finding{Key: "tabs", Value: "reads URL/title of every tab", Flag: module.FlagInfo})
	}

	// Severity = provenance × reach. All-sites access on UNSIGNED code is the
	// CursedChrome mechanism itself — a service-worker fetch with <all_urls> host
	// permission carries the victim's cookies, no proxy permission needed — so a
	// sideloaded extension with broad host (or proxy) is the real alarm. The SAME
	// reach on content-verified Web Store code is normal; a narrow sideloaded
	// extension is worth a look but low.
	reach := broad || proxy
	locLabel, _ := chromeLocation(loc)
	switch {
	case tr == trustSideloaded && reach:
		findings = append(findings, module.Finding{Key: "verdict",
			Value: "UNSIGNED code with all-sites access — can read/modify/exfiltrate every site you're logged into (the CursedChrome mechanism); assume malicious until the source is verified",
			Flag:  module.FlagForceMultiplier})
		summary = "sideloaded extension with all-sites access — assume malicious until verified"
	case tr == trustSideloaded:
		findings = append(findings, module.Finding{Key: "provenance",
			Value: locLabel + " — unsigned, not content-verified; narrow permissions, but verify why it is loaded", Flag: module.FlagWarn})
		summary = "sideloaded (unpacked) extension — verify why it is loaded"
	case tr == trustUnknown:
		findings = append(findings, module.Finding{Key: "provenance",
			Value: locLabel + " — claims Web Store origin but no signed verified_contents.json", Flag: module.FlagWarn})
		summary = "extension with unverified origin — verify"
	case tr == trustPolicy:
		findings = append(findings, module.Finding{Key: "provenance", Value: locLabel + " — admin-managed", Flag: module.FlagInfo})
		summary = "admin-managed extension"
	default: // trustWebstore
		findings = append(findings, module.Finding{Key: "provenance", Value: "Chrome Web Store, content-verified", Flag: module.FlagInfo})
		summary = "extension with notable browser permissions"
		if reach {
			summary = "extension with broad browser reach (Web Store, content-verified)"
		}
	}

	// Report a sideloaded extension regardless of permission breadth (provenance
	// is the signal); report a Web Store one only if it has real reach.
	risky = tr == trustSideloaded || broad || cookies || intercept || proxy || native
	return findings, risky, tr, summary
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

func hostSummary(hosts []string, granted bool) string {
	label := "host access"
	if granted {
		label = "host access (user-granted)"
	}
	if broadHost(hosts) {
		return " · " + label + ": ALL sites (<all_urls>)"
	}
	n := 0
	for _, h := range hosts {
		if strings.TrimSpace(h) != "" {
			n++
		}
	}
	if n == 0 {
		if granted {
			return " · " + label + ": none (on-click / no sites granted)"
		}
		return " · host access: none declared"
	}
	return " · " + label + ": " + itoa(n) + " site pattern(s)"
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
