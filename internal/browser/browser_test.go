package browser

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func hasFlag(fs []module.Finding, want module.FlagLevel) bool {
	for _, f := range fs {
		if f.Flag == want {
			return true
		}
	}
	return false
}

func TestScoreExtension(t *testing.T) {
	broadCaps := manifestFacts{mv: 3,
		permissions: []string{"cookies", "webRequest", "scripting", "tabs"},
		hostPerms:   []string{"<all_urls>"}}

	// Broad reach, UNPACKED (sideloaded) → notable (warn provenance), but NOT a
	// force multiplier: capability isn't malice. Capabilities are info.
	broadCaps.name = "Evil"
	fs, risky, tr, _ := scoreExtension(broadCaps, 4 /*unpacked*/, false)
	if !risky || tr != trustSideloaded {
		t.Fatalf("unpacked broad extension should be risky+sideloaded, got risky=%v tr=%v", risky, tr)
	}
	if hasFlag(fs, module.FlagForceMultiplier) {
		t.Errorf("a sideloaded extension WITHOUT proxy must not be a force multiplier: %+v", fs)
	}
	if !hasFlag(fs, module.FlagWarn) {
		t.Errorf("sideloaded provenance should be a warn: %+v", fs)
	}

	// The one alarm: proxy permission on unsigned code → force multiplier.
	withProxy := broadCaps
	withProxy.permissions = append([]string{"proxy"}, broadCaps.permissions...)
	if fs, _, _, _ := scoreExtension(withProxy, 4, false); !hasFlag(fs, module.FlagForceMultiplier) {
		t.Errorf("sideloaded + proxy should be a force multiplier: %+v", fs)
	}

	// Same broad reach, Web Store + content-verified → info only (no warn/fm).
	broadCaps.name = "uBlock"
	fs, risky, tr, _ = scoreExtension(broadCaps, 1 /*webstore*/, true)
	if !risky || tr != trustWebstore {
		t.Fatalf("webstore broad extension should be risky+webstore, got risky=%v tr=%v", risky, tr)
	}
	if hasFlag(fs, module.FlagForceMultiplier) || hasFlag(fs, module.FlagWarn) {
		t.Errorf("content-verified Web Store extension should be info-only: %+v", fs)
	}

	// Narrow, silent-permission extension → not reportable.
	benign := manifestFacts{name: "Nice", mv: 3, permissions: []string{"storage", "alarms"},
		hostPerms: []string{"https://example.com/*"}}
	if _, risky, _, _ := scoreExtension(benign, 1, true); risky {
		t.Errorf("narrow extension should not be risky")
	}
}

func TestScanUnpackedFromDisk(t *testing.T) {
	home := t.TempDir()
	prof := filepath.Join(home, ".config", "google-chrome", "Default")
	if err := os.MkdirAll(prof, 0o755); err != nil {
		t.Fatal(err)
	}
	// The unpacked extension's real folder + manifest.json — Chrome references it
	// in place and does NOT copy the manifest into Preferences.
	extDir := filepath.Join(home, "evil-ext")
	os.MkdirAll(extDir, 0o755)
	os.WriteFile(filepath.Join(extDir, "manifest.json"),
		[]byte(`{"name":"Disk Unpacked","manifest_version":3,"permissions":["cookies"],"host_permissions":["<all_urls>"]}`), 0o600)
	// Two unpacked entries with NO embedded manifest: one whose folder exists, one
	// whose folder is gone. Both must still surface.
	prefs := `{"extensions":{"settings":{
		"aaaabbbbccccddddeeeeffffgggghhhh":{"location":4,"path":"` + extDir + `"},
		"bbbbccccddddeeeeffffgggghhhhiiii":{"location":4,"path":"` + filepath.Join(home, "gone") + `"}}}}`
	if err := os.WriteFile(filepath.Join(prof, "Preferences"), []byte(prefs), 0o600); err != nil {
		t.Fatal(err)
	}
	notes := Scan(Options{Home: home, GOOS: "linux"})
	var fromDisk, unreadable bool
	for _, n := range notes {
		if strings.Contains(n.Title, "Disk Unpacked") && hasFlag(n.Findings, module.FlagWarn) {
			fromDisk = true
		}
		if strings.Contains(n.Title, "gone") && hasFlag(n.Findings, module.FlagWarn) {
			unreadable = true
		}
	}
	if !fromDisk {
		t.Errorf("unpacked extension with an on-disk manifest should be read + flagged: %+v", notes)
	}
	if !unreadable {
		t.Errorf("unpacked extension with a missing folder should still be flagged (IOC): %+v", notes)
	}
}

func TestWebStoreStatusSkipsNonStoreID(t *testing.T) {
	// A path-derived / non-store id must not trigger a network call and must not
	// be penalized (returns listed=true).
	if listed, _ := webStoreStatus("not-a-32char-a-p-id"); !listed {
		t.Error("non-store id should be treated as listed (no network, no penalty)")
	}
}

func TestClassifySessions(t *testing.T) {
	cs := []cookie{
		{"accounts.google.com", "SID"},    // IdP — presence counts
		{".github.com", "user_session"},   // VCS — auth cookie
		{"example.com", "_ga"},            // analytics — ignored
		{"login.okta.com", "sid"},         // IdP
		{"slack.com", "d"},                // collab but not auth-named → ignored
		{"gitlab.com", "_gitlab_session"}, // VCS — auth cookie
	}
	tiers := classifySessions(cs)
	if !tiers.idp["accounts.google.com"] || !tiers.idp["okta.com"] {
		t.Errorf("idp tier wrong: %+v", tiers.idp)
	}
	if !tiers.vcs["github.com"] || !tiers.vcs["gitlab.com"] {
		t.Errorf("vcs tier wrong: %+v", tiers.vcs)
	}
	if len(tiers.cloud) != 0 {
		t.Errorf("no cloud sessions expected: %+v", tiers.cloud)
	}
	// Sessions are informational — being logged in is normal, not a finding.
	fs := tiers.findings()
	if len(fs) == 0 {
		t.Fatal("expected session findings")
	}
	if hasFlag(fs, module.FlagForceMultiplier) || hasFlag(fs, module.FlagWarn) {
		t.Errorf("browser sessions must be informational, not warn/fm: %+v", fs)
	}
}

func TestScanFixtureProfile(t *testing.T) {
	home := t.TempDir()
	prof := filepath.Join(home, ".config", "google-chrome", "Default")
	if err := os.MkdirAll(prof, 0o755); err != nil {
		t.Fatal(err)
	}
	// Preferences with one unpacked (location 4) CursedChrome-grade extension.
	prefs := `{"extensions":{"settings":{"aaaabbbbccccddddeeeeffffgggghhhh":{
		"state":1,"location":4,"from_webstore":false,
		"manifest":{"name":"Totally Legit","manifest_version":3,
			"permissions":["cookies","webRequest","scripting"],
			"host_permissions":["<all_urls>"]}}}}}`
	if err := os.WriteFile(filepath.Join(prof, "Preferences"), []byte(prefs), 0o600); err != nil {
		t.Fatal(err)
	}
	// A synthetic Cookies DB (metadata only).
	cookiesPath := filepath.Join(prof, "Cookies")
	db, err := sql.Open("sqlite", "file:"+cookiesPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE cookies (host_key TEXT, name TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Exec("INSERT INTO cookies VALUES ('accounts.google.com','SID')")
	db.Exec("INSERT INTO cookies VALUES ('.github.com','user_session')")
	db.Close()

	// A second extension: claims Web Store origin (location 1, from_webstore) but
	// has NO signed verified_contents.json on disk → must NOT be trusted (Q1: the
	// from_webstore flag is spoofable; only Google-signed hashes earn trust).
	spoof := `{"extensions":{"settings":{"aaaabbbbccccddddeeeeffffgggghhhh":{
		"state":1,"location":4,"from_webstore":false,
		"manifest":{"name":"Totally Legit","manifest_version":3,
			"permissions":["cookies","webRequest","scripting"],
			"host_permissions":["<all_urls>"]}},
	  "bbbbccccddddeeeeffffgggghhhhiiii":{"state":1,"location":1,"from_webstore":true,
		"manifest":{"name":"Claims Store","manifest_version":3,
			"permissions":["cookies"],"host_permissions":["<all_urls>"]}}}}}`
	os.WriteFile(filepath.Join(prof, "Preferences"), []byte(spoof), 0o600)

	notes := Scan(Options{Home: home, GOOS: "linux", Intrusive: true})
	var gotExt, gotSess bool
	for _, n := range notes {
		// Unpacked extension → notable (warn provenance), not force multiplier.
		if strings.Contains(n.Title, "Totally Legit") && hasFlag(n.Findings, module.FlagWarn) {
			gotExt = true
		}
		// Session inventory present and informational (not warn/fm).
		if strings.Contains(n.Title, "browser sessions") && !hasFlag(n.Findings, module.FlagWarn) && !hasFlag(n.Findings, module.FlagForceMultiplier) {
			gotSess = true
		}
	}
	if !gotExt {
		t.Errorf("expected the unpacked extension flagged warn: %+v", notes)
	}
	if !gotSess {
		t.Errorf("expected an informational session Note: %+v", notes)
	}
	// The from_webstore-claiming extension without signed hashes must be reported
	// as unverified (a warn provenance line), not silently trusted away.
	var gotSpoof bool
	for _, n := range notes {
		if strings.Contains(n.Title, "Claims Store") {
			for _, f := range n.Findings {
				if f.Key == "provenance" && f.Flag == module.FlagWarn {
					gotSpoof = true
				}
			}
		}
	}
	if !gotSpoof {
		t.Errorf("from_webstore without signed hashes must be flagged unverified, not trusted: %+v", notes)
	}
}
