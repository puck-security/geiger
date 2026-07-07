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
	// CursedChrome-grade: <all_urls> + cookies + intercept + inject, sideloaded.
	cursed := manifestFacts{name: "Evil", mv: 3,
		permissions: []string{"cookies", "webRequest", "scripting", "tabs"},
		hostPerms:   []string{"<all_urls>"}}
	fs, risky, summary := scoreExtension(cursed, 4 /*unpacked*/, false)
	if !risky {
		t.Fatal("broad cookies+intercept+inject extension should be risky")
	}
	if !hasFlag(fs, module.FlagForceMultiplier) {
		t.Errorf("expected a force-multiplier finding, got %+v", fs)
	}
	if summary == "" || summary[:10] != "sideloaded" {
		t.Errorf("sideloaded CursedChrome summary expected, got %q", summary)
	}

	// Narrow, silent-permission extension → not reportable.
	benign := manifestFacts{name: "Nice", mv: 3, permissions: []string{"storage", "alarms"},
		hostPerms: []string{"https://example.com/*"}}
	if _, risky, _ := scoreExtension(benign, 1 /*webstore*/, true); risky {
		t.Errorf("narrow extension should not be risky")
	}

	// MV2 folds host patterns into permissions.
	mv2 := manifestFacts{name: "Old", mv: 2, permissions: []string{"cookies", "<all_urls>"}}
	if fs, risky, _ := scoreExtension(mv2, 1, true); !risky || !hasFlag(fs, module.FlagForceMultiplier) {
		t.Errorf("MV2 <all_urls>+cookies should be a force multiplier: %+v", fs)
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
	if !hasFlag(tiers.findings(), module.FlagForceMultiplier) {
		t.Error("idp sessions should be a force multiplier")
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

	notes := Scan(Options{Home: home, GOOS: "linux", Intrusive: true})
	var gotExt, gotSess bool
	for _, n := range notes {
		if strings.Contains(n.Title, "Totally Legit") && hasFlag(n.Findings, module.FlagForceMultiplier) {
			gotExt = true
		}
		if strings.Contains(n.Title, "browser sessions") && hasFlag(n.Findings, module.FlagForceMultiplier) {
			gotSess = true
		}
	}
	if !gotExt {
		t.Errorf("expected a force-multiplier extension Note: %+v", notes)
	}
	if !gotSess {
		t.Errorf("expected a force-multiplier session Note: %+v", notes)
	}
}
