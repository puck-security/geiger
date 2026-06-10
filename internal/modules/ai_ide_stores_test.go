package modules

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/puck-security/geiger/internal/dbrecon"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func writeVSCDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "state.vscdb")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	rows := [][2]string{
		{"cursorAuth/accessToken", "sk-or-v1-cafebabecafebabecafebabecafebabe"},
		{"cursorAuth/refreshToken", "ya29.refreshtokenvalue1234567890abcd"},
		{"cursorAuth/cachedEmail", "user@example.com"}, // not a token → not harvested
		{"telemetry.machineId", "ignored-not-credentialish"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO ItemTable (key,value) VALUES (?,?)`, r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestVSCDBReadAndHarvest(t *testing.T) {
	path := writeVSCDB(t, t.TempDir())
	findings, kv, err := dbrecon.ReconVSCDBFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if indexByKey(findings)["ide token store"].Flag != module.FlagForceMultiplier {
		t.Errorf("store should be a force multiplier: %+v", findings)
	}
	// harvest only the token-bearing keys (access + refresh), not email/machineId
	got := map[string]bool{}
	for _, s := range kv {
		got[s.Key] = true
	}
	if !got["cursorAuth/accessToken"] || !got["cursorAuth/refreshToken"] {
		t.Errorf("token rows not harvested: %+v", kv)
	}
	if got["cursorAuth/cachedEmail"] || got["telemetry.machineId"] {
		t.Errorf("non-token rows must not be harvested: %+v", kv)
	}
}

func TestVSCDBRecognizerMagicGate(t *testing.T) {
	// a real SQLite (magic header present) named .vscdb → recognized
	b := parse.Parse("SQLite format 3\x00\x01\x02 binary pages…", "/home/u/.config/Cursor/User/globalStorage/state.vscdb")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["ai_ide_store"]; !ok {
		t.Error("state.vscdb with SQLite magic not recognized")
	}
	// a .vscdb name without the SQLite magic (e.g. a crafted import) → refused
	b2 := parse.Parse("totally not a database", "state.vscdb")
	if _, ok := modulesOf(recognize.Recognize(b2, "", module.Default))["ai_ide_store"]; ok {
		t.Error("non-SQLite content must not match (magic-header guard)")
	}
}

func TestVSCDBNeedsIntrusive(t *testing.T) {
	mod, _ := module.Default.ByName("ai_ide_store")
	// live but NOT intrusive → must gate, no file read
	c := recon.New(nil, true)
	fs, _ := mod.Recon(context.Background(), c, module.Token{}, module.Fields{"path": "/nope/state.vscdb"})
	if indexByKey(fs)["token store"].Flag != module.FlagCantCharacterize {
		t.Errorf("without --intrusive the store must be gated: %+v", fs)
	}
}
