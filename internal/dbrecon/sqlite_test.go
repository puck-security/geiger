package dbrecon

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func TestReconSQLiteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER, email TEXT)`,
		`INSERT INTO users (id, email) VALUES (1,'a@b.com'),(2,'c@d.com'),(3,'e@f.com')`,
		`CREATE TABLE widgets (id INTEGER)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	fs, err := ReconSQLiteFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReconSQLiteFile: %v", err)
	}
	got := map[string]module.Finding{}
	for _, f := range fs {
		got[f.Key] = f
	}
	if got["tables"].Value != "2" {
		t.Errorf("tables = %q, want 2", got["tables"].Value)
	}
	if !strings.Contains(got["sensitive tables"].Value, "users(3)") || got["sensitive tables"].Flag != module.FlagForceMultiplier {
		t.Errorf("sensitive tables should report users(3) as a force multiplier: %+v", got["sensitive tables"])
	}
}

func TestReconSQLiteFileMissing(t *testing.T) {
	if _, err := ReconSQLiteFile(context.Background(), filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
