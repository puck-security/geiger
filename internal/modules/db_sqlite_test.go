package modules

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func TestTemplateDSNsFiltered(t *testing.T) {
	raw := "TEMPLATE_URL=postgresql://user:password@host:port/database\n" +
		"EXAMPLE_URL=postgresql://youruser:pw@localhost:5432/dbname\n" +
		"REAL_URL=postgresql://app:s3cr3tPassw0rd@db.prod.internal:5432/orders\n"
	b := parse.Parse(raw, ".env")
	matches := recognize.Recognize(b, "", module.Default)
	var real, templates int
	for _, m := range matches {
		if m.Module != "db_connection_string" {
			continue
		}
		switch {
		case strings.Contains(m.Secret, "db.prod.internal"):
			real++
		case strings.Contains(m.Secret, "@host:port"), strings.Contains(m.Secret, "@localhost:5432/dbname"):
			templates++
		}
	}
	if real != 1 {
		t.Errorf("the real DSN should be recognized once, got %d: %+v", real, matches)
	}
	if templates != 0 {
		t.Errorf("template/example DSNs must be dropped, got %d", templates)
	}
}

func TestSQLiteFileReadEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data", "knowledge.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE customers (id INTEGER, ssn TEXT)`)
	db.Exec(`INSERT INTO customers (id, ssn) VALUES (1,'x'),(2,'y')`)
	db.Close()

	// The .env lives in dir; its sqlite path is relative to that dir.
	envPath := filepath.Join(dir, ".env")
	b := parse.Parse("DATABASE_URL=sqlite:///./data/knowledge.db\n", envPath)
	var m recognize.Match
	for _, x := range recognize.Recognize(b, "", module.Default) {
		if x.Module == "db_connection_string" {
			m = x
		}
	}
	if m.Module == "" {
		t.Fatal("sqlite DATABASE_URL not recognized")
	}
	if m.Fields["source"] != envPath {
		t.Errorf("source not plumbed: %q", m.Fields["source"])
	}

	c := recon.New(nil, true) // live + intrusive: reads the local file (no network)
	c.SetIntrusive(true)
	mod, _ := module.Default.ByName("db_connection_string")
	fs, err := mod.Recon(context.Background(), c, module.Token{}, m.Fields)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["engine"].Value != "sqlite" {
		t.Errorf("engine = %q", got["engine"].Value)
	}
	if !strings.Contains(got["sensitive tables"].Value, "customers(2)") || got["sensitive tables"].Flag != module.FlagForceMultiplier {
		t.Errorf("expected customers(2) flagged as a force multiplier: %+v", got["sensitive tables"])
	}
}

func TestSQLiteNeedsIntrusive(t *testing.T) {
	b := parse.Parse("DATABASE_URL=sqlite:///./x.db\n", filepath.Join(t.TempDir(), ".env"))
	var m recognize.Match
	for _, x := range recognize.Recognize(b, "", module.Default) {
		if x.Module == "db_connection_string" {
			m = x
		}
	}
	c := recon.New(nil, true) // live but NOT intrusive
	mod, _ := module.Default.ByName("db_connection_string")
	fs, _ := mod.Recon(context.Background(), c, module.Token{}, m.Fields)
	got := indexByKey(fs)
	if got["data access"].Flag != module.FlagCantCharacterize || !strings.Contains(got["data access"].Value, "--live --intrusive") {
		t.Errorf("without --intrusive, SQLite should be gated: %+v", got["data access"])
	}
}
