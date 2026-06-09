package modules

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/puck-security/geiger/internal/parse"

	_ "modernc.org/sqlite"
)

func TestGcloudCredentialsDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO credentials VALUES (?, ?)`,
		"user@acme.com",
		`{"client_id":"32555940559.apps.googleusercontent.com","client_secret":"sec","refresh_token":"1//0gREFRESHtoken","type":"authorized_user"}`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	data, _ := os.ReadFile(path)
	b := parse.Parse(string(data), path)

	ms := recognizeGcloudDB(b, "", nil)
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %d", len(ms))
	}
	if ms[0].Module != "gcp_adc" {
		t.Errorf("module = %q", ms[0].Module)
	}
	if ms[0].Fields["refresh_token"] != "1//0gREFRESHtoken" {
		t.Errorf("refresh_token = %q", ms[0].Fields["refresh_token"])
	}
	if ms[0].Label != "gcloud credentials.db [user@acme.com]" {
		t.Errorf("label = %q", ms[0].Label)
	}
}

func TestGcloudDBBareRefreshUsesPublicClient(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.db")
	db, _ := sql.Open("sqlite", "file:"+path)
	db.Exec(`CREATE TABLE credentials (account_id TEXT, value BLOB)`)
	db.Exec(`INSERT INTO credentials VALUES (?, ?)`, "svc", `{"refresh_token":"1//bareToken"}`)
	db.Close()

	data, _ := os.ReadFile(path)
	ms := recognizeGcloudDB(parse.Parse(string(data), path), "", nil)
	if len(ms) != 1 || ms[0].Fields["client_id"] != gcloudClientID {
		t.Fatalf("bare refresh token should default to gcloud public client: %+v", ms)
	}
}

func TestGcloudDBIgnoresNonSQLite(t *testing.T) {
	if ms := recognizeGcloudDB(parse.Parse("not a database", "x.db"), "", nil); ms != nil {
		t.Errorf("non-sqlite should be ignored")
	}
}
