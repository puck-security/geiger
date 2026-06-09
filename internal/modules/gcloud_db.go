package modules

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"

	_ "modernc.org/sqlite"
)

// gcloud's well-known *public* OAuth client (shipped in the SDK, not a secret).
// Used when credentials.db stores a bare refresh token without the client pair.
const (
	gcloudClientID     = "32555940559.apps.googleusercontent.com"
	gcloudClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty"
)

// recognizeGcloudDB reads the gcloud SQLite credential stores
// (~/.config/gcloud/credentials.db) and extracts the user refresh tokens — the
// real gcloud login secrets, which a plain text scan misses because the store
// is a binary SQLite database. Routes each to the gcp_adc module.
func recognizeGcloudDB(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.HasPrefix(b.Raw, "SQLite format 3\x00") {
		return nil
	}
	path := b.File
	if path == "" {
		return nil // need a real file path; SQLite can't open a stream
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT account_id, value FROM credentials")
	if err != nil {
		return nil // not a gcloud credentials.db
	}
	defer rows.Close()

	var out []recognize.Match
	for rows.Next() {
		var acct, val string
		if rows.Scan(&acct, &val) != nil {
			continue
		}
		var c map[string]any
		if json.Unmarshal([]byte(val), &c) != nil {
			continue
		}
		rt, _ := c["refresh_token"].(string)
		if rt == "" {
			continue
		}
		cid, _ := c["client_id"].(string)
		csec, _ := c["client_secret"].(string)
		if cid == "" { // bare refresh token → use gcloud's public client
			cid, csec = gcloudClientID, gcloudClientSecret
		}
		out = append(out, recognize.Match{
			Module: "gcp_adc",
			Fields: module.Fields{"refresh_token": rt, "client_id": cid, "client_secret": csec},
			Secret: rt,
			Label:  "gcloud credentials.db [" + acct + "]",
		})
	}
	return out
}

func init() {
	recognize.RegisterRecognizer(recognizeGcloudDB)
}
