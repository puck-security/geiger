package modules

import (
	"net/http"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestMongoDBAtlasServiceAccountRecon(t *testing.T) {
	mux := http.NewServeMux()
	gotToken := false
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		gotToken = true
		u, p, ok := r.BasicAuth()
		if !ok || u != "mdb_sa_id_abc" || p != "mdb_sa_sk_xyz" {
			t.Errorf("client_credentials must use Basic client auth, got %q:%q ok=%v", u, p, ok)
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("wrong grant: %q", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"ATOK","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/api/atlas/v2/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ATOK" {
			t.Errorf("recon must use the exchanged token: %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.Header.Get("Accept"), "vnd.atlas") {
			t.Errorf("Admin API needs a versioned Accept header, got %q", r.Header.Get("Accept"))
		}
		respond(w, `{"results":[{"id":"o1","name":"Acme Org"}],"totalCount":1}`)
	})
	mux.HandleFunc("/api/atlas/v2/groups", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"results":[{"id":"p1"},{"id":"p2"},{"id":"p3"}],"totalCount":3}`)
	})

	got := driveModule(t, "mongodb_atlas", module.Fields{
		"client_id": "mdb_sa_id_abc", "client_secret": "mdb_sa_sk_xyz",
	}, mux)
	if !gotToken {
		t.Error("token endpoint never called")
	}
	if got["org"].Value != "Acme Org" {
		t.Errorf("org name wrong: %+v", got["org"])
	}
	if got["projects"].Value != "3" {
		t.Errorf("project count wrong: %+v", got["projects"])
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("Admin API reach should be a force multiplier: %+v", got["reach"])
	}
}

func TestMongoDBAtlasRecognizedByPrefix(t *testing.T) {
	raw := "MONGODB_ATLAS_CLIENT_ID=mdb_sa_id_68a1f2c3d4e5b6a7c8d9e0f1\n" +
		"MONGODB_ATLAS_CLIENT_SECRET=mdb_sa_sk_a1b2c3d4e5f60718293aabbccddeeff00\n"
	b := parse.Parse(raw, ".env")
	matches := recognize.Recognize(b, "", module.Default)
	by := modulesOf(matches)
	m, ok := by["mongodb_atlas"]
	if !ok {
		t.Fatalf("Atlas service account not recognized: %+v", by)
	}
	if m.Fields["client_id"] != "mdb_sa_id_68a1f2c3d4e5b6a7c8d9e0f1" {
		t.Errorf("client_id field wrong: %+v", m.Fields)
	}
	if !strings.HasPrefix(m.Secret, "mdb_sa_sk_") {
		t.Errorf("secret wrong: %q", m.Secret)
	}
	// The secret must not also surface as a bare generic_secret.
	if _, dup := by["generic_secret"]; dup {
		t.Errorf("Atlas secret leaked as generic_secret too: %+v", matches)
	}
}

func TestMongoDBAtlasNeedsBothHalves(t *testing.T) {
	// secret only, no id — can't run the grant, so don't claim the atlas module.
	b := parse.Parse("ATLAS_SECRET=mdb_sa_sk_a1b2c3d4e5f60718293aabbccddeeff00\n", ".env")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["mongodb_atlas"]; ok {
		t.Errorf("should not route to atlas module without the client_id half")
	}
}
