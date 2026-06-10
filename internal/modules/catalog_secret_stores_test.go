package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestInfisicalUniversalAuth(t *testing.T) {
	mux := http.NewServeMux()
	got := false
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		got = true
		if r.Method != http.MethodPost {
			t.Error("login must POST")
		}
		respond(w, `{"accessToken":"ITOK","tokenType":"Bearer"}`)
	})
	mux.HandleFunc("/api/v2/workspace", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ITOK" {
			t.Errorf("recon must use the exchanged token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"workspaces":[{"id":"a"},{"id":"b"}]}`)
	})
	out := driveModule(t, "infisical", module.Fields{"client_id": "id", "client_secret": "sec", "endpoint": "https://infisical.test"}, mux)
	if !got {
		t.Error("universal-auth login not called")
	}
	if out["projects"].Value != "2" {
		t.Errorf("projects = %q", out["projects"].Value)
	}
	if out["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("secret-read reach should be a force multiplier: %+v", out["reach"])
	}
}

func TestDelineaSecretServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "password" {
			t.Errorf("wrong grant: %q", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"DTOK","token_type":"bearer"}`)
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer DTOK" {
			t.Errorf("recon must use the exchanged token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"records":[],"total":42}`)
	})
	out := driveModule(t, "delinea_secret_server", module.Fields{"username": "u", "password": "p", "endpoint": "https://ss.test"}, mux)
	if out["secrets"].Value != "42" {
		t.Errorf("secrets count = %q", out["secrets"].Value)
	}
	if out["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("reach should be a force multiplier: %+v", out["reach"])
	}
}

func TestAkeylessAuthAndList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"token":"t-abc"}`)
	})
	mux.HandleFunc("/list-items", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"items":[{"item_name":"/a","item_type":"STATIC_SECRET"},{"item_name":"/b","item_type":"STATIC_SECRET"}]}`)
	})
	out := driveModule(t, "akeyless", module.Fields{"access_id": "p-x", "access_key": "k", "endpoint": "https://akl.test"}, mux)
	if out["items"].Value != "2" {
		t.Errorf("items = %q", out["items"].Value)
	}
	if out["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("reach should be a force multiplier: %+v", out["reach"])
	}
}

func TestSecretStoreRecognizers(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"INFISICAL_CLIENT_ID=id\nINFISICAL_CLIENT_SECRET=sec\n", "infisical"},
		{"INFISICAL_TOKEN=st.abc.def\n", "infisical"},
		{"AKEYLESS_ACCESS_ID=p-123\nAKEYLESS_ACCESS_KEY=deadbeefdeadbeef\n", "akeyless"},
		{"SECRET_SERVER_URL=https://ss.corp/SecretServer\nSECRET_SERVER_USERNAME=svc\nSECRET_SERVER_PASSWORD=Hunter2xx\n", "delinea_secret_server"},
		{"THYCOTIC_URL=https://ss.corp\nTHYCOTIC_USERNAME=svc\nTHYCOTIC_PASSWORD=Hunter2xx\n", "delinea_secret_server"},
	}
	for _, c := range cases {
		b := parse.Parse(c.raw, ".env")
		if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))[c.want]; !ok {
			t.Errorf("%q not recognized as %s", c.raw, c.want)
		}
	}
}
