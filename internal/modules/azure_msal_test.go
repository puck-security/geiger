package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recon"
)

func msalCache(t *testing.T) string {
	at := makeJWT(map[string]any{
		"tid": "11111111-2222-3333-4444-555555555555",
		"upn": "admin@acme.onmicrosoft.com",
		"aud": "https://management.azure.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	cache := map[string]any{
		"AccessToken": map[string]any{
			"k1": map[string]any{"credential_type": "AccessToken", "secret": at,
				"realm": "organizations", "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
				"target": "https://management.azure.com/.default"},
		},
		"RefreshToken": map[string]any{
			"k2": map[string]any{"credential_type": "RefreshToken", "secret": "0.AYrefreshtoken",
				"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"},
		},
		"Account": map[string]any{
			"k3": map[string]any{"username": "admin@acme.onmicrosoft.com", "realm": "11111111-2222-3333-4444-555555555555"},
		},
	}
	b, _ := json.Marshal(cache)
	return string(b)
}

func TestAzureMSALRecognizes(t *testing.T) {
	b := parse.Parse(msalCache(t), "msal_token_cache.json")
	ms := recognizeAzureMSAL(b, "", nil)
	if len(ms) != 1 || ms[0].Module != "azure_msal" {
		t.Fatalf("not recognized: %+v", ms)
	}
	if ms[0].Fields["refresh_token"] != "0.AYrefreshtoken" || ms[0].Fields["client_id"] == "" {
		t.Errorf("fields incomplete: %+v", ms[0].Fields)
	}
}

func TestAzureMSALRefreshAndGraphRecon(t *testing.T) {
	mux := http.NewServeMux()
	exchanged := false
	// realm is "organizations" so the module resolves the real tenant from the
	// JWT tid claim — the token endpoint path is that GUID.
	mux.HandleFunc("/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		exchanged = true
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected refresh_token grant, got %q", r.Form.Get("grant_type"))
		}
		_, _ = w.Write([]byte(`{"access_token":"GRAPHTOKEN","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer GRAPHTOKEN" {
			t.Errorf("recon not using exchanged token: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"displayName":"Acme Admin","userPrincipalName":"admin@acme.onmicrosoft.com"}`))
	})
	mux.HandleFunc("/organization", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"displayName":"Acme Corp"}]}`))
	})
	mux.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"a"},{"subscriptionId":"b"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	orig := azureMSALEndpoints
	azureMSALEndpoints.TokenTmpl = srv.URL + "/%s/oauth2/v2.0/token"
	azureMSALEndpoints.Graph = srv.URL
	azureMSALEndpoints.ARM = srv.URL
	defer func() { azureMSALEndpoints = orig }()

	b := parse.Parse(msalCache(t), "msal_token_cache.json")
	f := recognizeAzureMSAL(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true)
	m := azureMSAL{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !exchanged || tok.Bearer != "GRAPHTOKEN" {
		t.Fatalf("refresh exchange failed: token=%q exchanged=%v", tok.Bearer, exchanged)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["tenant"].Value != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("tenant from JWT wrong: %q", got["tenant"].Value)
	}
	if got["identity"].Value != "Acme Admin" {
		t.Errorf("graph /me identity wrong: %q", got["identity"].Value)
	}
	if got["azure subscriptions"].Value != "2 (cloud control plane)" || got["azure subscriptions"].Flag != module.FlagWarn {
		t.Errorf("subscriptions wrong: %+v", got["azure subscriptions"])
	}
}
