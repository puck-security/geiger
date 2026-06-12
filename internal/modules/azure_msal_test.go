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

func msalCache(t *testing.T, exp time.Time) string {
	at := makeJWT(map[string]any{
		"tid": "11111111-2222-3333-4444-555555555555",
		"upn": "admin@acme.onmicrosoft.com",
		"aud": "https://management.azure.com",
		"exp": float64(exp.Unix()),
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

// msalServer stands up the token + Graph + ARM endpoints and records whether the
// refresh token was redeemed and which bearer recon presented at /me.
func msalServer(t *testing.T) (exchanged *bool, meAuth *string, srv *httptest.Server) {
	ex, auth := false, ""
	mux := http.NewServeMux()
	// realm is "organizations" so the module resolves the real tenant from the JWT
	// tid claim — the token endpoint path is that GUID.
	mux.HandleFunc("/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		ex = true
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected refresh_token grant, got %q", r.Form.Get("grant_type"))
		}
		_, _ = w.Write([]byte(`{"access_token":"GRAPHTOKEN","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"displayName":"Acme Admin","userPrincipalName":"admin@acme.onmicrosoft.com"}`))
	})
	mux.HandleFunc("/organization", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"displayName":"Acme Corp"}]}`))
	})
	mux.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"a"},{"subscriptionId":"b"}]}`))
	})
	srv = httptest.NewServer(mux)
	orig := azureMSALEndpoints
	azureMSALEndpoints.TokenTmpl = srv.URL + "/%s/oauth2/v2.0/token"
	azureMSALEndpoints.Graph = srv.URL
	azureMSALEndpoints.ARM = srv.URL
	t.Cleanup(func() { azureMSALEndpoints = orig })
	return &ex, &auth, srv
}

func TestAzureMSALRecognizes(t *testing.T) {
	b := parse.Parse(msalCache(t, time.Now().Add(time.Hour)), "msal_token_cache.json")
	ms := recognizeAzureMSAL(b, "", nil)
	if len(ms) != 1 || ms[0].Module != "azure_msal" {
		t.Fatalf("not recognized: %+v", ms)
	}
	if ms[0].Fields["refresh_token"] != "0.AYrefreshtoken" || ms[0].Fields["client_id"] == "" {
		t.Errorf("fields incomplete: %+v", ms[0].Fields)
	}
}

// A still-valid cached access token reads Graph directly under plain --live — the
// refresh token is NOT redeemed (no new sign-in), but it is flagged as the exposure.
func TestAzureMSALCachedTokenNoRefresh(t *testing.T) {
	exchanged, meAuth, srv := msalServer(t)
	defer srv.Close()

	b := parse.Parse(msalCache(t, time.Now().Add(time.Hour)), "msal_token_cache.json")
	f := recognizeAzureMSAL(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true) // live, NOT intrusive
	m := azureMSAL{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Bearer != f["access_token"] {
		t.Fatalf("a valid cached token should be used verbatim, got %q", tok.Bearer)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	if *exchanged {
		t.Error("a valid cached token must NOT trigger a refresh under plain --live")
	}
	if *meAuth != "Bearer "+f["access_token"] {
		t.Errorf("recon should use the cached token, got %q", *meAuth)
	}
	got := indexByKey(fs)
	if got["identity"].Value != "Acme Admin" {
		t.Errorf("graph /me identity wrong: %q", got["identity"].Value)
	}
	if got["refresh token"].Flag != module.FlagForceMultiplier {
		t.Errorf("a usable refresh token must be a force multiplier: %+v", got["refresh token"])
	}
}

// --intrusive with an expired cached token: the refresh token IS redeemed and recon
// maps reach off the freshly minted Graph token.
func TestAzureMSALIntrusiveRefresh(t *testing.T) {
	exchanged, meAuth, srv := msalServer(t)
	defer srv.Close()

	b := parse.Parse(msalCache(t, time.Now().Add(-time.Hour)), "msal_token_cache.json") // expired
	f := recognizeAzureMSAL(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)
	m := azureMSAL{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !*exchanged || tok.Bearer != "GRAPHTOKEN" {
		t.Fatalf("refresh should run under --intrusive: token=%q exchanged=%v", tok.Bearer, *exchanged)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	if *meAuth != "Bearer GRAPHTOKEN" {
		t.Errorf("recon should use the exchanged token, got %q", *meAuth)
	}
	got := indexByKey(fs)
	if got["identity"].Value != "Acme Admin" {
		t.Errorf("graph /me identity wrong: %q", got["identity"].Value)
	}
	if got["azure subscriptions"].Value != "2 (cloud control plane)" || got["azure subscriptions"].Flag != module.FlagWarn {
		t.Errorf("subscriptions wrong: %+v", got["azure subscriptions"])
	}
}

// Expired cached token under plain --live (no --intrusive): geiger does NOT redeem
// the refresh token; it flags the re-mintable session and hints to add --intrusive.
func TestAzureMSALExpiredGatedBehindIntrusive(t *testing.T) {
	exchanged, _, srv := msalServer(t)
	defer srv.Close()

	b := parse.Parse(msalCache(t, time.Now().Add(-time.Hour)), "msal_token_cache.json")
	f := recognizeAzureMSAL(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true) // live, NOT intrusive
	m := azureMSAL{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if *exchanged || tok.Bearer != "" {
		t.Fatalf("expired token must NOT be refreshed without --intrusive: token=%q exchanged=%v", tok.Bearer, *exchanged)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["refresh token"].Flag != module.FlagForceMultiplier {
		t.Errorf("the usable refresh token must be flagged: %+v", got["refresh token"])
	}
	if got["deepen"].Value == "" {
		t.Errorf("expected an --intrusive deepen hint: %+v", fs)
	}
}
