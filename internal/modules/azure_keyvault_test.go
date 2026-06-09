package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// azureVaultMux builds an httptest server emulating the Entra token endpoint,
// ARM (subscriptions + vault list) and the Key Vault data plane.
func azureVaultMux(t *testing.T, vaultBase func() string) *http.ServeMux {
	mux := http.NewServeMux()
	// Token endpoint: hand out an audience-specific token so we can assert the
	// data-plane call used the vault-scoped one.
	mux.HandleFunc("/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		scope := r.Form.Get("scope")
		tok := "OTHER"
		switch {
		case strings.Contains(scope, "management.azure.com"):
			tok = "ARMTOKEN"
		case strings.Contains(scope, "vault.azure.net"):
			tok = "VAULTTOKEN"
		}
		_, _ = w.Write([]byte(`{"access_token":"` + tok + `","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ARMTOKEN" {
			t.Errorf("subscription list not using ARM token: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"sub-1"}]}`))
	})
	mux.HandleFunc("/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"properties":{"vaultUri":"` + vaultBase() + `/"}}]}`))
	})
	// Key Vault data plane (same server, distinct paths).
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer VAULTTOKEN" {
			t.Errorf("vault list not using vault token: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"` + vaultBase() + `/secrets/api-key"}]}`))
	})
	mux.HandleFunc("/secrets/api-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer VAULTTOKEN" {
			t.Errorf("vault get not using vault token: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":"sk-prod-downstream-secret","id":"` + vaultBase() + `/secrets/api-key"}`))
	})
	return mux
}

func TestEntraSPHarvestsKeyVault(t *testing.T) {
	var srv *httptest.Server
	mux := azureVaultMux(t, func() string { return srv.URL })
	srv = httptest.NewServer(mux)
	defer srv.Close()

	orig := azureMSALEndpoints
	azureMSALEndpoints.TokenTmpl = srv.URL + "/%s/oauth2/v2.0/token"
	azureMSALEndpoints.ARM = srv.URL
	defer func() { azureMSALEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)

	got := azureVaultHarvestSP(context.Background(), c, "11111111-2222-3333-4444-555555555555", "appid", "appsecret")
	if len(got) != 1 {
		t.Fatalf("expected 1 harvested vault secret, got %d: %+v", len(got), got)
	}
	if got[0].Value != "sk-prod-downstream-secret" {
		t.Errorf("vault secret value wrong: %q", got[0].Value)
	}
	if !strings.HasPrefix(got[0].Label, "azure keyvault:") {
		t.Errorf("provenance label wrong: %q", got[0].Label)
	}
}

func TestAzureMSALHarvestNeedsRefreshToken(t *testing.T) {
	c := recon.New(http.DefaultClient, true)
	c.SetIntrusive(true)
	// No refresh_token/client_id → nothing to re-scope, must no-op.
	got, err := azureMSAL{}.Harvest(context.Background(), c, module.Token{}, module.Fields{})
	if err != nil || got != nil {
		t.Errorf("expected no-op without refresh token, got %+v err=%v", got, err)
	}
}
