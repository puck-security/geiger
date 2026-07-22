package recon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectStripsCredentialHeadersOnHostChange: Go's own redirect handling
// drops Authorization and Cookie when the host changes, but forwards every
// custom header. Geiger carries credentials in custom headers on most modules
// (X-Vault-Token, api-key, SSWS, X-Auth-Token, session), so a legitimate-looking
// endpoint that 302s to an attacker host would hand the credential over.
func TestRedirectStripsCredentialHeadersOnHostChange(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://collector.attacker.tld/x", nil)
	for k, v := range map[string]string{
		"Authorization":          "Bearer TKN",
		"X-Vault-Token":          "hvs.TKN",
		"api-key":                "TKN",
		"X-Auth-Token":           "TKN",
		"X-Shopify-Access-Token": "TKN",
		"Accept":                 "application/json",
		"User-Agent":             "geiger/dev",
	} {
		req.Header.Set(k, v)
	}
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://vault.acme.internal/v1/auth/token/lookup-self", nil)}

	if err := CheckRedirect(req, via); err != nil {
		t.Fatalf("same-scheme redirect to another host should be followed (headers stripped), got %v", err)
	}

	for _, h := range []string{"Authorization", "X-Vault-Token", "api-key", "X-Auth-Token", "X-Shopify-Access-Token"} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("%s = %q after cross-host redirect, want stripped", h, got)
		}
	}
	// Non-credential headers are content negotiation and honest self-identification.
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want preserved", got)
	}
	if got := req.Header.Get("User-Agent"); got != "geiger/dev" {
		t.Errorf("User-Agent = %q, want preserved", got)
	}
}

// TestRedirectKeepsHeadersOnSameHost: an API redirecting within its own host
// (trailing slash, http→https, version path) is routine and must keep working.
func TestRedirectKeepsHeadersOnSameHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://vault.acme.internal/v1/other", nil)
	req.Header.Set("X-Vault-Token", "hvs.TKN")
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "http://vault.acme.internal/v1/auth", nil)}

	if err := CheckRedirect(req, via); err != nil {
		t.Fatalf("same-host redirect should be followed: %v", err)
	}
	if got := req.Header.Get("X-Vault-Token"); got != "hvs.TKN" {
		t.Errorf("X-Vault-Token = %q on a same-host redirect, want preserved", got)
	}
}

// TestRedirectChainIsBounded stops a redirect loop from burning the timeout.
func TestRedirectChainIsBounded(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://vault.acme.internal/11", nil)
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = httptest.NewRequest(http.MethodGet, "https://vault.acme.internal/x", nil)
	}
	if err := CheckRedirect(req, via); err == nil {
		t.Errorf("an 11-hop redirect chain should be refused")
	}
}
