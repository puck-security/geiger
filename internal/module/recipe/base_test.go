package recipe

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// hostOfPlanned returns the host of the i-th planned call, for asserting where a
// credential would actually have been sent.
func hostOfPlanned(t *testing.T, c *recon.Client, i int) string {
	t.Helper()
	p := c.Planned()
	if i >= len(p) {
		t.Fatalf("no planned call at index %d (%d planned)", i, len(p))
	}
	u, err := url.Parse(p[i].URL)
	if err != nil {
		t.Fatalf("planned URL %q unparseable: %v", p[i].URL, err)
	}
	return u.Host
}

// TestBaseSegmentCannotHijackHost: a field substituted into a *segment* of the
// base URL is a hostname label, not a URL. A value carrying a URL delimiter
// ("/", "#", "?", "@") would otherwise relocate the whole request — the token in
// https://{shop}.myshopify.com goes to the attacker when shop is "evil.tld/".
// Recognizers derive these segments from scanned data, so they are attacker-
// reachable and must never be able to move the host.
func TestBaseSegmentCannotHijackHost(t *testing.T) {
	hijacks := map[string]string{
		"path":     "evil.tld/",
		"fragment": "evil.tld#",
		"query":    "evil.tld?",
		"userinfo": "evil.tld@",
	}
	for name, shop := range hijacks {
		t.Run(name, func(t *testing.T) {
			spec := HTTP{
				ModuleName: "demo",
				Base:       "https://{shop}.myshopify.com",
				Auth:       AuthSpec{Kind: Bearer},
				Whoami:     GET("/admin/api/shop.json"),
			}
			c := recon.New(nil, false) // dry-run: records, sends nothing
			_, _ = spec.Module().Recon(context.Background(), c, module.Token{},
				module.Fields{"token": "TKN", "shop": shop})

			for i, p := range c.Planned() {
				host := hostOfPlanned(t, c, i)
				if !strings.HasSuffix(host, ".myshopify.com") {
					t.Errorf("credential would be sent to %q (planned %q); a base segment must not move the host",
						host, p.URL)
				}
			}
		})
	}
}

// TestBaseSegmentAllowsOrdinaryValue keeps the guard from breaking the normal
// case it exists to protect.
func TestBaseSegmentAllowsOrdinaryValue(t *testing.T) {
	spec := HTTP{
		ModuleName: "demo",
		Base:       "https://{shop}.myshopify.com",
		Auth:       AuthSpec{Kind: Bearer},
		Whoami:     GET("/admin/api/shop.json"),
	}
	c := recon.New(nil, false)
	_, _ = spec.Module().Recon(context.Background(), c, module.Token{},
		module.Fields{"token": "TKN", "shop": "acme-store"})

	if got := hostOfPlanned(t, c, 0); got != "acme-store.myshopify.com" {
		t.Errorf("host = %q, want acme-store.myshopify.com", got)
	}
}

// TestWholeBaseEndpointMustBeHTTPURL: for a "{endpoint}"-templated module the
// field IS the base URL, so it is validated as one. A non-http scheme must not
// reach the transport.
func TestWholeBaseEndpointMustBeHTTPURL(t *testing.T) {
	spec := HTTP{
		ModuleName: "demo",
		Base:       "{endpoint}",
		Auth:       AuthSpec{Kind: Bearer},
		Whoami:     GET("/api/v2/users/me"),
	}
	c := recon.New(nil, false)
	_, _ = spec.Module().Recon(context.Background(), c, module.Token{},
		module.Fields{"token": "TKN", "endpoint": "file:///etc/passwd"})

	if n := len(c.Planned()); n != 0 {
		t.Errorf("planned %d call(s) for a non-http endpoint: %+v", n, c.Planned())
	}
}

// TestWholeBaseEndpointAllowsSelfHostedURL: geiger's core job includes triaging
// self-hosted instances at arbitrary domains, so an ordinary https URL must
// still pass. The guard is about URL *structure*, not host reputation.
func TestWholeBaseEndpointAllowsSelfHostedURL(t *testing.T) {
	spec := HTTP{
		ModuleName: "demo",
		Base:       "{endpoint}",
		Auth:       AuthSpec{Kind: Bearer},
		Whoami:     GET("/api/v2/users/me"),
	}
	c := recon.New(nil, false)
	_, _ = spec.Module().Recon(context.Background(), c, module.Token{},
		module.Fields{"token": "TKN", "endpoint": "https://vault.acme.internal:8200"})

	if got := hostOfPlanned(t, c, 0); got != "vault.acme.internal:8200" {
		t.Errorf("host = %q, want vault.acme.internal:8200", got)
	}
}

// TestMissingEndpointIsNotDead: a {endpoint} module whose endpoint is simply
// unknown must not be summarized as DEAD. "No instance URL configured" says
// nothing about whether the credential is live, and burying a valid token as
// dead is the failure mode an operator acts on by ignoring it.
func TestMissingEndpointIsNotDead(t *testing.T) {
	spec := HTTP{
		ModuleName: "demo",
		Base:       "{endpoint}",
		Auth:       AuthSpec{Kind: Bearer},
		Whoami:     GET("/api/v2/users/me"),
	}
	mod := spec.Module()
	c := recon.New(nil, false)
	fs, err := mod.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "TKN"})
	if err != nil {
		t.Fatalf("a missing endpoint is not an error: %v", err)
	}
	if n := len(c.Planned()); n != 0 {
		t.Errorf("planned %d call(s) with no endpoint", n)
	}
	if note := mod.Summarize("demo", fs); note.Invalid {
		t.Errorf("summarized as DEAD (%q); a credential with no known endpoint is unproven, not dead", note.Reason)
	}
}
