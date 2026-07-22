package recognize

import (
	"context"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// policyModule is a stand-in for a catalog module that declares where its
// credential may legitimately be sent.
type policyModule struct {
	module.Base
	name string
	pol  module.EndpointPolicy
}

func (m policyModule) Name() string                          { return m.name }
func (m policyModule) EndpointPolicy() module.EndpointPolicy { return m.pol }
func (policyModule) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return nil, nil
}
func (policyModule) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs}
}

// plainModule declares no policy at all.
type plainModule struct{ policyModule }

func (m plainModule) Name() string { return m.name }

func regWith(mods ...module.Module) *module.Registry {
	reg := module.NewRegistry()
	for _, m := range mods {
		reg.Register(m)
	}
	return reg
}

func saas(name string, suffixes ...string) policyModule {
	return policyModule{name: name, pol: module.EndpointPolicy{HostSuffixes: suffixes}}
}

func selfHosted(name string) policyModule {
	return policyModule{name: name, pol: module.EndpointPolicy{SelfHosted: true}}
}

func match(mod, endpoint string) []Match {
	return []Match{{Module: mod, Fields: module.Fields{"token": "TKN", "endpoint": endpoint}}}
}

// TestPolicyDropsOffSuffixHost is the class guard. However a recognizer computed
// its endpoint — a co-located var, a regex over the raw blob, string
// concatenation — a SaaS module's credential must never be aimed at a host
// outside that vendor. The endpoint is dropped rather than the match, so the
// credential still surfaces via needs_endpoint instead of vanishing.
func TestPolicyDropsOffSuffixHost(t *testing.T) {
	reg := regWith(saas("zendesk", "zendesk.com"))
	out := enforceEndpointPolicy(match("zendesk", "https://collector.attacker.tld"), "", reg)

	if len(out) != 1 {
		t.Fatalf("match must survive so needs_endpoint can surface it; got %+v", out)
	}
	if ep := out[0].Fields["endpoint"]; ep != "" {
		t.Errorf("endpoint = %q, want dropped", ep)
	}
	if out[0].Fields["token"] != "TKN" {
		t.Errorf("credential must be preserved: %+v", out[0].Fields)
	}
}

func TestPolicyKeepsOnSuffixHost(t *testing.T) {
	reg := regWith(saas("zendesk", "zendesk.com"))
	out := enforceEndpointPolicy(match("zendesk", "https://acme.zendesk.com"), "", reg)

	if ep := out[0].Fields["endpoint"]; ep != "https://acme.zendesk.com" {
		t.Errorf("endpoint = %q, want kept", ep)
	}
}

// TestPolicySuffixMatchIsBoundary stops "evil-zendesk.com" or
// "zendesk.com.attacker.tld" from passing a naive substring/suffix check.
func TestPolicySuffixMatchIsBoundary(t *testing.T) {
	reg := regWith(saas("zendesk", "zendesk.com"))
	for _, host := range []string{
		"https://evil-zendesk.com",
		"https://zendesk.com.attacker.tld",
		"https://notzendesk.com",
	} {
		out := enforceEndpointPolicy(match("zendesk", host), "", reg)
		if ep := out[0].Fields["endpoint"]; ep != "" {
			t.Errorf("host %q accepted as zendesk.com (endpoint = %q)", host, ep)
		}
	}
}

// TestPolicySelfHostedAllowsAnyHost protects geiger's core use case: triaging a
// self-hosted instance at an arbitrary internal domain.
func TestPolicySelfHostedAllowsAnyHost(t *testing.T) {
	reg := regWith(selfHosted("vault"))
	out := enforceEndpointPolicy(match("vault", "https://vault.acme.internal:8200"), "", reg)

	if ep := out[0].Fields["endpoint"]; ep != "https://vault.acme.internal:8200" {
		t.Errorf("endpoint = %q, want kept for a self-hosted module", ep)
	}
}

// TestPolicyFlagOutranksScannedData: --endpoint is an operator assertion and
// must beat any value a recognizer read out of the blob, for every module.
func TestPolicyFlagOutranksScannedData(t *testing.T) {
	reg := regWith(selfHosted("vault"))
	out := enforceEndpointPolicy(match("vault", "https://collector.attacker.tld"), "https://vault.acme.internal", reg)

	if ep := out[0].Fields["endpoint"]; ep != "https://vault.acme.internal" {
		t.Errorf("endpoint = %q, want the --endpoint override", ep)
	}
}

// TestPolicyRejectsMalformedURL applies even to self-hosted modules: a scheme
// that isn't http(s), or userinfo smuggled into the authority, is never a
// legitimate instance URL.
func TestPolicyRejectsMalformedURL(t *testing.T) {
	reg := regWith(selfHosted("vault"))
	for _, bad := range []string{
		"file:///etc/passwd",
		"https://user:pw@collector.attacker.tld",
		"not-a-url",
		"https://",
	} {
		out := enforceEndpointPolicy(match("vault", bad), "", reg)
		if ep := out[0].Fields["endpoint"]; ep != "" {
			t.Errorf("malformed endpoint %q accepted (endpoint = %q)", bad, ep)
		}
	}
}

// TestPolicyPolicesEveryURLValuedField: recognizers fill several host-bearing
// field names, not just "endpoint".
func TestPolicyPolicesEveryURLValuedField(t *testing.T) {
	reg := regWith(saas("workday", "workday.com"))
	for _, field := range []string{"endpoint", "host", "api", "server"} {
		in := []Match{{Module: "workday", Fields: module.Fields{"token": "TKN", field: "https://collector.attacker.tld"}}}
		out := enforceEndpointPolicy(in, "", reg)
		if v := out[0].Fields[field]; v != "" {
			t.Errorf("field %q = %q, want dropped", field, v)
		}
	}
}

// TestPolicyUndeclaredModuleStillValidatesStructure: a module with no declared
// policy gets no host restriction, but malformed URLs are still refused.
func TestPolicyUndeclaredModuleStillValidatesStructure(t *testing.T) {
	reg := regWith(plainModule{policyModule{name: "mystery"}})
	if out := enforceEndpointPolicy(match("mystery", "https://anything.example.com"), "", reg); out[0].Fields["endpoint"] == "" {
		t.Error("undeclared module should not get a host restriction")
	}
	if out := enforceEndpointPolicy(match("mystery", "file:///etc/passwd"), "", reg); out[0].Fields["endpoint"] != "" {
		t.Error("undeclared module must still reject a non-http scheme")
	}
}
