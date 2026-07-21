package modules

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// findMatch returns the first match for a module name, or nil.
func findMatch(ms []recognize.Match, name string) *recognize.Match {
	for i := range ms {
		if ms[i].Module == name {
			return &ms[i]
		}
	}
	return nil
}

// TestEndpointVarDoesNotSteerUnrelatedService is the credential-exfiltration
// guard. An endpoint variable names the host of ONE service; it must never
// become the base URL for a different service's credential. Otherwise a single
// planted line (GRAFANA_URL=https://attacker.tld) in a file that already holds a
// real Zendesk token redirects that token to the attacker on the --live path.
func TestEndpointVarDoesNotSteerUnrelatedService(t *testing.T) {
	b := parse.Parse("GRAFANA_URL=https://collector.attacker.tld\n"+
		"ZENDESK_API_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n", ".env")
	ms := recognizeEnvNames(b, "", module.Default)

	z := findMatch(ms, "zendesk")
	if z == nil {
		t.Fatalf("zendesk not recognized; got %+v", ms)
	}
	if ep := z.Fields["endpoint"]; ep != "" {
		t.Errorf("zendesk endpoint = %q, want empty: a GRAFANA_URL must not steer a Zendesk token", ep)
	}
}

// TestEndpointVarSteersItsOwnService is the other half: binding must not break
// the legitimate case, where the endpoint belongs to the credential's service.
func TestEndpointVarSteersItsOwnService(t *testing.T) {
	b := parse.Parse("ZENDESK_URL=https://acme.zendesk.com\n"+
		"ZENDESK_API_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n", ".env")
	ms := recognizeEnvNames(b, "", module.Default)

	z := findMatch(ms, "zendesk")
	if z == nil {
		t.Fatalf("zendesk not recognized; got %+v", ms)
	}
	if ep := z.Fields["endpoint"]; ep != "https://acme.zendesk.com" {
		t.Errorf("zendesk endpoint = %q, want the co-located ZENDESK_URL", ep)
	}
}

// TestEndpointFlagOverridesFileDerived: the operator's explicit --endpoint is a
// deliberate assertion; a URL read out of scanned data is untrusted input. The
// flag must win, or a planted host silently beats the operator's choice.
// Splunk stands in for every recognizer that fills "endpoint" from the blob
// itself (resolveEndpoint's whole set, plus Databricks/Snowflake): file-derived
// data currently outranks the flag, because resolveEndpoint checks the blob
// first and injectEndpoint only fills an EMPTY endpoint.
func TestEndpointFlagOverridesFileDerived(t *testing.T) {
	b := parse.Parse("SPLUNK_URL=https://collector.attacker.tld\n"+
		"SPLUNK_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n", ".env")
	ms := recognize.Recognize(b, "https://splunk.acme.internal", module.Default)

	s := findMatch(ms, "splunk")
	if s == nil {
		t.Fatalf("splunk not recognized; got %+v", ms)
	}
	if ep := s.Fields["endpoint"]; ep != "https://splunk.acme.internal" {
		t.Errorf("splunk endpoint = %q, want the --endpoint override to win over the file's SPLUNK_URL", ep)
	}
}
