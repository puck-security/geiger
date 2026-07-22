// Package recognize routes parsed input to modules. It combines two sources:
// gitleaks (the broad net for prefixed/checksummed single strings) and a
// registry of custom recognizer funcs for the set-shaped and file-shaped
// credentials gitleaks handles poorly. Modules register their rule mappings and
// custom recognizers here.
package recognize

import (
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"net/url"
	"strings"
)

// Match is a recognized credential routed to a module.
type Match struct {
	Module string        // module name
	Fields module.Fields // extracted inputs (token, secret, tenant, endpoint, …)
	Secret string        // raw secret, for redaction in the note title
	Label  string        // where it came from, e.g. ".env: GITHUB_TOKEN"
	Line   int           // 1-based source line, 0 if unknown
	// Overrides lists module names this match supersedes for the same credential
	// (matched by secret containment). Lets a structured recognizer suppress a
	// broad-net hit that misattributed the same value — e.g. a WorkOS key claimed
	// over the gitleaks Stripe rule it collides with.
	Overrides []string
}

// RecognizerFunc inspects a parsed blob and returns any matches. endpoint is the
// --endpoint override (may be empty). reg lets a recognizer check which rule
// names route to modules.
type RecognizerFunc func(b parse.Blob, endpoint string, reg *module.Registry) []Match

var custom []RecognizerFunc

// RegisterRecognizer adds a custom recognizer (called by modules in init()).
func RegisterRecognizer(f RecognizerFunc) { custom = append(custom, f) }

// Recognize returns all matches for a blob: gitleaks hits routed by rule id,
// plus every custom recognizer's matches. Matches are deduped by (module,
// secret) keeping the richest one, and generic "unknown" matches whose value is
// already consumed by a recognized set/file match are suppressed as noise.
func Recognize(b parse.Blob, endpoint string, reg *module.Registry) []Match {
	var matches []Match
	matches = append(matches, gitleaksMatches(b, reg)...)
	for _, f := range custom {
		matches = append(matches, f(b, endpoint, reg)...)
	}
	matches = dedupe(matches)
	matches = enforceEndpointPolicy(matches, endpoint, reg)
	matches = suppressOverridden(matches)
	return suppressConsumedUnknowns(matches)
}

// enforceEndpointPolicy is the single chokepoint for every URL a credential may
// be sent to. It runs after all recognizers and before any module code, so it
// covers hand-written modules and Authenticate hooks — not just recipe bases.
//
// Recognizers only ever RETURN matches; they never dial. So however a recognizer
// derived its host (a co-located var, a regex over the raw blob, string
// concatenation), the result passes through here. A new module cannot opt out.
//
// For each URL-valued field:
//
//   - The operator's --endpoint overwrites it. The flag is an explicit assertion;
//     anything read out of the scanned blob is untrusted input that may have been
//     planted, so the flag must not be silently outranked by the file.
//   - The value must be a structurally valid http(s) URL.
//   - It must satisfy the module's declared EndpointPolicy.
//
// On violation the FIELD is cleared, not the match. The credential still
// surfaces — modules/catalog_needs_endpoint.go turns an endpoint-less
// instance-scoped credential into a "set --endpoint and re-run" note — so a
// planted URL degrades into a visible prompt rather than silently dropping a
// live credential (or, worse, shipping it to the planted host).
func enforceEndpointPolicy(in []Match, endpoint string, reg *module.Registry) []Match {
	for i := range in {
		if in[i].Fields == nil {
			in[i].Fields = module.Fields{}
		}
		pol := policyFor(in[i].Module, reg)
		for _, key := range module.URLValuedFields {
			v := in[i].Fields[key]
			// The flag applies to the module's primary endpoint field only; it
			// says nothing about a secondary host a recognizer paired with it.
			if endpoint != "" && key == "endpoint" {
				v = endpoint
			}
			if v == "" {
				continue
			}
			if !endpointPermitted(v, pol) {
				delete(in[i].Fields, key)
				continue
			}
			in[i].Fields[key] = v
		}
	}
	return in
}

// endpointPermitted reports whether a URL is structurally sound AND allowed by
// the module's policy.
func endpointPermitted(raw string, pol module.EndpointPolicy) bool {
	if err := module.ValidateEndpointURL(raw); err != nil {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return pol.HostAllowed(u.Host)
}

// policyFor returns the module's declared policy, or a permissive one when the
// module declares none (structural validation still applies).
func policyFor(name string, reg *module.Registry) module.EndpointPolicy {
	if reg == nil {
		return module.EndpointPolicy{SelfHosted: true}
	}
	m, ok := reg.ByName(name)
	if !ok {
		return module.EndpointPolicy{SelfHosted: true}
	}
	if es, ok := m.(module.EndpointScoped); ok {
		return es.EndpointPolicy()
	}
	return module.EndpointPolicy{SelfHosted: true}
}

// dedupe collapses (module, secret) collisions, preferring the match with the
// most fields (a complete set match beats an incomplete single-string hit).
func dedupe(in []Match) []Match {
	idx := map[string]int{}
	var out []Match
	for _, m := range in {
		key := m.Module + "\x00" + m.Secret
		if i, ok := idx[key]; ok {
			if len(m.Fields) > len(out[i].Fields) {
				out[i] = m
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, m)
	}
	return out
}

// isGeneric reports whether a match comes from a catch-all recognizer (an
// uncovered gitleaks hit, or the generic JWT decoder) that should yield to a
// specific structured recognizer claiming the same secret.
func isGeneric(m Match) bool {
	return strings.HasPrefix(m.Module, "__unknown__:") || m.Module == "jwt" || m.Module == "generic_secret"
}

// suppressOverridden drops matches a sibling explicitly supersedes via
// Overrides. Containment (not equality) is used because a broad-net detector
// like gitleaks may capture only a prefix of the full token (it stops at the
// first '+'/'/' in a base64 body), so the overriding match's secret contains the
// truncated one.
func suppressOverridden(in []Match) []Match {
	drop := make([]bool, len(in))
	for i := range in {
		for _, o := range in[i].Overrides {
			for j := range in {
				if j == i {
					continue
				}
				if in[j].Module == o && in[j].Secret != "" && strings.Contains(in[i].Secret, in[j].Secret) {
					drop[j] = true
				}
			}
		}
	}
	out := in[:0:0]
	for i, m := range in {
		if !drop[i] {
			out = append(out, m)
		}
	}
	return out
}

// suppressConsumedUnknowns drops generic matches whose secret value is already a
// field of a specific (structured) match — e.g. an AWS secret access key that
// also trips generic-api-key, or an SSO registration's clientSecret that also
// decodes as a bare JWT.
func suppressConsumedUnknowns(in []Match) []Match {
	consumed := map[string]bool{}
	for _, m := range in {
		if isGeneric(m) {
			continue
		}
		for _, v := range m.Fields {
			consumed[v] = true
		}
		consumed[m.Secret] = true
	}
	var out []Match
	for _, m := range in {
		if isGeneric(m) && consumed[m.Secret] {
			continue
		}
		out = append(out, m)
	}
	return out
}
