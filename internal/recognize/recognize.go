// Package recognize routes parsed input to modules. It combines two sources:
// gitleaks (the broad net for prefixed/checksummed single strings) and a
// registry of custom recognizer funcs for the set-shaped and file-shaped
// credentials gitleaks handles poorly. Modules register their rule mappings and
// custom recognizers here.
package recognize

import (
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
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
	matches = injectEndpoint(matches, endpoint)
	matches = suppressOverridden(matches)
	return suppressConsumedUnknowns(matches)
}

// injectEndpoint makes the --endpoint value available to every module templated
// on {endpoint}, including those recognized by gitleaks (whose matches carry
// only the token). A recognizer that already set "endpoint" wins.
func injectEndpoint(in []Match, endpoint string) []Match {
	if endpoint == "" {
		return in
	}
	for i := range in {
		if in[i].Fields == nil {
			in[i].Fields = module.Fields{}
		}
		if in[i].Fields["endpoint"] == "" {
			in[i].Fields["endpoint"] = endpoint
		}
	}
	return in
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
	for _, m := range in {
		for _, o := range m.Overrides {
			for j := range in {
				if in[j].Module == o && in[j].Secret != "" && strings.Contains(m.Secret, in[j].Secret) {
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
