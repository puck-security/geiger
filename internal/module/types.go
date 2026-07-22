// Package module defines Geiger's core domain types and the Module contract.
//
// A Module is the unit of credential coverage: it recognizes a credential
// (via the recognize package routing to it), optionally performs a single
// headless token exchange, runs read-only recon, and summarizes the result
// into a Note. The common bearer/basic case is built declaratively via the
// recipe subpackage; exotic-signing providers implement Module directly.
package module

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/recon"
)

// Candidate is a single recognized-or-candidate credential plus the context it
// was found in. Source context lets set-shaped recognizers pair co-located
// variables and pick up a tenant/instance/host from the same blob.
type Candidate struct {
	Value  string            // the raw credential string (a token, key, JSON, etc.)
	Source SourceKind        // how it was parsed
	File   string            // origin filename/label, if any
	Vars   map[string]string // co-located key/value pairs (env, dotenv, INI section)
}

// SourceKind records how a candidate was produced.
type SourceKind string

const (
	SourceStdin    SourceKind = "stdin"
	SourceFile     SourceKind = "file"
	SourceEnv      SourceKind = "env"
	SourceDotenv   SourceKind = "dotenv"
	SourceINI      SourceKind = "ini"
	SourceJSON     SourceKind = "json"
	SourceKube     SourceKind = "kubeconfig"
	SourceRegistry SourceKind = "registry"
)

// Fields are the recognizer's extracted, named inputs to a module (access key,
// secret, tenant, instance URL, …). Endpoint-bearing fields may be filled from
// the blob, a default, or the --endpoint flag.
type Fields map[string]string

// Get returns the field value or empty string.
func (f Fields) Get(k string) string { return f[k] }

// EndpointPolicy declares where a module's credential may legitimately be sent.
//
// Endpoints reach geiger from scanned data — a co-located env var, a URL matched
// out of a raw blob, a host concatenated by a recognizer — so they are untrusted:
// a planted value redirects a real credential to whoever planted it. Every module
// templated on a URL-valued field ({endpoint}, {host}, {api}, {server}) declares
// one of these, and recognize.Recognize enforces it centrally, before any module
// code runs. That placement is deliberate: a module that resolves its own host in
// a hand-written recognizer or an Authenticate hook cannot route around it.
//
// This polices the URL as a whole. It is NOT a substitute for recipe.renderBase,
// which polices field values spliced into a *segment* of a base template
// ("https://{shop}.myshopify.com") — that check needs the rendered template and
// so can only happen later. Both are required; neither subsumes the other.
type EndpointPolicy struct {
	// SelfHosted permits any host. Correct for services deployable at an
	// arbitrary domain — Vault, Splunk, GitLab, and every vendor shipping both a
	// SaaS and an on-prem edition. Pinning suffixes for those would break real
	// customer deployments, which is why geiger has no global host allowlist.
	SelfHosted bool
	// HostSuffixes pins a SaaS-only vendor to its own domains. A data-derived
	// host must equal one of these or be a subdomain of it. Include every region
	// and government host the vendor operates: a missing suffix is a broken
	// deployment, not a safe default.
	HostSuffixes []string
}

// EndpointScoped is implemented by modules that declare an EndpointPolicy.
// Modules without one get no host restriction (their endpoint is still required
// to be a structurally valid http(s) URL).
type EndpointScoped interface {
	EndpointPolicy() EndpointPolicy
}

// URLValuedFields are the field names whose value is a whole base URL, as
// opposed to a hostname label spliced into one. These are what EndpointPolicy
// polices.
var URLValuedFields = []string{"endpoint", "host", "api", "server"}

// ValidateEndpointURL enforces the structural rules on a URL that will carry a
// credential: absolute http(s), a host present, and no embedded userinfo.
func ValidateEndpointURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("unparseable URL %q: %w", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not http(s)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("no host in %q", s)
	}
	if u.User != nil {
		return fmt.Errorf("URL carries userinfo")
	}
	return nil
}

// Declared reports whether a policy was actually stated, as opposed to being the
// zero value. recipe.HTTP embeds an EndpointPolicy by value, so every recipe
// module satisfies EndpointScoped whether or not its author filled the field in;
// the catalog guard asserts on this rather than on the interface, or it would
// pass vacuously.
func (p EndpointPolicy) Declared() bool { return p.SelfHosted || len(p.HostSuffixes) > 0 }

// HostAllowed reports whether host satisfies the policy. Matching is on a label
// boundary, so "zendesk.com" accepts "acme.zendesk.com" but not
// "evil-zendesk.com" or "zendesk.com.attacker.tld".
func (p EndpointPolicy) HostAllowed(host string) bool {
	if p.SelfHosted || len(p.HostSuffixes) == 0 {
		return true
	}
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, suf := range p.HostSuffixes {
		suf = strings.ToLower(suf)
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// Token is the result of an authenticate phase (or empty when none is needed).
type Token struct {
	Bearer      string
	InstanceURL string            // e.g. Salesforce instance_url
	Extra       map[string]string // grant-specific extras (scope, expiry, …)
}

// FlagLevel classifies the significance of a finding for the note.
type FlagLevel int

const (
	FlagNone             FlagLevel = iota
	FlagInfo                       // ordinary identity/inventory detail
	FlagWarn                       // notable (prod, PII, broad read)
	FlagForceMultiplier            // turns "valid key" into "incident"
	FlagCantCharacterize           // capability exists but can't be proven read-only
)

// Finding is one line of a Note: a labeled value with a significance flag.
type Finding struct {
	Key   string // short stable key (identity, account, scopes, buckets, …)
	Value string // human-readable value (already redacted where needed)
	Flag  FlagLevel
	// Detail holds the full expansion behind a summarized Value (e.g. the
	// individual file paths behind "8 editor local-history snapshots"). The
	// terminal shows it only with -v; JSON always emits it. Optional.
	Detail []string
}

// Note is a module's summary for one credential.
type Note struct {
	Title    string    // e.g. "GitHub PAT ghp_…JV3Q (from .env: GITHUB_TOKEN)"
	Findings []Finding // ordered lines
	Summary  string    // one-line takeaway, e.g. "org-admin bot token"
	Invalid  bool      // recon proved the credential dead/expired
	Reason   string    // why invalid, or why it could not be characterized
}

// Module is the unit of credential coverage.
type Module interface {
	// Name is the stable module identifier (also used for dedupe).
	Name() string
	// Authenticate performs the optional single headless token exchange.
	// Modules that need no exchange return an empty Token and nil error.
	Authenticate(ctx context.Context, c *recon.Client, f Fields) (Token, error)
	// Recon runs the read-only recipe and returns findings.
	Recon(ctx context.Context, c *recon.Client, t Token, f Fields) ([]Finding, error)
	// Summarize turns findings into the printed Note.
	Summarize(title string, fs []Finding) Note
}

// Harvested is a downstream secret pulled from a secrets store, to be fed back
// through recognition and triaged recursively.
type Harvested struct {
	Label string // provenance, e.g. "secretsmanager:prod/db-password"
	Value string // the extracted secret value
}

// Harvester is implemented by modules that can read a secrets store. Harvest
// EXTRACTS secret values (not just metadata), so the pipeline only calls it
// under --live --intrusive and within a bounded recursion depth/budget.
type Harvester interface {
	Harvest(ctx context.Context, c *recon.Client, t Token, f Fields) ([]Harvested, error)
}

// Base provides a no-op Authenticate so direct-auth modules can embed it.
type Base struct{}

// Authenticate returns an empty token (no exchange).
func (Base) Authenticate(context.Context, *recon.Client, Fields) (Token, error) {
	return Token{}, nil
}
