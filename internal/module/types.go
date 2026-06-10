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
