// Package recipe builds declarative HTTP modules. The common bearer/basic
// whoami-plus-counts credential becomes a small data value; recipe.HTTP{...}
// .Module() returns a module.Module that the registry can hold alongside the
// hand-written exotic-signing modules.
package recipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// AuthKind selects how the credential is attached to each request.
type AuthKind int

const (
	// Bearer sets "Authorization: Bearer <token>".
	Bearer AuthKind = iota
	// BasicKeyUser sets HTTP Basic with the token as username, empty password
	// (Stripe, Twilio-style).
	BasicKeyUser
	// Basic uses Fields[UserField]:Fields[PassField] as HTTP Basic.
	Basic
	// Header sets a custom header (HeaderName) to ValuePrefix+token.
	Header
	// PreAuthed means Authenticate already produced a bearer Token; attach it.
	PreAuthed
	// None attaches no auth (token is in the URL or in static Headers).
	None
)

// AuthSpec describes request authentication.
type AuthSpec struct {
	Kind        AuthKind
	HeaderName  string // for Header
	ValuePrefix string // for Header (e.g. "token ", "SSWS ")
	UserField   string // for Basic
	PassField   string // for Basic
	TokenField  string // Fields key holding the secret; defaults to "token"
	// RawAuth, with PreAuthed, sets Authorization to ValuePrefix+token instead of
	// the default "Bearer " scheme (e.g. CyberArk PVWA's raw session token).
	RawAuth bool
}

// Extract pulls a labeled value out of a JSON response body.
type Extract struct {
	Key  string
	Path string // dotted JSON path
	Flag module.FlagLevel
}

// CountSpec sizes blast radius cheaply.
type CountSpec struct {
	Key          string
	Path         string // count = numeric value at path, or array length at path
	ArrayLen     bool   // treat Path as an array and use its length
	FromLinkLast bool   // parse Link rel="last" page number from the response
	Flag         module.FlagLevel
}

// Signal raises a flag when a response field contains/matches something.
type Signal struct {
	Path     string // JSON path to inspect (string or joined array)
	Contains string // substring trigger
	Regex    string // regex trigger (alternative to Contains)
	Key      string // finding key to emit
	Value    string // finding value (defaults to the matched field value)
	Flag     module.FlagLevel
}

// Call is one read-only request in a recipe.
type Call struct {
	Method       string // default GET
	Path         string // appended to Base; may template {field}
	Accept       string
	ReadOnlyPOST bool
	Body         string
	Fields       []Extract
	Count        *CountSpec
	Signals      []Signal
	Optional     bool // a failure here doesn't abort the whole recon
}

// GET is a convenience constructor.
func GET(path string) Call { return Call{Method: http.MethodGet, Path: path} }

// Field adds a labeled extraction (builder style).
func (c Call) Field(key, path string) Call {
	c.Fields = append(c.Fields, Extract{Key: key, Path: path})
	return c
}

// FlagField adds a labeled extraction carrying a flag level.
func (c Call) FlagField(key, path string, fl module.FlagLevel) Call {
	c.Fields = append(c.Fields, Extract{Key: key, Path: path, Flag: fl})
	return c
}

// Signal adds a flag-raising signal (builder style).
func (c Call) Signal(s Signal) Call {
	c.Signals = append(c.Signals, s)
	return c
}

// CountFrom adds a count extraction from a numeric JSON path.
func (c Call) CountFrom(path, key string) Call {
	c.Count = &CountSpec{Key: key, Path: path}
	return c
}

// CountArray counts the length of a JSON array at path.
func (c Call) CountArray(path, key string) Call {
	c.Count = &CountSpec{Key: key, Path: path, ArrayLen: true}
	return c
}

// CountFlag is like CountFrom but tags the count with a flag level (e.g. to
// mark access to a PII or data-store resource).
func (c Call) CountFlag(path, key string, fl module.FlagLevel) Call {
	c.Count = &CountSpec{Key: key, Path: path, Flag: fl}
	return c
}

// CountArrayFlag is like CountArray with a flag level.
func (c Call) CountArrayFlag(path, key string, fl module.FlagLevel) Call {
	c.Count = &CountSpec{Key: key, Path: path, ArrayLen: true, Flag: fl}
	return c
}

// HTTP is a declarative module specification.
type HTTP struct {
	Rule       string            // gitleaks rule id (routing); may be empty for custom-recognized
	ModuleName string            // overrides the module name (defaults to Rule)
	Base       string            // base URL, may template {field}
	Accept     string            // default Accept header for all calls
	Headers    map[string]string // static extra headers on every request
	Auth       AuthSpec
	Whoami     Call
	Calls      []Call // additional inventory/count calls
	// TitlePrefix is shown before the redacted key in the note title.
	TitlePrefix string
	// Summarize, if set, produces the one-line takeaway from findings.
	Summarize func([]module.Finding) string
	// Authenticate, if set, runs the optional headless token exchange before
	// recon; its Token is attached when Auth.Kind == PreAuthed.
	Authenticate func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error)
	// Static findings are appended unconditionally (e.g. "scopes not
	// introspectable read-only" for restricted keys).
	Static []module.Finding
	// Harvest, if set, extracts downstream secret values for recursive triage.
	// The pipeline only invokes it under --live --intrusive within the bounded
	// recursion budget; implementations must self-gate on c.Live()/c.Intrusive().
	Harvest func(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error)
}

// Module materializes the spec into a module.Module.
func (h HTTP) Module() module.Module {
	name := h.ModuleName
	if name == "" {
		name = h.Rule
	}
	return &recipeModule{spec: h, name: name}
}

type recipeModule struct {
	module.Base
	spec HTTP
	name string
}

func (m *recipeModule) Name() string { return m.name }

// Authenticate runs the optional token-exchange hook.
func (m *recipeModule) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	if m.spec.Authenticate != nil {
		return m.spec.Authenticate(ctx, c, f)
	}
	return module.Token{}, nil
}

// Harvest runs the optional downstream-secret-extraction hook. Recipe modules
// without one harvest nothing.
func (m *recipeModule) Harvest(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error) {
	if m.spec.Harvest != nil {
		return m.spec.Harvest(ctx, c, t, f)
	}
	return nil, nil
}

var fieldRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

func tmpl(s string, f module.Fields) string {
	return fieldRe.ReplaceAllStringFunc(s, func(sub string) string {
		key := strings.Trim(sub, "{}")
		return f[key]
	})
}

// tmplJSON substitutes fields like tmpl but JSON-escapes each value, for use in
// JSON request bodies. Raw substitution of a credential containing a quote or
// backslash would otherwise break the body or inject additional JSON keys.
func tmplJSON(s string, f module.Fields) string {
	return fieldRe.ReplaceAllStringFunc(s, func(sub string) string {
		key := strings.Trim(sub, "{}")
		b, err := json.Marshal(f[key])
		if err != nil {
			return ""
		}
		return string(b[1 : len(b)-1]) // strip the surrounding quotes json.Marshal adds
	})
}

func (m *recipeModule) applyAuth(req *http.Request, f module.Fields, t module.Token) {
	a := m.spec.Auth
	tokField := a.TokenField
	if tokField == "" {
		tokField = "token"
	}
	tok := f[tokField]
	switch a.Kind {
	case Bearer:
		req.Header.Set("Authorization", "Bearer "+tok)
	case PreAuthed:
		// Default scheme is Bearer on the Authorization header; ValuePrefix with
		// RawAuth overrides the scheme (CyberArk PVWA's raw session token). A set
		// HeaderName carries the exchanged token on a non-Authorization header
		// instead (Splunk "Authorization: Splunk", Commvault "Authtoken: QSDK",
		// Puppet "X-Authentication", SaltStack "X-Auth-Token").
		header, prefix := "Authorization", "Bearer "
		if a.RawAuth {
			prefix = a.ValuePrefix
		}
		if a.HeaderName != "" {
			header, prefix = a.HeaderName, a.ValuePrefix
		}
		req.Header.Set(header, prefix+t.Bearer)
	case BasicKeyUser:
		req.SetBasicAuth(tok, "")
	case Basic:
		req.SetBasicAuth(f[a.UserField], f[a.PassField])
	case Header:
		req.Header.Set(a.HeaderName, a.ValuePrefix+tok)
	case None:
		// token is carried in the URL or in static Headers
	}
}

func (m *recipeModule) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	base := tmpl(m.spec.Base, f)
	if t.InstanceURL != "" && base == "" {
		base = t.InstanceURL
	}
	var findings []module.Finding
	// A successful token exchange already proves the credential is valid, so a
	// scoped recon failure afterwards must not mark it dead.
	if m.spec.Auth.Kind == PreAuthed && t.Bearer != "" && t.Bearer != "<dry-run-token>" {
		findings = append(findings, module.Finding{Key: "authenticated", Value: "token exchange succeeded — credential is valid", Flag: module.FlagInfo})
	}

	calls := []Call{m.spec.Whoami}
	if !c.MinFootprint() { // OPSEC: identity-only run skips the inventory fan-out
		calls = append(calls, m.spec.Calls...)
	}
	// Per-call errors are non-fatal: a valid-but-scoped key may be denied on the
	// whoami yet succeed elsewhere. But a 401 on the whoami means the credential
	// itself is rejected, so stop there rather than fan out against a dead key
	// (403 = authenticated-but-forbidden, i.e. scoped → keep probing).
	//
	// We also track *why* recon came up empty so we don't bury a live credential
	// as DEAD: a 2xx/403 means the token was accepted (authed) even if we failed
	// to parse identity; a transport error means the endpoint was unreachable
	// (which says nothing about validity); only a 401 on the whoami is dead.
	var authed, sawHTTP, rejected, transportErr bool
	for i, call := range calls {
		fs, status, err := m.runCall(ctx, c, base, call, f, t)
		if err != nil {
			var se statusErr
			if errors.As(err, &se) {
				sawHTTP = true
				if se.code == http.StatusForbidden {
					authed = true // authenticated but forbidden → scoped, not dead
				}
				if i == 0 && se.code == http.StatusUnauthorized {
					rejected = true
					break
				}
			} else {
				transportErr = true // DNS/refused/timeout — not a verdict on the key
			}
			continue
		}
		if status == 0 {
			continue // dry-run: no live response
		}
		sawHTTP = true
		if status >= 200 && status < 300 {
			authed = true
		}
		findings = append(findings, fs...)
	}
	if len(findings) > 0 {
		// Static findings (e.g. "scopes not introspectable") only accompany a
		// live credential, i.e. when recon actually produced findings.
		findings = append(findings, m.spec.Static...)
		return dedupeByKey(findings), nil
	}
	// Empty recon: classify rather than defaulting to DEAD (Summarize marks an
	// empty note Invalid). Only an outright 401 leaves it empty.
	switch {
	case rejected:
		// genuinely rejected → leave empty so Summarize marks it Invalid (DEAD).
	case authed:
		findings = append(findings, module.Finding{Key: "authenticated",
			Value: "credential accepted (HTTP 2xx/403) but identity not parsed — scoped key or the API shape changed",
			Flag:  module.FlagWarn})
	case transportErr && !sawHTTP:
		findings = append(findings, module.Finding{Key: "unreachable",
			Value: "endpoint unreachable from here — credential may be valid in its own network",
			Flag:  module.FlagInfo})
	case sawHTTP:
		findings = append(findings, module.Finding{Key: "unconfirmed",
			Value: "endpoint returned an unexpected response — could not confirm credential validity",
			Flag:  module.FlagInfo})
	}
	return dedupeByKey(findings), nil
}

// dedupeByKey keeps the first finding per key (heuristic privilege/PII signals
// can be emitted by several calls; they should appear once).
func dedupeByKey(in []module.Finding) []module.Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		out = append(out, f)
	}
	return out
}

// runCall executes one recipe call and returns its findings, the HTTP status
// code (0 for a dry-run or a transport error), and any error. The status lets
// Recon distinguish an accepted credential from a rejected or unreachable one.
func (m *recipeModule) runCall(ctx context.Context, c *recon.Client, base string, call Call, f module.Fields, t module.Token) ([]module.Finding, int, error) {
	method := call.Method
	if method == "" {
		method = http.MethodGet
	}
	url := base + tmpl(call.Path, f)
	var body []byte
	if call.Body != "" {
		body = []byte(tmplJSON(call.Body, f)) // bodies are JSON; escape field values
	}
	req, err := recon.NewRequest(ctx, method, url, body)
	if err != nil {
		return nil, 0, err
	}
	m.applyAuth(req, f, t)
	accept := call.Accept
	if accept == "" {
		accept = m.spec.Accept
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for k, v := range m.spec.Headers {
		req.Header.Set(k, tmpl(v, f))
	}
	if call.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: call.ReadOnlyPOST})
	if err != nil {
		return nil, 0, err
	}
	if resp.DryRun {
		return nil, 0, nil
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return nil, resp.Status, statusErr{resp.Status}
	}
	var decoded any
	_ = json.Unmarshal(resp.Body, &decoded)

	var out []module.Finding
	for _, e := range call.Fields {
		if v, ok := getString(decoded, e.Path); ok && v != "" {
			out = append(out, module.Finding{Key: e.Key, Value: v, Flag: e.Flag})
		}
	}
	if cs := call.Count; cs != nil {
		if n, ok := countValue(decoded, resp, cs); ok {
			out = append(out, module.Finding{Key: cs.Key, Value: strconv.Itoa(n), Flag: cs.Flag})
		}
	}
	for _, s := range call.Signals {
		if v, ok := getString(decoded, s.Path); ok {
			matched := false
			if s.Contains != "" && strings.Contains(v, s.Contains) {
				matched = true
			}
			if s.Regex != "" {
				if re, err := regexp.Compile(s.Regex); err == nil && re.MatchString(v) {
					matched = true
				}
			}
			if matched {
				val := s.Value
				if val == "" {
					val = v
				}
				out = append(out, module.Finding{Key: s.Key, Value: val, Flag: s.Flag})
			}
		}
	}
	// Drift-resilient supplement: scan the response for privilege/PII signals,
	// and fall back to a generic identity/count when declared paths matched
	// nothing (e.g. the API changed shape).
	out = append(out, heuristicFindings(decoded, len(out) == 0)...)
	return out, resp.Status, nil
}

func countValue(decoded any, resp *recon.Response, cs *CountSpec) (int, bool) {
	if cs.FromLinkLast {
		if n, ok := linkLastPage(resp.Header.Get("Link")); ok {
			return n, true
		}
		return 0, false
	}
	if cs.ArrayLen {
		return arrayLen(decoded, cs.Path)
	}
	if s, ok := getString(decoded, cs.Path); ok {
		if n, err := strconv.Atoi(s); err == nil {
			return n, true
		}
	}
	return 0, false
}

var linkLastRe = regexp.MustCompile(`[?&]page=(\d+)>; rel="last"`)

func linkLastPage(link string) (int, bool) {
	m := linkLastRe.FindStringSubmatch(link)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func (m *recipeModule) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid = true
		n.Reason = "no identity returned"
		return n
	}
	if m.spec.Summarize != nil {
		n.Summary = m.spec.Summarize(fs)
	}
	return n
}

// statusErr carries an HTTP status from a recon call so the driver can tell a
// rejected credential (401) from a scoped-but-valid one (403).
type statusErr struct{ code int }

func (e statusErr) Error() string { return fmt.Sprintf("status %d", e.code) }
