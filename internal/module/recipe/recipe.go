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
	"net/url"
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
	// Endpoint declares where this module's credential may legitimately be sent.
	// Required for any spec whose Base is templated on a URL-valued field; the
	// catalog guard test fails without it. See module.EndpointPolicy.
	Endpoint module.EndpointPolicy
	// MultiScope marks an API where the whoami can 401 for a token that is still
	// live against a different scope (e.g. Cloudflare's user-scoped
	// /user/tokens/verify rejects an account/zone-scoped token). For these we keep
	// probing the other calls after a whoami 401 instead of stopping early, so a
	// scoped-but-live key isn't falsely declared DEAD. Default off preserves the
	// OPSEC early-stop for single-scope APIs.
	MultiScope bool
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

// EndpointPolicy exposes the spec's declared policy to the recognize-time guard.
func (m *recipeModule) EndpointPolicy() module.EndpointPolicy { return m.spec.Endpoint }

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

// hostSegment matches a value safe to splice into the authority of a base URL:
// a hostname label or account id. Anything else (a URL delimiter, whitespace)
// could relocate the request.
var hostSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ErrUnsafeBase is returned when a templated base URL would resolve somewhere
// the module did not intend.
var ErrUnsafeBase = errors.New("recipe: refused unsafe base URL")

// errNoBase means the base template needs an endpoint the caller never supplied.
// Distinct from ErrUnsafeBase: an unknown instance URL is a gap in what we were
// told, not a hostile value, and says nothing about the credential's validity.
var errNoBase = errors.New("recipe: no endpoint supplied")

// authorityEnd returns the index in a base template where the authority
// (host[:port]) ends — the first "/" after the scheme, or the end of string.
func authorityEnd(s string) int {
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + 3
	}
	if j := strings.Index(s[start:], "/"); j >= 0 {
		return start + j
	}
	return len(s)
}

// renderBase substitutes fields into the base URL, refusing any substitution
// that could move the request to another host.
//
// Field values reach here from scanned data (a .env, a config file, a harvested
// secret), so they are untrusted. Three positions, three rules:
//
//   - A field at position 0 IS the base URL ("{endpoint}", "{endpoint}/api/v2").
//     It must be an absolute http(s) URL with a host and no userinfo. Any host is
//     allowed — triaging a self-hosted instance at an arbitrary domain is the
//     tool's job — but the structure is checked.
//   - A field inside the authority ("https://{shop}.myshopify.com") is a
//     hostname label. A "/", "#", "?" or "@" there re-points the whole request,
//     so only hostSegment values are accepted.
//   - A field in the path cannot change the host; it is only checked for control
//     characters and whitespace (values like a Telegram token carry ":").
func renderBase(base string, f module.Fields) (string, error) {
	authEnd := authorityEnd(base)
	var bad error
	out := fieldRe.ReplaceAllStringFunc(base, func(sub string) string {
		loc := strings.Index(base, sub)
		key := strings.Trim(sub, "{}")
		v := f[key]
		switch {
		case loc == 0: // the field is the base URL itself
			if v == "" {
				if bad == nil {
					bad = fmt.Errorf("%w: field %q", errNoBase, key)
				}
				return ""
			}
			if err := validateBaseURL(v); err != nil && bad == nil {
				bad = fmt.Errorf("%w: field %q: %v", ErrUnsafeBase, key, err)
			}
			return strings.TrimRight(v, "/")
		case loc < authEnd: // the field is a hostname label
			if !hostSegment.MatchString(v) && bad == nil {
				bad = fmt.Errorf("%w: field %q = %q is not a hostname label", ErrUnsafeBase, key, v)
			}
			return v
		default: // path position: cannot move the host
			if strings.ContainsAny(v, " \t\r\n") && bad == nil {
				bad = fmt.Errorf("%w: field %q contains whitespace", ErrUnsafeBase, key)
			}
			return v
		}
	})
	if bad != nil {
		return "", bad
	}
	if out == "" {
		return "", nil // no base; the caller may supply one from the token exchange
	}
	if err := validateBaseURL(out); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeBase, err)
	}
	return out, nil
}

// validateBaseURL enforces the structural rules on a fully-rendered base: an
// absolute http(s) URL, with a host, carrying no embedded credentials.
func validateBaseURL(s string) error {
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
	base, err := renderBase(m.spec.Base, f)
	switch {
	case errors.Is(err, errNoBase):
		// Not a verdict on the credential: we simply don't know where its
		// instance lives. Surface that instead of letting an empty recon be
		// summarized as DEAD.
		return []module.Finding{{Key: "needs_endpoint",
			Value: "instance URL unknown — re-run with --endpoint <host> to characterize this credential",
			Flag:  module.FlagInfo}}, nil
	case err != nil:
		// Refuse before a packet leaves the host: an unsafe base means the
		// credential would be sent somewhere the module did not intend.
		return nil, err
	}
	if t.InstanceURL != "" && base == "" {
		if err := validateBaseURL(t.InstanceURL); err != nil {
			return nil, fmt.Errorf("%w: instance URL: %v", ErrUnsafeBase, err)
		}
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
	// whoami yet succeed elsewhere (403 = authenticated-but-forbidden, scoped).
	//
	// A 401 on the whoami is a strong dead signal. For a single-scope API we stop
	// there (OPSEC: don't fan out against an apparently-dead key). For a MultiScope
	// API the whoami can 401 while the token is live against another scope, so we
	// keep probing and only treat it as DEAD if nothing else accepts it.
	//
	// We track *why* recon came up empty so we don't bury a live credential as
	// DEAD: a 2xx/403 means the token was accepted (authed) even if we failed to
	// parse identity; a transport error means the endpoint was unreachable (says
	// nothing about validity); a whoami 401 with no other acceptance is dead.
	var authed, sawHTTP, whoami401, transportErr bool
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
					whoami401 = true
					if !m.spec.MultiScope {
						break // single-scope: an apparently-dead key, stop early
					}
					// MultiScope: keep probing — other scopes may accept it.
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
	// empty note Invalid). Acceptance anywhere (authed) wins over a whoami 401.
	switch {
	case authed:
		findings = append(findings, module.Finding{Key: "authenticated",
			Value: "credential accepted (HTTP 2xx/403) but identity not parsed — scoped key or the API shape changed",
			Flag:  module.FlagWarn})
	case whoami401:
		// identity call rejected the token and nothing else accepted it →
		// genuinely dead. Leave empty so Summarize marks it Invalid (DEAD).
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
