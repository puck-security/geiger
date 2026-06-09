// Package recon provides the single HTTP client every module uses for recon.
//
// It enforces Geiger's safety model structurally: only GET/HEAD are allowed,
// plus POST when explicitly opted in via CallOpts.ReadOnlyPOST (the documented
// introspection carve-outs and the one auth token exchange). Any other method,
// or a POST without the opt-in, is refused before a packet leaves the host.
//
// In dry-run mode (the default) the client records each planned call and
// returns a synthetic response instead of hitting the network.
package recon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/redact"
)

// ErrMutatingCall is returned when a module attempts a non-read-only request.
var ErrMutatingCall = errors.New("recon: refused non-read-only request")

// PlannedCall is a recorded request (used for dry-run output and audit).
type PlannedCall struct {
	Method     string
	URL        string
	Headers    map[string]string // values redacted
	Body       string            // redacted request body (for non-GET calls)
	Note       string            // optional human description, e.g. "auth token exchange"
	RespStatus int               // captured only under --trace
	RespBody   string            // masked, truncated response body (--trace only)
}

// Curl renders the planned call as a copy-pasteable curl command. Secrets appear
// either as a redacted form or, when known, as a shell variable reference
// (e.g. $OPENAI_API_KEY) — never the raw value. Args that reference a variable
// are double-quoted so the shell expands them.
func (p PlannedCall) Curl() string {
	var b strings.Builder
	b.WriteString("curl -sS")
	if p.Method != http.MethodGet {
		b.WriteString(" -X " + p.Method)
	}
	// Authorization first, then the rest sorted, for stable output.
	keys := make([]string, 0, len(p.Headers))
	for k := range p.Headers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ai, aj := strings.EqualFold(keys[i], "authorization"), strings.EqualFold(keys[j], "authorization")
		if ai != aj {
			return ai
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Fprintf(&b, " -H %s", shellArg(k+": "+p.Headers[k]))
	}
	if p.Body != "" {
		fmt.Fprintf(&b, " --data %s", shellArg(p.Body))
	}
	fmt.Fprintf(&b, " %s", shellArg(p.URL))
	return b.String()
}

// shellArg quotes an argument for a POSIX shell. It single-quotes by default,
// but double-quotes (so $VAR expands) when the value references a shell variable.
func shellArg(s string) string {
	if strings.Contains(s, "$") {
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`")
		return `"` + r.Replace(s) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// CallOpts modifies a single request.
type CallOpts struct {
	// ReadOnlyPOST permits a POST for the documented carve-outs only:
	// STS GetCallerIdentity, k8s SelfSubjectRulesReview, Slack auth.test,
	// read-only SQL/GraphQL queries, and the single auth token exchange.
	ReadOnlyPOST bool
	// Note describes why a POST is read-only, recorded in the plan/audit.
	Note string
}

// Client is the read-only-enforcing HTTP client.
type Client struct {
	http         *http.Client
	live         bool
	intrusive    bool
	minFootprint bool
	correlate    bool
	trace        bool
	planned      []PlannedCall
	secrets      []secretRepl // known secrets and what to display them as
}

type secretRepl struct{ value, repl string }

// RegisterSecret marks a value as secret so it is scrubbed (to a redacted form)
// from every recorded URL and header.
func (c *Client) RegisterSecret(s string) {
	if len(s) >= 4 {
		c.secrets = append(c.secrets, secretRepl{s, redact.Secret(s)})
	}
}

// RegisterSecretRef is like RegisterSecret but displays the secret as repl
// (e.g. "$OPENAI_API_KEY") so the rendered curl is runnable after the variable
// is exported, without ever printing the value.
func (c *Client) RegisterSecretRef(s, repl string) {
	if len(s) >= 4 {
		c.secrets = append(c.secrets, secretRepl{s, repl})
	}
}

// scrub replaces every known secret occurrence with its display form.
func (c *Client) scrub(s string) string {
	for _, sr := range c.secrets {
		if sr.value != "" && strings.Contains(s, sr.value) {
			s = strings.ReplaceAll(s, sr.value, sr.repl)
		}
	}
	return s
}

// UserAgent is sent on every recon request that doesn't already set one. The
// CLI sets it to "geiger/<version>" (overridable via --user-agent). A clear,
// branded agent matches geiger's read-only, authorized-use, no-evasion stance
// and lets defenders attribute the calls in their own logs.
var UserAgent = "geiger"

// New returns a client. When live is false the client records calls instead of
// sending them.
func New(h *http.Client, live bool) *Client {
	if h == nil {
		h = http.DefaultClient
	}
	return &Client{http: h, live: live}
}

// Live reports whether the client makes real network calls.
func (c *Client) Live() bool { return c.live }

// SetIntrusive enables read-only-but-invasive actions (DB connect, k8s live
// API). Off by default; the CLI turns it on with --intrusive.
func (c *Client) SetIntrusive(v bool) { c.intrusive = v }

// Intrusive reports whether invasive read-only actions are permitted. A module
// must check this (in addition to Live) before connecting to a database,
// hitting a cluster API, or harvesting downstream secrets.
func (c *Client) Intrusive() bool { return c.intrusive }

// SetMinFootprint enables OPSEC mode: modules should run only their identity
// call and skip the inventory/count fan-out.
func (c *Client) SetMinFootprint(v bool) { c.minFootprint = v }

// MinFootprint reports whether modules should minimize their call count.
func (c *Client) MinFootprint() bool { return c.minFootprint }

// SetCorrelate enables reading bounded local hints (SSH config/known_hosts/
// shell history) to correlate keys to candidate hosts.
func (c *Client) SetCorrelate(v bool) { c.correlate = v }

// Correlate reports whether local-hint correlation is enabled.
func (c *Client) Correlate() bool { return c.correlate }

// SetTrace enables capturing the (masked) response body of each live call.
func (c *Client) SetTrace(v bool) { c.trace = v }

// Planned returns the recorded calls (dry-run, or audit trail in live mode).
func (c *Client) Planned() []PlannedCall { return c.planned }

func allowed(method string, o CallOpts) error {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return nil
	case http.MethodPost:
		if o.ReadOnlyPOST {
			return nil
		}
		return fmt.Errorf("%w: POST without ReadOnlyPOST opt-in", ErrMutatingCall)
	default:
		return fmt.Errorf("%w: method %s", ErrMutatingCall, method)
	}
}

func (c *Client) record(req *http.Request, note string) PlannedCall {
	// Scrub known secrets first (to a $VAR ref or redacted form), then run the
	// generic redactor over what remains. Doing scrub first lets the $VAR
	// reference survive (redact.Line leaves $-prefixed placeholders alone).
	clean := func(s string) string { return redact.Line(c.scrub(s)) }
	hdr := make(map[string]string, len(req.Header))
	for k, v := range req.Header {
		joined := strings.Join(v, ", ")
		// The User-Agent is deliberately public — keep it legible in the audit
		// trail (still scrub known secrets, but skip the generic token redactor).
		if k == "User-Agent" {
			hdr[k] = c.scrub(joined)
			continue
		}
		hdr[k] = clean(joined)
	}
	body := ""
	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			b, _ := io.ReadAll(io.LimitReader(rc, 8192))
			rc.Close()
			body = clean(string(b))
		}
	}
	// The URL is only scrubbed of known secrets (e.g. a token in the path), never
	// run through the generic redactor — that would mangle the host/path and
	// defeat the audit trail.
	return PlannedCall{Method: req.Method, URL: c.scrub(req.URL.String()), Headers: hdr, Body: body, Note: note}
}

// Do executes (live) or records (dry-run) a request after the read-only check.
// In dry-run it returns a synthetic 200 with an empty body and DryRun set.
func (c *Client) Do(req *http.Request, o CallOpts) (*Response, error) {
	if err := allowed(req.Method, o); err != nil {
		return nil, err
	}
	// Identify ourselves before recording, so the agent is honest and the
	// printed curl matches what's sent. A module that set its own UA wins.
	if UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	plan := c.record(req, o.Note)
	c.planned = append(c.planned, plan)
	idx := len(c.planned) - 1
	if !c.live {
		return &Response{DryRun: true, plan: plan}, nil
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if c.trace {
		c.planned[idx].RespStatus = resp.StatusCode
		masked := redact.Line(c.scrub(string(body)))
		if len(masked) > 4096 {
			masked = masked[:4096] + "…(truncated)"
		}
		c.planned[idx].RespBody = masked
	}
	return &Response{
		Status: resp.StatusCode,
		Header: resp.Header,
		Body:   body,
	}, nil
}

// Response is a recon response (real or synthetic in dry-run).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	DryRun bool
	plan   PlannedCall
}

// NewRequest builds a GET request with a context (convenience).
func NewRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	return http.NewRequestWithContext(ctx, method, url, r)
}
