package modules

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// cfBase is overridable in tests.
var cfBase = "https://api.cloudflare.com/client/v4"

// cloudflareKey characterizes a Cloudflare API token. Default --live confirms the
// token and counts reachable accounts and zones; --cloudflare-intrusive names the
// zones (the domains whose DNS it controls) and probes Workers and R2 reach
// (code execution and object storage). Each call may 403 on a scoped token, in
// which case geiger skips it.
type cloudflareKey struct{ module.Base }

func (cloudflareKey) Name() string { return "cloudflare" }

func (m cloudflareKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	tok := f["token"]
	var out []module.Finding
	lv := &liveness{}

	if d, resp := m.get(ctx, c, tok, "/user/tokens/verify"); resp != nil {
		lv.observe(resp, nil, true)
		if d != nil {
			if status := jsonPath2(d, "result", "status"); status != "" {
				out = append(out, module.Finding{Key: "token-status", Value: status, Flag: module.FlagInfo})
			}
		}
	}
	if d, resp := m.get(ctx, c, tok, "/accounts"); d != nil {
		lv.observe(resp, nil, false)
		if n, ok := cfTotal(d); ok {
			out = append(out, module.Finding{Key: "accounts", Value: strconv.Itoa(n), Flag: module.FlagInfo})
		}
	}
	if d, resp := m.get(ctx, c, tok, "/zones"); d != nil {
		lv.observe(resp, nil, false)
		if n, ok := cfTotal(d); ok {
			out = append(out, module.Finding{Key: "zones", Value: strconv.Itoa(n), Flag: module.FlagWarn})
		}
	}
	if d, _ := m.get(ctx, c, tok, "/user"); d != nil {
		if email := jsonPath2(d, "result", "email"); email != "" {
			out = append(out, module.Finding{Key: "email", Value: email, Flag: module.FlagInfo})
		}
	}

	if c.MinFootprint() {
		return withLiveness(out, 0, lv), nil
	}
	if c.CloudflareIntrusive() {
		out = append(out, m.deepReach(ctx, c, tok)...)
	}
	return withLiveness(out, 0, lv), nil
}

func (m cloudflareKey) get(ctx context.Context, c *recon.Client, tok, path string) (map[string]any, *recon.Response) {
	req, err := recon.NewRequest(ctx, http.MethodGet, cfBase+path, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.Do(req, recon.CallOpts{Note: "cloudflare GET " + path + " (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil, resp
	}
	return jsonDecode(resp.Body), resp
}

// deepReach names the zones the token controls and probes Workers/R2 reach.
func (m cloudflareKey) deepReach(ctx context.Context, c *recon.Client, tok string) []module.Finding {
	var out []module.Finding

	if names, more := m.resultNames(ctx, c, tok, "/zones?per_page=50", "name"); len(names) > 0 {
		val := strings.Join(names, ", ")
		if more {
			val += ", …"
		}
		out = append(out, module.Finding{Key: "domains", Value: "controls DNS for: " + val, Flag: module.FlagForceMultiplier})
	}

	// Workers and R2 reach on the first reachable account.
	if acct := m.firstAccountID(ctx, c, tok); acct != "" {
		if d, _ := m.get(ctx, c, tok, "/accounts/"+acct+"/workers/scripts"); d != nil {
			if arr, ok := d["result"].([]any); ok {
				out = append(out, module.Finding{Key: "workers", Value: strconv.Itoa(len(arr)) + " Worker scripts (code execution at the edge)", Flag: module.FlagForceMultiplier})
			}
		}
		if d, _ := m.get(ctx, c, tok, "/accounts/"+acct+"/r2/buckets"); d != nil {
			if n := cfR2Count(d); n >= 0 {
				out = append(out, module.Finding{Key: "r2", Value: strconv.Itoa(n) + " R2 buckets", Flag: module.FlagWarn})
			}
		}
	}
	return out
}

func (m cloudflareKey) firstAccountID(ctx context.Context, c *recon.Client, tok string) string {
	d, _ := m.get(ctx, c, tok, "/accounts")
	if d == nil {
		return ""
	}
	arr, _ := d["result"].([]any)
	for _, it := range arr {
		if mm, ok := it.(map[string]any); ok {
			if id, _ := mm["id"].(string); id != "" {
				return id
			}
		}
	}
	return ""
}

// resultNames returns a bounded sample of a named field across result entries.
func (m cloudflareKey) resultNames(ctx context.Context, c *recon.Client, tok, path, field string) ([]string, bool) {
	d, _ := m.get(ctx, c, tok, path)
	if d == nil {
		return nil, false
	}
	arr, _ := d["result"].([]any)
	var names []string
	for _, it := range arr {
		mm, _ := it.(map[string]any)
		if v, _ := mm[field].(string); v != "" {
			names = append(names, v)
		}
		if len(names) >= 10 {
			break
		}
	}
	return names, len(arr) > len(names)
}

func (cloudflareKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "Cloudflare token not accepted"
		return n
	}
	for _, f := range fs {
		if f.Key == "domains" || f.Key == "workers" {
			n.Summary = "Cloudflare token — DNS/edge control"
			return n
		}
	}
	n.Summary = "Cloudflare API token"
	return n
}

// cfTotal reads result_info.total_count.
func cfTotal(d map[string]any) (int, bool) {
	ri, ok := d["result_info"].(map[string]any)
	if !ok {
		return 0, false
	}
	if t, ok := ri["total_count"].(float64); ok {
		return int(t), true
	}
	return 0, false
}

// cfR2Count reads the bucket count from an R2 list response.
func cfR2Count(d map[string]any) int {
	res, ok := d["result"].(map[string]any)
	if !ok {
		return -1
	}
	if b, ok := res["buckets"].([]any); ok {
		return len(b)
	}
	return -1
}

// jsonPath2 reads a two-level string field from a decoded map.
func jsonPath2(d map[string]any, a, b string) string {
	m, _ := d[a].(map[string]any)
	s, _ := m[b].(string)
	return s
}

// cfTokenRe matches Cloudflare's prefixed API tokens. The body is intentionally
// permissive — the module re-validates the value, so over-matching the shape is
// free (a non-token simply fails /user/tokens/verify).
var cfTokenRe = regexp.MustCompile(`cf(?:at|ut)_[A-Za-z0-9_-]{20,}`)

// recognizeCloudflare catches tokens gitleaks' context-keyword rule misses: the
// newer prefixed formats (cfat_ account, cfut_ user) anywhere in the blob, the
// legacy un-prefixed token by variable name, and the Global API Key with its
// account email. suppressConsumedUnknowns drops the generic_secret mis-hit.
func recognizeCloudflare(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	seen := map[string]bool{}
	add := func(tok, label string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module: "cloudflare",
			Fields: module.Fields{"token": tok},
			Secret: tok, Label: label,
		})
	}
	if tok := firstVar(b.Vars, "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_TOKEN"); tok != "" {
		add(tok, "CLOUDFLARE_API_TOKEN")
	}
	for _, tok := range cfTokenRe.FindAllString(b.Raw, -1) {
		add(tok, "cloudflare-api-token")
	}
	if key := firstVar(b.Vars, "CLOUDFLARE_API_KEY", "CF_API_KEY", "CLOUDFLARE_GLOBAL_API_KEY"); key != "" {
		if email := firstVar(b.Vars, "CLOUDFLARE_EMAIL", "CF_API_EMAIL", "CLOUDFLARE_ACCOUNT_EMAIL"); email != "" {
			out = append(out, recognize.Match{
				Module: "cloudflare_global",
				Fields: module.Fields{"token": key, "email": email},
				Secret: key, Label: "CLOUDFLARE_API_KEY",
			})
		}
	}
	return out
}

func init() {
	module.Register(cloudflareKey{})
	module.MapRule("cloudflare-api-key", "cloudflare")
	recognize.RegisterRecognizer(recognizeCloudflare)
}
