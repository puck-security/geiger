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

// slackAPIBase is overridable in tests.
var slackAPIBase = "https://slack.com/api"

// slackKey characterizes a leaked Slack token. auth.test (no scope required,
// generous rate limit) confirms identity and, via the X-OAuth-Scopes response
// header, reveals the token's granted scopes — the authoritative capability
// surface. --slack-intrusive then sizes reach with read-only paginated list
// calls. No write method is ever called; impersonation is inferred from the
// chat:write scope, not exercised.
type slackKey struct{ module.Base }

func (slackKey) Name() string { return "slack" }

func (m slackKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	tok := f["token"]
	if tok == "" {
		return nil, nil
	}
	out := []module.Finding{{Key: "type", Value: slackTokenType(tok), Flag: module.FlagInfo}}
	evidence := len(out) // the "type" line echoes our input, not the tenant's answer

	resp := m.get(ctx, c, "/auth.test", tok, "slack auth.test (read-only)")
	if resp == nil {
		return out, nil
	}
	// Slack returns HTTP 200 for a rejected token too; the body's "ok" field is
	// the real verdict. Only an explicit auth error means dead. An unparseable
	// 200 is ambiguous, so the shared liveness helper classifies it rather than
	// defaulting to DEAD.
	lv := &liveness{}
	lv.observe(resp, nil, true)
	if !resp.DryRun {
		d := jsonDecode(resp.Body)
		okField, hasOK := d["ok"].(bool)
		switch {
		case hasOK && !okField:
			if e := slackErr(d); slackDeadError(e) {
				return []module.Finding{{Key: "validity", Value: "invalid: " + e, Flag: module.FlagWarn}}, nil
			}
			// non-auth error on a 200 (ratelimited, internal_error): ambiguous.
		case hasOK && okField:
			if v, _ := d["url"].(string); v != "" {
				out = append(out, module.Finding{Key: "workspace", Value: v, Flag: module.FlagInfo})
			}
			if v, _ := d["team"].(string); v != "" {
				out = append(out, module.Finding{Key: "team", Value: v, Flag: module.FlagInfo})
			}
			if v, _ := d["user"].(string); v != "" {
				out = append(out, module.Finding{Key: "identity", Value: v, Flag: module.FlagInfo})
			}
			if ent, _ := d["is_enterprise_install"].(bool); ent {
				out = append(out, module.Finding{Key: "enterprise", Value: "org-wide (Enterprise Grid) install", Flag: module.FlagWarn})
			}
			out = append(out, slackCapabilities(splitScopes(resp.Header.Get("X-OAuth-Scopes")))...)
		}
	}
	// A 2xx we could not parse means the token was accepted — never DEAD.
	out = withLiveness(out, evidence, lv)

	if c.MinFootprint() {
		return out, nil
	}
	if c.SlackIntrusive() {
		out = append(out, m.deepReach(ctx, c, tok)...)
	}
	return out, nil
}

func (m slackKey) get(ctx context.Context, c *recon.Client, path, tok, note string) *recon.Response {
	req, err := recon.NewRequest(ctx, http.MethodGet, slackAPIBase+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.Do(req, recon.CallOpts{Note: note})
	if err != nil {
		return nil
	}
	return resp
}

// deepReach sizes what the token can see: workspace identity, member roster,
// channel inventory (flagging visible private channels), and file count. Each
// call is read-only; a denied scope simply yields no finding.
func (m slackKey) deepReach(ctx context.Context, c *recon.Client, tok string) []module.Finding {
	var out []module.Finding

	if resp := m.get(ctx, c, "/team.info", tok, "slack team.info (read-only)"); resp != nil && !resp.DryRun {
		d := jsonDecode(resp.Body)
		if t, _ := d["team"].(map[string]any); t != nil {
			name, _ := t["name"].(string)
			domain, _ := t["domain"].(string)
			if name != "" {
				v := name
				if domain != "" {
					v += " (" + domain + ".slack.com)"
				}
				out = append(out, module.Finding{Key: "workspace name", Value: v, Flag: module.FlagInfo})
			}
		}
	}

	if n, more := m.countList(ctx, c, tok, "/users.list?limit=1000", "members"); n > 0 {
		out = append(out, module.Finding{Key: "users", Value: countStr(n, more) + " members visible", Flag: module.FlagInfo})
	}

	if n, priv, more := m.countChannels(ctx, c, tok); n > 0 {
		val := countStr(n, more) + " channels visible"
		flag := module.FlagInfo
		if priv > 0 {
			flag = module.FlagWarn
			val += " (incl. " + strconv.Itoa(priv) + " private)"
		}
		out = append(out, module.Finding{Key: "channels", Value: val, Flag: flag})
	}

	if n := m.fileTotal(ctx, c, tok); n > 0 {
		out = append(out, module.Finding{Key: "files", Value: strconv.Itoa(n) + " files accessible", Flag: module.FlagInfo})
	}
	return out
}

// countList fetches one page of a cursor-paginated list and returns the element
// count and whether a next page exists.
func (m slackKey) countList(ctx context.Context, c *recon.Client, tok, path, arrayKey string) (int, bool) {
	resp := m.get(ctx, c, path, tok, "slack "+strings.TrimPrefix(strings.SplitN(path, "?", 2)[0], "/")+" (read-only)")
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return 0, false
	}
	d := jsonDecode(resp.Body)
	if ok, _ := d["ok"].(bool); !ok {
		return 0, false
	}
	arr, _ := d[arrayKey].([]any)
	return len(arr), slackHasNextCursor(d)
}

func (m slackKey) countChannels(ctx context.Context, c *recon.Client, tok string) (total, private int, more bool) {
	resp := m.get(ctx, c, "/conversations.list?types=public_channel,private_channel&limit=1000", tok, "slack conversations.list (read-only)")
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return 0, 0, false
	}
	d := jsonDecode(resp.Body)
	if ok, _ := d["ok"].(bool); !ok {
		return 0, 0, false
	}
	chans, _ := d["channels"].([]any)
	for _, ch := range chans {
		if cm, ok := ch.(map[string]any); ok {
			if p, _ := cm["is_private"].(bool); p {
				private++
			}
		}
	}
	return len(chans), private, slackHasNextCursor(d)
}

// fileTotal reads files.list's paging.total, which gives the full count without
// enumerating every file.
func (m slackKey) fileTotal(ctx context.Context, c *recon.Client, tok string) int {
	resp := m.get(ctx, c, "/files.list?count=1", tok, "slack files.list (read-only)")
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return 0
	}
	d := jsonDecode(resp.Body)
	if ok, _ := d["ok"].(bool); !ok {
		return 0
	}
	if p, _ := d["paging"].(map[string]any); p != nil {
		if t, ok := p["total"].(float64); ok {
			return int(t)
		}
	}
	return 0
}

func (slackKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "slack auth.test returned no identity"
		return n
	}
	for _, f := range fs {
		if f.Key == "validity" && strings.HasPrefix(f.Value, "invalid") {
			n.Invalid, n.Reason = true, "Slack token rejected"
			return n
		}
	}
	// Did auth.test confirm an identity at all? A token with only a "type" line
	// was never exercised (dry-run) — report it as undetermined, not valid.
	confirmed := false
	for _, f := range fs {
		switch f.Key {
		case "workspace", "team", "identity", "authenticated", "unreachable":
			confirmed = true
		}
	}
	if !confirmed {
		n.Summary = "Slack token (not exercised)"
		return n
	}
	var parts []string
	for _, f := range fs {
		if f.Key == "capability" && f.Flag == module.FlagForceMultiplier {
			// take the scope name up to the em-dash separator
			label := f.Value
			if i := strings.Index(label, " — "); i > 0 {
				label = label[:i]
			}
			parts = append(parts, label)
		}
		if f.Key == "enterprise" {
			parts = append(parts, "Enterprise Grid")
		}
	}
	if len(parts) == 0 {
		n.Summary = "valid Slack token"
	} else {
		n.Summary = "Slack token — " + strings.Join(parts, " + ")
	}
	return n
}

// ---- helpers ----

func slackTokenType(tok string) string {
	switch {
	case strings.HasPrefix(tok, "xoxb-"):
		return "bot token"
	case strings.HasPrefix(tok, "xoxp-"):
		return "user token"
	case strings.HasPrefix(tok, "xapp-"):
		return "app-level token"
	case strings.HasPrefix(tok, "xoxe-"), strings.HasPrefix(tok, "xoxe."):
		return "config/refresh token"
	case strings.HasPrefix(tok, "xoxa-"), strings.HasPrefix(tok, "xoxa."):
		return "workspace token"
	case strings.HasPrefix(tok, "xoxr-"):
		return "refresh token"
	default:
		return "token"
	}
}

func slackErr(d map[string]any) string {
	if e, _ := d["error"].(string); e != "" {
		return e
	}
	return "rejected"
}

// slackDeadError reports whether an auth.test error means the token is
// genuinely unusable (as opposed to scope/rate errors, which leave it valid).
func slackDeadError(e string) bool {
	switch e {
	case "invalid_auth", "not_authed", "account_inactive", "token_revoked",
		"token_expired", "token_type_not_allowed", "no_user_token":
		return true
	}
	return false
}

func splitScopes(h string) []string {
	var out []string
	for _, s := range strings.Split(h, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func slackHasNextCursor(d map[string]any) bool {
	if rm, _ := d["response_metadata"].(map[string]any); rm != nil {
		if cur, _ := rm["next_cursor"].(string); cur != "" {
			return true
		}
	}
	return false
}

func countStr(n int, more bool) string {
	s := strconv.Itoa(n)
	if more {
		s += "+"
	}
	return s
}

// slackCapabilities maps granted scopes to impact. High-impact scopes are
// grouped into one finding each so the score reflects the capability without
// every related scope compounding separately.
func slackCapabilities(scopes []string) []module.Finding {
	if len(scopes) == 0 {
		return nil
	}
	out := []module.Finding{{
		Key:   "scopes",
		Value: strconv.Itoa(len(scopes)) + " granted: " + strings.Join(capScopes(scopes, 25), ", "),
		Flag:  module.FlagInfo,
	}}
	var admin, history []string
	var chatWrite, search, files, emails bool
	for _, s := range scopes {
		switch {
		case s == "admin" || strings.HasPrefix(s, "admin."):
			admin = append(admin, s)
		case strings.HasPrefix(s, "chat:write"):
			chatWrite = true
		case strings.HasPrefix(s, "search:read"):
			search = true
		case strings.HasSuffix(s, ":history"):
			history = append(history, s)
		case s == "files:read":
			files = true
		case s == "users:read.email":
			emails = true
		}
	}
	if len(admin) > 0 {
		out = append(out, module.Finding{Key: "capability", Value: "admin scopes (" + strconv.Itoa(len(admin)) + ") — org/workspace control", Flag: module.FlagForceMultiplier})
	}
	if chatWrite {
		out = append(out, module.Finding{Key: "capability", Value: "chat:write — post messages as this identity (impersonation)", Flag: module.FlagForceMultiplier})
	}
	if search {
		out = append(out, module.Finding{Key: "capability", Value: "search:read — read every message this user can access", Flag: module.FlagForceMultiplier})
	}
	if len(history) > 0 {
		out = append(out, module.Finding{Key: "capability", Value: strings.Join(history, ", ") + " — read conversation history", Flag: module.FlagWarn})
	}
	if files {
		out = append(out, module.Finding{Key: "capability", Value: "files:read — read files", Flag: module.FlagWarn})
	}
	if emails {
		out = append(out, module.Finding{Key: "capability", Value: "users:read.email — read member emails (PII)", Flag: module.FlagWarn})
	}
	return out
}

func capScopes(scopes []string, n int) []string {
	if len(scopes) <= n {
		return scopes
	}
	return append(scopes[:n:n], "…")
}

// slackTokenRe matches the API-exercisable Slack token prefixes (bot, user,
// app-level, legacy-workspace, and the config ACCESS token). It does NOT match
// the config REFRESH token (xoxe-<d>-…), which auth.test cannot exercise and
// which would therefore read as dead. The slack module relies on gitleaks for
// recognition; this native recognizer is a robustness guard against format
// drift or truncation, routing the whole token to slack and superseding a
// generic name/shape match.
var slackTokenRe = regexp.MustCompile(`(?:xoxe\.xox[bp]|xox[bpaos]|xapp)-[A-Za-z0-9-]{8,}`)

func recognizeSlackToken(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	seen := map[string]bool{}
	var out []recognize.Match
	emit := func(tok, label string, line int) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module:    "slack",
			Fields:    module.Fields{"token": tok},
			Secret:    tok,
			Label:     label,
			Line:      line,
			Overrides: []string{"generic_secret", "slack"},
		})
	}
	for k, v := range b.Vars {
		if slackTokenRe.FindString(v) == v {
			emit(v, k, b.Lines[k])
		}
	}
	for _, m := range slackTokenRe.FindAllString(b.Raw, -1) {
		emit(m, "slack token", 0)
	}
	return out
}

func init() {
	module.Register(slackKey{})
	for _, rule := range []string{
		"slack-bot-token", "slack-user-token", "slack-app-token", "slack-legacy-bot-token",
		"slack-legacy-token", "slack-legacy-workspace-token", "slack-config-access-token",
	} {
		module.MapRule(rule, "slack")
	}
	recognize.RegisterRecognizer(recognizeSlackToken)
}
