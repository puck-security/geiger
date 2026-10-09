package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// gitlabBase is overridable in tests.
var gitlabBase = "https://gitlab.com/api/v4"

// gitlabKey characterizes a leaked GitLab token. GET /user confirms identity
// and instance-admin status; GET /personal_access_tokens/self reveals the
// token's scopes (api and sudo are the dangerous ones). --gitlab-intrusive then
// sizes reach: project and group counts (exact from the X-Total header when
// present), maintainer/owner reach, and the keys of CI/CD variables on projects
// and groups the token maintains. Variable VALUES are deliberately not surfaced
// — the keys alone show what the pipelines are wired to.
type gitlabKey struct{ module.Base }

func (gitlabKey) Name() string { return "gitlab" }

func (m gitlabKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	tok := f["token"]
	if tok == "" {
		return nil, nil
	}
	out := []module.Finding{{Key: "type", Value: gitlabTokenType(tok), Flag: module.FlagInfo}}
	evidence := len(out)

	lv := &liveness{}
	// Identity: /user works for PATs and OAuth tokens and reveals instance admin.
	resp := m.get(ctx, c, "/user", tok, "gitlab GET /user (read-only)")
	lv.observe(resp, nil, true)
	if resp != nil && !resp.DryRun && resp.Status < 300 {
		d := jsonDecode(resp.Body)
		if u, _ := d["username"].(string); u != "" {
			out = append(out, module.Finding{Key: "user", Value: u, Flag: module.FlagInfo})
		}
		if adm, _ := d["is_admin"].(bool); adm {
			out = append(out, module.Finding{Key: "instance admin", Value: "token user is a GitLab instance administrator", Flag: module.FlagForceMultiplier})
		}
	}

	// Token scopes (PATs and project/group access tokens); 401/404 for other
	// token kinds, which simply adds nothing.
	if sresp := m.get(ctx, c, "/personal_access_tokens/self", tok, "gitlab GET /personal_access_tokens/self (read-only)"); sresp != nil && !sresp.DryRun && sresp.Status < 300 {
		d := jsonDecode(sresp.Body)
		scopes := jsonStringList(d["scopes"])
		if len(scopes) > 0 {
			flag := module.FlagInfo
			if gitlabForceScope(scopes) {
				flag = module.FlagForceMultiplier
			}
			out = append(out, module.Finding{Key: "scopes", Value: strings.Join(scopes, ", "), Flag: flag})
		}
		if exp, _ := d["expires_at"].(string); exp != "" {
			out = append(out, module.Finding{Key: "expires", Value: exp, Flag: module.FlagInfo})
		}
	}

	out = withLiveness(out, evidence, lv)

	if c.MinFootprint() {
		return out, nil
	}
	if c.GitLabIntrusive() {
		out = append(out, m.deepReach(ctx, c, tok)...)
	}
	return out, nil
}

func (m gitlabKey) get(ctx context.Context, c *recon.Client, path, tok, note string) *recon.Response {
	req, err := recon.NewRequest(ctx, http.MethodGet, gitlabBase+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	resp, err := c.Do(req, recon.CallOpts{Note: note})
	if err != nil {
		return nil
	}
	return resp
}

// deepReach sizes project and group reach and reads CI/CD variable keys on the
// projects and groups the token maintains. Read-only; a missing scope or role
// yields a non-2xx and no finding.
func (m gitlabKey) deepReach(ctx context.Context, c *recon.Client, tok string) []module.Finding {
	var out []module.Finding

	// All accessible projects (membership=true), exact from X-Total when present.
	if resp := m.get(ctx, c, "/projects?membership=true&simple=true&per_page=1", tok, "gitlab GET /projects (read-only)"); resp != nil && !resp.DryRun && resp.Status < 300 {
		out = append(out, module.Finding{Key: "projects", Value: gitlabCount(resp, 1) + " accessible", Flag: module.FlagInfo})
	}

	// Projects the token can maintain (push, manage CI). One page gives both the
	// count (X-Total) and the ids to sample variables from.
	mproj := m.listIDs(ctx, c, tok, "/projects?membership=true&min_access_level=40&simple=true&per_page=20", "maintainer projects")
	if mproj.countStr != "" {
		out = append(out, module.Finding{Key: "maintain projects", Value: mproj.countStr + " (maintainer+)", Flag: module.FlagWarn})
	}
	// Groups the token can maintain.
	mgrp := m.listIDs(ctx, c, tok, "/groups?min_access_level=40&per_page=20", "maintainer groups")
	if mgrp.countStr != "" {
		out = append(out, module.Finding{Key: "maintain groups", Value: mgrp.countStr + " (maintainer+)", Flag: module.FlagWarn})
	}

	const sample = 5
	for i, id := range mproj.ids {
		if i >= sample {
			break
		}
		if keys, total := m.variableKeys(ctx, c, tok, "/projects/"+id+"/variables"); total > 0 {
			out = append(out, module.Finding{Key: "project ci variables", Value: id + ": " + secretsValue(keys, total), Flag: module.FlagForceMultiplier})
		}
	}
	for i, id := range mgrp.ids {
		if i >= sample {
			break
		}
		if keys, total := m.variableKeys(ctx, c, tok, "/groups/"+id+"/variables"); total > 0 {
			out = append(out, module.Finding{Key: "group ci variables", Value: id + ": " + secretsValue(keys, total), Flag: module.FlagForceMultiplier})
		}
	}
	return out
}

type gitlabListing struct {
	countStr string
	ids      []string
}

// listIDs fetches one page of an offset-paginated collection, returning a count
// string (exact from X-Total, else a floor) and the ids on the page.
func (m gitlabKey) listIDs(ctx context.Context, c *recon.Client, tok, path, note string) gitlabListing {
	resp := m.get(ctx, c, path, tok, "gitlab GET "+note+" (read-only)")
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return gitlabListing{}
	}
	var arr []struct {
		ID float64 `json:"id"`
	}
	if json.Unmarshal(resp.Body, &arr) != nil {
		return gitlabListing{}
	}
	if len(arr) == 0 {
		return gitlabListing{}
	}
	ids := make([]string, 0, len(arr))
	for _, e := range arr {
		ids = append(ids, strconv.FormatInt(int64(e.ID), 10))
	}
	return gitlabListing{countStr: gitlabCount(resp, len(arr)), ids: ids}
}

// variableKeys lists CI/CD variable keys (the endpoint also returns values,
// which are intentionally discarded — only the keys are surfaced).
func (m gitlabKey) variableKeys(ctx context.Context, c *recon.Client, tok, path string) ([]string, int) {
	resp := m.get(ctx, c, path+"?per_page=100", tok, "gitlab GET ci variables (read-only, keys only)")
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return nil, 0
	}
	var vars []struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(resp.Body, &vars) != nil || len(vars) == 0 {
		return nil, 0
	}
	keys := make([]string, 0, 8)
	for i, v := range vars {
		if i >= 8 {
			break
		}
		keys = append(keys, v.Key)
	}
	return keys, len(vars)
}

func (gitlabKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "GitLab token returned no identity"
		return n
	}
	confirmed := false
	for _, f := range fs {
		switch f.Key {
		case "user", "scopes", "authenticated", "unreachable", "instance admin":
			confirmed = true
		}
	}
	if !confirmed {
		n.Summary = "GitLab token (not exercised)"
		return n
	}
	var bits []string
	for _, f := range fs {
		switch f.Key {
		case "instance admin":
			bits = append(bits, "instance admin")
		case "scopes":
			if f.Flag == module.FlagForceMultiplier {
				bits = append(bits, "scopes "+f.Value)
			}
		case "project ci variables", "group ci variables":
			bits = append(bits, "CI variable access")
		}
	}
	if len(bits) == 0 {
		n.Summary = "valid GitLab token"
	} else {
		n.Summary = "GitLab token — " + strings.Join(dedup(bits), "; ")
	}
	return n
}

// ---- helpers ----

func gitlabTokenType(tok string) string {
	switch {
	case strings.HasPrefix(tok, "glpat-"):
		return "personal access token"
	case strings.HasPrefix(tok, "gldt-"):
		return "deploy token"
	case strings.HasPrefix(tok, "glptt-"):
		return "pipeline trigger token"
	case strings.HasPrefix(tok, "glrt-"):
		return "runner token"
	case strings.HasPrefix(tok, "glft-"):
		return "feed token"
	case strings.HasPrefix(tok, "glsoat-"):
		return "scoped OAuth token"
	default:
		return "token"
	}
}

// gitlabForceScope reports whether a scope set includes full-API or impersonation
// power.
func gitlabForceScope(scopes []string) bool {
	for _, s := range scopes {
		switch s {
		case "api", "sudo", "admin_mode":
			return true
		}
	}
	return false
}

// gitlabCount returns an exact count from X-Total when GitLab provides it, a
// 10000+ floor when it omits the header for a large collection (documented
// behaviour above 10k items), else the page length.
func gitlabCount(resp *recon.Response, pageLen int) string {
	if v := resp.Header.Get("X-Total"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return strconv.Itoa(n)
		}
	}
	if resp.Header.Get("X-Next-Page") != "" {
		return "10000+" // GitLab omits X-Total above 10,000 items
	}
	return strconv.Itoa(pageLen)
}

func jsonStringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// gitlabTokenRe matches the API-exercisable GitLab token formats (personal and
// scoped-OAuth access tokens) by prefix. The embedded gitleaks gitlab-pat rule
// captures exactly 20 body characters, so it misses or truncates the newer,
// longer "routable" token format; this native recognizer captures the whole
// token regardless of length and routes it to the gitlab module.
// The classic format is glpat-<20 chars>; the newer "routable" format is
// glpat-<base64>.<version>.<crc>, so dot-separated segments must be captured
// too (without grabbing a trailing sentence period).
var gitlabTokenRe = regexp.MustCompile(`gl(?:pat|soat)-[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*`)

func recognizeGitLabToken(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	seen := map[string]bool{}
	var out []recognize.Match
	emit := func(tok, label string, line int) {
		if tok == "" || seen[tok] || !gitlabTokenRe.MatchString(tok) {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module: "gitlab",
			Fields: module.Fields{"token": tok},
			Secret: tok,
			Label:  label,
			Line:   line,
			// Supersede the generic name/shape match and any truncated gitleaks
			// gitlab hit that captured only a prefix of this token.
			Overrides: []string{"generic_secret", "gitlab"},
		})
	}
	// Exact values from env/dotenv/INI, where the whole value is the token.
	for k, v := range b.Vars {
		if gitlabTokenRe.FindString(v) == v {
			emit(v, k, b.Lines[k])
		}
	}
	// Free-text occurrences (config files, URLs, logs).
	for _, m := range gitlabTokenRe.FindAllString(b.Raw, -1) {
		emit(m, "gitlab token", 0)
	}
	return out
}

func init() {
	module.Register(gitlabKey{})
	for _, rule := range []string{
		"gitlab-pat", "gitlab-pat-routable", "gitlab-deploy-token",
		"gitlab-feed-token", "gitlab-ptt", "gitlab-rrt",
	} {
		module.MapRule(rule, "gitlab")
	}
	recognize.RegisterRecognizer(recognizeGitLabToken)
}
