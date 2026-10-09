package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// githubPAT covers classic and fine-grained personal access tokens, plus the
// gho_/ghu_/ghs_ app/oauth tokens. Recon: GET /user, read X-OAuth-Scopes
// (classic only — fine-grained exposes no scope introspection), and size repo
// reach from the Link rel="last" page number.
type githubPAT struct{ module.Base }

func (githubPAT) Name() string { return "github_pat" }

func (m githubPAT) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	tok := f["token"]
	installation := strings.HasPrefix(tok, "ghs_")
	fineGrained := strings.HasPrefix(tok, "github_pat_")

	var out []module.Finding

	userPath := "https://api.github.com/user"
	if installation {
		userPath = "https://api.github.com/installation/repositories"
	}
	req, _ := recon.NewRequest(ctx, http.MethodGet, userPath, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil {
		return nil, err
	}
	if resp.DryRun {
		// still record the follow-up calls so dry-run previews the full recipe
		if !installation && !c.MinFootprint() {
			_ = m.repoSurvey(ctx, c, tok, c.GitHubIntrusive(), nil)
			_ = m.orgAdmin(ctx, c, tok)
		}
		return nil, nil
	}
	if resp.Status == http.StatusUnauthorized {
		return nil, errStatus(resp.Status)
	}
	// Transport errors, dry-runs and 401s have all returned by here, so this
	// records an accepted-or-unexpected response — enough to keep a live token
	// off the DEAD path when /user returns a shape we can't parse.
	var lv liveness
	lv.observe(resp, nil, true)
	if sso := resp.Header.Get("X-GitHub-SSO"); sso != "" {
		out = append(out, module.Finding{Key: "saml-sso", Value: "org requires SSO authorization", Flag: module.FlagWarn})
	}

	if installation {
		out = append(out, module.Finding{Key: "type", Value: "GitHub App installation token (ghs_)", Flag: module.FlagInfo})
	} else {
		login := jsonField(resp.Body, "login")
		if login != "" {
			out = append(out, module.Finding{Key: "user", Value: login, Flag: module.FlagInfo})
		}
		if t := jsonField(resp.Body, "type"); t != "" {
			out = append(out, module.Finding{Key: "account-type", Value: t, Flag: module.FlagInfo})
		}
	}

	if fineGrained {
		out = append(out, module.Finding{
			Key:   "scopes",
			Value: "fine-grained PAT — scopes not enumerable via API",
			Flag:  module.FlagCantCharacterize,
		})
	} else if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
		flag := module.FlagInfo
		if hasForceScope(scopes) {
			flag = module.FlagForceMultiplier
		}
		out = append(out, module.Finding{Key: "scopes", Value: scopes, Flag: flag})
	}

	// Repo reach + write/admin access. The per-repo `permissions` object is
	// returned read-only, so we learn write/admin even for fine-grained PATs
	// that expose no scopes.
	if !installation && !c.MinFootprint() {
		var adminRepos []string
		out = append(out, m.repoSurvey(ctx, c, tok, c.GitHubIntrusive(), &adminRepos)...)
		out = append(out, m.orgAdmin(ctx, c, tok)...)
		if c.GitHubIntrusive() {
			out = append(out, m.deepReach(ctx, c, tok, adminRepos)...)
		}
	}
	// An installation token's reach is the set of repositories it was granted.
	if installation && c.GitHubIntrusive() && !c.MinFootprint() {
		out = append(out, m.installationReach(ctx, c, tok)...)
	}
	return withLiveness(out, 0, &lv), nil
}

// deepReach is the --github-intrusive tier: org member counts and the names of
// Actions secrets at the org level and on repos the token administers. Secret
// values are never returned by the API; the names alone reveal which external
// systems the CI/CD pipelines are wired to. Each probe is read-only and skipped
// on any non-2xx (missing scope, SSO gate), so a narrow token simply adds
// nothing here.
func (m githubPAT) deepReach(ctx context.Context, c *recon.Client, tok string, adminRepos []string) []module.Finding {
	var out []module.Finding
	for i, org := range m.userOrgs(ctx, c, tok) {
		if i >= 10 { // bounded fan-out
			break
		}
		if n, ok := m.orgMemberCount(ctx, c, tok, org); ok {
			out = append(out, module.Finding{Key: "org members", Value: org + ": " + n + " members", Flag: module.FlagInfo})
		}
		if names, total := m.actionsSecrets(ctx, c, tok, "https://api.github.com/orgs/"+org+"/actions/secrets"); total > 0 {
			out = append(out, module.Finding{
				Key:   "org ci secrets",
				Value: org + ": " + secretsValue(names, total),
				Flag:  module.FlagForceMultiplier,
			})
		}
	}
	// Repo-level CI secrets for a bounded sample of administered repos.
	const repoCap = 5
	for i, full := range adminRepos {
		if i >= repoCap {
			break
		}
		if names, total := m.actionsSecrets(ctx, c, tok, "https://api.github.com/repos/"+full+"/actions/secrets"); total > 0 {
			out = append(out, module.Finding{
				Key:   "repo ci secrets",
				Value: full + ": " + secretsValue(names, total),
				Flag:  module.FlagForceMultiplier,
			})
		}
	}
	return out
}

// userOrgs returns the login names of the orgs the token's user belongs to.
func (githubPAT) userOrgs(ctx context.Context, c *recon.Client, tok string) []string {
	req, _ := recon.NewRequest(ctx, http.MethodGet, "https://api.github.com/user/orgs?per_page=100", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var orgs []map[string]any
	if json.Unmarshal(resp.Body, &orgs) != nil {
		return nil
	}
	var out []string
	for _, o := range orgs {
		if login, _ := o["login"].(string); login != "" {
			out = append(out, login)
		}
	}
	return out
}

// orgMemberCount returns a member-count floor from the members list's Link
// rel="last" page number (per_page=1 makes the page number the exact count).
func (githubPAT) orgMemberCount(ctx context.Context, c *recon.Client, tok, org string) (string, bool) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, "https://api.github.com/orgs/"+org+"/members?per_page=1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return "", false
	}
	if n, ok := linkLast(resp.Header.Get("Link")); ok {
		return strconv.Itoa(n), true
	}
	// No Link header means a single page: count the array.
	var members []map[string]any
	if json.Unmarshal(resp.Body, &members) == nil {
		return strconv.Itoa(len(members)), true
	}
	return "", false
}

// actionsSecrets lists Actions secret names (never values) at a secrets URL,
// returning a bounded sample of names and the total count.
func (githubPAT) actionsSecrets(ctx context.Context, c *recon.Client, tok, url string) ([]string, int) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, url+"?per_page=100", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil, 0
	}
	var body struct {
		TotalCount int `json:"total_count"`
		Secrets    []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if json.Unmarshal(resp.Body, &body) != nil {
		return nil, 0
	}
	var names []string
	for i, s := range body.Secrets {
		if i >= 8 {
			break
		}
		names = append(names, s.Name)
	}
	total := body.TotalCount
	if total == 0 {
		total = len(body.Secrets)
	}
	return names, total
}

// installationReach reports how many repositories a GitHub App installation
// token can act on, from /installation/repositories' total_count.
func (githubPAT) installationReach(ctx context.Context, c *recon.Client, tok string) []module.Finding {
	req, _ := recon.NewRequest(ctx, http.MethodGet, "https://api.github.com/installation/repositories?per_page=1", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var body struct {
		TotalCount int `json:"total_count"`
	}
	if json.Unmarshal(resp.Body, &body) != nil || body.TotalCount == 0 {
		return nil
	}
	return []module.Finding{{
		Key:   "installation reach",
		Value: strconv.Itoa(body.TotalCount) + " repositories the app can act on",
		Flag:  module.FlagForceMultiplier,
	}}
}

func secretsValue(names []string, total int) string {
	v := strconv.Itoa(total) + " Actions secrets"
	if len(names) > 0 {
		shown := names
		if len(shown) > total {
			shown = shown[:total]
		}
		v += " (" + strings.Join(shown, ", ")
		if total > len(shown) {
			v += ", …"
		}
		v += ")"
	}
	return v
}

// repoSurvey reports total accessible repos (cheap, from the Link header) plus
// write/admin counts and any prod-ish repo names from a bounded sample. Under
// --github-intrusive the sample cap is raised so the write/admin counts are
// accurate in large accounts. adminRepos, when non-nil, collects the full names
// of repos the token administers so the deep tier can read their CI secrets.
func (githubPAT) repoSurvey(ctx context.Context, c *recon.Client, tok string, deep bool, adminRepos *[]string) []module.Finding {
	var out []module.Finding
	total, haveTotal := 0, false
	var writable, admin, examined int
	var notable []string

	maxPages := 3 // bounded: up to 300 repos sampled
	if deep {
		maxPages = 10
	}
	for page := 1; page <= maxPages; page++ {
		url := "https://api.github.com/user/repos?per_page=100&visibility=all&page=" + strconv.Itoa(page)
		req, _ := recon.NewRequest(ctx, http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := c.Do(req, recon.CallOpts{})
		if err != nil || resp.DryRun || resp.Status >= 300 {
			break
		}
		if !haveTotal {
			if n, ok := linkLast(resp.Header.Get("Link")); ok {
				total, haveTotal = n*100, true // pages × per_page (upper bound)
			}
		}
		var repos []map[string]any
		if json.Unmarshal(resp.Body, &repos) != nil || len(repos) == 0 {
			break
		}
		for _, r := range repos {
			examined++
			name, _ := r["full_name"].(string)
			perms, _ := r["permissions"].(map[string]any)
			if b, _ := perms["admin"].(bool); b {
				admin++
				if adminRepos != nil && name != "" {
					*adminRepos = append(*adminRepos, name)
				}
			} else if b, _ := perms["push"].(bool); b {
				writable++
			}
			if name != "" && len(notable) < 5 && sensitiveNames([]string{name}) != "" {
				notable = append(notable, name)
			}
		}
		if len(repos) < 100 {
			break
		}
	}
	if examined == 0 {
		return out
	}
	reach := strconv.Itoa(examined)
	if haveTotal && total > examined {
		reach = "~" + strconv.Itoa(total)
	}
	out = append(out, module.Finding{Key: "repos accessible", Value: reach, Flag: module.FlagInfo})
	if writable > 0 {
		out = append(out, module.Finding{Key: "write access", Value: strconv.Itoa(writable) + " repos (push)", Flag: module.FlagWarn})
	}
	if admin > 0 {
		out = append(out, module.Finding{Key: "repo admin", Value: strconv.Itoa(admin) + " repos", Flag: module.FlagForceMultiplier})
	}
	if len(notable) > 0 {
		out = append(out, module.Finding{Key: "notable repos", Value: strings.Join(notable, ", "), Flag: module.FlagWarn})
	}
	return out
}

// orgAdmin lists orgs where the token's user holds the admin role (read-only).
func (githubPAT) orgAdmin(ctx context.Context, c *recon.Client, tok string) []module.Finding {
	req, _ := recon.NewRequest(ctx, http.MethodGet, "https://api.github.com/user/memberships/orgs?per_page=100", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var memberships []map[string]any
	if json.Unmarshal(resp.Body, &memberships) != nil {
		return nil
	}
	var adminOrgs []string
	for _, mem := range memberships {
		if role, _ := mem["role"].(string); role == "admin" {
			org, _ := mem["organization"].(map[string]any)
			if login, _ := org["login"].(string); login != "" {
				adminOrgs = append(adminOrgs, login)
			}
		}
	}
	if len(adminOrgs) == 0 {
		return nil
	}
	return []module.Finding{{Key: "org admin", Value: strings.Join(adminOrgs, ", "), Flag: module.FlagForceMultiplier}}
}

func (githubPAT) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "GET /user did not return an identity"
		return n
	}
	var bits []string
	for _, f := range fs {
		switch f.Key {
		case "scopes":
			if f.Flag == module.FlagForceMultiplier {
				bits = append(bits, "scopes "+f.Value)
			}
		case "org admin":
			bits = append(bits, "org-admin on "+f.Value)
		case "repo admin":
			bits = append(bits, "admin on "+f.Value)
		case "write access":
			bits = append(bits, f.Value)
		}
	}
	if len(bits) > 0 {
		n.Summary = "GitHub token — " + strings.Join(bits, "; ")
		return n
	}
	n.Summary = "valid GitHub token (read)"
	return n
}

var ghLinkLast = regexp.MustCompile(`[?&]page=(\d+)>;\s*rel="last"`)

func linkLast(link string) (int, bool) {
	m := ghLinkLast.FindStringSubmatch(link)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func hasForceScope(scopes string) bool {
	for _, s := range []string{"admin:org", "repo", "workflow", "delete_repo", "admin:enterprise"} {
		for _, have := range strings.Split(scopes, ",") {
			if strings.TrimSpace(have) == s {
				return true
			}
		}
	}
	return false
}

func init() {
	module.Register(githubPAT{})
	module.MapRule("github-pat", "github_pat")
	module.MapRule("github-fine-grained-pat", "github_pat")
	module.MapRule("github-oauth", "github_pat")
	module.MapRule("github-app-token", "github_pat")
	module.MapRule("github-refresh-token", "github_pat")
}
