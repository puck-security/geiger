package modules

import (
	"context"
	"net/http"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// oktaKey characterizes an Okta API token (SSWS). The token inherits the rights
// of the admin who created it, so an Okta token is frequently the IdP's crown
// jewels — it sits in front of every SSO-integrated app. Default --live confirms
// identity; --okta-intrusive sizes the real reach: whether the token can read
// the user directory (all employee PII), which apps Okta fronts, and whether it
// holds admin (System Log read is an admin-only tell).
type oktaKey struct{ module.Base }

func (oktaKey) Name() string { return "okta" }

func (oktaKey) EndpointPolicy() module.EndpointPolicy {
	return saasOnly("okta.com", "oktapreview.com", "okta-emea.com", "okta-gov.com")
}

func (m oktaKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	base := f["endpoint"]
	if base == "" {
		return nil, nil // endpoint-scoped: the pipeline emits a "set --endpoint" note
	}
	tok := f["token"]
	var out []module.Finding
	lv := &liveness{}
	// Identity: /users/me resolves for a user-bound token; SSWS org tokens 403
	// here but remain valid, so this is best-effort.
	if resp := m.get(ctx, c, base, "/api/v1/users/me", tok); resp != nil {
		lv.observe(resp, nil, true)
		if !resp.DryRun && resp.Status < 300 {
			if login := jsonPath(resp.Body, "profile.login"); login != "" {
				out = append(out, module.Finding{Key: "user", Value: login, Flag: module.FlagInfo})
			}
		}
	}

	if !c.MinFootprint() && c.OktaIntrusive() {
		out = append(out, m.deepReach(ctx, c, base, tok)...)
	}

	// Classify an accepted-but-unparsed response as live rather than dead; an
	// all-rejected token leaves out empty so Summarize marks it invalid.
	out = withLiveness(out, 0, lv)
	if len(out) > 0 {
		// The token is live/able — prepend the advisory note as context.
		out = append([]module.Finding{{Key: "note", Value: "SSWS inherits the creating admin's rights; super_admin = IdP takeover", Flag: module.FlagInfo}}, out...)
	}
	return out, nil
}

func (m oktaKey) get(ctx context.Context, c *recon.Client, base, path, tok string) *recon.Response {
	req, err := recon.NewRequest(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "SSWS "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req, recon.CallOpts{Note: "okta GET " + path + " (read-only)"})
	if err != nil {
		return nil
	}
	return resp
}

// deepReach sizes the token's reach: directory read (all user PII), the SSO apps
// Okta fronts, and admin access (System Log). All read-only; a denied scope just
// yields no finding.
func (m oktaKey) deepReach(ctx context.Context, c *recon.Client, base, tok string) []module.Finding {
	var out []module.Finding

	// Directory read = every employee's profile and PII.
	if resp := m.get(ctx, c, base, "/api/v1/users?limit=1", tok); resp != nil && !resp.DryRun && resp.Status < 300 {
		out = append(out, module.Finding{
			Key:   "directory",
			Value: "can read the user directory (all employee profiles / PII)",
			Flag:  module.FlagWarn,
		})
	}

	// SSO apps = what sits behind Okta (the downstream blast radius).
	if names, more := m.appNames(ctx, c, base, tok); len(names) > 0 {
		val := strings.Join(names, ", ")
		if more {
			val += ", …"
		}
		out = append(out, module.Finding{Key: "sso apps", Value: "fronts: " + val, Flag: module.FlagForceMultiplier})
	}

	// System Log read is an admin-only capability — a strong admin tell.
	if resp := m.get(ctx, c, base, "/api/v1/logs?limit=1", tok); resp != nil && !resp.DryRun && resp.Status < 300 {
		out = append(out, module.Finding{
			Key:   "admin",
			Value: "System Log readable — token holds an admin role",
			Flag:  module.FlagForceMultiplier,
		})
	}
	return out
}

// appNames returns a bounded sample of the SSO application labels the token can
// see, and whether more exist.
func (m oktaKey) appNames(ctx context.Context, c *recon.Client, base, tok string) ([]string, bool) {
	resp := m.get(ctx, c, base, "/api/v1/apps?limit=20", tok)
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return nil, false
	}
	arr, ok := jsonDecodeArray(resp.Body)
	if !ok {
		return nil, false
	}
	var names []string
	for _, it := range arr {
		mm, _ := it.(map[string]any)
		if label, _ := mm["label"].(string); label != "" {
			names = append(names, label)
		}
		if len(names) >= 8 {
			break
		}
	}
	return names, len(arr) > len(names)
}

func (oktaKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "Okta token returned no response"
		return n
	}
	for _, f := range fs {
		if f.Key == "admin" {
			n.Summary = "Okta token — admin (IdP control)"
			return n
		}
	}
	for _, f := range fs {
		if f.Key == "sso apps" || f.Key == "directory" {
			n.Summary = "Okta token — directory/app read"
			return n
		}
	}
	n.Summary = "Okta API token"
	return n
}

func init() {
	module.Register(oktaKey{})
	module.MapRule("okta-access-token", "okta")
}
