package modules

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// awsSSOPortalBase is overridable in tests; empty means derive from region.
var awsSSOPortalBase = ""

func ssoBase(region string) string {
	if awsSSOPortalBase != "" {
		return awsSSOPortalBase
	}
	if region == "" {
		region = "us-east-1"
	}
	return "https://portal.sso." + region + ".amazonaws.com"
}

// awsSSO triages an AWS SSO token cache (~/.aws/sso/cache/*.json). With the
// cached accessToken it enumerates, via the SSO portal API, every account and
// permission set the user can assume — the real blast radius of an SSO session.
type awsSSO struct{ module.Base }

func (awsSSO) Name() string { return "aws_sso" }

func (m awsSSO) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding
	if su := f["start_url"]; su != "" {
		out = append(out, module.Finding{Key: "start url", Value: su, Flag: module.FlagInfo})
	}
	// Validity is offline-checkable from expiresAt.
	if exp := f["expires_at"]; exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil && time.Now().After(t) {
			out = append(out, module.Finding{Key: "validity", Value: "EXPIRED " + exp, Flag: module.FlagWarn})
			return out, nil
		}
		out = append(out, module.Finding{Key: "valid until", Value: exp + "  (live)", Flag: module.FlagInfo})
	}

	base := ssoBase(f["region"])
	accounts := m.listAccounts(ctx, c, base, f["access_token"])
	if accounts == nil {
		// no accessToken response — either dry-run or token rejected
		if !c.Live() {
			return nil, nil
		}
		out = append(out, module.Finding{Key: "session", Value: "token did not enumerate accounts (expired or revoked)", Flag: module.FlagInfo})
		return out, nil
	}
	out = append(out, module.Finding{Key: "accounts", Value: strconv.Itoa(len(accounts)) + " assumable", Flag: module.FlagInfo})

	var adminOn, prodOn []string
	limit := len(accounts)
	if !c.MinFootprint() {
		if limit > 15 {
			limit = 15
		}
		for i := 0; i < limit; i++ {
			a := accounts[i]
			roles := m.listRoles(ctx, c, base, f["access_token"], a.id)
			if hasAdminRole(roles) {
				adminOn = append(adminOn, a.label())
			}
			if isProd(a.name) {
				prodOn = append(prodOn, a.label())
			}
		}
	}
	if len(prodOn) > 0 {
		out = append(out, module.Finding{Key: "prod accounts", Value: strings.Join(prodOn, ", "), Flag: module.FlagWarn})
	}
	if len(adminOn) > 0 {
		out = append(out, module.Finding{Key: "admin", Value: "AdministratorAccess on " + strings.Join(adminOn, ", "), Flag: module.FlagForceMultiplier})
	}
	return out, nil
}

func (m awsSSO) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "SSO token did not enumerate anything"
		return n
	}
	for _, f := range fs {
		if f.Key == "validity" && strings.HasPrefix(f.Value, "EXPIRED") {
			n.Invalid, n.Reason = true, "SSO session expired"
			return n
		}
	}
	for _, f := range fs {
		if f.Key == "admin" {
			n.Summary = "active SSO session — admin on a prod account"
			return n
		}
	}
	if len(fs) > 0 {
		n.Summary = "active SSO session"
	}
	return n
}

type ssoAccount struct{ id, name string }

func (a ssoAccount) label() string {
	if a.name != "" {
		return a.name + " (" + a.id + ")"
	}
	return a.id
}

func (m awsSSO) listAccounts(ctx context.Context, c *recon.Client, base, token string) []ssoAccount {
	req, _ := recon.NewRequest(ctx, http.MethodGet, base+"/assignment/accounts?max_result=100", nil)
	req.Header.Set("x-amz-sso_bearer_token", token)
	resp, err := c.Do(req, recon.CallOpts{Note: "sso:ListAccounts (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	d := jsonDecode(resp.Body)
	list, _ := d["accountList"].([]any)
	out := make([]ssoAccount, 0, len(list))
	for _, a := range list {
		am, _ := a.(map[string]any)
		id, _ := am["accountId"].(string)
		name, _ := am["accountName"].(string)
		out = append(out, ssoAccount{id: id, name: name})
	}
	return out
}

func (m awsSSO) listRoles(ctx context.Context, c *recon.Client, base, token, accountID string) []string {
	u := base + "/assignment/roles?max_result=100&account_id=" + url.QueryEscape(accountID)
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("x-amz-sso_bearer_token", token)
	resp, err := c.Do(req, recon.CallOpts{Note: "sso:ListAccountRoles (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	d := jsonDecode(resp.Body)
	list, _ := d["roleList"].([]any)
	var roles []string
	for _, r := range list {
		rm, _ := r.(map[string]any)
		if rn, ok := rm["roleName"].(string); ok {
			roles = append(roles, rn)
		}
	}
	return roles
}

func hasAdminRole(roles []string) bool {
	for _, r := range roles {
		l := strings.ToLower(r)
		if strings.Contains(l, "administrator") || strings.Contains(l, "admin") {
			return true
		}
	}
	return false
}

// ---- recognition ----

// recognizeAWSSSO handles both files under ~/.aws/sso/cache/: the token cache
// (has accessToken) and the OIDC client registration (clientId+clientSecret,
// no accessToken) which is not a usable session.
func recognizeAWSSSO(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	access, _ := b.JSON["accessToken"].(string)
	startURL, _ := b.JSON["startUrl"].(string)
	region, _ := b.JSON["region"].(string)
	if access != "" {
		expires, _ := b.JSON["expiresAt"].(string)
		return []recognize.Match{{
			Module: "aws_sso",
			Fields: module.Fields{"access_token": access, "start_url": startURL, "region": region, "expires_at": expires},
			Secret: access,
			Label:  "SSO token cache",
		}}
	}
	// registration file: clientId + clientSecret, no session token.
	cid, _ := b.JSON["clientId"].(string)
	csec, _ := b.JSON["clientSecret"].(string)
	if cid != "" && csec != "" {
		expires, _ := b.JSON["expiresAt"].(string)
		return []recognize.Match{{
			Module: "aws_sso_registration",
			Fields: module.Fields{"client_secret": csec, "expires_at": expires},
			Secret: csec,
			Label:  "SSO client registration",
		}}
	}
	return nil
}

// awsSSORegistration characterizes the OIDC client-registration cache offline —
// it is not a session token, so it can't be exercised.
type awsSSORegistration struct{ module.Base }

func (awsSSORegistration) Name() string { return "aws_sso_registration" }

func (awsSSORegistration) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{
		Key:   "type",
		Value: "AWS SSO OIDC client registration — not a session; the usable accessToken is in the sibling token-cache file",
		Flag:  module.FlagCantCharacterize,
	}}
	if exp := f["expires_at"]; exp != "" {
		out = append(out, module.Finding{Key: "registration expires", Value: exp, Flag: module.FlagInfo})
	}
	return out, nil
}

func (awsSSORegistration) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "SSO client registration (no session)"}
}

func init() {
	module.Register(awsSSO{})
	module.Register(awsSSORegistration{})
	recognize.RegisterRecognizer(recognizeAWSSSO)
}
