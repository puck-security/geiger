package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// privescActions is the curated set of IAM/STS privilege-escalation primitives.
// Each, if allowed, lets the principal grant itself more power. We learn the
// answer read-only via iam:SimulatePrincipalPolicy — nothing is performed.
var privescActions = []struct{ action, why string }{
	{"iam:CreateAccessKey", "mint access keys for any user"},
	{"iam:CreateLoginProfile", "set a console password for any user"},
	{"iam:AttachUserPolicy", "attach AdministratorAccess to a user"},
	{"iam:AttachRolePolicy", "attach AdministratorAccess to a role"},
	{"iam:PutUserPolicy", "inline-grant any permission to a user"},
	{"iam:CreatePolicyVersion", "rewrite a managed policy"},
	{"iam:UpdateAssumeRolePolicy", "hijack a role's trust policy"},
	{"iam:PassRole", "pass a privileged role to a new resource"},
	{"sts:AssumeRole", "pivot into other roles"},
}

// awsPrivesc simulates the curated privesc primitives against the caller and
// reports which are allowed. PolicySourceArn must be a user or role ARN, so an
// assumed-role session ARN is normalized to its role ARN first.
func (m awsKey) privesc(ctx context.Context, c *recon.Client, f module.Fields, callerARN string) []module.Finding {
	src := roleARNFor(callerARN)
	if src == "" {
		return nil
	}
	form := url.Values{}
	form.Set("Action", "SimulatePrincipalPolicy")
	form.Set("Version", "2010-05-08")
	form.Set("PolicySourceArn", src)
	for i, a := range privescActions {
		form.Set("ActionNames.member."+itoaInt(i+1), a.action)
	}
	body := []byte(form.Encode())
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.sign(ctx, req, f, body, "iam") != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:SimulatePrincipalPolicy (read-only privesc check)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	allowed := allowedActions(resp.Body)
	var out []module.Finding
	for _, a := range privescActions {
		if allowed[a.action] {
			out = append(out, module.Finding{
				Key:   "privesc",
				Value: a.action + " — " + a.why,
				Flag:  module.FlagForceMultiplier,
			})
		}
	}
	if len(out) == 0 && len(allowed) >= 0 {
		// simulation ran but found no escalation edge
		out = append(out, module.Finding{Key: "privesc", Value: "no escalation edge among checked primitives", Flag: module.FlagInfo})
	}
	return out
}

// roleARNFor returns a user/role ARN suitable for SimulatePrincipalPolicy.
// arn:aws:sts::acct:assumed-role/Role/session -> arn:aws:iam::acct:role/Role.
func roleARNFor(arn string) string {
	if strings.Contains(arn, ":user/") {
		return arn
	}
	if i := strings.Index(arn, ":assumed-role/"); i > 0 {
		acct := arnAccount(arn)
		rest := arn[i+len(":assumed-role/"):]
		role := rest
		if j := strings.IndexByte(rest, '/'); j > 0 {
			role = rest[:j]
		}
		if acct != "" && role != "" {
			return "arn:aws:iam::" + acct + ":role/" + role
		}
	}
	if strings.Contains(arn, ":role/") {
		return arn
	}
	return ""
}

func arnAccount(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// allowedActions parses SimulatePrincipalPolicy XML, returning actions whose
// decision is "allowed".
func allowedActions(body []byte) map[string]bool {
	out := map[string]bool{}
	names := xmlFields(body, "EvalActionName")
	decisions := xmlFields(body, "EvalDecision")
	for i := range names {
		if i < len(decisions) && decisions[i] == "allowed" {
			out[names[i]] = true
		}
	}
	return out
}
