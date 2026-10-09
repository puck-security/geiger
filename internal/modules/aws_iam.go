package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// accountAuthDetails calls iam:GetAccountAuthorizationDetails — one read-only
// API that returns every user, role, group and managed policy in the account.
// This is the data Cloudsplaining and pmapper build their graphs from: if the
// key can read it, that read alone is a major blast-radius signal and enables
// full offline privesc analysis. The result is Marker-paginated; we follow a
// bounded number of pages to size the account.
func (m awsKey) accountAuthDetails(ctx context.Context, c *recon.Client, f module.Fields) (module.Finding, bool) {
	const maxPages = 10
	var users, roles, groups, policies int
	marker := ""
	got := false
	for range maxPages {
		form := url.Values{}
		form.Set("Action", "GetAccountAuthorizationDetails")
		form.Set("Version", "2010-05-08")
		form.Set("MaxItems", "1000")
		if marker != "" {
			form.Set("Marker", marker)
		}
		body := []byte(form.Encode())
		req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if m.sign(ctx, req, f, body, "iam") != nil {
			return module.Finding{}, false
		}
		resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:GetAccountAuthorizationDetails (read-only, full IAM graph)"})
		if err != nil || resp.DryRun || resp.Status >= 300 {
			if !got {
				return module.Finding{}, false
			}
			break
		}
		got = true
		// Each entity carries exactly one *Id tag at its top level; attached
		// managed policies inside users/roles/groups use PolicyArn, not PolicyId,
		// so these counts do not double-count.
		users += len(xmlFields(resp.Body, "UserId"))
		roles += len(xmlFields(resp.Body, "RoleId"))
		groups += len(xmlFields(resp.Body, "GroupId"))
		policies += len(xmlFields(resp.Body, "PolicyId"))
		if xmlField(resp.Body, "IsTruncated") != "true" {
			break
		}
		marker = xmlField(resp.Body, "Marker")
		if marker == "" {
			break
		}
	}
	if !got {
		return module.Finding{}, false
	}
	principals := users + roles
	val := fmt.Sprintf("%d IAM principals readable (full account authorization detail) — %d users, %d roles, %d groups, %d managed policies",
		principals, users, roles, groups, policies)
	return module.Finding{Key: "account iam", Value: val, Flag: module.FlagForceMultiplier}, true
}

// selfGrants unrolls where the caller's own power comes from: group membership
// and attached/inline managed policies. Simulation already answers whether the
// principal is effectively admin; this names the provenance (which group, which
// policy) that reviewers and reports need.
func (m awsKey) selfGrants(ctx context.Context, c *recon.Client, f module.Fields, callerARN string) []module.Finding {
	var out []module.Finding
	if strings.Contains(callerARN, ":user/") {
		name := arnResourceName(callerARN)
		if name == "" {
			return nil
		}
		if groups := m.iamList(ctx, c, f, "ListGroupsForUser", "UserName", name, "GroupName"); len(groups) > 0 {
			out = append(out, groupFinding(groups))
		}
		attached := m.iamList(ctx, c, f, "ListAttachedUserPolicies", "UserName", name, "PolicyName")
		inline := m.iamList(ctx, c, f, "ListUserPolicies", "UserName", name, "member")
		if fnd, ok := policyFinding(attached, inline); ok {
			out = append(out, fnd)
		}
		return out
	}
	// role or assumed-role session
	src := roleARNFor(callerARN)
	name := arnResourceName(src)
	if name == "" {
		return nil
	}
	attached := m.iamList(ctx, c, f, "ListAttachedRolePolicies", "RoleName", name, "PolicyName")
	inline := m.iamList(ctx, c, f, "ListRolePolicies", "RoleName", name, "member")
	if fnd, ok := policyFinding(attached, inline); ok {
		out = append(out, fnd)
	}
	return out
}

// iamList runs a read-only IAM list call with a single name parameter and
// returns the values of the named result tag.
func (m awsKey) iamList(ctx context.Context, c *recon.Client, f module.Fields, action, param, value, resultTag string) []string {
	form := url.Values{}
	form.Set("Action", action)
	form.Set("Version", "2010-05-08")
	form.Set(param, value)
	body := []byte(form.Encode())
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.sign(ctx, req, f, body, "iam") != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:" + action + " (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return xmlFields(resp.Body, resultTag)
}

func groupFinding(groups []string) module.Finding {
	flag := module.FlagInfo
	for _, g := range groups {
		if looksAdmin(g) {
			flag = module.FlagWarn
		}
	}
	return module.Finding{Key: "groups", Value: "member of: " + strings.Join(groups, ", "), Flag: flag}
}

func policyFinding(attached, inline []string) (module.Finding, bool) {
	if len(attached) == 0 && len(inline) == 0 {
		return module.Finding{}, false
	}
	flag := module.FlagInfo
	for _, p := range attached {
		if looksAdmin(p) {
			flag = module.FlagWarn
		}
	}
	var parts []string
	if len(attached) > 0 {
		parts = append(parts, "attached: "+strings.Join(attached, ", "))
	}
	if len(inline) > 0 {
		parts = append(parts, fmt.Sprintf("%d inline", len(inline)))
	}
	return module.Finding{Key: "policies", Value: strings.Join(parts, "; "), Flag: flag}, true
}

// accessKeyLastUsed reports when a long-term (AKIA) key was last used and for
// which service — a dormant long-lived key sitting in a file is a finding on its
// own. Temporary (ASIA) keys have no last-used record, so they are skipped.
func (m awsKey) accessKeyLastUsed(ctx context.Context, c *recon.Client, f module.Fields) (module.Finding, bool) {
	ak := f["access_key"]
	if !strings.HasPrefix(ak, "AKIA") {
		return module.Finding{}, false
	}
	form := url.Values{}
	form.Set("Action", "GetAccessKeyLastUsed")
	form.Set("Version", "2010-05-08")
	form.Set("AccessKeyId", ak)
	body := []byte(form.Encode())
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.sign(ctx, req, f, body, "iam") != nil {
		return module.Finding{}, false
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:GetAccessKeyLastUsed (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return module.Finding{}, false
	}
	used := xmlField(resp.Body, "LastUsedDate")
	svc := xmlField(resp.Body, "ServiceName")
	if used == "" || svc == "N/A" {
		return module.Finding{Key: "key activity", Value: "never used (dormant long-term key)", Flag: module.FlagWarn}, true
	}
	val := "last used " + used
	if svc != "" {
		val += " for " + svc
	}
	flag := module.FlagInfo
	if t, perr := time.Parse(time.RFC3339, used); perr == nil {
		days := int(time.Since(t).Hours() / 24)
		val += fmt.Sprintf(" (%dd ago)", days)
		if days >= 90 {
			flag = module.FlagWarn
			val += " — dormant"
		}
	}
	return module.Finding{Key: "key activity", Value: val, Flag: flag}, true
}

// arnResourceName returns the final resource name of a user or role ARN,
// stripping any path. arn:aws:iam::acct:role/path/Name -> Name.
func arnResourceName(arn string) string {
	for _, p := range []string{":user/", ":role/"} {
		if i := strings.Index(arn, p); i > 0 {
			rest := arn[i+len(p):]
			if j := strings.LastIndexByte(rest, '/'); j >= 0 {
				rest = rest[j+1:]
			}
			return rest
		}
	}
	return ""
}

func looksAdmin(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, "admin") || strings.HasSuffix(l, "fullaccess") || l == "poweruseraccess"
}
