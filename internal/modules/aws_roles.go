package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// roleGraph enumerates account roles and reads each trust policy to find where
// the key can pivot (roles assumable in-account or by anyone) and where the
// account is exposed to outsiders (roles trusting external accounts). This is
// the edge data pmapper computes. It calls iam:ListRoles and reads every trust
// document, a lot of CloudTrail noise, so it runs only under --aws-intrusive.
func (m awsKey) roleGraph(ctx context.Context, c *recon.Client, f module.Fields, callerARN string) []module.Finding {
	if !c.AWSIntrusive() {
		return nil
	}
	self := arnAccount(callerARN)
	const maxPages = 5
	var docs []string
	marker := ""
	got := false
	for range maxPages {
		form := url.Values{}
		form.Set("Action", "ListRoles")
		form.Set("Version", "2010-05-08")
		form.Set("MaxItems", "200")
		if marker != "" {
			form.Set("Marker", marker)
		}
		body := []byte(form.Encode())
		req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if m.sign(ctx, req, f, body, "iam") != nil {
			return nil
		}
		resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:ListRoles (read-only, trust-policy graph)"})
		if err != nil || resp.DryRun || resp.Status >= 300 {
			if !got {
				return nil
			}
			break
		}
		got = true
		docs = append(docs, xmlFields(resp.Body, "AssumeRolePolicyDocument")...)
		if xmlField(resp.Body, "IsTruncated") != "true" {
			break
		}
		marker = xmlField(resp.Body, "Marker")
		if marker == "" {
			break
		}
	}
	if !got {
		return nil
	}

	var inAccount, world int
	external := map[string]bool{}
	for _, raw := range docs {
		dec, err := url.QueryUnescape(raw)
		if err != nil {
			dec = raw
		}
		principals := trustPrincipals(dec)
		for _, p := range principals {
			switch {
			case p == "*":
				world++
			case principalInAccount(p, self):
				inAccount++
			default:
				if acct := principalAccount(p); acct != "" && acct != self {
					external[acct] = true
				}
			}
		}
	}

	var out []module.Finding
	if world > 0 {
		out = append(out, module.Finding{
			Key:   "assumable roles",
			Value: strconv.Itoa(world) + " roles trust any principal (*) — world-assumable",
			Flag:  module.FlagForceMultiplier,
		})
	}
	if inAccount > 0 {
		out = append(out, module.Finding{
			Key:   "assumable roles",
			Value: strconv.Itoa(inAccount) + " roles assumable in-account (pivot targets with sts:AssumeRole)",
			Flag:  module.FlagWarn,
		})
	}
	if len(external) > 0 {
		accts := make([]string, 0, len(external))
		for a := range external {
			accts = append(accts, a)
		}
		sort.Strings(accts)
		out = append(out, module.Finding{
			Key:   "cross-account trust",
			Value: "roles trust external accounts: " + strings.Join(accts, ", "),
			Flag:  module.FlagWarn,
		})
	}
	return out
}

// trustPrincipals returns the AWS principals named in a trust policy's Allow
// statements. Service and Federated principals are ignored; only "AWS" ones
// (account roots, ARNs, or "*") describe cross-principal assume reach.
func trustPrincipals(doc string) []string {
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return nil
	}
	var stmts []struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
	}
	// Statement may be a single object or an array.
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
		}
		if json.Unmarshal(d.Statement, &one) != nil {
			return nil
		}
		stmts = append(stmts, one)
	}
	var out []string
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		out = append(out, awsPrincipalValues(s.Principal)...)
	}
	return out
}

// awsPrincipalValues extracts the "AWS" principal values. Principal can be the
// string "*", or an object whose "AWS" field is a string or a string array.
func awsPrincipalValues(raw json.RawMessage) []string {
	var star string
	if json.Unmarshal(raw, &star) == nil {
		if star == "*" {
			return []string{"*"}
		}
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	awsField, ok := obj["AWS"]
	if !ok {
		return nil
	}
	var one string
	if json.Unmarshal(awsField, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(awsField, &many) == nil {
		return many
	}
	return nil
}

func principalInAccount(p, self string) bool {
	if self == "" {
		return false
	}
	return p == self || strings.Contains(p, "::"+self+":")
}

// principalAccount pulls the 12-digit account id out of an ARN-style principal.
func principalAccount(p string) string {
	parts := strings.Split(p, ":")
	if len(parts) >= 5 && len(parts[4]) == 12 {
		return parts[4]
	}
	if len(p) == 12 {
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	return ""
}
