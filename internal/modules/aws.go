package modules

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/sign"
)

// awsEndpoints are overridable in tests.
var awsEndpoints = struct{ STS, IAM, S3, Secrets string }{
	STS:     "https://sts.amazonaws.com/",
	IAM:     "https://iam.amazonaws.com/",
	S3:      "https://s3.amazonaws.com/",
	Secrets: "https://secretsmanager.us-east-1.amazonaws.com/",
}

// awsKey covers long-term (AKIA) and temporary (ASIA) access keys. Recon starts
// with sts:GetCallerIdentity (needs no IAM permission, works under explicit
// deny), then sizes reach with read-only IAM/S3/SecretsManager calls.
type awsKey struct{ module.Base }

func (awsKey) Name() string { return "aws" }

func (m awsKey) sign(ctx context.Context, req *http.Request, f module.Fields, body []byte, svcName string) error {
	return sign.SigV4(ctx, req, f["access_key"], f["secret_key"], f["session_token"], svcName, "us-east-1", body)
}

func (m awsKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding

	// 1. whoami — sts:GetCallerIdentity (read-only POST).
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.STS, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := m.sign(ctx, req, f, body, "sts"); err != nil {
		return nil, err
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "sts:GetCallerIdentity (read-only)"})
	if err != nil {
		return nil, err
	}
	var callerARN string
	if !resp.DryRun {
		if resp.Status >= 400 {
			return nil, errStatus(resp.Status)
		}
		arn := xmlField(resp.Body, "Arn")
		account := xmlField(resp.Body, "Account")
		if arn == "" {
			return nil, errStatus(resp.Status)
		}
		callerARN = arn
		out = append(out, module.Finding{Key: "identity", Value: arn + "   (" + arnKind(arn) + ")", Flag: module.FlagInfo})
		if account != "" {
			out = append(out, module.Finding{Key: "account", Value: account, Flag: module.FlagInfo})
		}
	}

	if c.MinFootprint() { // OPSEC: identity only (one CloudTrail event)
		return out, nil
	}

	// Findings beyond this point characterize reach. Remember the floor so we can
	// state explicitly when every read-only probe came back empty — a key that
	// only proves its identity should read as "scope not surfaced", not as "safe".
	base := len(out)

	// 2. account alias (prod tell) — iam:ListAccountAliases.
	if alias := m.iamAlias(ctx, c, f); alias != "" {
		flag := module.FlagInfo
		if isProd(alias) {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "alias", Value: alias, Flag: flag})
	}

	// 3. bucket inventory — s3:ListBuckets.
	if names, ok := m.s3Buckets(ctx, c, f); ok {
		flag := module.FlagInfo
		val := strconv.Itoa(len(names)) + " visible"
		if sens := sensitiveNames(names); sens != "" {
			flag = module.FlagWarn
			val += " — incl. " + sens
		}
		out = append(out, module.Finding{Key: "buckets", Value: val, Flag: flag})
	}

	// 4. secrets-store reach — secretsmanager:ListSecrets (force multiplier).
	if n, ok := m.secretsCount(ctx, c, f); ok {
		out = append(out, module.Finding{
			Key:   "secrets",
			Value: "can list " + strconv.Itoa(n) + " secrets",
			Flag:  module.FlagForceMultiplier,
		})
	}

	// 5. privesc edges — iam:SimulatePrincipalPolicy (read-only).
	if callerARN != "" {
		out = append(out, m.privesc(ctx, c, f, callerARN)...)
	}

	// Make the negative space legible: a valid key whose every reach probe was
	// denied or empty otherwise renders as a bare identity, which reads as "narrow
	// and safe" when geiger simply found no access it could prove read-only.
	if callerARN != "" && len(out) == base {
		out = append(out, module.Finding{
			Key:   "reach",
			Value: "identity only — read-only probes (IAM alias, S3, Secrets Manager, privesc) surfaced no further access",
			Flag:  module.FlagInfo,
		})
	}
	return out, nil
}

func (m awsKey) iamAlias(ctx context.Context, c *recon.Client, f module.Fields) string {
	body := []byte("Action=ListAccountAliases&Version=2010-05-08")
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.IAM, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if m.sign(ctx, req, f, body, "iam") != nil {
		return ""
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "iam:ListAccountAliases"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	return xmlField(resp.Body, "member")
}

func (m awsKey) s3Buckets(ctx context.Context, c *recon.Client, f module.Fields) ([]string, bool) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, awsEndpoints.S3, nil)
	if m.sign(ctx, req, f, nil, "s3") != nil {
		return nil, false
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "s3:ListBuckets"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil, false
	}
	return xmlFields(resp.Body, "Name"), true
}

func (m awsKey) secretsCount(ctx context.Context, c *recon.Client, f module.Fields) (int, bool) {
	body := []byte(`{}`)
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.Secrets, body)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.ListSecrets")
	if m.sign(ctx, req, f, body, "secretsmanager") != nil {
		return 0, false
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "secretsmanager:ListSecrets (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return 0, false
	}
	d := jsonDecode(resp.Body)
	if list, ok := d["SecretList"].([]any); ok {
		return len(list), true
	}
	return 0, false
}

// Harvest pulls values from Secrets Manager: list the secrets, then
// GetSecretValue each (read-only POSTs that extract the value). The pipeline
// recursively triages whatever comes back. Bounded to avoid extracting a huge
// store in one shot.
func (m awsKey) Harvest(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	names := m.listSecretNames(ctx, c, f)
	const cap = 25
	var out []module.Harvested
	for i, name := range names {
		if i >= cap {
			break
		}
		if v := m.getSecretValue(ctx, c, f, name); v != "" {
			out = append(out, module.Harvested{Label: name, Value: v})
		}
	}
	return out, nil
}

func (m awsKey) listSecretNames(ctx context.Context, c *recon.Client, f module.Fields) []string {
	body := []byte(`{"MaxResults":100}`)
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.Secrets, body)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.ListSecrets")
	if m.sign(ctx, req, f, body, "secretsmanager") != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "secretsmanager:ListSecrets (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	d := jsonDecode(resp.Body)
	list, _ := d["SecretList"].([]any)
	var names []string
	for _, it := range list {
		if mm, ok := it.(map[string]any); ok {
			if n, ok := mm["Name"].(string); ok {
				names = append(names, n)
			}
		}
	}
	return names
}

func (m awsKey) getSecretValue(ctx context.Context, c *recon.Client, f module.Fields, name string) string {
	body := []byte(`{"SecretId":` + jsonQuote(name) + `}`)
	req, _ := recon.NewRequest(ctx, http.MethodPost, awsEndpoints.Secrets, body)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	if m.sign(ctx, req, f, body, "secretsmanager") != nil {
		return ""
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "secretsmanager:GetSecretValue (read-only, extracts value)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	return jsonField(resp.Body, "SecretString")
}

func (awsKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "sts:GetCallerIdentity returned no identity"
		return n
	}
	parts := []string{}
	for _, f := range fs {
		switch f.Key {
		case "alias":
			if f.Flag == module.FlagWarn {
				parts = append(parts, "prod account")
			}
		case "secrets":
			parts = append(parts, "secrets access")
		case "buckets":
			if f.Flag == module.FlagWarn {
				parts = append(parts, "sensitive buckets")
			}
		}
	}
	if len(parts) == 0 {
		n.Summary = "valid AWS key"
	} else {
		n.Summary = strings.Join(parts, " + ")
	}
	return n
}

// ---- recognition ----

func recognizeAWS(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var matches []recognize.Match
	add := func(ak, sk, st, label string, line int) {
		if ak == "" || sk == "" {
			return
		}
		matches = append(matches, recognize.Match{
			Module: "aws",
			Fields: module.Fields{"access_key": ak, "secret_key": sk, "session_token": st},
			Secret: ak,
			Label:  label,
			Line:   line,
		})
	}
	// INI sections (~/.aws/credentials).
	for _, s := range b.INI {
		add(s.Keys["aws_access_key_id"], s.Keys["aws_secret_access_key"], s.Keys["aws_session_token"], "["+s.Name+"]", b.Lines[s.Name+".aws_access_key_id"])
	}
	// env / dotenv.
	add(b.Vars["AWS_ACCESS_KEY_ID"], b.Vars["AWS_SECRET_ACCESS_KEY"], b.Vars["AWS_SESSION_TOKEN"], "AWS_ACCESS_KEY_ID", b.Lines["AWS_ACCESS_KEY_ID"])
	return matches
}

func arnKind(arn string) string {
	switch {
	case strings.Contains(arn, ":user/"):
		return "IAM user"
	case strings.Contains(arn, ":assumed-role/"):
		return "assumed role"
	case strings.Contains(arn, ":federated-user/"):
		return "federated user"
	case strings.Contains(arn, ":root"):
		return "ROOT"
	default:
		return "principal"
	}
}

func isProd(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "prod") || strings.Contains(s, "production")
}

func sensitiveNames(names []string) string {
	var hits []string
	for _, n := range names {
		l := strings.ToLower(n)
		for _, kw := range []string{"prod", "pii", "customer", "backup", "secret", "private"} {
			if strings.Contains(l, kw) {
				hits = append(hits, n)
				break
			}
		}
		if len(hits) >= 3 {
			break
		}
	}
	return strings.Join(hits, ", ")
}

func init() {
	module.Register(awsKey{})
	module.MapRule("aws-access-token", "aws")
	recognize.RegisterRecognizer(recognizeAWS)
}
