package modules

import (
	"bytes"
	"encoding/base64"
	"regexp"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// WorkOS API keys are sk_<env>_ + base64("key_<id>"); the body always decodes to
// ASCII beginning with "key_". Stripe keys share the sk_ prefix but are random
// alphanumeric and won't decode this way — so we can claim a WorkOS key offline
// and Override the gitleaks Stripe misattribution. The paired client_id
// (client_<ULID>) is carried as context only; it is never required for a match.

var (
	workosKeyRe      = regexp.MustCompile(`sk_(?:test|live)_([A-Za-z0-9+/]+=*)`)
	workosClientIDRe = regexp.MustCompile(`\bclient_[0-9A-Z]{26}\b`)
)

func init() { registerWorkOS() }

func registerWorkOS() {
	add("", r.HTTP{
		ModuleName: "workos", Base: "https://api.workos.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/organizations?limit=1").Field("org", "data.0.name").Field("org-id", "data.0.id"),
		Calls: []r.Call{
			r.GET("/sso/connections?limit=1").FlagField("sso-connections", "data.0.id", fmFlag),
			r.GET("/directories?limit=1").FlagField("directory-connections", "data.0.id", warnFlag),
			r.GET("/directory_users?limit=1").FlagField("directory-PII", "data.0.id", warnFlag),
			r.GET("/user_management/users?limit=1").FlagField("user-PII", "data.0.id", warnFlag),
		},
		Static: []module.Finding{{Key: "reach", Value: "environment-scoped API key — manage SSO connections (federation trust), read Directory Sync employee PII, and User Management (create/delete users, reset passwords, revoke sessions)", Flag: fmFlag}},
		Summarize: func(fs []module.Finding) string {
			for _, f := range fs {
				if f.Key == "directory-PII" || f.Key == "user-PII" {
					return "WorkOS API key — SSO/federation control + employee/user PII"
				}
			}
			return "WorkOS API key — SSO/Directory Sync/User Management control"
		},
	}.Module())

	recognize.RegisterRecognizer(workosRecognizer)
}

func workosRecognizer(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var tokens []string
	seen := map[string]bool{}
	addTok := func(tok string) {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			tokens = append(tokens, tok)
		}
	}
	// Var name is authoritative; structural scan catches bare tokens / odd names.
	addTok(firstVar(b.Vars, "WORKOS_API_KEY", "WORKOS_SECRET_KEY", "WORKOS_KEY"))
	for _, tok := range scanWorkOSKeys(b.Raw) {
		addTok(tok)
	}
	if len(tokens) == 0 {
		return nil
	}
	cid := firstVar(b.Vars, "WORKOS_CLIENT_ID", "WORKOS_CLIENTID", "WORKOS_CLIENT", "NEXT_PUBLIC_WORKOS_CLIENT_ID")
	if cid == "" {
		cid = workosClientIDRe.FindString(b.Raw)
	}
	var out []recognize.Match
	for _, tok := range tokens {
		fields := module.Fields{"token": tok}
		if cid != "" {
			fields["client_id"] = cid
		}
		out = append(out, recognize.Match{
			Module: "workos", Fields: fields, Secret: tok,
			Label: workosLabel(b, tok), Overrides: []string{"stripe"},
		})
	}
	return out
}

// workosLabel returns the env-var name holding tok, else a sensible default.
func workosLabel(b parse.Blob, tok string) string {
	for k, v := range b.Vars {
		if v == tok {
			return k
		}
	}
	return "WORKOS_API_KEY"
}

// scanWorkOSKeys returns every sk_(test|live)_ token in raw whose base64 body
// decodes to ASCII beginning with "key_" (the WorkOS structure).
func scanWorkOSKeys(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range workosKeyRe.FindAllStringSubmatch(raw, -1) {
		full, body := m[0], m[1]
		if seen[full] {
			continue
		}
		if dec, ok := decodeBase64(body); ok && bytes.HasPrefix(dec, []byte("key_")) {
			out = append(out, full)
			seen[full] = true
		}
	}
	return out
}

// decodeBase64 tries standard (padded) then raw (unpadded) base64.
func decodeBase64(s string) ([]byte, bool) {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	return nil, false
}
