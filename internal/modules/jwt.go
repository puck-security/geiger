package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// genericJWT decodes a JWT entirely offline: no network call is made or needed.
// It surfaces issuer/subject/audience/expiry/scope and hints at the provider
// the issuer maps to.
type genericJWT struct{ module.Base }

func (genericJWT) Name() string { return "jwt" }

func (genericJWT) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	hdr, payload, err := decodeJWT(f["token"])
	if err != nil {
		return nil, err
	}
	var out []module.Finding
	if iss, _ := payload["iss"].(string); iss != "" {
		val := iss
		if hint := issuerHint(iss); hint != "" {
			val += "   (" + hint + ")"
		}
		out = append(out, module.Finding{Key: "issuer", Value: val, Flag: module.FlagInfo})
	}
	if sub, _ := payload["sub"].(string); sub != "" {
		out = append(out, module.Finding{Key: "subject", Value: sub, Flag: module.FlagInfo})
	}
	if aud := claimString(payload["aud"]); aud != "" {
		out = append(out, module.Finding{Key: "audience", Value: aud, Flag: module.FlagInfo})
	}
	if scope := claimScopes(payload); scope != "" {
		out = append(out, module.Finding{Key: "scopes/roles", Value: scope, Flag: module.FlagInfo})
	}
	if exp, ok := claimTime(payload["exp"]); ok {
		flag := module.FlagInfo
		val := exp.UTC().Format("2006-01-02 15:04Z")
		if time.Now().After(exp) {
			val += "  (EXPIRED)"
			flag = module.FlagWarn
		} else {
			val += "  (live)"
		}
		out = append(out, module.Finding{Key: "expires", Value: val, Flag: flag})
	}
	if alg, _ := hdr["alg"].(string); alg != "" {
		out = append(out, module.Finding{Key: "alg", Value: alg, Flag: module.FlagInfo})
	}
	return out, nil
}

func (genericJWT) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "could not decode JWT"
		return n
	}
	n.Summary = "decoded offline — no network call made; map issuer to its provider for live recon"
	for _, f := range fs {
		if f.Key == "expires" && strings.Contains(f.Value, "EXPIRED") {
			n.Summary = "expired JWT"
		}
	}
	return n
}

func decodeJWT(tok string) (hdr, payload map[string]any, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("not a JWT")
	}
	dec := func(s string) (map[string]any, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		return m, json.Unmarshal(b, &m)
	}
	if hdr, err = dec(parts[0]); err != nil {
		return nil, nil, err
	}
	if payload, err = dec(parts[1]); err != nil {
		return nil, nil, err
	}
	return hdr, payload, nil
}

func issuerHint(iss string) string {
	switch {
	case strings.Contains(iss, "login.microsoftonline.com"), strings.Contains(iss, "sts.windows.net"):
		return "Entra/Azure AD"
	case strings.Contains(iss, "accounts.google.com"), strings.Contains(iss, "securetoken.google.com"):
		return "Google/Firebase"
	case strings.Contains(iss, "okta.com"):
		return "Okta"
	case strings.Contains(iss, "auth0.com"):
		return "Auth0"
	case strings.Contains(iss, "cognito"):
		return "AWS Cognito"
	case strings.Contains(iss, "token.actions.githubusercontent.com"):
		return "GitHub Actions OIDC"
	case strings.Contains(iss, "supabase"):
		return "Supabase"
	default:
		return ""
	}
}

func claimString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

func claimScopes(p map[string]any) string {
	for _, k := range []string{"scope", "scp", "roles", "permissions"} {
		if v := claimString(p[k]); v != "" {
			return v
		}
	}
	return ""
}

func claimTime(v any) (time.Time, bool) {
	if f, ok := v.(float64); ok {
		return time.Unix(int64(f), 0), true
	}
	return time.Time{}, false
}

func init() {
	module.Register(genericJWT{})
	module.MapRule("jwt", "jwt")
	module.MapRule("jwt-base64", "jwt")
}
