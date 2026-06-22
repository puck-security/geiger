package modules

import (
	"regexp"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Cloudflare API tokens are poorly served by recognition: gitleaks'
// cloudflare-api-key rule is a context-keyword regex that only fires when the
// literal word "cloudflare" sits right next to a bare 40-char value, so it misses
// most `CLOUDFLARE_API_TOKEN=<hi-entropy>` lines — and it doesn't know the newer
// prefixed formats at all (cfat_ account tokens, cfut_ user tokens). Recognize
// them directly and route to the existing cloudflare / cloudflare_global modules,
// which validate live (/user/tokens/verify for tokens, /user for the global key).
// suppressConsumedUnknowns drops the generic_secret mis-hit on the same value.

// cfTokenRe matches Cloudflare's prefixed API tokens. The body is intentionally
// permissive — the module re-validates the value, so over-matching the shape is
// free (a non-token simply fails /user/tokens/verify).
var cfTokenRe = regexp.MustCompile(`cf(?:at|ut)_[A-Za-z0-9_-]{20,}`)

func init() { recognize.RegisterRecognizer(recognizeCloudflare) }

func recognizeCloudflare(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	seen := map[string]bool{}
	add := func(tok, label string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module: "cloudflare",
			Fields: module.Fields{"token": tok},
			Secret: tok, Label: label,
		})
	}
	// Legacy un-prefixed token by variable name (the shape is too generic to match
	// on its own; the name is the signal gitleaks keys on but often misses).
	if tok := firstVar(b.Vars, "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_TOKEN"); tok != "" {
		add(tok, "CLOUDFLARE_API_TOKEN")
	}
	// Prefixed tokens anywhere in the blob (bare on stdin, or as any value).
	for _, tok := range cfTokenRe.FindAllString(b.Raw, -1) {
		add(tok, "cloudflare-api-token")
	}
	// Legacy Global API Key needs the account email for the X-Auth-* headers.
	if key := firstVar(b.Vars, "CLOUDFLARE_API_KEY", "CF_API_KEY", "CLOUDFLARE_GLOBAL_API_KEY"); key != "" {
		if email := firstVar(b.Vars, "CLOUDFLARE_EMAIL", "CF_API_EMAIL", "CLOUDFLARE_ACCOUNT_EMAIL"); email != "" {
			out = append(out, recognize.Match{
				Module: "cloudflare_global",
				Fields: module.Fields{"token": key, "email": email},
				Secret: key, Label: "CLOUDFLARE_API_KEY",
			})
		}
	}
	return out
}
