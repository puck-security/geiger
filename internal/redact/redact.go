// Package redact masks secret material so it never appears in Geiger output.
package redact

import (
	"regexp"
	"strings"
)

// Secret masks a credential, preserving only a short tail for correlation.
// Short secrets are fully masked. Examples:
//
//	Secret("ghp_aBcD...wXyZJV3Q") => "ghp_…JV3Q"
//	Secret("abc")                 => "…"
func Secret(s string) string {
	if s == "" {
		return ""
	}
	// Keep a recognizable prefix up to and including the first underscore
	// (e.g. "ghp_", "sk_live_") when present and short.
	prefix := ""
	if i := strings.IndexByte(s, '_'); i >= 0 && i < 10 {
		// include trailing underscores of a multi-part prefix like sk_live_
		end := i + 1
		if j := strings.IndexByte(s[end:], '_'); j >= 0 && end+j < 12 {
			end = end + j + 1
		}
		prefix = s[:end]
		s = s[end:]
	}
	if len(s) <= 4 {
		return prefix + "…"
	}
	return prefix + "…" + s[len(s)-4:]
}

// tokenish matches long credential-shaped substrings (base64/hex/jwt-ish runs).
// A leading $ is included so a "$VAR_NAME" placeholder is matched whole and can
// be skipped rather than partially redacted.
var tokenish = regexp.MustCompile(`[$A-Za-z0-9_\-\.+/=]{16,}`)

// Line redacts any token-shaped substring inside free text, so accidental
// echoes of a raw secret in a log line or error message are masked.
func Line(s string) string {
	return tokenish.ReplaceAllStringFunc(s, func(m string) string {
		// Leave shell variable references ($OPENAI_API_KEY) intact — they're
		// placeholders the scrubber put there, not secrets.
		if strings.HasPrefix(m, "$") {
			return m
		}
		// Leave clearly non-secret words (no digit and no separator) alone to
		// avoid mangling ordinary prose; secrets almost always mix classes.
		if !strings.ContainsAny(m, "0123456789_-./+") {
			return m
		}
		return Secret(m)
	})
}
