// Package redact masks secret material so it never appears in Geiger output.
package redact

import (
	"regexp"
	"strings"
	"unicode"
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

// Line redacts any credential-shaped substring inside free text, so accidental
// echoes of a raw secret in a log line or error message are masked.
//
// Length alone does not make a run a secret. A media type, a reverse-DNS
// identifier and a package path are all long, and masking them destroys the
// thing the reader came for — an audit line that reads
// "Accept: …json, …ream" says nothing. Known secrets are replaced exactly
// before this runs (see recon.Client.scrub); this pass is the net for the ones
// nobody registered, so it masks only what has the shape of one.
func Line(s string) string {
	return tokenish.ReplaceAllStringFunc(s, func(m string) string {
		// Leave shell variable references ($OPENAI_API_KEY) intact — they're
		// placeholders the scrubber put there, not secrets. A reference can sit
		// inside a longer run ("Credential=$AWS_ACCESS_KEY_ID/20260911/…"), and
		// masking that run would throw away the one thing that makes the
		// rendered command runnable. The shape is the scrubber's own: a $ and
		// an upper-case variable name, which a bcrypt hash ($2b$…) is not.
		if varRef.MatchString(m) {
			return m
		}
		// A run that names a credential is masked before any other test: the
		// value beside "password=" is a password however plainly it reads.
		if namesCredential(m) {
			return Secret(m)
		}
		// Leave clearly non-secret words (no digit and no separator) alone to
		// avoid mangling ordinary prose; secrets almost always mix classes.
		if !strings.ContainsAny(m, "0123456789_-./+") {
			return m
		}
		if structural(m) {
			return m
		}
		return Secret(m)
	})
}

// structural reports whether a run is a punctuation-joined identifier rather
// than a credential: "application/json", "text/event-stream",
// "io.modelcontextprotocol/clientCapabilities", "application/x-amz-json-1.1",
// "Version=2011-06-15", "20260911T192325Z".
//
// A separator has to be present — that is what tells these from a one-piece
// token — and every segment has to be a word, a short number, or a timestamp.
// A base64, hex or prefixed token has at least one segment mixing letters and
// digits, so it still masks. A run naming a credential (password=…, token=…)
// never reaches here — Line masks it first.
func structural(s string) bool {
	if timestamp(s) {
		return true
	}
	if !strings.ContainsAny(s, "./=") {
		return false
	}
	for _, seg := range strings.FieldsFunc(s, isSep) {
		if !wordish(seg) && !shortNumber(seg) && !timestamp(seg) {
			return false
		}
	}
	return true
}

// namesCredential reports whether a segment of a run says the run carries a
// secret.
func namesCredential(s string) bool {
	for _, seg := range strings.FieldsFunc(s, isSep) {
		if credentialWords[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// credentialWords name a secret, so a run containing one is masked even when
// the value beside it reads as a word.
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "secret": true, "token": true,
	"key": true, "apikey": true, "auth": true, "credential": true, "credentials": true,
	"signature": true, "session": true, "cookie": true, "bearer": true,
}

// isSep reports whether r joins two segments of an identifier.
func isSep(r rune) bool {
	switch r {
	case '.', '/', '_', '-', '+', '=', ':':
		return true
	}
	return false
}

// wordish reports a segment of plain letters.
func wordish(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// shortNumber reports a segment that is a version, a port or a date part —
// digits, and too few of them to be a secret.
func shortNumber(s string) bool {
	if s == "" || len(s) > 8 {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// varRef matches the shell variable reference RegisterSecretRef leaves behind.
var varRef = regexp.MustCompile(`\$[A-Z][A-Z0-9_]*`)

// stamp matches the timestamp forms that turn up in signed request headers.
var stamp = regexp.MustCompile(`^\d{8}T\d{6}Z$|^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}\S*)?$`)

// timestamp reports whether a run is a date or a request timestamp.
func timestamp(s string) bool { return stamp.MatchString(s) }
