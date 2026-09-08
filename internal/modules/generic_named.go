package modules

import (
	"context"
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// genericSecret is the catch-all for credential-shaped values whose variable
// name says "secret" but which no specific module recognizes (e.g. an internal
// or newly-minted token format). It can't be exercised, but it shouldn't be
// silently dropped either.
type genericSecret struct{ module.Base }

func (genericSecret) Name() string { return "generic_secret" }

func (genericSecret) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{
		Key:   "status",
		Value: "credential-shaped value matched by variable name — no specific module to exercise it",
		Flag:  module.FlagCantCharacterize,
	}}
	if hint := prefixHint(f["token"]); hint != "" {
		out = append(out, module.Finding{Key: "likely", Value: hint, Flag: module.FlagWarn})
	}
	return out, nil
}

func (genericSecret) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs, Summary: "unrecognized credential (matched by name)"}
	for _, f := range fs {
		if f.Key == "likely" {
			n.Summary = f.Value + " (no module)"
		}
	}
	return n
}

// secretNameRe matches variable names that denote a secret.
var secretNameRe = regexp.MustCompile(`(?i)(passw(or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)`)

// notSecretNameRe excludes names that merely locate or describe a secret, plus
// identifiers, timestamps and enums that sit next to one. Checksum and digest
// fields are here too: a lockfile pairs a path with a sha256 that looks
// credential-shaped and is not a secret.
var notSecretNameRe = regexp.MustCompile(`(?i)(public|id$|_ids$|uuid|url|uri|host|endpoint|username|user$|email|_file$|_path$|expir|region|name$|enabled|date$|createdat|updatedat|type$|tier$|mode$|public_key|sha\d|md5|checksum|integrity|digest|hash|fingerprint)`)

// secretParents are object names that make their direct children credentials
// even when the child's own key does not say so: `secrets: {stripe: "..."}`.
// The match is on the whole segment, not a substring, because a parent called
// `oauthAccount` says nothing about the fields inside it.
var secretParents = map[string]bool{
	"secret": true, "secrets": true, "credential": true, "credentials": true,
	"auth": true, "token": true, "tokens": true, "keys": true, "apikeys": true,
}

// nameLooksSecret decides from a flattened variable name.
//
// Blobs are flattened as a.b.c, so the name carries every enclosing object and,
// in ~/.claude.json, the project's directory path as well. Matching the whole
// string means an object called `oauthAccount` marks its every field as a
// credential, and a project directory called `bad-password-generator` marks
// every setting under it. Only the key the value is actually stored under
// decides, with one exception for the container names above.
func nameLooksSecret(name string) bool {
	segs := strings.Split(name, ".")
	leaf := segs[len(segs)-1]
	if secretNameRe.MatchString(leaf) {
		return !notSecretNameRe.MatchString(leaf)
	}
	if len(segs) > 1 && secretParents[strings.ToLower(segs[len(segs)-2])] {
		return true
	}
	return false
}

func recognizeGenericSecret(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	for name, val := range b.Vars {
		if !nameLooksSecret(name) {
			continue
		}
		if !valueLooksSecret(val) {
			continue
		}
		out = append(out, recognize.Match{
			Module: "generic_secret",
			Fields: module.Fields{"token": val},
			Secret: val,
			Label:  name,
			Line:   b.Lines[name],
		})
	}
	return out
}

var placeholderRe = regexp.MustCompile(`(?i)^(changeme|change_me|password|secret|example|your[_-].*|xxx+|\.+|none|null|true|false|placeholder|todo|test|dummy|redacted|<.*>|\$\{?.*)$`)

// Shapes that are identifiers or metadata rather than credentials. A config
// sitting beside a real token is full of these, and reporting them buries the
// one line that matters.
var (
	uuidValueRe      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	timestampValueRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}|$)`)
	emailValueRe     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$`)
)

// valueLooksSecret applies cheap heuristics to avoid flagging placeholders,
// flags, paths, and plain words while still catching opaque tokens.
func valueLooksSecret(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 || len(v) > 4096 {
		return false
	}
	if placeholderRe.MatchString(v) {
		return false
	}
	if uuidValueRe.MatchString(v) || timestampValueRe.MatchString(v) || emailValueRe.MatchString(v) {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "~/") {
		return false // a path, not a secret
	}
	// require some character-class variety typical of tokens/passwords.
	var hasDigit, hasAlpha, hasOther bool
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlpha = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, b := range []bool{hasDigit, hasAlpha, hasOther} {
		if b {
			classes++
		}
	}
	return hasAlpha && classes >= 2
}

// prefixHint names the credential when a known opaque prefix is present that
// the dedicated modules/gitleaks don't already cover.
func prefixHint(v string) string {
	switch {
	case strings.HasPrefix(v, "sk-ant-oat"):
		return "Anthropic OAuth token (Claude subscription)"
	case strings.HasPrefix(v, "sk-ant-"):
		return "Anthropic API key"
	case strings.HasPrefix(v, "GOCSPX-"):
		return "Google OAuth client secret"
	case strings.HasPrefix(v, "xoxe-"):
		return "Slack token-rotation refresh token"
	case strings.HasPrefix(v, "eyJ"):
		return "JWT"
	case strings.HasPrefix(v, "-----BEGIN"):
		return "PEM private key"
	default:
		return ""
	}
}

func init() {
	module.Register(genericSecret{})
	// Route gitleaks' broad generic-secret rules here too, so a generic hit
	// renders with the variable-name framing and a type hint instead of a bare
	// "unknown".
	module.MapRule("generic-api-key", "generic_secret")
	recognize.RegisterRecognizer(recognizeGenericSecret)
}
