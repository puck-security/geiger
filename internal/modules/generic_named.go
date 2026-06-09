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
// checksum/digest fields (lockfiles and manifests pair a file path with a
// sha256/integrity hash that looks credential-shaped but is not a secret).
var notSecretNameRe = regexp.MustCompile(`(?i)(public|_id$|_ids$|url|uri|host|endpoint|username|user$|_file$|_path$|expir|region|name$|enabled|public_key|sha\d|md5|checksum|integrity|digest|hash|fingerprint)`)

func recognizeGenericSecret(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	for name, val := range b.Vars {
		if !secretNameRe.MatchString(name) || notSecretNameRe.MatchString(name) {
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
