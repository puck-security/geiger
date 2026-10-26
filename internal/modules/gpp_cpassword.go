package modules

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Group Policy Preferences cpassword (MS14-025). GPP XML in SYSVOL
// (Groups.xml, Services.xml, ScheduledTasks.xml, and friends) can carry a
// cpassword attribute: a password AES-256 encrypted with a key Microsoft
// published, so anyone who can read the file can recover the plaintext. These
// are frequently a local administrator password pushed domain-wide, which is
// why reading SYSVOL is a classic lateral-movement win.

// gppAESKey is the static AES-256 key Microsoft published in MSDN for GPP
// cpassword. It is public; decryption needs no secret and no network.
var gppAESKey, _ = hex.DecodeString("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

type gppCpassword struct{ module.Base }

func (gppCpassword) Name() string { return "gpp_cpassword" }

func (gppCpassword) Recon(_ context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	pw, err := decryptGPPCpassword(f["cpassword"])
	if err != nil || pw == "" {
		return []module.Finding{{Key: "cpassword", Value: "present but could not be decrypted (truncated or non-standard value)", Flag: module.FlagWarn}}, nil
	}
	user := f["username"]
	var out []module.Finding
	if user != "" {
		out = append(out, module.Finding{Key: "account", Value: user, Flag: module.FlagInfo})
	}
	out = append(out, module.Finding{
		Key:   "password",
		Value: pw + "  (GPP cpassword, MS14-025 — recovered with the published AES key)",
		Flag:  module.FlagForceMultiplier,
	})

	// --intrusive validates the recovered credential against local Windows auth
	// (the LogonUser API). This is an authentication attempt: it writes a logon
	// event and counts toward account lockout, so it is gated behind --intrusive.
	if c != nil && c.Intrusive() && user != "" {
		switch ok, supported, detail := validateWindowsLogon(user, pw); {
		case !supported:
			out = append(out, module.Finding{Key: "validation", Value: "skipped — local Windows logon validation runs only on a Windows host", Flag: module.FlagInfo})
		case ok:
			out = append(out, module.Finding{Key: "validation", Value: "VALID — the recovered credential is accepted by Windows on this host", Flag: module.FlagForceMultiplier})
		default:
			out = append(out, module.Finding{Key: "validation", Value: "rejected (password likely rotated since the GPP was written): " + detail, Flag: module.FlagWarn})
		}
	}
	return out, nil
}

func (gppCpassword) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "no cpassword value"
		return n
	}
	for _, f := range fs {
		if f.Key == "password" {
			n.Summary = "GPP cpassword — recovered plaintext credential"
			return n
		}
	}
	n.Summary = "GPP cpassword (undecryptable)"
	return n
}

// decryptGPPCpassword decrypts a base64 cpassword to its plaintext. The value is
// AES-256-CBC with a zero IV and the public key; the plaintext is UTF-16LE.
func decryptGPPCpassword(enc string) (string, error) {
	enc = strings.TrimSpace(enc)
	if enc == "" {
		return "", fmt.Errorf("empty cpassword")
	}
	// Microsoft omits base64 padding; restore it.
	if m := len(enc) % 4; m != 0 {
		enc += strings.Repeat("=", 4-m)
	}
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not a block multiple")
	}
	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		return "", err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(pt, ct)
	return utf16LEString(stripPKCS7(pt)), nil
}

func stripPKCS7(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n < 1 || n > aes.BlockSize || n > len(b) {
		return b
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return b // not valid PKCS7 padding; leave as-is
		}
	}
	return b[:len(b)-n]
}

func utf16LEString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// gppTagRe matches a GPP XML element carrying a non-empty cpassword, so the
// associated account can be read from the same element.
var gppTagRe = regexp.MustCompile(`<[^>]*\bcpassword="([^"]+)"[^>]*>`)
var gppUserRe = regexp.MustCompile(`\b(?:userName|accountName|runAs|newName)="([^"]*)"`)

func recognizeGPPCpassword(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	for _, m := range gppTagRe.FindAllStringSubmatch(b.Raw, -1) {
		cp := m[1]
		user := ""
		// Take the first non-empty account attribute in the element (newName is
		// often present but empty, so a first-match-wins grab would miss userName).
		for _, um := range gppUserRe.FindAllStringSubmatch(m[0], -1) {
			if um[1] != "" {
				user = um[1]
				break
			}
		}
		out = append(out, recognize.Match{
			Module: "gpp_cpassword",
			Fields: module.Fields{"cpassword": cp, "username": user},
			Secret: cp,
			Label:  "GPP cpassword",
		})
	}
	return out
}

func init() {
	module.Register(gppCpassword{})
	recognize.RegisterRecognizer(recognizeGPPCpassword)
}
