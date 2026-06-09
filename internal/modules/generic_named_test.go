package modules

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestValueLooksSecret(t *testing.T) {
	yes := []string{"s3cr3t-Hunter2-xyz", "sk-ant-oat01-aBcD1234efGH", "Aa1!longenough"}
	no := []string{"changeme", "true", "1234567", "/etc/passwd", "${DB_PASS}", "<your-token>", "password"}
	for _, v := range yes {
		if !valueLooksSecret(v) {
			t.Errorf("valueLooksSecret(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if valueLooksSecret(v) {
			t.Errorf("valueLooksSecret(%q) = true, want false", v)
		}
	}
}

func TestGenericSecretCatchesNamedToken(t *testing.T) {
	b := parse.Parse("CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123\n", ".env")
	ms := recognizeGenericSecret(b, "", nil)
	if len(ms) != 1 || ms[0].Module != "generic_secret" {
		t.Fatalf("not caught: %+v", ms)
	}
	if h := prefixHint(ms[0].Fields["token"]); h == "" {
		t.Errorf("expected an Anthropic hint")
	}
}

func TestGenericSecretExcludesLocators(t *testing.T) {
	b := parse.Parse("PUBLIC_KEY_ID=abc123\nTOKEN_URL=https://x/y\nDB_HOSTNAME=prod-db\n", ".env")
	if ms := recognizeGenericSecret(b, "", nil); len(ms) != 0 {
		t.Errorf("locator vars should not be flagged: %+v", ms)
	}
}

func TestGenericSecretExcludesChecksums(t *testing.T) {
	// Lockfile/manifest lines pair a path with a sha256/integrity hash; the key
	// contains "token" (e.g. _tokenizer.py) but the value is a digest, not a secret.
	raw := "packaging/_tokenizer.py,sha256=AAAA1111bbbb2222cccc3333\n" +
		"some_token_integrity=sha512-deadbeefcafebabe0123\n"
	b := parse.Parse(raw, "RECORD")
	if ms := recognizeGenericSecret(b, "", nil); len(ms) != 0 {
		t.Errorf("checksum/digest fields should not be flagged: %+v", ms)
	}
}

func TestGenericSecretSuppressedWhenClaimed(t *testing.T) {
	// AWS_SECRET_ACCESS_KEY is claimed by the AWS module; the generic catch-all
	// for that same value must be suppressed.
	raw := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	b := parse.Parse(raw, ".env")
	matches := recognize.Recognize(b, "", module.Default)
	for _, m := range matches {
		if m.Module == "generic_secret" && m.Fields["token"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
			t.Errorf("AWS secret should be claimed by aws module, not generic_secret")
		}
	}
}
