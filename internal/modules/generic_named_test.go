package modules

import (
	"strings"
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

// google_oauth_client claims GOCSPX- values, so this hint is only reached when
// that recognizer stood down — a Google credential file shape it deliberately
// leaves to another module. Naming the credential still beats "unrecognized".
func TestPrefixHintNamesGoogleClientSecret(t *testing.T) {
	if h := prefixHint("GOCSPX-MjlfId78mAbCdEfGhIjKlMnOp"); h == "" {
		t.Fatal("GOCSPX- should be named as a Google OAuth client secret")
	}
}

// ~/.claude.json is the worst case for name-based matching: an object called
// oauthAccount, project keys that are filesystem paths, and a pile of UUIDs,
// timestamps and enum strings sitting beside one real bearer token. Matching
// the flattened path meant reporting eleven identifiers and missing nothing
// useful.
func TestGenericSecretIgnoresClaudeConfigMetadata(t *testing.T) {
	raw := `{
	  "claudeCodeFirstTokenDate": "2026-01-04T11:22:33.714Z",
	  "oauthAccount": {
	    "accountUuid": "1f0c9a3e-2b7d-4c11-9f2a-0a1b2c3dd685",
	    "emailAddress": "someone@example.com",
	    "accountCreatedAt": "2025-11-02T08:09:10.933Z",
	    "organizationRateLimitTier": "default_claude_max_20x",
	    "billingType": "stripe_subscription",
	    "organizationType": "claude_max"
	  },
	  "projects": {
	    "/home/u/code/bad-password-generator": {
	      "lastSessionId": "7b2c3d4e-5f60-4718-9a2b-3c4d5e6fcb13"
	    },
	    "/home/u/code/app": {
	      "mcpServers": {
	        "lab": {"url": "https://lab.example.com/mcp",
	                "headers": {"Authorization": "Bearer sk-lab-abc123def456"}}
	      }
	    }
	  }
	}`
	ms := recognizeGenericSecret(parse.Parse(raw, ".claude.json"), "", nil)
	if len(ms) != 1 {
		var got []string
		for _, m := range ms {
			got = append(got, m.Label)
		}
		t.Fatalf("expected only the bearer token, got %d: %v", len(ms), got)
	}
	if !strings.HasSuffix(ms[0].Label, "Authorization") {
		t.Errorf("the surviving match should be the header, got %q", ms[0].Label)
	}
}

// A parent object whose own name is a secret container still marks its children,
// because that is how a credential map is written.
func TestGenericSecretHonoursSecretContainers(t *testing.T) {
	if !nameLooksSecret("secrets.stripe") {
		t.Error("secrets.stripe should be a credential")
	}
	if nameLooksSecret("oauthAccount.emailAddress") {
		t.Error("a field under oauthAccount is not a credential just because the parent contains 'auth'")
	}
	if nameLooksSecret("projects./home/u/bad-password-generator.lastSessionId") {
		t.Error("a directory name must not make every setting under it a credential")
	}
	if !nameLooksSecret("mcpServers.x.headers.Authorization") {
		t.Error("the leaf key is what decides, and Authorization is one")
	}
}

func TestValueLooksSecretRejectsIdentifiers(t *testing.T) {
	for _, v := range []string{
		"1f0c9a3e-2b7d-4c11-9f2a-0a1b2c3dd685",
		"2026-01-04T11:22:33.714Z",
		"2026-01-04",
		"someone@example.com",
	} {
		if valueLooksSecret(v) {
			t.Errorf("valueLooksSecret(%q) = true — an identifier, not a credential", v)
		}
	}
}
