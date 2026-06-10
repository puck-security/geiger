package note

import (
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func TestTextDetailOnlyInVerbose(t *testing.T) {
	n := module.Note{
		Title: "openai …AT51 (from .env: OPENAI_API_KEY)",
		Findings: []module.Finding{
			{Key: "also exposed in", Value: "8 editor local-history snapshots", Flag: module.FlagInfo,
				Detail: []string{"/a/History/x/1.py", "/a/History/x/2.py"}},
		},
	}
	// default (summarized): the grouped value shows, the paths do not.
	plain := Text(n)
	if !strings.Contains(plain, "8 editor local-history snapshots") {
		t.Errorf("summary value missing:\n%s", plain)
	}
	if strings.Contains(plain, "1.py") {
		t.Errorf("Detail paths must NOT appear in default output:\n%s", plain)
	}
	// verbose: the paths expand under the finding.
	v := TextVerbose(n)
	if !strings.Contains(v, "/a/History/x/1.py") || !strings.Contains(v, "/a/History/x/2.py") {
		t.Errorf("Detail paths missing from verbose output:\n%s", v)
	}
	// JSON always carries the full Detail.
	j := JSON(n)
	if !strings.Contains(j, "\"detail\":[") || !strings.Contains(j, "2.py") {
		t.Errorf("JSON detail missing:\n%s", j)
	}
}

func TestTextRendersForceMultiplierAndCantCharacterize(t *testing.T) {
	n := module.Note{
		Title: "GitHub PAT ghp_…JV3Q (from .env: GITHUB_TOKEN)",
		Findings: []module.Finding{
			{Key: "user", Value: "octo-ci-bot", Flag: module.FlagInfo},
			{Key: "scopes", Value: "repo, admin:org", Flag: module.FlagForceMultiplier},
			{Key: "fine-grained scopes", Value: "not enumerable via API", Flag: module.FlagCantCharacterize},
		},
		Summary: "org-admin bot token",
	}
	out := Text(n)
	if !strings.Contains(out, "force multiplier") {
		t.Errorf("force-multiplier mark missing:\n%s", out)
	}
	if !strings.Contains(out, "can't determine with read-only access") {
		t.Errorf("cant-characterize mark missing:\n%s", out)
	}
	if !strings.Contains(out, "→ org-admin bot token") {
		t.Errorf("summary missing:\n%s", out)
	}
}

func TestTextInvalid(t *testing.T) {
	out := Text(module.Note{Title: "X", Invalid: true, Reason: "401 expired"})
	if !strings.Contains(out, "invalid") || !strings.Contains(out, "401 expired") {
		t.Errorf("invalid render wrong:\n%s", out)
	}
}

func TestJSON(t *testing.T) {
	out := JSON(module.Note{
		Title:    "T",
		Summary:  "s",
		Findings: []module.Finding{{Key: "k", Value: "v", Flag: module.FlagForceMultiplier}},
	})
	if !strings.Contains(out, `"flag":"force_multiplier"`) || !strings.Contains(out, `"key":"k"`) {
		t.Errorf("json wrong: %s", out)
	}
}

func TestSanitizeStripsTerminalInjection(t *testing.T) {
	n := module.Note{
		Title: "evil \x1b]0;pwned\x07 title",
		Findings: []module.Finding{
			{Key: "login", Value: "bob\x1b[31m\x07\nINJECTED", Flag: module.FlagInfo},
		},
	}
	out := Text(n)
	if strings.ContainsRune(out, '\x1b') || strings.ContainsRune(out, '\x07') {
		t.Errorf("control chars not stripped: %q", out)
	}
	if strings.Contains(out, "\nINJECTED\n") {
		// newline within a value would forge a new line; it must be collapsed
		t.Errorf("embedded newline not neutralized: %q", out)
	}
}

func TestSanitizeCapsLength(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'A'
	}
	out := Text(module.Note{Title: "t", Findings: []module.Finding{{Key: "k", Value: string(long)}}})
	if len(out) > 1000 {
		t.Errorf("value not capped, output len %d", len(out))
	}
}
