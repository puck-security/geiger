package parse

import (
	"strings"
	"testing"
)

// A module that reads its secrets from the environment is the GOOD pattern, and
// must not be reported as leaking them. The arrow function's "=>" used to be
// split as an assignment, producing a variable named "slackBotToken: ()" whose
// value was a fragment of code that looked credential-shaped.
func TestArrowFunctionIsNotAnAssignment(t *testing.T) {
	src := `export const env = {
  slackBotToken: () => getEnv("APP_BOT_TOKEN"),
  oktaOidcClientSecret: () => getEnv("OKTA_OIDC_CLIENT_SECRET"),
  freshApiKey: () => getEnv("FRESH_API_KEY"),
};
`
	b := Parse(src, "lib/env.ts")
	for k, v := range b.Vars {
		// The defect was a variable carrying a fragment of the arrow function.
		// (`env` = `{` from the opening line is inert: the name isn't secret-like
		// and the value is too short to look credential-shaped.)
		if strings.Contains(v, "getEnv(") || strings.Contains(v, "=>") {
			t.Errorf("code fragment captured as a value: %q = %q", k, v)
		}
		if !plausibleVarName(k) {
			t.Errorf("implausible variable name extracted: %q", k)
		}
	}
}

// Comparisons are not assignments either.
func TestComparisonsAreNotAssignments(t *testing.T) {
	for _, src := range []string{
		`if (apiToken == "expected") { }`,
		`if (apiSecret != other) { }`,
		`if (tokenCount >= 10) { }`,
		`if (tokenCount <= 10) { }`,
	} {
		b := Parse(src, "check.ts")
		for k, v := range b.Vars {
			t.Errorf("%s: extracted %q = %q", src, k, v)
		}
	}
}

// The guard must not cost us a real hardcoded secret in the same kind of file —
// that is the leak geiger exists to catch.
func TestHardcodedSecretInSourceStillParses(t *testing.T) {
	src := `const APP_BOT_TOKEN = "placeholder-not-a-real-token-0123456789";
let apiKey = "placeholder-not-a-real-key-abcdef"
`
	b := Parse(src, "config.ts")
	if got := b.Vars["APP_BOT_TOKEN"]; got == "" {
		t.Errorf("a real hardcoded assignment must still be captured, got %v", b.Vars)
	}
	if got := b.Vars["apiKey"]; got == "" {
		t.Errorf("let-assignment lost: %v", b.Vars)
	}
}

// Ordinary dotenv and INI keys must be unaffected.
func TestNormalKeysStillParse(t *testing.T) {
	b := Parse("AWS_SECRET_ACCESS_KEY=abc123\nsome-key=v\nsection.key=v2\narr[0]=v3\n", ".env")
	for _, k := range []string{"AWS_SECRET_ACCESS_KEY", "some-key", "section.key", "arr[0]"} {
		if _, ok := b.Vars[k]; !ok {
			t.Errorf("legitimate key %q was dropped: %v", k, b.Vars)
		}
	}
}

// A key that cannot name a variable is a parse artifact, not a finding.
func TestImplausibleNamesRejected(t *testing.T) {
	b := Parse(`token: () = "abc12345"`+"\n"+`my key = "abc12345"`+"\n", "x.ts")
	for k := range b.Vars {
		t.Errorf("implausible name kept: %q", k)
	}
}

// A statement terminator is not part of the secret. Carrying `";` through would
// put it on the wire and make a live credential report as dead.
func TestStatementTerminatorStrippedFromValue(t *testing.T) {
	b := Parse(`const APP_BOT_TOKEN = "placeholder-not-a-real-token-0123";`+"\n"+
		`let apiSecret = 'abc12345',`+"\n", "config.ts")
	if got := b.Vars["APP_BOT_TOKEN"]; got != "placeholder-not-a-real-token-0123" {
		t.Errorf("APP_BOT_TOKEN = %q, want the value without the terminator", got)
	}
	if got := b.Vars["apiSecret"]; got != "abc12345" {
		t.Errorf("apiSecret = %q", got)
	}
}

// An unquoted dotenv value that really ends in a comma must survive intact.
func TestUnquotedValueKeepsTrailingComma(t *testing.T) {
	b := Parse("HOSTS=a.example.com,b.example.com,\n", ".env")
	if got := b.Vars["HOSTS"]; got != "a.example.com,b.example.com," {
		t.Errorf("HOSTS = %q, want the trailing comma preserved", got)
	}
}
