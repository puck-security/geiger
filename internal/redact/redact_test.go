package redact

import "testing"

func TestSecret(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"abc", "…"},
		{"abcd", "…"},
		{"abcde", "…bcde"},
		{"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01JV3Q", "ghp_…JV3Q"},
		{"sk_live_4eC39HqLyjWDarjtT1zdp7dc", "sk_live_…p7dc"},
		{"AKIAIOSFODNN7EXAMPLE", "…MPLE"},
	}
	for _, c := range cases {
		if got := Secret(c.in); got != c.want {
			t.Errorf("Secret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLineRedactsTokensButKeepsProse(t *testing.T) {
	in := "auth failed for ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01JV3Q on host api"
	got := Line(in)
	if want := "ghp_…JV3Q"; !contains(got, want) {
		t.Errorf("Line did not redact secret: %q", got)
	}
	if !contains(got, "auth failed for") || !contains(got, "host") {
		t.Errorf("Line mangled prose: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLineKeepsStructuralIdentifiers(t *testing.T) {
	// Header values and JSON keys are not credentials. Masking them turns an
	// audit line into noise, which is what this rule exists to prevent.
	keep := []string{
		"application/json",
		"text/event-stream",
		"io.modelcontextprotocol/clientCapabilities",
		"github.com/puck-security/geiger",
		"application/vnd.api+json",
		"application/x-amz-json-1.1",
		"Version=2011-06-15",
		"20260911T192325Z",
		"Action=GetCallerIdentity",
	}
	for _, in := range keep {
		if got := Line(in); got != in {
			t.Errorf("Line(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestLineStillRedactsTokensWithSeparators(t *testing.T) {
	// A dot or a slash in a run is not a licence to print it: these carry
	// digits, which is what tells a token from an identifier.
	cases := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		"AKIAIOSFODNN7EXAMPLE",
		"sk-proj-4eC39HqLyjWDarjtT1zdp7dc",
		"xoxb-realtokenvalue-12345",
		// A run that names a credential is masked whatever the value reads
		// like: a passphrase is all letters and still a passphrase.
		"password=correcthorsebatterystaple",
		"api_key=someplainlookingvalue",
	}
	for _, in := range cases {
		if got := Line(in); got == in {
			t.Errorf("Line(%q) left a credential unmasked", in)
		}
	}
}

func TestLineKeepsPlaceholdersButNotHashes(t *testing.T) {
	// The scrubber's own placeholder must survive, inside a longer run too.
	const ref = "Credential=$AWS_ACCESS_KEY_ID/20260911/us-east-1/sts/aws4_request"
	if got := Line(ref); got != ref {
		t.Errorf("placeholder mangled: %q", got)
	}
	// A dollar sign is not a licence: a hash is not a placeholder.
	const hash = "$2b$12$abcdefghijklmnopqrstuv"
	if got := Line(hash); got == hash {
		t.Errorf("hash left unmasked: %q", got)
	}
}
