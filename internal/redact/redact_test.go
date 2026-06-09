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
