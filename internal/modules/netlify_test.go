package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestNetlifyRecognizer(t *testing.T) {
	const pat = "nfp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
	cases := []struct{ name, env, secret string }{
		{"nfp by var", "NETLIFY_AUTH_TOKEN=" + pat + "\n", pat},
		{"nfc bare", "nfc_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0\n", "nfc_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0"},
		// legacy un-prefixed token recognized by var name (gitleaks' keyword rule misses bare)
		{"legacy by var", "NETLIFY_TOKEN=0123456789abcdef0123456789abcdef01234567\n", "0123456789abcdef0123456789abcdef01234567"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.env, ".env"), "", module.Default))
			m, ok := by["netlify"]
			if !ok {
				t.Fatalf("netlify not recognized: %+v", by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
		})
	}
}

func TestNetlifyRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer nfp_TOK" {
			t.Errorf("netlify must use Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"email":"ann@acme.com","full_name":"Ann"}`)
	})
	mux.HandleFunc("/api/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"id":"s1"},{"id":"s2"}]`)
	})
	mux.HandleFunc("/api/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"name":"Acme","role":"Owner"}]`)
	})
	got := driveModule(t, "netlify", module.Fields{"token": "nfp_TOK"}, mux)
	if got["email"].Value != "ann@acme.com" || got["sites"].Value != "2" || got["team"].Value != "Acme" {
		t.Errorf("netlify fields wrong: %+v", got)
	}
	// unscoped PAT + Owner role + readable build env → all force multipliers.
	for _, k := range []string{"scope", "role", "build env"} {
		if got[k].Flag != module.FlagForceMultiplier {
			t.Errorf("%q should be a force multiplier: %+v", k, got[k])
		}
	}
}
