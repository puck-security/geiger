package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestCloudflareRecognizer(t *testing.T) {
	cases := []struct {
		name, env, module, secret string
	}{
		// the reported bug: a cfat_ token (prefixed format gitleaks misses)
		{"cfat by var", "CLOUDFLARE_API_TOKEN=cfat_k9Qx2mZv7Lp3Rt8Wc1Nf6Hb4Jd0Ys5Ge9Ua2Io\n", "cloudflare", "cfat_k9Qx2mZv7Lp3Rt8Wc1Nf6Hb4Jd0Ys5Ge9Ua2Io"},
		{"cfut bare", "cfut_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\n", "cloudflare", "cfut_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"},
		// legacy un-prefixed token recognized by variable name (gitleaks misses these)
		{"legacy by var", "CF_API_TOKEN=k9Qx2mZv7Lp3Rt8Wc1Nf6Hb4Jd0Ys5Ge9Ua2Io\n", "cloudflare", "k9Qx2mZv7Lp3Rt8Wc1Nf6Hb4Jd0Ys5Ge9Ua2Io"},
		// global API key needs the account email for X-Auth headers
		{"global key+email", "CLOUDFLARE_API_KEY=0123456789abcdef0123456789abcdef01234\nCLOUDFLARE_EMAIL=a@b.com\n", "cloudflare_global", "0123456789abcdef0123456789abcdef01234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.env, ".env")
			by := modulesOf(recognize.Recognize(b, "", module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
			// regression: the value must no longer fall through to generic_secret.
			if _, isGeneric := by["generic_secret"]; isGeneric {
				t.Errorf("value leaked to generic_secret instead of %s", tc.module)
			}
		})
	}
}

func TestCloudflareScopedTokenStillLive(t *testing.T) {
	// A zone-scoped token 401s on the user-scoped /user/tokens/verify but is live
	// against /zones — it must be characterized, not declared DEAD.
	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	mux.HandleFunc("/client/v4/accounts", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	mux.HandleFunc("/client/v4/zones", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"result":[{"id":"z1"}],"result_info":{"total_count":7}}`)
	})
	mux.HandleFunc("/client/v4/user", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	got := driveModule(t, "cloudflare", module.Fields{"token": "ZONESCOPED"}, mux)
	if got["zones"].Value != "7" {
		t.Errorf("zone-scoped token should be live with zones, not DEAD: %+v", got)
	}
}

func TestCloudflareRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer CFTOK" {
			t.Errorf("cloudflare must use Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"success":true,"result":{"id":"tok123","status":"active"}}`)
	})
	mux.HandleFunc("/client/v4/accounts", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"result":[{"id":"a1"}],"result_info":{"total_count":3}}`)
	})
	mux.HandleFunc("/client/v4/zones", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"result":[{"id":"z1"}],"result_info":{"total_count":7}}`)
	})
	mux.HandleFunc("/client/v4/user", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"result":{"id":"u1","email":"ops@acme.com"}}`)
	})
	got := driveModule(t, "cloudflare", module.Fields{"token": "CFTOK"}, mux)
	if got["token-status"].Value != "active" {
		t.Errorf("token-status wrong: %+v", got)
	}
	if got["accounts"].Value != "3" || got["zones"].Value != "7" {
		t.Errorf("blast-radius counts wrong: %+v", got)
	}
	if got["email"].Value != "ops@acme.com" {
		t.Errorf("identity not characterized: %+v", got)
	}
}
