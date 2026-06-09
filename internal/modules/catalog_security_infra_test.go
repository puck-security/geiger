package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestSumoLogicRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "AID" || p != "AKEY" {
			t.Errorf("sumo must use Basic accessId:accessKey, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"data":[{"id":"u1"}]}`)
	})
	got := driveModule(t, "sumologic", module.Fields{"access_id": "AID", "access_key": "AKEY", "endpoint": "https://api.sumologic.com"}, mux)
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("log-search reach should be fm: %+v", got)
	}
}

func TestLaceworkAuthAndRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/access/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-LW-UAKS") != "LWSEC" {
			t.Errorf("token request must carry X-LW-UAKS, got %q", r.Header.Get("X-LW-UAKS"))
		}
		respond(w, `{"token":"LWT","expiresAt":"2099-01-01"}`)
	})
	mux.HandleFunc("/api/v2/UserProfile", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer LWT" {
			t.Errorf("recon not using temp token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":[{"orgAccountName":"ACME"}]}`)
	})
	got := driveModule(t, "lacework", module.Fields{"key_id": "LWKEY", "secret": "LWSEC", "endpoint": "https://acme.lacework.net"}, mux)
	if got["account"].Value != "ACME" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("lacework fields wrong: %+v", got)
	}
}

func TestWizClientCredentialsAndGraphQL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("audience") != "wiz-api" || r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("wiz token req wrong: %v", r.Form)
		}
		respond(w, `{"access_token":"WIZT","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer WIZT" {
			t.Errorf("graphql not using token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":{"__typename":"Query"}}`)
	})
	got := driveModule(t, "wiz", module.Fields{"client_id": "c", "client_secret": "s", "endpoint": "https://api.us1.app.wiz.io/graphql"}, mux)
	if got["graphql"].Value != "Query" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("wiz fields wrong: %+v", got)
	}
}

func TestTailscaleRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tskey-api-abc" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"devices":[{"nodeId":"n1"},{"nodeId":"n2"}]}`)
	})
	got := driveModule(t, "tailscale", module.Fields{"token": "tskey-api-abc"}, mux)
	if got["devices (network nodes)"].Value != "2" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("tailscale fields wrong: %+v", got)
	}
}

func TestRenderRailwayFlyioRecon(t *testing.T) {
	// Render
	rmux := http.NewServeMux()
	rmux.HandleFunc("/v1/services", func(w http.ResponseWriter, r *http.Request) { respond(w, `[{"service":{"id":"srv-1"}}]`) })
	if got := driveModule(t, "render", module.Fields{"token": "rnd_x"}, rmux); got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("render reach should be fm: %+v", got)
	}
	// Railway
	wmux := http.NewServeMux()
	wmux.HandleFunc("/graphql/v2", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"data":{"me":{"email":"a@acme.com"}}}`) })
	if got := driveModule(t, "railway", module.Fields{"token": "rwt"}, wmux); got["user"].Value != "a@acme.com" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("railway fields wrong: %+v", got)
	}
	// Fly.io
	fmux := http.NewServeMux()
	fmux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"data":{"viewer":{"email":"b@acme.com"}}}`) })
	if got := driveModule(t, "flyio", module.Fields{"token": "FlyV1 x"}, fmux); got["user"].Value != "b@acme.com" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("flyio fields wrong: %+v", got)
	}
}

func TestSecurityInfraRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"sumologic (default host)", "SUMO_ACCESS_ID=aid\nSUMO_ACCESS_KEY=akey\n", "", "sumologic", "akey"},
		{"lacework (account→host)", "LACEWORK_ACCOUNT=acme\nLACEWORK_API_KEY=k\nLACEWORK_API_SECRET=s\n", "", "lacework", "s"},
		{"wiz", "WIZ_API_URL=https://api.us1.app.wiz.io/graphql\nWIZ_CLIENT_ID=c\nWIZ_CLIENT_SECRET=s\n", "", "wiz", "s"},
		{"tailscale (tskey-api prefix)", "FOO=tskey-api-abcdef\n", "", "tailscale", "tskey-api-abcdef"},
		{"render", "RENDER_API_KEY=rnd_x\n", "", "render", "rnd_x"},
		{"railway", "RAILWAY_TOKEN=rwt\n", "", "railway", "rwt"},
		{"flyio", "FLY_API_TOKEN=fo1_x\n", "", "flyio", "fo1_x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.env, ".env")
			by := modulesOf(recognize.Recognize(b, tc.endpoint, module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
		})
	}
}
