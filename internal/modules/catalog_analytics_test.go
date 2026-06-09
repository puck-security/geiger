package modules

import (
	"context"
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestKlaviyoRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Klaviyo-API-Key KLVK" {
			t.Errorf("klaviyo auth scheme wrong: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("revision") == "" {
			t.Errorf("missing revision header")
		}
		respond(w, `{"data":[{"id":"AccID","type":"account"}]}`)
	})
	got := driveModule(t, "klaviyo", module.Fields{"token": "KLVK"}, mux)
	if got["account"].Value != "AccID" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("klaviyo fields wrong: %+v", got)
	}
}

func TestBrazeRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/campaigns/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer BRZ" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"campaigns":[{"id":"c1"},{"id":"c2"}],"message":"success"}`)
	})
	got := driveModule(t, "braze", module.Fields{"token": "BRZ", "endpoint": "https://rest.iad-01.braze.com"}, mux)
	if got["campaigns"].Value != "2" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("braze fields wrong: %+v", got)
	}
}

func TestAnalyticsFlaggedRecognizers(t *testing.T) {
	cases := []struct{ name, env, module, secret string }{
		{"segment", "SEGMENT_WRITE_KEY=swk\n", "segment", "swk"},
		{"mixpanel", "MIXPANEL_API_SECRET=mps\n", "mixpanel", "mps"},
		{"amplitude", "AMPLITUDE_SECRET_KEY=ask\n", "amplitude", "ask"},
		{"customerio", "CUSTOMERIO_APP_API_KEY=cak\n", "customerio", "cak"},
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
			mod, _ := module.Default.ByName(tc.module)
			got := indexByKey(mustRecon(t, mod, m.Fields))
			if got["reach"].Flag != module.FlagWarn {
				t.Errorf("%s should flag a PII-reach warning: %+v", tc.module, got)
			}
			if got["validation"].Flag != module.FlagCantCharacterize {
				t.Errorf("%s should be marked not-exercised: %+v", tc.module, got)
			}
		})
	}
}

func mustRecon(t *testing.T, m module.Module, f module.Fields) []module.Finding {
	t.Helper()
	fs, err := m.Recon(context.Background(), nil, module.Token{}, f)
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	return fs
}
