package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestOktaIntrusiveReach(t *testing.T) {
	hits := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS tok" {
			t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"status":"ACTIVE","profile":{"login":"admin@acme.com"}}`))
	})
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		hits["users"] = true
		_, _ = w.Write([]byte(`[{"id":"u1"}]`))
	})
	mux.HandleFunc("/api/v1/apps", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"label":"AWS SSO"},{"label":"Office 365"}]`))
	})
	mux.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := recon.New(srv.Client(), true)
	c.SetOktaIntrusive(true)
	fs, err := oktaKey{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"token": "tok", "endpoint": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["user"].Value != "admin@acme.com" {
		t.Errorf("user = %q", got["user"].Value)
	}
	if got["directory"].Flag != module.FlagWarn {
		t.Errorf("directory finding missing: %+v", got["directory"])
	}
	if got["sso apps"].Flag != module.FlagForceMultiplier || !strings.Contains(got["sso apps"].Value, "AWS SSO") {
		t.Errorf("sso apps finding wrong: %+v", got["sso apps"])
	}
	if got["admin"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin finding missing: %+v", got["admin"])
	}
}

func TestOktaGateOffAndNoEndpoint(t *testing.T) {
	// no endpoint: nothing to probe
	c := recon.New(http.DefaultClient, true)
	c.SetOktaIntrusive(true)
	if fs, _ := (oktaKey{}).Recon(context.Background(), c, module.Token{}, module.Fields{"token": "tok"}); fs != nil {
		t.Errorf("no endpoint should yield no findings, got %+v", fs)
	}

	// endpoint present but gate off: deep endpoints not hit
	deep := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/me", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"profile":{"login":"x"}}`)) })
	for _, p := range []string{"/api/v1/users", "/api/v1/apps", "/api/v1/logs"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { deep = true; _, _ = w.Write([]byte(`[]`)) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c2 := recon.New(srv.Client(), true) // not okta-intrusive
	_, _ = oktaKey{}.Recon(context.Background(), c2, module.Token{}, module.Fields{"token": "tok", "endpoint": srv.URL})
	if deep {
		t.Error("deep Okta endpoints must not be hit without --okta-intrusive")
	}
}

func TestOktaDeadTokenIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	c.SetOktaIntrusive(true)
	fs, _ := oktaKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "dead", "endpoint": srv.URL})
	if n := (oktaKey{}).Summarize("t", fs); !n.Invalid {
		t.Errorf("a token rejected everywhere must be invalid, got %+v", fs)
	}
}
