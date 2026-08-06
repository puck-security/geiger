package modules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// A credential the tenant ACCEPTED must never be summarized as rejected. Every
// module is driven against a 200 whose body it cannot possibly parse: that is a
// live key, and reporting DEAD would send a responder straight past it.
//
// This runs over the whole registry rather than the three modules fixed
// alongside it, so a hand-written module added later inherits the guard instead
// of having to remember the rule. It found duo, conjur and github_pat.
func TestNoModuleReportsDeadOnAcceptedCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()
	hc := &http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}

	var bad []string
	for _, m := range module.Default.All() {
		func() {
			// A module panicking on a hostile body is a separate bug; this test
			// is only about the live-vs-dead verdict.
			defer func() { _ = recover() }()
			c := recon.New(hc, true)
			tok, err := m.Authenticate(context.Background(), c, dummyFields())
			if err != nil {
				return // auth exchange rejected the stub — not the case under test
			}
			fs, err := m.Recon(context.Background(), c, tok, dummyFields())
			if err != nil {
				return
			}
			if len(c.Planned()) == 0 {
				return // made no call, so it never learned the credential was accepted
			}
			if n := m.Summarize("t", fs); n.Invalid {
				bad = append(bad, m.Name())
			}
		}()
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("modules reporting DEAD on a 200 they could not parse: %s\n"+
			"a 2xx means the credential authenticated; observe the response with "+
			"liveness and fall back to withLiveness so an unparsed body is not a "+
			"death sentence", strings.Join(bad, ", "))
	}
}

func TestLivenessClassify(t *testing.T) {
	ok := &recon.Response{Status: 200}
	forbidden := &recon.Response{Status: 403}
	unauthorized := &recon.Response{Status: 401}
	teapot := &recon.Response{Status: 418}

	for _, tc := range []struct {
		name string
		obs  func(*liveness)
		want string // finding key, "" for none (i.e. genuinely dead)
	}{
		{"accepted", func(l *liveness) { l.observe(ok, nil, true) }, "authenticated"},
		{"forbidden is authenticated, not dead", func(l *liveness) { l.observe(forbidden, nil, true) }, "authenticated"},
		{"identity 401 is dead", func(l *liveness) { l.observe(unauthorized, nil, true) }, ""},
		{"non-identity 401 is not dead", func(l *liveness) { l.observe(unauthorized, nil, false) }, "unconfirmed"},
		{"acceptance outranks an identity 401", func(l *liveness) {
			l.observe(unauthorized, nil, true)
			l.observe(ok, nil, false)
		}, "authenticated"},
		{"transport error is unreachable, not dead", func(l *liveness) {
			l.observe(nil, errors.New("dial tcp: refused"), true)
		}, "unreachable"},
		{"an HTTP reply outranks a transport error", func(l *liveness) {
			l.observe(nil, errors.New("dial tcp: refused"), false)
			l.observe(teapot, nil, true)
		}, "unconfirmed"},
		{"unexpected status is unconfirmed", func(l *liveness) { l.observe(teapot, nil, true) }, "unconfirmed"},
		{"dry-run carries no verdict", func(l *liveness) {
			l.observe(&recon.Response{Status: 200, DryRun: true}, nil, true)
		}, ""},
		{"no probes at all", func(l *liveness) {}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lv liveness
			tc.obs(&lv)
			got := lv.classify()
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Key != tc.want {
				t.Fatalf("want key %q, got %+v", tc.want, got)
			}
		})
	}
}

// withLiveness must not paper over a module that did produce real findings, and
// must not count the module's own input echo as evidence the tenant answered.
func TestWithLivenessOnlyFillsAnEmptyRecon(t *testing.T) {
	var lv liveness
	lv.observe(&recon.Response{Status: 200}, nil, true)

	real := []module.Finding{{Key: "user", Value: "alice"}}
	if got := withLiveness(real, 0, &lv); len(got) != 1 || got[0].Key != "user" {
		t.Fatalf("real findings must pass through untouched, got %+v", got)
	}

	echo := []module.Finding{{Key: "integration key", Value: "DI123"}}
	got := withLiveness(echo, 1, &lv)
	if len(got) != 2 || got[1].Key != "authenticated" {
		t.Fatalf("input echo must not count as evidence; want the marker appended, got %+v", got)
	}
}

// The dead path has to keep working, or the fix would simply mark everything
// live and the DEAD tier would stop meaning anything.
func TestRejectedCredentialIsStillDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	hc := &http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}

	for _, name := range []string{"duo", "conjur"} {
		m, ok := module.Default.ByName(name)
		if !ok {
			t.Fatalf("module %q not registered", name)
		}
		c := recon.New(hc, true)
		tok, err := m.Authenticate(context.Background(), c, dummyFields())
		if err != nil {
			continue // auth exchange itself rejected it — already dead
		}
		fs, err := m.Recon(context.Background(), c, tok, dummyFields())
		if err != nil {
			continue
		}
		if n := m.Summarize("t", fs); !n.Invalid {
			t.Errorf("%s: 401 on the identity call must stay DEAD, got %+v", name, fs)
		}
	}
}
