package recipe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestTmplJSONEscapesInjection(t *testing.T) {
	f := module.Fields{"secret": `a"b\c`, "x": `","admin":true,"y":"`}
	got := tmplJSON(`{"secret":"{secret}","note":"{x}"}`, f)
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("tmplJSON produced invalid JSON %q: %v", got, err)
	}
	if m["secret"] != `a"b\c` {
		t.Errorf("secret not round-tripped: %v", m["secret"])
	}
	if _, injected := m["admin"]; injected {
		t.Errorf("field injection succeeded: %v", m)
	}
}

func TestRecipeWhoamiCountSignal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/account", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer TKN" {
			t.Errorf("auth header = %q", got)
		}
		_, _ = w.Write([]byte(`{"account":{"email":"a@b.com","status":"active","role":"owner"}}`))
	})
	mux.HandleFunc("/v2/droplets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"total":42}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	spec := HTTP{
		ModuleName: "demo",
		Base:       srv.URL,
		Auth:       AuthSpec{Kind: Bearer},
		Whoami: GET("/v2/account").
			Field("email", "account.email").
			Field("status", "account.status"),
		Calls: []Call{
			GET("/v2/droplets").CountFrom("meta.total", "droplets"),
			{Method: http.MethodGet, Path: "/v2/account", Signals: []Signal{
				{Path: "account.role", Contains: "owner", Key: "role", Flag: module.FlagForceMultiplier},
			}},
		},
	}
	m := spec.Module()
	c := recon.New(srv.Client(), true)
	fs, err := m.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "TKN"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]module.Finding{}
	for _, f := range fs {
		got[f.Key] = f
	}
	if got["email"].Value != "a@b.com" {
		t.Errorf("email = %q", got["email"].Value)
	}
	if got["droplets"].Value != "42" {
		t.Errorf("droplets = %q", got["droplets"].Value)
	}
	if got["role"].Flag != module.FlagForceMultiplier {
		t.Errorf("role flag = %v", got["role"].Flag)
	}
}

func TestRecipeDryRunNoNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("dry-run must not hit network")
	}))
	defer srv.Close()
	m := HTTP{ModuleName: "d", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").Field("a", "a")}.Module()
	c := recon.New(srv.Client(), false)
	if _, err := m.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	if len(c.Planned()) != 1 {
		t.Errorf("expected 1 planned call, got %d", len(c.Planned()))
	}
}

func TestRecipeInvalidWhenNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	m := HTTP{ModuleName: "d", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").Field("a", "a")}.Module()
	c := recon.New(srv.Client(), true)
	fs, _ := m.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "t"})
	note := m.Summarize("T", fs)
	if !note.Invalid {
		t.Errorf("expected invalid note on 401")
	}
}

func TestCountFlagTagsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":4200}`))
	}))
	defer srv.Close()
	m := HTTP{ModuleName: "d", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").CountFlag("count", "customers (PII)", module.FlagForceMultiplier)}.Module()
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Key != "customers (PII)" || fs[0].Value != "4200" || fs[0].Flag != module.FlagForceMultiplier {
		t.Errorf("flagged count wrong: %+v", fs)
	}
}

func TestRecipeNonFatalWhoami(t *testing.T) {
	// whoami is permission-denied, but a later call succeeds → still characterized.
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	mux.HandleFunc("/things", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"count":5}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := HTTP{ModuleName: "x", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/whoami").Field("id", "id"),
		Calls:  []Call{GET("/things").CountFrom("count", "things")}}.Module()
	fs, _ := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	note := m.Summarize("T", fs)
	if note.Invalid {
		t.Errorf("scoped key (whoami 403, things 200) must not be dead: %+v", fs)
	}
}

func TestRecipeWhoami401ButScopedCallLive(t *testing.T) {
	// A multi-scope API (e.g. Cloudflare) can 401 the user-scoped whoami for an
	// account/zone-scoped token that is live elsewhere → must NOT be DEAD.
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result_info":{"total_count":7}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := HTTP{ModuleName: "cf", Base: srv.URL, Auth: AuthSpec{Kind: Bearer}, MultiScope: true,
		Whoami: GET("/verify").Field("status", "result.status"),
		Calls:  []Call{GET("/zones").CountFrom("result_info.total_count", "zones")}}.Module()
	fs, _ := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	note := m.Summarize("T", fs)
	if note.Invalid {
		t.Errorf("token live against /zones must not be DEAD despite whoami 401: %+v", fs)
	}
	if len(fs) == 0 || fs[0].Key != "zones" || fs[0].Value != "7" {
		t.Errorf("expected zones=7 finding: %+v", fs)
	}
}

func TestRecipeOAuthValidDespiteScopedRecon(t *testing.T) {
	// Token exchange succeeds but every recon call 403s → still valid, not dead.
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := HTTP{ModuleName: "o", Base: srv.URL, Auth: AuthSpec{Kind: PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return module.Token{Bearer: "REALTOKEN"}, nil
		},
		Whoami: GET("/x").Field("id", "id")}.Module()
	c := recon.New(srv.Client(), true)
	tok, _ := m.Authenticate(context.Background(), c, module.Fields{})
	fs, _ := m.Recon(context.Background(), c, tok, module.Fields{})
	note := m.Summarize("T", fs)
	if note.Invalid {
		t.Errorf("oauth token that exchanged should be valid even if recon is denied: %+v", fs)
	}
}

func findingByKey(fs []module.Finding, key string) (module.Finding, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return module.Finding{}, false
}

func TestRecipe2xxEmptyIsAuthenticatedNotDead(t *testing.T) {
	// A valid credential whose whoami returns 200 but a body whose shape our
	// field paths don't match (API drift, or an empty account) must NOT be
	// reported as DEAD — the token was accepted.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"totally":"unexpected shape"}`))
	}))
	defer srv.Close()
	m := HTTP{ModuleName: "d", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").Field("a", "a")}.Module()
	fs, _ := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	if m.Summarize("T", fs).Invalid {
		t.Errorf("accepted (2xx) credential must not be dead: %+v", fs)
	}
	if _, ok := findingByKey(fs, "authenticated"); !ok {
		t.Errorf("expected an 'authenticated' finding on 2xx-but-empty, got %+v", fs)
	}
}

func TestRecipeUnreachableHostNotDead(t *testing.T) {
	// A live host that refuses the connection says nothing about the credential —
	// it must NOT be reported as DEAD (this is the analog of the DB path treating
	// unreachable as not-dead).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base, client := srv.URL, srv.Client()
	srv.Close() // now refuses connections → transport error, not an HTTP status
	m := HTTP{ModuleName: "d", Base: base, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").Field("a", "a")}.Module()
	fs, _ := m.Recon(context.Background(), recon.New(client, true), module.Token{}, module.Fields{"token": "t"})
	if m.Summarize("T", fs).Invalid {
		t.Errorf("unreachable host must not be dead: %+v", fs)
	}
	if _, ok := findingByKey(fs, "unreachable"); !ok {
		t.Errorf("expected an 'unreachable' finding, got %+v", fs)
	}
}

func TestRecipe401StopsEarly(t *testing.T) {
	// A dead key (401 on whoami) must NOT fan out to the inventory calls.
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1); w.WriteHeader(401) })
	mux.HandleFunc("/inv", func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1); w.WriteHeader(401) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := HTTP{ModuleName: "x", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/whoami").Field("id", "id"),
		Calls:  []Call{GET("/inv").CountFrom("n", "n")}}.Module()
	fs, _ := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	if m.Summarize("T", fs).Invalid != true {
		t.Errorf("dead key should be invalid")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("401 whoami should stop early; made %d calls (want 1)", hits)
	}
}
