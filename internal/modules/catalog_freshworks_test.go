package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/score"
)

// freshRun drives a hand-written Freshworks module against a stub tenant and
// returns the findings plus every path the module requested, in order.
func freshRun(t *testing.T, name string, h http.HandlerFunc) ([]module.Finding, module.Note, []string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		h(w, r)
	}))
	defer srv.Close()

	m, ok := module.Default.ByName(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	f := module.Fields{"token": "abc123key", "password": "X", "endpoint": srv.URL}
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, f)
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	return fs, m.Summarize(name+" …key", fs), paths
}

// The single most important correction in the research: /api/v2/agents/me is
// documented for Freshdesk ONLY. Freshservice must validate against the
// documented list endpoint, never treat /me as the probe that decides live-dead.
func TestFreshserviceValidatesViaDocumentedEndpoint(t *testing.T) {
	_, _, paths := freshRun(t, "freshservice", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/agents" {
			_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	if len(paths) == 0 || paths[0] != "/api/v2/agents" {
		t.Fatalf("first call was %v, want the documented /api/v2/agents list probe", paths)
	}
	// /me may be attempted afterwards for identity, but never before — the
	// documented endpoint is what decides live-vs-dead.
	for i, p := range paths {
		if p == "/api/v2/agents/me" && i == 0 {
			t.Fatal("undocumented /agents/me was used as the validation probe")
		}
	}
}

// The key goes in the username slot with a NON-EMPTY dummy password. recipe's
// BasicKeyUser sends an empty one, which is why these modules are hand-written.
func TestFreshworksSendsKeyAsUsernameWithDummyPassword(t *testing.T) {
	for _, name := range []string{"freshservice", "freshdesk"} {
		var user, pass string
		var okBasic bool
		_, _, _ = freshRun(t, name, func(w http.ResponseWriter, r *http.Request) {
			if user == "" {
				user, pass, okBasic = r.BasicAuth()
			}
			w.WriteHeader(http.StatusUnauthorized)
		})
		if !okBasic {
			t.Errorf("%s: no Basic auth header sent", name)
			continue
		}
		if user != "abc123key" {
			t.Errorf("%s: username = %q, want the API key", name, user)
		}
		if pass == "" {
			t.Errorf("%s: password is empty — Freshworks requires a non-empty dummy", name)
		}
	}
}

func TestFreshworks401IsDead(t *testing.T) {
	for _, name := range []string{"freshservice", "freshdesk"} {
		_, n, _ := freshRun(t, name, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		if got := score.TierFor(n, score.Context{}); got != score.TierDead {
			t.Errorf("%s: tier = %s, want DEAD", name, got)
		}
	}
}

// A tenant that never answers proves nothing either way — that is UNKNOWN, not
// DEAD, and the reason has to say so.
func TestFreshworksUnreachableIsUnknown(t *testing.T) {
	m, _ := module.Default.ByName("freshservice")
	f := module.Fields{"token": "k", "password": "X", "endpoint": "https://gone.freshservice.com"}
	// A client whose transport always fails, standing in for an unroutable tenant.
	c := recon.New(&http.Client{Transport: failTransport{}}, true)
	fs, err := m.Recon(context.Background(), c, module.Token{}, f)
	if err != nil {
		t.Fatal(err)
	}
	n := m.Summarize("freshservice …k", fs)
	if !n.Undetermined {
		t.Errorf("unreachable tenant should be undetermined: %+v", n)
	}
	if got := score.TierFor(n, score.Context{}); got != score.TierUnknown {
		t.Errorf("tier = %s, want UNKNOWN", got)
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrServerClosed
}

// An admin key is the incident case: it can mint new agents, so rotating the key
// alone does not end the compromise. That has to outrank an ordinary agent key.
func TestFreshserviceAdminKeyOutranksScopedKey(t *testing.T) {
	admin := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents":
			_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
		case "/api/v2/agents/me":
			_, _ = w.Write([]byte(`{"agent":{"id":7,"email":"it@acme.com","roles":[{"role_id":3,"assignment_scope":"entire_helpdesk"}]}}`))
		case "/api/v2/roles":
			_, _ = w.Write([]byte(`{"roles":[{"id":3,"name":"Account Admin"},{"id":9,"name":"IT Agent"}]}`))
		default:
			_, _ = w.Write([]byte(`{"tickets":[{"id":1}],"requesters":[{"id":1}],"assets":[{"id":1}]}`))
		}
	}
	scoped := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents":
			w.WriteHeader(http.StatusForbidden)
		case "/api/v2/agents/me":
			_, _ = w.Write([]byte(`{"agent":{"id":8,"email":"agent@acme.com","roles":[{"role_id":9,"assignment_scope":"assigned_only"}]}}`))
		case "/api/v2/roles":
			_, _ = w.Write([]byte(`{"roles":[{"id":9,"name":"IT Agent"}]}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}

	adminFs, adminNote, _ := freshRun(t, "freshservice", admin)
	scopedFs, scopedNote, _ := freshRun(t, "freshservice", scoped)

	ai := indexByKey(adminFs)
	if ai["roles"].Value != "Account Admin" {
		t.Errorf("admin role not resolved from role_id: %+v", adminFs)
	}
	if ai["agent creation"].Flag != module.FlagForceMultiplier {
		t.Errorf("agent creation should be a force multiplier: %+v", ai["agent creation"])
	}
	if ai["pivot"].Value == "" {
		t.Error("admin key should report the orchestration/discovery pivot")
	}

	adminTier := score.TierFor(adminNote, score.Context{})
	scopedTier := score.TierFor(scopedNote, score.Context{})
	if score.Rank(adminTier) <= score.Rank(scopedTier) {
		t.Errorf("admin key ranked %s, scoped key %s — admin must outrank", adminTier, scopedTier)
	}
	if adminTier != score.TierCritical {
		t.Errorf("admin key tier = %s, want CRITICAL (score %d)", adminTier, score.BlastRadius(adminNote, score.Context{}))
	}
	// The scoped key must not inherit any admin claim.
	si := indexByKey(scopedFs)
	if si["agent creation"].Value != "" || si["pivot"].Value != "" {
		t.Errorf("scoped key gained an admin finding: %+v", scopedFs)
	}
}

// The pivot wording must not trip the harvest rollup: those credentials are not
// readable through the API, so "re-run --intrusive to harvest" would be wrong.
func TestFreshservicePivotDoesNotClaimHarvestable(t *testing.T) {
	for _, bad := range []string{"secret", "vault", "harvest"} {
		if strings.Contains(strings.ToLower(freshPivotValue), bad) {
			t.Errorf("pivot wording contains %q, which makes geiger advise harvesting credentials that cannot be read", bad)
		}
	}
}

// Freshdesk's agent schema is flat with a nested contact and a numeric
// ticket_scope — the attributes Freshservice deprecated. Parsing the wrong one
// silently reports nothing.
func TestFreshdeskParsesItsOwnSchema(t *testing.T) {
	fs, _, paths := freshRun(t, "freshdesk", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents/me":
			_, _ = w.Write([]byte(`{"id":5,"ticket_scope":1,"role_ids":[2],"contact":{"email":"sup@acme.com"}}`))
		case "/api/v2/roles":
			_, _ = w.Write([]byte(`{"roles":[{"id":2,"name":"Administrator"}]}`))
		default:
			_, _ = w.Write([]byte(`{"tickets":[{"id":1}],"contacts":[{"id":1}]}`))
		}
	})
	if paths[0] != "/api/v2/agents/me" {
		t.Errorf("Freshdesk should use its documented whoami first, got %v", paths)
	}
	idx := indexByKey(fs)
	if idx["identity"].Value != "sup@acme.com" {
		t.Errorf("nested contact.email not parsed: %+v", fs)
	}
	if !strings.Contains(idx["scope"].Value, "global") {
		t.Errorf("ticket_scope 1 should read as global: %q", idx["scope"].Value)
	}
	if idx["agent creation"].Flag != module.FlagForceMultiplier {
		t.Errorf("Administrator role should earn the agent-creation multiplier: %+v", fs)
	}
}

// --min-footprint must stop after identity — no reach fan-out.
func TestFreshworksMinFootprintSkipsReach(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents":
			_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
		case "/api/v2/agents/me":
			_, _ = w.Write([]byte(`{"agent":{"id":7,"email":"a@b.com"}}`))
		default:
			t.Errorf("min-footprint made an inventory call: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	m, _ := module.Default.ByName("freshservice")
	c := recon.New(srv.Client(), true)
	c.SetMinFootprint(true)
	if _, err := m.Recon(context.Background(), c, module.Token{},
		module.Fields{"token": "k", "password": "X", "endpoint": srv.URL}); err != nil {
		t.Fatal(err)
	}
}

// --- recognizers ---

func TestFreshworksRecognizers(t *testing.T) {
	cases := []struct {
		name, env, wantModule, wantEndpoint string
	}{
		{"freshservice bare subdomain", "FRESHSERVICE_API_KEY=abc123\nFRESHSERVICE_DOMAIN=acme\n",
			"freshservice", "https://acme.freshservice.com"},
		{"freshservice full host", "FRESHSERVICE_API_KEY=abc123\nFRESHSERVICE_DOMAIN=acme.freshservice.com\n",
			"freshservice", "https://acme.freshservice.com"},
		{"freshdesk", "FRESHDESK_API_KEY=abc123\nFRESHDESK_DOMAIN=acme\n",
			"freshdesk", "https://acme.freshdesk.com"},
		{"freshchat defaults to the US host", "FRESHCHAT_API_TOKEN=abc123\n",
			"freshchat", "https://api.freshchat.com"},
		{"freshchat region host", "FRESHCHAT_API_TOKEN=abc123\nFRESHCHAT_REGION=eu\n",
			"freshchat", "https://api.eu.freshchat.com"},
		{"freshsales bundle alias", "FRESHSALES_API_KEY=abc123\nFRESHSALES_BUNDLE_ALIAS=acme\n",
			"freshsales", "https://acme.myfreshworks.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.env, ".env"), "", module.Default))
			m, ok := by[tc.wantModule]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.wantModule, by)
			}
			if m.Fields["endpoint"] != tc.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", m.Fields["endpoint"], tc.wantEndpoint)
			}
			if m.Secret != "abc123" {
				t.Errorf("secret = %q", m.Secret)
			}
		})
	}
}

// An endpoint variable names exactly one service's host. A planted Freshdesk
// domain must never become the base URL a Freshservice key is sent to.
func TestFreshdeskDomainDoesNotSteerFreshserviceKey(t *testing.T) {
	env := "FRESHSERVICE_API_KEY=abc123\nFRESHDESK_DOMAIN=attacker\n"
	by := modulesOf(recognize.Recognize(parse.Parse(env, ".env"), "", module.Default))
	if m, ok := by["freshservice"]; ok {
		t.Errorf("freshservice matched using another service's domain: %+v", m.Fields)
	}
}

// A planted domain outside the vendor must lose the endpoint rather than
// receive the key — enforceEndpointPolicy clears the field, saasOnly pins it.
func TestFreshserviceRejectsForeignHost(t *testing.T) {
	env := "FRESHSERVICE_API_KEY=abc123\nFRESHSERVICE_DOMAIN=attacker.tld\n"
	by := modulesOf(recognize.Recognize(parse.Parse(env, ".env"), "", module.Default))
	if m, ok := by["freshservice"]; ok && m.Fields["endpoint"] != "" {
		t.Errorf("endpoint %q survived the saasOnly policy", m.Fields["endpoint"])
	}
}

// The case that started this: a Freshworks key with no tenant domain used to
// degrade to generic_secret ("credential-shaped value matched by variable
// name"). It must now name the service and say what to do next.
func TestFreshworksWithoutDomainReportsNeedsEndpoint(t *testing.T) {
	for _, env := range []string{
		"FRESHSERVICE_API_KEY=abc123def456\n",
		"FRESHDESK_API_KEY=abc123def456\n",
	} {
		by := modulesOf(recognize.Recognize(parse.Parse(env, ".env"), "", module.Default))
		m, ok := by["needs_endpoint"]
		if !ok {
			t.Errorf("%q: want needs_endpoint, got %v", strings.TrimSpace(env), by)
			continue
		}
		if !strings.Contains(strings.ToLower(m.Fields["service"]), "fresh") {
			t.Errorf("needs_endpoint should name the service, got %q", m.Fields["service"])
		}
		if _, dup := by["generic_secret"]; dup {
			t.Errorf("%q: generic_secret should be suppressed", strings.TrimSpace(env))
		}
	}
}

// A 2xx proves the key authenticated even when the body isn't the shape we
// expected. Without an explicit marker the findings come back empty and
// Summarize reports a LIVE credential as rejected.
func TestFreshdeskLiveButUnparsedIsNotDead(t *testing.T) {
	fs, n, _ := freshRun(t, "freshdesk", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/agents/me" {
			_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	if n.Invalid {
		t.Errorf("a 200 response must not be reported as a rejected credential: %+v", fs)
	}
	if got := score.TierFor(n, score.Context{}); got == score.TierDead {
		t.Errorf("tier = DEAD for a key the tenant accepted: %+v", fs)
	}
}

// enforceEndpointPolicy clears a host outside the vendor's domains, so Recon is
// reachable with no base URL. That is "we don't know where the tenant is", not a
// rejected credential.
func TestFreshworksEmptyEndpointIsNotDead(t *testing.T) {
	for _, tc := range []struct{ name, domainVar string }{
		{"freshservice", "FRESHSERVICE_DOMAIN"},
		{"freshdesk", "FRESHDESK_DOMAIN"},
	} {
		m, _ := module.Default.ByName(tc.name)
		fs, err := m.Recon(context.Background(), recon.New(nil, false), module.Token{},
			module.Fields{"token": "k", "password": "X", "endpoint": ""})
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		n := m.Summarize(tc.name+" …k", fs)
		if n.Invalid {
			t.Errorf("%s: no endpoint reported as a rejected credential", tc.name)
		}
		if idx := indexByKey(fs); !strings.Contains(idx["needs_endpoint"].Value, tc.domainVar) {
			t.Errorf("%s: should name the variable to set, got %+v", tc.name, fs)
		}
	}
}

// Agents routinely hold several roles. An anchored pattern tested against the
// roles joined into one string matches nothing unless the admin role happens to
// be first — silently missing the case this module exists to catch.
func TestFreshserviceDetectsAdminRoleInAnyPosition(t *testing.T) {
	for _, order := range [][]string{
		{`{"role_id":3},{"role_id":9}`, "admin first"},
		{`{"role_id":9},{"role_id":3}`, "admin second"},
	} {
		roles, label := order[0], order[1]
		fs, _, _ := freshRun(t, "freshservice", func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v2/agents":
				_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
			case "/api/v2/agents/me":
				_, _ = w.Write([]byte(`{"agent":{"email":"a@b.com","roles":[` + roles + `]}}`))
			case "/api/v2/roles":
				_, _ = w.Write([]byte(`{"roles":[{"id":9,"name":"IT Agent"},{"id":3,"name":"Admin"}]}`))
			default:
				w.WriteHeader(http.StatusForbidden)
			}
		})
		if indexByKey(fs)["agent creation"].Flag != module.FlagForceMultiplier {
			t.Errorf("%s: admin role not detected: %+v", label, fs)
		}
	}
}

// A role whose name merely contains "admin" must not be read as an admin role.
func TestFreshserviceDoesNotOvermatchRoleNames(t *testing.T) {
	fs, _, _ := freshRun(t, "freshservice", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents":
			_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
		case "/api/v2/agents/me":
			_, _ = w.Write([]byte(`{"agent":{"email":"a@b.com","roles":[{"role_id":4}]}}`))
		case "/api/v2/roles":
			_, _ = w.Write([]byte(`{"roles":[{"id":4,"name":"Non-Admin Reviewer"}]}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	})
	if v := indexByKey(fs)["agent creation"].Value; v != "" {
		t.Errorf("%q was read as an admin role", v)
	}
}

// The two recipe products get driven end-to-end too, not just their recognizers.
func TestFreshchatAndFreshsalesRecon(t *testing.T) {
	chat := http.NewServeMux()
	chat.HandleFunc("/v2/agents", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer abc123key" {
			t.Errorf("freshchat auth = %q, want a Bearer", got)
		}
		respond(w, `{"agents":[{"id":"a"},{"id":"b"}]}`)
	})
	got := driveModule(t, "freshchat", module.Fields{"token": "abc123key", "endpoint": "https://api.freshchat.com"}, chat)
	if got["agents"].Value != "2" {
		t.Errorf("freshchat agents = %q", got["agents"].Value)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("freshchat reach should be a force multiplier: %+v", got["reach"])
	}

	sales := http.NewServeMux()
	sales.HandleFunc("/crm/sales/api/selector/owners", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token token=abc123key" {
			t.Errorf("freshsales auth = %q, want the Token token= scheme", got)
		}
		respond(w, `{"users":[{"id":1}]}`)
	})
	gotS := driveModule(t, "freshsales", module.Fields{"token": "abc123key", "endpoint": "https://acme.myfreshworks.com"}, sales)
	if gotS["CRM users"].Value != "1" {
		t.Errorf("freshsales users = %q", gotS["CRM users"].Value)
	}
}

// A row count sizes the blast radius where bare reachability only asserts it:
// score.reachBonus reads the number out of the finding value.
func TestFreshserviceCountsRowsFromLinkHeader(t *testing.T) {
	fs, _, _ := freshRun(t, "freshservice", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agents":
			_, _ = w.Write([]byte(`{"agents":[{"id":1}]}`))
		case "/api/v2/requesters":
			w.Header().Set("Link", `<https://acme.freshservice.com/api/v2/requesters?per_page=1&page=8412>; rel="last"`)
			_, _ = w.Write([]byte(`{"requesters":[{"id":1}]}`))
		default:
			_, _ = w.Write([]byte(`{"tickets":[{"id":1}],"assets":[{"id":1}]}`))
		}
	})
	idx := indexByKey(fs)
	if !strings.Contains(idx["requester PII"].Value, "8412") {
		t.Errorf("row count not taken from the Link header: %q", idx["requester PII"].Value)
	}
	// An endpoint that sends no rel="last" degrades to plain reachability.
	if idx["tickets"].Value != "reachable" {
		t.Errorf("without a Link header the value should be bare reachability, got %q", idx["tickets"].Value)
	}
}
