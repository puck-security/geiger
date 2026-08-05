package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/score"
)

// A rejected key must not inherit the module's Static force-multiplier. Some
// APIs answer 200 with {"success":false,"errors":[…]}; counting that error list
// as recon output made a dead credential report HIGH "full account access".
func TestFailureEnvelopeDoesNotEarnForceMultiplier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"}],"messages":[],"result":null}`))
	}))
	defer srv.Close()

	m := HTTP{
		ModuleName: "cf_like", Base: srv.URL, Auth: AuthSpec{Kind: None},
		Whoami: GET("/user").Field("email", "result.email"),
		Static: []module.Finding{{Key: "note", Value: "full account access", Flag: module.FlagForceMultiplier}},
	}.Module()

	c := recon.New(srv.Client(), true)
	fs, err := m.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "deadbeef"})
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	for _, f := range fs {
		if f.Flag == module.FlagForceMultiplier {
			t.Errorf("rejected credential earned a force multiplier: %+v", f)
		}
		if f.Key == "errors" {
			t.Errorf("an API error list must not be reported as a detected collection: %+v", f)
		}
	}
	n := m.Summarize("t", fs)
	if tier := score.TierFor(n, score.Context{}); tier == score.TierHigh || tier == score.TierCritical {
		t.Errorf("rejected credential scored %s: %+v", tier, n)
	}
}

// A successful response that merely CARRIES an empty errors key is not a
// rejection — that is what a healthy Cloudflare-style body looks like.
func TestEmptyErrorsArrayIsNotARejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"email":"a@b.com","id":"x"}}`))
	}))
	defer srv.Close()

	m := HTTP{
		ModuleName: "cf_ok", Base: srv.URL, Auth: AuthSpec{Kind: None},
		Whoami: GET("/user").Field("email", "result.email"),
		Static: []module.Finding{{Key: "note", Value: "full account access", Flag: module.FlagForceMultiplier}},
	}.Module()

	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "live"})
	if err != nil {
		t.Fatal(err)
	}
	var gotEmail, gotStatic bool
	for _, f := range fs {
		if f.Key == "email" && f.Value == "a@b.com" {
			gotEmail = true
		}
		if f.Flag == module.FlagForceMultiplier {
			gotStatic = true
		}
	}
	if !gotEmail {
		t.Errorf("live credential lost its identity: %+v", fs)
	}
	if !gotStatic {
		t.Errorf("a live credential should still carry the module's Static findings: %+v", fs)
	}
}

// An API whose real payload is a list of errors must still characterize, so long
// as the module's declared fields matched.
func TestErrorListAsRealDataStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"account":"acme","errors":[{"id":1},{"id":2}]}`))
	}))
	defer srv.Close()

	m := HTTP{
		ModuleName: "errlog", Base: srv.URL, Auth: AuthSpec{Kind: None},
		Whoami: GET("/errors").Field("account", "account"),
	}.Module()

	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "live"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.Key == "account" && f.Value == "acme" {
			found = true
		}
	}
	if !found {
		t.Errorf("declared field extracted nothing; error-list payload was misread as a rejection: %+v", fs)
	}
}

// A credential the API ACCEPTED (2xx/403) but whose body we couldn't parse is
// live — it must keep the module's Static description. Dropping it left a proven
// token reading LOW with nothing describing it.
func TestAuthenticatedButUnparsedKeepsStatic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()

	m := HTTP{
		ModuleName: "s", Base: srv.URL, Auth: AuthSpec{Kind: None},
		Whoami: GET("/me").Field("account", "account.email"),
		Static: []module.Finding{{Key: "type", Value: "described type", Flag: module.FlagInfo}},
	}.Module()

	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "live"})
	if err != nil {
		t.Fatal(err)
	}
	var gotStatic, gotAuthed bool
	for _, f := range fs {
		if f.Key == "type" {
			gotStatic = true
		}
		if f.Key == "authenticated" {
			gotAuthed = true
		}
	}
	if !gotAuthed {
		t.Fatalf("expected the authenticated marker: %+v", fs)
	}
	if !gotStatic {
		t.Errorf("a live credential lost its Static description: %+v", fs)
	}
}
