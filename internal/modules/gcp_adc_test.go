package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recon"
)

const gcpADCFile = `{"type":"authorized_user","client_id":"cid.apps.googleusercontent.com","client_secret":"fake-secret","refresh_token":"fake-refresh-token"}`

func TestGCPADCRecognizes(t *testing.T) {
	b := parse.Parse(gcpADCFile, "application_default_credentials.json")
	ms := recognizeGCPADC(b, "", nil)
	if len(ms) != 1 || ms[0].Module != "gcp_adc" {
		t.Fatalf("not recognized: %+v", ms)
	}
}

// Plain --live must NOT redeem the user refresh token (an active token grant);
// geiger flags it as re-mintable and hints to add --intrusive.
func TestGCPADCGatedBehindIntrusive(t *testing.T) {
	exchanged := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanged = true
		_, _ = w.Write([]byte(`{"access_token":"GTOK","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	orig := gcpEndpoints
	gcpEndpoints.Token = srv.URL
	defer func() { gcpEndpoints = orig }()

	b := parse.Parse(gcpADCFile, "application_default_credentials.json")
	f := recognizeGCPADC(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true) // live, NOT intrusive
	m := gcpADC{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if exchanged || tok.Bearer != "" {
		t.Fatalf("plain --live must not redeem the refresh token: token=%q exchanged=%v", tok.Bearer, exchanged)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["refresh token"].Flag != module.FlagForceMultiplier {
		t.Errorf("refresh token must be flagged re-mintable: %+v", got["refresh token"])
	}
	if got["deepen"].Value == "" {
		t.Errorf("expected an --intrusive deepen hint: %+v", got)
	}
}

// --intrusive: the refresh token is redeemed and recon runs off the minted token.
func TestGCPADCIntrusiveRefresh(t *testing.T) {
	exchanged := false
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		exchanged = true
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected refresh_token grant, got %q", r.Form.Get("grant_type"))
		}
		_, _ = w.Write([]byte(`{"access_token":"GTOK","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"email":"dev@acme.iam.gserviceaccount.com"}`))
	})
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"p1"},{"projectId":"p2"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig, origUI := gcpEndpoints, gcpUserinfo
	gcpEndpoints.Token = srv.URL + "/token"
	gcpEndpoints.ResourceManager = srv.URL + "/projects"
	gcpUserinfo = srv.URL + "/userinfo"
	defer func() { gcpEndpoints = orig; gcpUserinfo = origUI }()

	b := parse.Parse(gcpADCFile, "application_default_credentials.json")
	f := recognizeGCPADC(b, "", nil)[0].Fields
	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)
	m := gcpADC{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !exchanged || tok.Bearer != "GTOK" {
		t.Fatalf("refresh should run under --intrusive: token=%q exchanged=%v", tok.Bearer, exchanged)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["user"].Value != "dev@acme.iam.gserviceaccount.com" {
		t.Errorf("userinfo wrong: %+v", got["user"])
	}
	if got["reachable projects"].Value != "2" {
		t.Errorf("reachable projects wrong: %+v", got["reachable projects"])
	}
}
