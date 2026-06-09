package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/puck-security/geiger/internal/recon"
)

func tokenServer(t *testing.T, postCount *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(postCount, 1)
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"BEARER123","token_type":"Bearer","scope":"read","expires_in":3600,"instance_url":"https://acme.my.salesforce.com"}`))
	}))
}

func TestClientCredentialsOnePost(t *testing.T) {
	var posts int32
	srv := tokenServer(t, &posts)
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	tok, err := ClientCredentials(context.Background(), c, srv.URL, "cid", "csecret", url.Values{"scope": {"x/.default"}})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Bearer != "BEARER123" {
		t.Errorf("bearer = %q", tok.Bearer)
	}
	if tok.InstanceURL != "https://acme.my.salesforce.com" {
		t.Errorf("instance = %q", tok.InstanceURL)
	}
	if atomic.LoadInt32(&posts) != 1 {
		t.Errorf("expected exactly 1 POST, got %d", posts)
	}
}

func TestGrantsDryRunMakesNoCall(t *testing.T) {
	var posts int32
	srv := tokenServer(t, &posts)
	defer srv.Close()
	c := recon.New(srv.Client(), false) // dry-run
	tok, err := JWTBearer(context.Background(), c, srv.URL, "assertion.jwt.here", nil)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&posts) != 0 {
		t.Errorf("dry-run made %d POSTs", posts)
	}
	if tok.Bearer == "" {
		t.Error("expected synthetic dry-run token")
	}
}

func TestRefreshAndPasswordGrants(t *testing.T) {
	var posts int32
	srv := tokenServer(t, &posts)
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	if _, err := RefreshToken(context.Background(), c, srv.URL, "cid", "sec", "1//refresh", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Password(context.Background(), c, srv.URL, "cid", "sec", "user", "pass", nil); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&posts) != 2 {
		t.Errorf("expected 2 POSTs, got %d", posts)
	}
}
