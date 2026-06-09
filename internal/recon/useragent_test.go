package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserAgentApplied(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	orig := UserAgent
	defer func() { UserAgent = orig }()
	UserAgent = "geiger/9.9.9"

	c := New(srv.Client(), true)
	req, _ := NewRequest(context.Background(), http.MethodGet, srv.URL, nil)
	if _, err := c.Do(req, CallOpts{}); err != nil {
		t.Fatal(err)
	}
	if got != "geiger/9.9.9" {
		t.Errorf("User-Agent = %q, want geiger/9.9.9", got)
	}
}

func TestUserAgentNotOverridden(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	orig := UserAgent
	defer func() { UserAgent = orig }()
	UserAgent = "geiger/9.9.9"

	c := New(srv.Client(), true)
	req, _ := NewRequest(context.Background(), http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "custom/1.0") // a module set its own — keep it
	if _, err := c.Do(req, CallOpts{}); err != nil {
		t.Fatal(err)
	}
	if got != "custom/1.0" {
		t.Errorf("a caller-set User-Agent must be preserved, got %q", got)
	}
}

// The recorded audit call (the printed curl) carries the agent too.
func TestUserAgentInAuditTrail(t *testing.T) {
	orig := UserAgent
	defer func() { UserAgent = orig }()
	UserAgent = "geiger/9.9.9"

	c := New(nil, false) // dry-run: records without sending
	req, _ := NewRequest(context.Background(), http.MethodGet, "https://api.example.com/x", nil)
	if _, err := c.Do(req, CallOpts{}); err != nil {
		t.Fatal(err)
	}
	planned := c.Planned()
	if len(planned) != 1 || planned[0].Headers["User-Agent"] != "geiger/9.9.9" {
		t.Errorf("recorded call missing User-Agent: %+v", planned)
	}
}
