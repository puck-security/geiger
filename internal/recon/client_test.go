package recon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestReadOnlyEnforcement(t *testing.T) {
	// GET / HEAD allowed
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if err := allowed(m, CallOpts{}); err != nil {
			t.Errorf("%s should be allowed: %v", m, err)
		}
	}
	// POST refused without opt-in, allowed with it
	if err := allowed(http.MethodPost, CallOpts{}); !errors.Is(err, ErrMutatingCall) {
		t.Errorf("POST without opt-in should be refused, got %v", err)
	}
	if err := allowed(http.MethodPost, CallOpts{ReadOnlyPOST: true}); err != nil {
		t.Errorf("POST with opt-in should be allowed: %v", err)
	}
	// PUT/DELETE/PATCH always refused
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if err := allowed(m, CallOpts{ReadOnlyPOST: true}); !errors.Is(err, ErrMutatingCall) {
			t.Errorf("%s should always be refused, got %v", m, err)
		}
	}
}

func TestDryRunDoesNotHitNetwork(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := New(srv.Client(), false) // dry-run
	req, _ := NewRequest(context.Background(), http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer ghp_secretsecretsecretsecret1234")
	resp, err := c.Do(req, CallOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.DryRun {
		t.Error("expected dry-run response")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("dry-run hit the network %d times", hits)
	}
	if got := len(c.Planned()); got != 1 {
		t.Fatalf("expected 1 planned call, got %d", got)
	}
	// Secret must be redacted in the recorded headers.
	if h := c.Planned()[0].Headers["Authorization"]; h == "Bearer ghp_secretsecretsecretsecret1234" {
		t.Errorf("secret not redacted in planned headers: %q", h)
	}
}

func TestLiveDoReturnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New(srv.Client(), true)
	req, _ := NewRequest(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req, CallOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 201 || string(resp.Body) != `{"ok":true}` {
		t.Errorf("unexpected response: %d %s", resp.Status, resp.Body)
	}
}

func TestDoRefusesMutating(t *testing.T) {
	c := New(nil, true)
	req, _ := NewRequest(context.Background(), http.MethodDelete, "http://example.invalid", nil)
	if _, err := c.Do(req, CallOpts{ReadOnlyPOST: true}); !errors.Is(err, ErrMutatingCall) {
		t.Errorf("expected ErrMutatingCall, got %v", err)
	}
}
