package modules

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestGCPADCHarvestsSecretManager(t *testing.T) {
	mux := http.NewServeMux()
	// reachable projects
	mux.HandleFunc("/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"acme-prod"}]}`))
	})
	// list secrets in the project
	mux.HandleFunc("/sm/v1/projects/acme-prod/secrets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"secrets":[{"name":"projects/123/secrets/db-password"}]}`))
	})
	// access latest version
	mux.HandleFunc("/sm/v1/projects/123/secrets/db-password/versions/latest:access", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ACCESSTOKEN" {
			t.Errorf("harvest not using access token: %q", r.Header.Get("Authorization"))
		}
		data := base64.StdEncoding.EncodeToString([]byte("super-secret-db-pw"))
		_, _ = w.Write([]byte(`{"payload":{"data":"` + data + `"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	orig := gcpEndpoints
	gcpEndpoints.ResourceManager = srv.URL + "/v1/projects"
	gcpEndpoints.SecretManager = srv.URL + "/sm/v1"
	defer func() { gcpEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)
	tok := module.Token{Bearer: "ACCESSTOKEN"}

	got, err := gcpADC{}.Harvest(context.Background(), c, tok, module.Fields{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 harvested secret, got %d: %+v", len(got), got)
	}
	if got[0].Value != "super-secret-db-pw" {
		t.Errorf("payload not base64-decoded: %q", got[0].Value)
	}
	if got[0].Label != "gcp secretmanager:projects/123/secrets/db-password" {
		t.Errorf("provenance label wrong: %q", got[0].Label)
	}
}

func TestGCPHarvestGatedOffWithoutIntrusive(t *testing.T) {
	c := recon.New(http.DefaultClient, true) // live but NOT intrusive
	got, err := gcpADC{}.Harvest(context.Background(), c, module.Token{Bearer: "x"}, module.Fields{})
	if err != nil || got != nil {
		t.Errorf("harvest must no-op without --intrusive, got %+v err=%v", got, err)
	}
}
