package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestGCPImpactPermissionProbe(t *testing.T) {
	// The identity holds one privesc and one data permission, no code-exec.
	granted := map[string]bool{
		"iam.serviceAccounts.getAccessToken": true,
		"secretmanager.versions.access":      true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"email":"sa@acme.iam.gserviceaccount.com"}`))
	})
	mux.HandleFunc("/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"acme-prod"}]}`))
	})
	mux.HandleFunc("/v1/projects/acme-prod:testIamPermissions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Permissions []string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var out []string
		for _, p := range body.Permissions {
			if granted[p] {
				out = append(out, p)
			}
		}
		resp, _ := json.Marshal(map[string][]string{"permissions": out})
		_, _ = w.Write(resp)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origRM, origUI := gcpEndpoints.ResourceManager, gcpUserinfo
	gcpEndpoints.ResourceManager = srv.URL + "/v1/projects"
	gcpUserinfo = srv.URL + "/userinfo"
	defer func() { gcpEndpoints.ResourceManager, gcpUserinfo = origRM, origUI }()

	c := recon.New(srv.Client(), true)
	c.SetGCPIntrusive(true)
	fs, err := gcpMetadata{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"access_token": "ya29.test"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if pe, ok := got["gcp-privesc"]; !ok || pe.Flag != module.FlagForceMultiplier || !strings.Contains(pe.Value, "getAccessToken") {
		t.Errorf("gcp-privesc finding wrong: %+v", got["gcp-privesc"])
	}
	if da, ok := got["gcp-data-access"]; !ok || !strings.Contains(da.Value, "secretmanager.versions.access") {
		t.Errorf("gcp-data-access finding wrong: %+v", got["gcp-data-access"])
	}
	if _, ok := got["gcp-code-exec"]; ok {
		t.Errorf("gcp-code-exec should be absent (no granted perms): %+v", got["gcp-code-exec"])
	}
}

func TestGCPImpactGateOff(t *testing.T) {
	probed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"email":"x"}`)) })
	mux.HandleFunc("/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"p"}]}`))
	})
	mux.HandleFunc("/v1/projects/p:testIamPermissions", func(w http.ResponseWriter, r *http.Request) {
		probed = true
		_, _ = w.Write([]byte(`{"permissions":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origRM, origUI := gcpEndpoints.ResourceManager, gcpUserinfo
	gcpEndpoints.ResourceManager = srv.URL + "/v1/projects"
	gcpUserinfo = srv.URL + "/userinfo"
	defer func() { gcpEndpoints.ResourceManager, gcpUserinfo = origRM, origUI }()

	c := recon.New(srv.Client(), true) // not gcp-intrusive
	_, _ = gcpMetadata{}.Recon(context.Background(), c, module.Token{}, module.Fields{"access_token": "ya29.test"})
	if probed {
		t.Error("testIamPermissions must not be called without --gcp-intrusive")
	}
}
