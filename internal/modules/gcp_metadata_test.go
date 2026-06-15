package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func TestGCPMetadataRecognizes(t *testing.T) {
	b := parse.Parse("GOOGLE_OAUTH_ACCESS_TOKEN=ya29.test\nGCP_SA_EMAIL=svc@p.iam.gserviceaccount.com\n", "metadata: gcp")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["gcp_metadata"]; !ok {
		t.Fatal("ya29 token under GOOGLE_OAUTH_ACCESS_TOKEN not recognized as gcp_metadata")
	}
	// A non-ya29 value must not trip it.
	b2 := parse.Parse("GOOGLE_OAUTH_ACCESS_TOKEN=not-a-token\n", "")
	if _, ok := modulesOf(recognize.Recognize(b2, "", module.Default))["gcp_metadata"]; ok {
		t.Error("gcp_metadata fired on a non-ya29 value")
	}
}

func TestGCPMetadataRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"email":"svc@p.iam.gserviceaccount.com"}`))
	})
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"a"},{"projectId":"b"},{"projectId":"c"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	origUI, origRM := gcpUserinfo, gcpEndpoints.ResourceManager
	gcpUserinfo = srv.URL + "/userinfo"
	gcpEndpoints.ResourceManager = srv.URL + "/projects"
	defer func() { gcpUserinfo = origUI; gcpEndpoints.ResourceManager = origRM }()

	c := recon.New(srv.Client(), true)
	fs, err := gcpMetadata{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"access_token": "ya29.test", "scopes": "cloud-platform"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["identity"].Value != "svc@p.iam.gserviceaccount.com" {
		t.Errorf("identity = %+v", got["identity"])
	}
	if got["reachable projects"].Value != "3" {
		t.Errorf("reachable projects = %+v", got["reachable projects"])
	}
	if got["scopes"].Flag != module.FlagWarn {
		t.Errorf("cloud-platform scope should warn: %+v", got["scopes"])
	}
}
