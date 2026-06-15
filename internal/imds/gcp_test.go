package imds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchGCP(t *testing.T) {
	base := "/computeMetadata/v1/instance/service-accounts/default/"
	mux := http.NewServeMux()
	mux.HandleFunc(base+"token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("GCP metadata requires the Metadata-Flavor: Google header")
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.abc123","expires_in":3599,"token_type":"Bearer"}`))
	})
	mux.HandleFunc(base+"email", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("svc@proj.iam.gserviceaccount.com"))
	})
	mux.HandleFunc(base+"scopes", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https://www.googleapis.com/auth/cloud-platform\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := gcpMetadataBase
	gcpMetadataBase = srv.URL
	defer func() { gcpMetadataBase = orig }()

	creds := fetchGCP(context.Background(), srv.Client())
	if len(creds) != 1 || creds[0].Secret != "ya29.abc123" {
		t.Fatalf("gcp cred not harvested: %+v", creds)
	}
	if !strings.Contains(creds[0].Label, "svc@proj") {
		t.Errorf("label = %q", creds[0].Label)
	}
	if !strings.Contains(creds[0].Blob, "GCP_SCOPES=") {
		t.Errorf("scopes missing from blob: %q", creds[0].Blob)
	}
	if !recognizesAs(t, creds[0], "gcp_metadata") {
		t.Error("harvested GCP blob did not recognize as gcp_metadata")
	}
}
