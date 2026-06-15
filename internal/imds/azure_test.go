package imds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchAzure(t *testing.T) {
	gotResources := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			t.Errorf("Azure IMDS requires the Metadata: true header")
		}
		gotResources[r.URL.Query().Get("resource")] = true
		// A JWT-shaped token (header.payload.sig, base64url) so recognizeAzureToken fires.
		_, _ = w.Write([]byte(`{"access_token":"eyJ0eXAiOiJKV1QifQ.eyJ0aWQiOiJ0LTEifQ.sig","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	orig := azureMetadataBase
	azureMetadataBase = srv.URL
	defer func() { azureMetadataBase = orig }()

	creds := fetchAzure(context.Background(), srv.Client())
	if len(creds) != len(azureResources) {
		t.Fatalf("want one cred per resource (%d), got %d", len(azureResources), len(creds))
	}
	if !gotResources["https://management.azure.com/"] || !gotResources["https://graph.microsoft.com/"] {
		t.Errorf("expected ARM + Graph resource tokens to be requested: %v", gotResources)
	}
	if !recognizesAs(t, creds[0], "azure_msal") {
		t.Error("harvested Azure managed-identity token did not recognize as azure_msal")
	}
}
