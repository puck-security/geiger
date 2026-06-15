package imds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// azureMetadataBase is overridable in tests.
var azureMetadataBase = "http://169.254.169.254"

// azureResources are the audiences a managed identity can mint tokens for. Tokens
// are audience-specific, so we fetch one per resource and let azure_msal exercise
// each against its matching endpoints (cross-audience calls just 401 and drop).
var azureResources = []struct{ name, resource string }{
	{"Graph", "https://graph.microsoft.com/"},
	{"ARM", "https://management.azure.com/"},
	{"KeyVault", "https://vault.azure.net/"},
	{"Storage", "https://storage.azure.com/"},
}

// fetchAzure pulls a managed-identity access token per resource audience.
func fetchAzure(ctx context.Context, hc *http.Client) []Cred {
	var creds []Cred
	for _, r := range azureResources {
		u := azureMetadataBase + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + url.QueryEscape(r.resource)
		body, ok := get(ctx, hc, u, azureHdr)
		if !ok {
			continue
		}
		var tr struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(body, &tr) != nil || !strings.HasPrefix(tr.AccessToken, "eyJ") {
			continue
		}
		creds = append(creds, Cred{
			Cloud:  "azure",
			Label:  "metadata: azure managed-identity (" + r.name + ")",
			Blob:   "AZURE_ACCESS_TOKEN=" + tr.AccessToken + "\n",
			Secret: tr.AccessToken,
		})
	}
	return creds
}

func azureHdr(req *http.Request) { req.Header.Set("Metadata", "true") }
