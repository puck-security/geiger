package imds

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// gcpMetadataBase is overridable in tests.
var gcpMetadataBase = "http://metadata.google.internal"

// fetchGCP reads the instance default service account's access token (plus its
// email and scopes for context) from the GCP metadata server.
func fetchGCP(ctx context.Context, hc *http.Client) []Cred {
	const sa = "/computeMetadata/v1/instance/service-accounts/default/"
	tokBody, ok := get(ctx, hc, gcpMetadataBase+sa+"token", gcpHdr)
	if !ok {
		return nil
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(tokBody, &tr) != nil || !strings.HasPrefix(tr.AccessToken, "ya29.") {
		return nil
	}
	email := ""
	if b, ok := get(ctx, hc, gcpMetadataBase+sa+"email", gcpHdr); ok {
		email = strings.TrimSpace(string(b))
	}
	scopes := ""
	if b, ok := get(ctx, hc, gcpMetadataBase+sa+"scopes", gcpHdr); ok {
		scopes = strings.Join(strings.Fields(string(b)), ",")
	}
	blob := "GOOGLE_OAUTH_ACCESS_TOKEN=" + tr.AccessToken + "\n"
	if email != "" {
		blob += "GCP_SA_EMAIL=" + email + "\n"
	}
	if scopes != "" {
		blob += "GCP_SCOPES=" + scopes + "\n"
	}
	label := "metadata: gcp service account"
	if email != "" {
		label += " " + email
	}
	return []Cred{{Cloud: "gcp", Label: label, Blob: blob, Secret: tr.AccessToken}}
}

func gcpHdr(req *http.Request) { req.Header.Set("Metadata-Flavor", "Google") }
