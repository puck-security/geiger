package imds

import (
	"context"
	"net/http"
	"strings"
)

// digitalOceanBase is overridable in tests.
var digitalOceanBase = "http://169.254.169.254"

// fetchDigitalOcean reads droplet user-data. DigitalOcean's metadata service
// exposes no instance API token, so the credential-bearing surface is user-data
// (cloud-init scripts routinely embed secrets) — returned as a blob for the normal
// pipeline to triage. (AWS IMDS lives at the same IP but answers different paths,
// so this 404s on AWS and doesn't cross-fire.)
func fetchDigitalOcean(ctx context.Context, hc *http.Client) []Cred {
	ud, ok := get(ctx, hc, digitalOceanBase+"/metadata/v1/user-data", nil)
	if !ok || strings.TrimSpace(string(ud)) == "" {
		return nil
	}
	return []Cred{{Cloud: "digitalocean", Label: "metadata: digitalocean user-data", Blob: string(ud)}}
}
