package modules

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// GCP Secret Manager transitive harvest. Supply-chain malware (Shai-Hulud) runs
// `list_GCP_secrets` to drain every accessible secret once it has a token; this
// is the responder/red-teamer's read-only mirror, gated on --live --intrusive.
//
// Both the service-account key and the gcloud ADC user token mint an access
// token whose scope (cloud-platform.read-only) already permits
// secretmanager.versions.access, so the same harvest path serves both.

const (
	gcpSecretProjectCap = 10 // bound project fan-out
	gcpSecretCap        = 50 // bound secrets pulled per run
)

// gcpHarvestSecrets lists and accesses Secret Manager payloads across the given
// projects, returning the extracted values for recursive triage.
func gcpHarvestSecrets(ctx context.Context, c *recon.Client, bearer string, projects []string) []module.Harvested {
	if bearer == "" {
		return nil
	}
	var out []module.Harvested
	seenProj := map[string]bool{}
	for _, proj := range projects {
		if proj == "" || seenProj[proj] || len(seenProj) >= gcpSecretProjectCap {
			continue
		}
		seenProj[proj] = true
		for _, name := range gcpListSecretNames(ctx, c, bearer, proj) {
			if len(out) >= gcpSecretCap {
				return out
			}
			if v := gcpAccessSecret(ctx, c, bearer, name); v != "" {
				out = append(out, module.Harvested{Label: "gcp secretmanager:" + name, Value: v})
			}
		}
	}
	return out
}

// gcpListSecretNames returns the resource names (projects/N/secrets/ID) of every
// secret visible in a project.
func gcpListSecretNames(ctx context.Context, c *recon.Client, bearer, project string) []string {
	u := gcpEndpoints.SecretManager + "/projects/" + url.PathEscape(project) + "/secrets?pageSize=100"
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{Note: "secretmanager.secrets.list (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var names []string
	if secrets, ok := jsonDecode(resp.Body)["secrets"].([]any); ok {
		for _, s := range secrets {
			if m, ok := s.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && n != "" {
					names = append(names, n)
				}
			}
		}
	}
	return names
}

// gcpAccessSecret accesses the latest version of a secret and returns the
// decoded payload (the secret value itself).
func gcpAccessSecret(ctx context.Context, c *recon.Client, bearer, name string) string {
	u := gcpEndpoints.SecretManager + "/" + name + "/versions/latest:access"
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{Note: "secretmanager.versions.access (read-only, extracts value)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	payload, _ := jsonDecode(resp.Body)["payload"].(map[string]any)
	data, _ := payload["data"].(string)
	if data == "" {
		return ""
	}
	dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(dec)
}

// gcpProjectIDs discovers reachable project IDs via Resource Manager, so harvest
// can sweep beyond the credential's home project.
func gcpProjectIDs(ctx context.Context, c *recon.Client, bearer string) []string {
	req, _ := recon.NewRequest(ctx, http.MethodGet, gcpEndpoints.ResourceManager, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var ids []string
	if projs, ok := jsonDecode(resp.Body)["projects"].([]any); ok {
		for _, p := range projs {
			if m, ok := p.(map[string]any); ok {
				if id, ok := m["projectId"].(string); ok && id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}
