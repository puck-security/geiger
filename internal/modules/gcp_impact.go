package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// GCP IAM blast radius. The read-only testIamPermissions call (no permission
// required to invoke) returns the subset of a requested permission list that the
// caller actually holds on a project — the GCP analog of AWS
// SimulatePrincipalPolicy. We probe curated high-impact permissions, grouped by
// what they enable, so a leaked GCP credential reports what it can DO, not just
// which projects it can see. The permission names come from Rhino Security Labs'
// GCP privilege-escalation catalog.
//
// Each category is a separate testIamPermissions call: the API rejects the whole
// request with 400 if any permission is not applicable to the project resource,
// so isolating categories keeps one unknown permission from voiding the rest.
// Every probe is read-only; a 400 or 403 simply yields nothing for that group.

type gcpPermGroup struct {
	key, label string
	perms      []string
}

var gcpPermGroups = []gcpPermGroup{
	{
		key:   "gcp-privesc",
		label: "privilege escalation",
		perms: []string{
			"iam.serviceAccounts.getAccessToken",
			"iam.serviceAccounts.actAs",
			"iam.serviceAccounts.signJwt",
			"iam.serviceAccounts.signBlob",
			"iam.serviceAccountKeys.create",
			"iam.roles.update",
			"resourcemanager.projects.setIamPolicy",
		},
	},
	{
		key:   "gcp-code-exec",
		label: "code execution / deploy",
		perms: []string{
			"run.services.create",
			"cloudfunctions.functions.create",
			"compute.instances.create",
			"compute.instances.setMetadata",
			"deploymentmanager.deployments.create",
			"cloudbuild.builds.create",
		},
	},
	{
		key:   "gcp-data-access",
		label: "data access",
		perms: []string{
			"secretmanager.versions.access",
			"storage.objects.get",
			"bigquery.tables.getData",
		},
	},
}

// gcpImpact probes effective permissions across up to maxGCPImpactProjects
// reachable projects and reports what the identity can do in each.
func gcpImpact(ctx context.Context, c *recon.Client, bearer string, projectIDs []string) []module.Finding {
	const maxGCPImpactProjects = 5
	var out []module.Finding
	seen := map[string]bool{}
	tested := 0
	for _, pid := range projectIDs {
		if pid == "" || seen[pid] {
			continue
		}
		seen[pid] = true
		if tested >= maxGCPImpactProjects {
			break
		}
		tested++
		for _, g := range gcpPermGroups {
			if allowed := gcpTestPermissions(ctx, c, bearer, pid, g.perms); len(allowed) > 0 {
				out = append(out, module.Finding{
					Key:   g.key,
					Value: pid + ": " + g.label + " (" + strings.Join(allowed, ", ") + ")",
					Flag:  module.FlagForceMultiplier,
				})
			}
		}
	}
	return out
}

// gcpTestPermissions returns the subset of perms the caller holds on projectID,
// via cloudresourcemanager projects.testIamPermissions (read-only POST).
func gcpTestPermissions(ctx context.Context, c *recon.Client, bearer, projectID string, perms []string) []string {
	body, _ := json.Marshal(map[string][]string{"permissions": perms})
	url := gcpEndpoints.ResourceManager + "/" + projectID + ":testIamPermissions"
	req, err := recon.NewRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "cloudresourcemanager testIamPermissions (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return jsonStringList(jsonDecode(resp.Body)["permissions"])
}
