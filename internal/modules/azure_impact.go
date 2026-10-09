package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// Azure blast radius: what an Entra identity can actually do. Two read-only
// planes answer it. Microsoft Graph /me/memberOf returns the directory roles the
// identity holds (Global Administrator and friends grant tenant-wide control).
// Azure Resource Manager role assignments return the RBAC roles it holds on
// subscriptions (Owner and User Access Administrator can grant themselves
// anything). Both are read-only; a missing scope just yields nothing.

// Privileged Entra directory roles, by well-known roleTemplateId. Holding any of
// these is effectively tenant admin or a direct path to it.
var azurePrivilegedRoleTemplates = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
}

// Privileged Azure RBAC built-in roles, by roleDefinition GUID suffix. Owner and
// User Access Administrator can modify IAM (grant roles); Contributor is broad
// write without IAM.
var azurePrivilegedRBAC = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
}

// azureImpact mints Graph and ARM tokens from the public-client refresh token
// and reports the identity's Entra directory roles and Azure RBAC assignments.
func azureImpact(ctx context.Context, c *recon.Client, tenant, clientID, refresh string) []module.Finding {
	if refresh == "" || clientID == "" {
		return nil
	}
	var out []module.Finding

	graphTok := azureResourceToken(ctx, c, tenant, clientID, refresh, "https://graph.microsoft.com/.default")
	oid := ""
	if graphTok != "" {
		oid = azureMe(ctx, c, graphTok)
		out = append(out, azureDirectoryRoles(ctx, c, graphTok)...)
	}

	armTok := azureResourceToken(ctx, c, tenant, clientID, refresh, "https://management.azure.com/.default")
	if armTok != "" && oid != "" {
		out = append(out, azureRBAC(ctx, c, armTok, oid)...)
	}
	return out
}

func azureGraphGet(ctx context.Context, c *recon.Client, bearer, path string) []byte {
	req, err := recon.NewRequest(ctx, http.MethodGet, azureMSALEndpoints.Graph+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return resp.Body
}

// azureMe returns the identity's object id (needed to filter RBAC assignments).
func azureMe(ctx context.Context, c *recon.Client, bearer string) string {
	body := azureGraphGet(ctx, c, bearer, "/me?$select=id")
	if body == nil {
		return ""
	}
	var d struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &d)
	return d.ID
}

// azureDirectoryRoles reports the Entra directory roles the identity holds,
// flagging privileged ones as force multipliers.
func azureDirectoryRoles(ctx context.Context, c *recon.Client, bearer string) []module.Finding {
	body := azureGraphGet(ctx, c, bearer, "/me/memberOf?$select=id,displayName,roleTemplateId")
	if body == nil {
		return nil
	}
	var d struct {
		Value []struct {
			Type           string `json:"@odata.type"`
			DisplayName    string `json:"displayName"`
			RoleTemplateID string `json:"roleTemplateId"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil
	}
	var roles, privileged []string
	for _, e := range d.Value {
		if !strings.Contains(e.Type, "directoryRole") {
			continue
		}
		roles = append(roles, e.DisplayName)
		if _, ok := azurePrivilegedRoleTemplates[e.RoleTemplateID]; ok {
			privileged = append(privileged, e.DisplayName)
		}
	}
	var out []module.Finding
	if len(privileged) > 0 {
		out = append(out, module.Finding{Key: "entra roles", Value: "privileged: " + strings.Join(privileged, ", "), Flag: module.FlagForceMultiplier})
	} else if len(roles) > 0 {
		out = append(out, module.Finding{Key: "entra roles", Value: strings.Join(roles, ", "), Flag: module.FlagWarn})
	}
	return out
}

// azureRBAC reports the identity's privileged RBAC role assignments across up to
// a few subscriptions.
func azureRBAC(ctx context.Context, c *recon.Client, bearer, oid string) []module.Finding {
	subs := azureSubscriptionIDs(ctx, c, bearer)
	var out []module.Finding
	for i, sub := range subs {
		if i >= azureSubCap {
			break
		}
		for _, role := range azureRoleAssignments(ctx, c, bearer, sub, oid) {
			out = append(out, module.Finding{
				Key:   "azure rbac",
				Value: sub + ": " + role,
				Flag:  module.FlagForceMultiplier,
			})
		}
	}
	return out
}

// azureRoleAssignments returns the names of privileged built-in roles assigned to
// oid on a subscription. The roleDefinitionId ends in the role's GUID.
func azureRoleAssignments(ctx context.Context, c *recon.Client, bearer, subscription, oid string) []string {
	u := azureMSALEndpoints.ARM + "/subscriptions/" + subscription +
		"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=" +
		url.QueryEscape("principalId eq '"+oid+"'")
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var d struct {
		Value []struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
			} `json:"properties"`
		} `json:"value"`
	}
	if json.Unmarshal(resp.Body, &d) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range d.Value {
		guid := a.Properties.RoleDefinitionID
		if i := strings.LastIndex(guid, "/"); i >= 0 {
			guid = guid[i+1:]
		}
		if name, ok := azurePrivilegedRBAC[guid]; ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}
