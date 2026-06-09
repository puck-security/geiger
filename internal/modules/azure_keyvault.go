package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// Azure Key Vault transitive harvest. Supply-chain malware (Shai-Hulud) runs
// `list_Azure_secrets` to drain Key Vault once it holds an `az` session; this is
// the read-only mirror, gated on --live --intrusive.
//
// Key Vault and ARM are separate audiences from Graph, so harvest mints fresh
// resource-scoped tokens from the public-client refresh token (no secret).

const (
	azureSubCap         = 5  // bound subscription fan-out
	azureVaultCap       = 10 // bound vaults visited
	azureVaultSecretCap = 50 // bound secrets pulled per run
)

// vaultAPIVersion / armVaultAPIVersion pin the data- and control-plane APIs.
const (
	vaultAPIVersion    = "7.4"
	armVaultListAPIVer = "2022-07-01"
	armSubListAPIVer   = "2020-01-01"
)

// Harvest mints ARM + Key Vault tokens from the refresh token, enumerates vaults
// across reachable subscriptions, and drains their secret values.
func (m azureMSAL) Harvest(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	rt, cid := f["refresh_token"], f["client_id"]
	if rt == "" || cid == "" {
		return nil, nil // need the public-client refresh token to re-scope
	}
	tenant := tenantOf(f)
	armTok := azureResourceToken(ctx, c, tenant, cid, rt, "https://management.azure.com/.default")
	vaultTok := azureResourceToken(ctx, c, tenant, cid, rt, "https://vault.azure.net/.default")
	if vaultTok == "" || armTok == "" {
		return nil, nil
	}
	vaults := azureListVaultURIs(ctx, c, armTok)
	return azureHarvestVaults(ctx, c, vaultTok, vaults), nil
}

// azureResourceToken re-scopes the public-client refresh token to a specific
// resource audience (ARM, Key Vault) and returns the access token.
func azureResourceToken(ctx context.Context, c *recon.Client, tenant, clientID, refresh, scope string) string {
	tokenURL := fmt.Sprintf(azureMSALEndpoints.TokenTmpl, tenant)
	tok, err := auth.RefreshToken(ctx, c, tokenURL, clientID, "", refresh,
		url.Values{"scope": {scope + " offline_access"}})
	if err != nil {
		return ""
	}
	return tok.Bearer
}

// azureSPToken mints a resource-scoped token for an Entra service principal via
// the client_credentials grant.
func azureSPToken(ctx context.Context, c *recon.Client, tenant, clientID, clientSecret, scope string) string {
	tokenURL := fmt.Sprintf(azureMSALEndpoints.TokenTmpl, tenant)
	tok, err := auth.ClientCredentials(ctx, c, tokenURL, clientID, clientSecret, url.Values{"scope": {scope}})
	if err != nil {
		return ""
	}
	return tok.Bearer
}

// azureVaultHarvestSP enumerates and drains Key Vault for an Entra service
// principal (client_id + secret). A confidential app with a vault access policy
// or RBAC role is the worm's richest Azure secrets-store target.
func azureVaultHarvestSP(ctx context.Context, c *recon.Client, tenant, clientID, clientSecret string) []module.Harvested {
	armTok := azureSPToken(ctx, c, tenant, clientID, clientSecret, "https://management.azure.com/.default")
	vaultTok := azureSPToken(ctx, c, tenant, clientID, clientSecret, "https://vault.azure.net/.default")
	if armTok == "" || vaultTok == "" {
		return nil
	}
	return azureHarvestVaults(ctx, c, vaultTok, azureListVaultURIs(ctx, c, armTok))
}

// azureListVaultURIs walks subscriptions and returns each Key Vault's data-plane
// URI (https://NAME.vault.azure.net/).
func azureListVaultURIs(ctx context.Context, c *recon.Client, armTok string) []string {
	var uris []string
	for i, sub := range azureSubscriptionIDs(ctx, c, armTok) {
		if i >= azureSubCap {
			break
		}
		u := azureMSALEndpoints.ARM + "/subscriptions/" + url.PathEscape(sub) +
			"/providers/Microsoft.KeyVault/vaults?api-version=" + armVaultListAPIVer
		req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+armTok)
		resp, err := c.Do(req, recon.CallOpts{Note: "keyvault vaults.list (read-only)"})
		if err != nil || resp.DryRun || resp.Status >= 300 {
			continue
		}
		if arr, ok := jsonDecode(resp.Body)["value"].([]any); ok {
			for _, v := range arr {
				vm, _ := v.(map[string]any)
				props, _ := vm["properties"].(map[string]any)
				if uri, _ := props["vaultUri"].(string); uri != "" {
					uris = append(uris, uri)
				}
			}
		}
	}
	return uris
}

func azureSubscriptionIDs(ctx context.Context, c *recon.Client, armTok string) []string {
	req, _ := recon.NewRequest(ctx, http.MethodGet, azureMSALEndpoints.ARM+"/subscriptions?api-version="+armSubListAPIVer, nil)
	req.Header.Set("Authorization", "Bearer "+armTok)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var ids []string
	if arr, ok := jsonDecode(resp.Body)["value"].([]any); ok {
		for _, v := range arr {
			if vm, ok := v.(map[string]any); ok {
				if id, _ := vm["subscriptionId"].(string); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

// azureHarvestVaults lists and reads every secret across the given vault URIs.
func azureHarvestVaults(ctx context.Context, c *recon.Client, vaultTok string, vaults []string) []module.Harvested {
	var out []module.Harvested
	for i, vault := range vaults {
		if i >= azureVaultCap {
			break
		}
		for _, id := range azureListVaultSecretIDs(ctx, c, vaultTok, vault) {
			if len(out) >= azureVaultSecretCap {
				return out
			}
			if v := azureGetVaultSecret(ctx, c, vaultTok, id); v != "" {
				out = append(out, module.Harvested{Label: "azure keyvault:" + id, Value: v})
			}
		}
	}
	return out
}

// azureListVaultSecretIDs returns the secret identifiers in a vault.
func azureListVaultSecretIDs(ctx context.Context, c *recon.Client, vaultTok, vaultURI string) []string {
	u := strings.TrimSuffix(vaultURI, "/") + "/secrets?api-version=" + vaultAPIVersion
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+vaultTok)
	resp, err := c.Do(req, recon.CallOpts{Note: "keyvault secrets.list (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	var ids []string
	if arr, ok := jsonDecode(resp.Body)["value"].([]any); ok {
		for _, v := range arr {
			if vm, ok := v.(map[string]any); ok {
				if id, _ := vm["id"].(string); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

// azureGetVaultSecret reads a secret's current value.
func azureGetVaultSecret(ctx context.Context, c *recon.Client, vaultTok, secretID string) string {
	u := secretID + "?api-version=" + vaultAPIVersion
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+vaultTok)
	resp, err := c.Do(req, recon.CallOpts{Note: "keyvault secret.get (read-only, extracts value)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	v, _ := jsonDecode(resp.Body)["value"].(string)
	return v
}
