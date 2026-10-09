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

// entraSP handles an Entra (Azure AD) service-principal secret: tenant +
// client_id + client_secret. Authenticate mints a Graph token via
// client_credentials; its `roles` claim is the set of application permissions
// granted to the app — the blast radius. Default --live flags dangerous app
// permissions and names the tenant; --azure-intrusive additionally maps the SP's
// Azure RBAC role assignments. --intrusive drains Key Vault (unchanged).
type entraSP struct{}

func (entraSP) Name() string { return "entra_sp" }

func (entraSP) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	tokenURL := fmt.Sprintf(azureMSALEndpoints.TokenTmpl, f["tenant"])
	return auth.ClientCredentials(ctx, c, tokenURL, f["client_id"], f["client_secret"],
		url.Values{"scope": {"https://graph.microsoft.com/.default"}})
}

// entraDangerousAppPerms are application (app-role) permissions that grant tenant
// takeover or broad data access.
var entraDangerousAppPerms = map[string]bool{
	"Directory.ReadWrite.All":            true,
	"Application.ReadWrite.All":          true,
	"AppRoleAssignment.ReadWrite.All":    true,
	"RoleManagement.ReadWrite.Directory": true,
	"Group.ReadWrite.All":                true,
	"GroupMember.ReadWrite.All":          true,
	"User.ReadWrite.All":                 true,
	"User.Export.All":                    true,
	"Mail.Read":                          true,
	"Mail.ReadWrite":                     true,
	"Sites.FullControl.All":              true,
	"full_access_as_app":                 true,
}

func (m entraSP) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{Key: "note", Value: "service-principal app permissions are in the token's roles claim; Directory.ReadWrite.All = tenant takeover", Flag: module.FlagInfo}}

	if t.Bearer != "" {
		// App permissions (application roles) ride in the token's roles claim.
		if _, payload, err := decodeJWT(t.Bearer); err == nil {
			out = append(out, entraAppPermFindings(jsonStringList(payload["roles"]))...)
		}
		// Tenant identity.
		if resp := m.graphGet(ctx, c, t.Bearer, "/organization"); resp != nil && !resp.DryRun && resp.Status < 300 {
			if name := jsonPath(resp.Body, "value.0.displayName"); name != "" {
				out = append(out, module.Finding{Key: "tenant", Value: name, Flag: module.FlagInfo})
			}
		}
	}

	if c.MinFootprint() {
		return out, nil
	}
	// --azure-intrusive: map the SP's Azure RBAC role assignments. The SP's object
	// id is the oid claim of its ARM token.
	if c.AzureIntrusive() {
		armTok := azureSPToken(ctx, c, f["tenant"], f["client_id"], f["client_secret"], "https://management.azure.com/.default")
		if armTok != "" {
			if _, payload, err := decodeJWT(armTok); err == nil {
				if oid, _ := payload["oid"].(string); oid != "" {
					out = append(out, azureRBAC(ctx, c, armTok, oid)...)
				}
			}
		}
	}
	return out, nil
}

func (m entraSP) graphGet(ctx context.Context, c *recon.Client, bearer, path string) *recon.Response {
	req, err := recon.NewRequest(ctx, http.MethodGet, azureMSALEndpoints.Graph+path, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil {
		return nil
	}
	return resp
}

// entraAppPermFindings splits the granted app permissions into dangerous and
// ordinary, emitting a force multiplier for the dangerous set.
func entraAppPermFindings(roles []string) []module.Finding {
	if len(roles) == 0 {
		return nil
	}
	var danger, other []string
	for _, r := range roles {
		if entraDangerousAppPerms[r] {
			danger = append(danger, r)
		} else {
			other = append(other, r)
		}
	}
	var out []module.Finding
	if len(danger) > 0 {
		out = append(out, module.Finding{Key: "app permissions", Value: "privileged: " + strings.Join(danger, ", "), Flag: module.FlagForceMultiplier})
	} else if len(other) > 0 {
		out = append(out, module.Finding{Key: "app permissions", Value: strings.Join(capScopes(other, 12), ", "), Flag: module.FlagWarn})
	}
	return out
}

// Harvest drains Key Vault for the service principal (unchanged, --intrusive).
func (m entraSP) Harvest(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	return azureVaultHarvestSP(ctx, c, f["tenant"], f["client_id"], f["client_secret"]), nil
}

func (entraSP) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "client-credentials token exchange failed"
		return n
	}
	for _, f := range fs {
		if f.Key == "app permissions" && f.Flag == module.FlagForceMultiplier {
			n.Summary = "Entra service principal — privileged app permissions"
			return n
		}
	}
	n.Summary = "Entra service principal"
	return n
}

func init() {
	module.Register(entraSP{})
	module.MapRule("azure-ad-client-secret", "entra_sp")
}
