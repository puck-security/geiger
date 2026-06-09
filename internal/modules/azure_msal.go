package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// azureMSALEndpoints are overridable in tests.
var azureMSALEndpoints = struct{ TokenTmpl, Graph, ARM string }{
	TokenTmpl: "https://login.microsoftonline.com/%s/oauth2/v2.0/token",
	Graph:     "https://graph.microsoft.com/v1.0",
	ARM:       "https://management.azure.com",
}

// azureMSAL triages an `az` CLI / MSAL token cache (~/.azure/msal_token_cache.json):
// a cached Entra access-token JWT plus a refresh token for the public `az`
// client. The refresh token mints a fresh Graph token with no client secret
// (public client), so the session can be exercised headlessly.
type azureMSAL struct{}

func (azureMSAL) Name() string { return "azure_msal" }

func tenantOf(f module.Fields) string {
	realm := f["tenant"]
	if realm != "" && realm != "organizations" && realm != "common" {
		return realm
	}
	// fall back to the tid claim of the cached access token
	if _, payload, err := decodeJWT(f["access_token"]); err == nil {
		if tid, _ := payload["tid"].(string); tid != "" {
			return tid
		}
	}
	return "organizations"
}

func (m azureMSAL) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	// Prefer a refresh-token exchange (public client → reliable Graph token).
	if rt := f["refresh_token"]; rt != "" && f["client_id"] != "" {
		tokenURL := fmt.Sprintf(azureMSALEndpoints.TokenTmpl, tenantOf(f))
		tok, err := auth.RefreshToken(ctx, c, tokenURL, f["client_id"], "", rt,
			url.Values{"scope": {"https://graph.microsoft.com/.default offline_access"}})
		if err == nil && tok.Bearer != "" {
			return tok, nil
		}
	}
	// Otherwise use the cached access token directly (works while it's live).
	if at := f["access_token"]; at != "" {
		return module.Token{Bearer: at}, nil
	}
	return module.Token{}, nil
}

func (m azureMSAL) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding

	// Offline: decode the cached access-token JWT for identity/tenant/expiry.
	if _, payload, err := decodeJWT(f["access_token"]); err == nil {
		if upn := firstClaim(payload, "upn", "unique_name", "preferred_username"); upn != "" {
			out = append(out, module.Finding{Key: "user", Value: upn, Flag: module.FlagInfo})
		} else if u := f["username"]; u != "" {
			out = append(out, module.Finding{Key: "user", Value: u, Flag: module.FlagInfo})
		}
		if tid, _ := payload["tid"].(string); tid != "" {
			out = append(out, module.Finding{Key: "tenant", Value: tid, Flag: module.FlagInfo})
		}
		if roles := claimString(payload["roles"]); roles != "" {
			out = append(out, module.Finding{Key: "app roles", Value: roles, Flag: module.FlagWarn})
		}
		if exp, ok := claimTime(payload["exp"]); ok {
			v := exp.UTC().Format("2006-01-02 15:04Z")
			flag := module.FlagInfo
			if time.Now().After(exp) {
				v += "  (cached token EXPIRED — refresh token still usable)"
			} else {
				v += "  (live)"
			}
			out = append(out, module.Finding{Key: "cached token", Value: v, Flag: flag})
		}
	} else if u := f["username"]; u != "" {
		out = append(out, module.Finding{Key: "user", Value: u, Flag: module.FlagInfo})
	}

	// Intune (device management) rides on the same Graph token; a token scoped
	// to managed devices can remotely wipe them. Detect offline from the scopes.
	if intuneScoped(f) {
		out = append(out, module.Finding{Key: "intune",
			Value: "token carries Intune device-management scope — POST /deviceManagement/managedDevices/{id}/wipe is a remote device wipe (retire / passcode reset too)",
			Flag:  module.FlagForceMultiplier})
	}

	if t.Bearer == "" || !c.Live() {
		return out, nil
	}

	// Live: who the token is, the tenant, and ARM control-plane reach.
	out = append(out, m.graphGet(ctx, c, t.Bearer, "/me", "identity", "displayName")...)
	out = append(out, m.graphGet(ctx, c, t.Bearer, "/organization", "tenant name", "value.0.displayName")...)
	if n, ok := m.subscriptions(ctx, c, t.Bearer); ok {
		out = append(out, module.Finding{Key: "azure subscriptions", Value: strconv.Itoa(n) + " (cloud control plane)", Flag: module.FlagWarn})
	}
	return out, nil
}

func (m azureMSAL) graphGet(ctx context.Context, c *recon.Client, bearer, path, key, field string) []module.Finding {
	req, _ := recon.NewRequest(ctx, http.MethodGet, azureMSALEndpoints.Graph+path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	if v := jsonPath(resp.Body, field); v != "" {
		return []module.Finding{{Key: key, Value: v, Flag: module.FlagInfo}}
	}
	return nil
}

func (m azureMSAL) subscriptions(ctx context.Context, c *recon.Client, bearer string) (int, bool) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, azureMSALEndpoints.ARM+"/subscriptions?api-version=2020-01-01", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return 0, false
	}
	if arr, ok := jsonDecode(resp.Body)["value"].([]any); ok {
		return len(arr), true
	}
	return 0, false
}

func (azureMSAL) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "no usable token in MSAL cache"
		return n
	}
	n.Summary = "Azure CLI session — Entra identity, refreshable headlessly"
	return n
}

// intuneScoped reports whether the cached token's scopes (cache target plus the
// access token's scp/roles claims) grant Intune device management.
func intuneScoped(f module.Fields) bool {
	hay := f["scopes"]
	if _, payload, err := decodeJWT(f["access_token"]); err == nil {
		hay += " " + claimString(payload["scp"]) + " " + claimString(payload["roles"])
	}
	return strings.Contains(hay, "DeviceManagement")
}

func firstClaim(p map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := p[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// jsonPath is a tiny dotted-path string getter (a.b.0.c) for module use.
func jsonPath(body []byte, path string) string {
	var v any
	d := jsonDecode(body)
	v = d
	for _, seg := range strings.Split(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			v = node[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return ""
			}
			v = node[i]
		default:
			return ""
		}
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func recognizeAzureMSAL(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	at, _ := b.JSON["AccessToken"].(map[string]any)
	rt, _ := b.JSON["RefreshToken"].(map[string]any)
	if at == nil && rt == nil {
		return nil
	}
	f := module.Fields{}
	for _, v := range at {
		e, _ := v.(map[string]any)
		f["access_token"], _ = e["secret"].(string)
		f["tenant"], _ = e["realm"].(string)
		f["scopes"], _ = e["target"].(string)
		f["client_id"], _ = e["client_id"].(string)
		break
	}
	for _, v := range rt {
		e, _ := v.(map[string]any)
		f["refresh_token"], _ = e["secret"].(string)
		if f["client_id"] == "" {
			f["client_id"], _ = e["client_id"].(string)
		}
		break
	}
	if acct, _ := b.JSON["Account"].(map[string]any); acct != nil {
		for _, v := range acct {
			e, _ := v.(map[string]any)
			f["username"], _ = e["username"].(string)
			break
		}
	}
	secret := f["refresh_token"]
	if secret == "" {
		secret = f["access_token"]
	}
	return []recognize.Match{{Module: "azure_msal", Fields: f, Secret: secret, Label: "Azure MSAL cache"}}
}

func init() {
	module.Register(azureMSAL{})
	recognize.RegisterRecognizer(recognizeAzureMSAL)
}
