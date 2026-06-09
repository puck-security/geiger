package modules

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// Secrets-store harvest for the enterprise secrets managers (Doppler, 1Password
// Connect) plus the offline-only 1Password service-account flag. Gated, like the
// cloud harvesters, on --live --intrusive within the bounded recursion budget.

const (
	dopplerProjectCap = 10
	dopplerConfigCap  = 8
	enterpriseSecCap  = 60 // total secrets pulled per run
	opVaultCap        = 10
	opItemCap         = 60
)

var dopplerTokenRe = regexp.MustCompile(`^dp\.[a-z]{2}\.[A-Za-z0-9]{16,}$`)

// ---- Doppler: read every secret value across reachable projects/configs ----

func dopplerHarvest(ctx context.Context, c *recon.Client, token string) []module.Harvested {
	if token == "" {
		return nil
	}
	var out []module.Harvested
	for i, proj := range dopplerProjects(ctx, c, token) {
		if i >= dopplerProjectCap {
			break
		}
		for j, cfg := range dopplerConfigs(ctx, c, token, proj) {
			if j >= dopplerConfigCap {
				break
			}
			for name, val := range dopplerSecrets(ctx, c, token, proj, cfg) {
				if len(out) >= enterpriseSecCap {
					return out
				}
				out = append(out, module.Harvested{Label: "doppler:" + proj + "/" + cfg + "/" + name, Value: val})
			}
		}
	}
	return out
}

func dopplerGET(ctx context.Context, c *recon.Client, token, path string) []byte {
	req, _ := recon.NewRequest(ctx, http.MethodGet, dopplerAPI+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req, recon.CallOpts{Note: "doppler read (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return resp.Body
}

func dopplerProjects(ctx context.Context, c *recon.Client, token string) []string {
	var names []string
	if arr, ok := jsonDecode(dopplerGET(ctx, c, token, "/v3/projects"))["projects"].([]any); ok {
		for _, p := range arr {
			if m, ok := p.(map[string]any); ok {
				if s, _ := m["slug"].(string); s != "" {
					names = append(names, s)
				}
			}
		}
	}
	return names
}

func dopplerConfigs(ctx context.Context, c *recon.Client, token, project string) []string {
	var names []string
	if arr, ok := jsonDecode(dopplerGET(ctx, c, token, "/v3/configs?project="+project))["configs"].([]any); ok {
		for _, cf := range arr {
			if m, ok := cf.(map[string]any); ok {
				if s, _ := m["name"].(string); s != "" {
					names = append(names, s)
				}
			}
		}
	}
	return names
}

func dopplerSecrets(ctx context.Context, c *recon.Client, token, project, config string) map[string]string {
	body := dopplerGET(ctx, c, token, "/v3/configs/config/secrets?project="+project+"&config="+config)
	secrets, _ := jsonDecode(body)["secrets"].(map[string]any)
	out := map[string]string{}
	for name, v := range secrets {
		if m, ok := v.(map[string]any); ok {
			if val, _ := m["computed"].(string); val != "" {
				out[name] = val
			}
		}
	}
	return out
}

// ---- 1Password Connect: read every item's concealed fields ----

func opConnectHarvest(ctx context.Context, c *recon.Client, base, token string) []module.Harvested {
	if base == "" || token == "" {
		return nil
	}
	var out []module.Harvested
	for i, vault := range opVaultIDs(ctx, c, base, token) {
		if i >= opVaultCap {
			break
		}
		for _, itemID := range opItemIDs(ctx, c, base, token, vault) {
			if len(out) >= opItemCap {
				return out
			}
			for label, val := range opItemSecrets(ctx, c, base, token, vault, itemID) {
				out = append(out, module.Harvested{Label: "1password:" + label, Value: val})
			}
		}
	}
	return out
}

func opGET(ctx context.Context, c *recon.Client, base, token, path string) []byte {
	req, _ := recon.NewRequest(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req, recon.CallOpts{Note: "1password connect read (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return resp.Body
}

func opVaultIDs(ctx context.Context, c *recon.Client, base, token string) []string {
	var ids []string
	if arr, ok := jsonDecodeArray(opGET(ctx, c, base, token, "/v1/vaults")); ok {
		for _, v := range arr {
			if m, ok := v.(map[string]any); ok {
				if id, _ := m["id"].(string); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func opItemIDs(ctx context.Context, c *recon.Client, base, token, vault string) []string {
	var ids []string
	if arr, ok := jsonDecodeArray(opGET(ctx, c, base, token, "/v1/vaults/"+vault+"/items")); ok {
		for _, v := range arr {
			if m, ok := v.(map[string]any); ok {
				if id, _ := m["id"].(string); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

func opItemSecrets(ctx context.Context, c *recon.Client, base, token, vault, item string) map[string]string {
	body := opGET(ctx, c, base, token, "/v1/vaults/"+vault+"/items/"+item)
	d := jsonDecode(body)
	title, _ := d["title"].(string)
	if title == "" {
		title = item
	}
	out := map[string]string{}
	fields, _ := d["fields"].([]any)
	for _, fv := range fields {
		fm, ok := fv.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := fm["type"].(string)
		purpose, _ := fm["purpose"].(string)
		val, _ := fm["value"].(string)
		if val == "" || (typ != "CONCEALED" && purpose != "PASSWORD") {
			continue
		}
		label, _ := fm["label"].(string)
		if label == "" {
			label = purpose
		}
		out[title+"/"+label] = val
	}
	return out
}

// ---- 1Password service account: offline flag only (CLI/SDK transport) ----

type onePasswordSA struct{ module.Base }

func (onePasswordSA) Name() string { return "onepassword_sa" }

func (onePasswordSA) Recon(_ context.Context, _ *recon.Client, _ module.Token, _ module.Fields) ([]module.Finding, error) {
	return []module.Finding{
		{Key: "type", Value: "1Password service-account token (ops_…)", Flag: module.FlagInfo},
		{Key: "reach", Value: "reads every secret in every vault granted to the service account — exercise with `op` CLI / SDK (no plain REST endpoint)", Flag: module.FlagForceMultiplier},
	}, nil
}

func (onePasswordSA) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "1Password service account — vault secret access (CLI/SDK only)"}
}
