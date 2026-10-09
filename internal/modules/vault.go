package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// vaultKey characterizes a HashiCorp Vault token. lookup-self gives the token's
// policies (the root policy is total compromise); --vault-intrusive inventories
// the secret-engine mounts and probes the token's read/list capability on them,
// which is the real secrets-store reach.
type vaultKey struct{ module.Base }

func (vaultKey) Name() string { return "vault" }

func (vaultKey) EndpointPolicy() module.EndpointPolicy { return selfHosted }

func (m vaultKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	base := f["endpoint"]
	if base == "" {
		return nil, nil // self-hosted: pipeline emits a "set --endpoint" note
	}
	tok := f["token"]
	var out []module.Finding
	lv := &liveness{}

	if resp := m.get(ctx, c, base, "/v1/auth/token/lookup-self", nil, tok); resp != nil {
		lv.observe(resp, nil, true)
		if !resp.DryRun && resp.Status < 300 {
			d := jsonDecode(resp.Body)
			data, _ := d["data"].(map[string]any)
			if dn, _ := data["display_name"].(string); dn != "" {
				out = append(out, module.Finding{Key: "token", Value: dn, Flag: module.FlagInfo})
			}
			policies := jsonStringList(data["policies"])
			if len(policies) > 0 {
				flag := module.FlagWarn
				if containsStr(policies, "root") {
					flag = module.FlagForceMultiplier
				}
				out = append(out, module.Finding{Key: "policies", Value: strings.Join(policies, ", "), Flag: flag})
			}
		}
	}

	if c.MinFootprint() {
		return withLiveness(out, 0, lv), nil
	}
	if c.VaultIntrusive() {
		out = append(out, m.deepReach(ctx, c, base, tok)...)
	}
	return withLiveness(out, 0, lv), nil
}

func (m vaultKey) get(ctx context.Context, c *recon.Client, base, path string, body []byte, tok string) *recon.Response {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := recon.NewRequest(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Vault-Token", tok)
	opts := recon.CallOpts{Note: "vault " + path + " (read-only)"}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		opts.ReadOnlyPOST = true // capabilities-self is a read, expressed as POST
	}
	resp, err := c.Do(req, opts)
	if err != nil {
		return nil
	}
	return resp
}

// deepReach inventories secret-engine mounts and probes read/list capability on
// them — what secrets the token can actually reach.
func (m vaultKey) deepReach(ctx context.Context, c *recon.Client, base, tok string) []module.Finding {
	mounts := m.mountPaths(ctx, c, base, tok)
	var out []module.Finding
	if len(mounts) > 0 {
		shown := mounts
		if len(shown) > 10 {
			shown = shown[:10]
		}
		out = append(out, module.Finding{Key: "mounts", Value: strconv.Itoa(len(mounts)) + " secret engines: " + strings.Join(shown, ", "), Flag: module.FlagWarn})
	}
	if readable := m.readablePaths(ctx, c, base, tok, mounts); len(readable) > 0 {
		out = append(out, module.Finding{
			Key:   "secrets reach",
			Value: "can read/list: " + strings.Join(readable, ", "),
			Flag:  module.FlagForceMultiplier,
		})
	}
	return out
}

// mountPaths lists the secret-engine mount paths, excluding Vault's built-ins.
func (m vaultKey) mountPaths(ctx context.Context, c *recon.Client, base, tok string) []string {
	resp := m.get(ctx, c, base, "/v1/sys/mounts", nil, tok)
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	d := jsonDecode(resp.Body)
	// Mounts may be at the top level or under "data" depending on Vault version.
	src := d
	if data, ok := d["data"].(map[string]any); ok {
		src = data
	}
	var paths []string
	for path := range src {
		switch strings.TrimSuffix(path, "/") {
		case "sys", "identity", "cubbyhole":
			continue
		}
		if mm, ok := src[path].(map[string]any); ok {
			if _, hasType := mm["type"]; hasType {
				paths = append(paths, path)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// readablePaths probes capabilities-self on the mount paths and returns those the
// token can read or list.
func (m vaultKey) readablePaths(ctx context.Context, c *recon.Client, base, tok string, mounts []string) []string {
	if len(mounts) == 0 {
		return nil
	}
	probe := mounts
	if len(probe) > 15 {
		probe = probe[:15]
	}
	body, _ := json.Marshal(map[string][]string{"paths": probe})
	resp := m.get(ctx, c, base, "/v1/sys/capabilities-self", body, tok)
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	d := jsonDecode(resp.Body)
	var readable []string
	for _, p := range probe {
		caps := jsonStringList(d[p])
		if containsStr(caps, "read") || containsStr(caps, "list") || containsStr(caps, "root") || containsStr(caps, "sudo") {
			readable = append(readable, p)
		}
	}
	return readable
}

func (vaultKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "Vault token lookup-self failed (revoked or expired)"
		return n
	}
	for _, f := range fs {
		if f.Key == "policies" && strings.Contains(f.Value, "root") {
			n.Summary = "Vault root token — total compromise"
			return n
		}
	}
	for _, f := range fs {
		if f.Key == "secrets reach" {
			n.Summary = "Vault token — secrets-store reach"
			return n
		}
	}
	n.Summary = "Vault token"
	return n
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func init() {
	module.Register(vaultKey{})
	module.MapRule("vault-service-token", "vault")
	module.MapRule("vault-batch-token", "vault")
}
