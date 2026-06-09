package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// CyberArk: PVWA/Privilege Cloud logon (helper for the recipe module) and Conjur
// (a hand-written module — it exchanges a long-lived API key for a short-lived
// token, uses the non-standard `Token token="..."` header, and harvests secrets).

// cyberArkLogon authenticates against PVWA and returns the raw session token
// (the body is a quoted JSON string), attached to subsequent calls verbatim.
func cyberArkLogon(ctx context.Context, c *recon.Client, base, user, pass string) (module.Token, error) {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	u := strings.TrimRight(base, "/") + "/PasswordVault/API/Auth/CyberArk/Logon"
	req, err := recon.NewRequest(ctx, http.MethodPost, u, body)
	if err != nil {
		return module.Token{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "cyberark logon (session token)"})
	if err != nil {
		return module.Token{}, err
	}
	if resp.DryRun {
		return module.Token{Bearer: "<dry-run-token>"}, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return module.Token{}, errStatus(resp.Status)
	}
	tok := strings.Trim(strings.TrimSpace(string(resp.Body)), `"`)
	if tok == "" {
		return module.Token{}, fmt.Errorf("cyberark: empty session token")
	}
	return module.Token{Bearer: tok}, nil
}

// ---- CyberArk Conjur (OSS / Enterprise / Cloud secrets manager) ----

type conjur struct{}

func (conjur) Name() string { return "conjur" }

// Authenticate exchanges the long-lived API key for a short-lived access token
// (base64, ~8 min TTL) via the authn endpoint.
func (conjur) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	u := strings.TrimRight(f["endpoint"], "/") + "/authn/" + url.PathEscape(f["account"]) + "/" + url.PathEscape(f["login"]) + "/authenticate"
	req, err := recon.NewRequest(ctx, http.MethodPost, u, []byte(f["api_key"]))
	if err != nil {
		return module.Token{}, err
	}
	req.Header.Set("Accept-Encoding", "base64") // ask for the ready-to-use base64 token
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "conjur authenticate (API key → access token)"})
	if err != nil {
		return module.Token{}, err
	}
	if resp.DryRun {
		return module.Token{Bearer: "<dry-run-token>"}, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return module.Token{}, errStatus(resp.Status)
	}
	tok := strings.TrimSpace(string(resp.Body))
	if tok == "" {
		return module.Token{}, fmt.Errorf("conjur: empty access token")
	}
	return module.Token{Bearer: tok}, nil
}

func conjurAuthHeader(tok string) string { return `Token token="` + tok + `"` }

func (m conjur) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding
	account := f["account"]

	// whoami: who is this token / role.
	req, _ := recon.NewRequest(ctx, http.MethodGet, strings.TrimRight(f["endpoint"], "/")+"/whoami", nil)
	req.Header.Set("Authorization", conjurAuthHeader(t.Bearer))
	if resp, err := c.Do(req, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
		d := jsonDecode(resp.Body)
		if u, _ := d["username"].(string); u != "" {
			out = append(out, module.Finding{Key: "role", Value: u, Flag: module.FlagInfo})
		}
		if a, _ := d["account"].(string); a != "" {
			account = a
			out = append(out, module.Finding{Key: "account", Value: a, Flag: module.FlagInfo})
		}
	}

	if c.MinFootprint() {
		return out, nil
	}

	// size the secret blast radius (count of reachable variables).
	cu := strings.TrimRight(f["endpoint"], "/") + "/resources/" + url.PathEscape(account) + "?kind=variable&count=true"
	creq, _ := recon.NewRequest(ctx, http.MethodGet, cu, nil)
	creq.Header.Set("Authorization", conjurAuthHeader(t.Bearer))
	if resp, err := c.Do(creq, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
		if n, ok := jsonDecode(resp.Body)["count"].(float64); ok {
			out = append(out, module.Finding{Key: "secrets in reach", Value: strconv.Itoa(int(n)) + " variables", Flag: module.FlagForceMultiplier})
		}
	}
	return out, nil
}

// Harvest reads the values of every reachable Conjur variable (gated).
func (m conjur) Harvest(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	account := f["account"]
	ids := conjurVariableIDs(ctx, c, f["endpoint"], account, t.Bearer)
	var out []module.Harvested
	for _, id := range ids {
		if len(out) >= enterpriseSecCap {
			break
		}
		if v := conjurSecret(ctx, c, f["endpoint"], account, id, t.Bearer); v != "" {
			out = append(out, module.Harvested{Label: "conjur:" + id, Value: v})
		}
	}
	return out, nil
}

func conjurVariableIDs(ctx context.Context, c *recon.Client, base, account, tok string) []string {
	u := strings.TrimRight(base, "/") + "/resources/" + url.PathEscape(account) + "?kind=variable&limit=200"
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", conjurAuthHeader(tok))
	resp, err := c.Do(req, recon.CallOpts{Note: "conjur list variables (read-only)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	arr, _ := jsonDecodeArray(resp.Body)
	var ids []string
	for _, v := range arr {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// resource id is "account:variable:the/name"; we want the trailing id.
		full, _ := m["id"].(string)
		if i := strings.LastIndex(full, ":"); i >= 0 && i+1 < len(full) {
			ids = append(ids, full[i+1:])
		}
	}
	return ids
}

func conjurSecret(ctx context.Context, c *recon.Client, base, account, id, tok string) string {
	u := strings.TrimRight(base, "/") + "/secrets/" + url.PathEscape(account) + "/variable/" + url.PathEscape(id)
	req, _ := recon.NewRequest(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", conjurAuthHeader(tok))
	resp, err := c.Do(req, recon.CallOpts{Note: "conjur read secret (read-only, extracts value)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	return strings.TrimSpace(string(resp.Body))
}

func (conjur) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "API key exchange or /whoami failed"
		return n
	}
	n.Summary = "CyberArk Conjur — secrets-manager access (reads downstream secret values)"
	return n
}

func recognizeConjur(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	key := firstVar(b.Vars, "CONJUR_AUTHN_API_KEY")
	login := firstVar(b.Vars, "CONJUR_AUTHN_LOGIN")
	account := firstVar(b.Vars, "CONJUR_ACCOUNT")
	base := endpoint
	if base == "" {
		base = firstVar(b.Vars, "CONJUR_APPLIANCE_URL", "CONJUR_URL")
	}
	if key == "" || login == "" || account == "" || base == "" {
		return nil
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasSuffix(base, "/api") && !strings.Contains(base, "secretsmgr.cyberark.cloud") {
		// OSS/Enterprise appliances serve the API under /api; Cloud does not.
		base += "/api"
	}
	return []recognize.Match{{Module: "conjur",
		Fields: module.Fields{"endpoint": base, "api_key": key, "login": login, "account": account},
		Secret: key, Label: "CONJUR_AUTHN_API_KEY", Line: b.Lines["CONJUR_AUTHN_API_KEY"]}}
}

func init() {
	module.Register(conjur{})
	recognize.RegisterRecognizer(recognizeConjur)
}
