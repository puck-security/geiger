package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Secret-store coverage beyond Vault/Conjur/CyberArk/Doppler/1Password/Bitwarden:
// Infisical, Delinea (Thycotic) Secret Server, and Akeyless. The shared shape is
// "a credential that reads OTHER credentials" — so recon validates + sizes the
// store and (under --live --intrusive) harvest drains plaintext secret values
// for recursive triage. The high-impact capability is named, never abused.

func init() {
	registerInfisical()
	registerDelineaSecretServer()
	module.Register(akeyless{})
	recognize.RegisterRecognizer(recognizeAkeyless)
}

const secretStoreCap = 60 // total secrets pulled per store per run

// ---- Infisical: machine-identity (Universal Auth) or service token ----

func registerInfisical() {
	add("", r.HTTP{
		ModuleName: "infisical", Base: "{endpoint}", Accept: "application/json", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			if f["client_id"] != "" { // Universal Auth machine identity
				return sessionLogin(ctx, c, f["endpoint"]+"/api/v1/auth/universal-auth/login",
					jsonBody("clientId", f["client_id"], "clientSecret", f["client_secret"]),
					"application/json", "accessToken", "")
			}
			return module.Token{Bearer: f["token"]}, nil // service token (st.)
		},
		Whoami: r.GET("/api/v2/workspace").CountArrayFlag("workspaces", "projects", warnFlag),
		Static: []module.Finding{
			{Key: "reach", Value: "reads plaintext secrets (GET /api/v3/secrets/raw) for every project/environment this identity is authorized for", Flag: fmFlag},
			{Key: "harvest", Value: "secret values are read with a project + environment context — not auto-enumerated here", Flag: cantFlag},
		},
		Summarize: func([]module.Finding) string { return "Infisical — secret-store read across authorized projects" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "INFISICAL_API_URL", "INFISICAL_URL")
		if ep == "" {
			ep = "https://app.infisical.com"
		}
		if id := firstVar(b.Vars, "INFISICAL_CLIENT_ID", "INFISICAL_MACHINE_IDENTITY_CLIENT_ID"); id != "" {
			if sec := firstVar(b.Vars, "INFISICAL_CLIENT_SECRET", "INFISICAL_MACHINE_IDENTITY_CLIENT_SECRET"); sec != "" {
				return []recognize.Match{{Module: "infisical",
					Fields: module.Fields{"client_id": id, "client_secret": sec, "endpoint": ep},
					Secret: sec, Label: "INFISICAL_CLIENT_SECRET"}}
			}
		}
		if tok := firstVar(b.Vars, "INFISICAL_TOKEN", "INFISICAL_SERVICE_TOKEN"); strings.HasPrefix(tok, "st.") {
			return []recognize.Match{{Module: "infisical",
				Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "INFISICAL_TOKEN"}}
		}
		return nil
	})
}

// ---- Delinea / Thycotic Secret Server: OAuth2 password grant → bearer ----

func registerDelineaSecretServer() {
	add("", r.HTTP{
		ModuleName: "delinea_secret_server", Base: "{endpoint}", Accept: "application/json", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.Exchange(ctx, c, f["endpoint"]+"/oauth2/token",
				url.Values{"grant_type": {"password"}, "username": {f["username"]}, "password": {f["password"]}}, nil)
		},
		Whoami: r.GET("/api/v1/secrets?take=1").CountFlag("total", "secrets", warnFlag),
		Static: []module.Finding{{Key: "reach", Value: "reads any authorized secret's fields (GET /api/v1/secrets/{id}) — passwords, keys, and connection strings", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "Delinea/Thycotic Secret Server — vaulted-secret read access"
		},
		Harvest: func(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error) {
			if !c.Live() || !c.Intrusive() {
				return nil, nil
			}
			return delineaHarvest(ctx, c, f["endpoint"], t.Bearer), nil
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "SECRET_SERVER_URL", "DELINEA_URL", "DELINEA_SECRET_SERVER_URL", "THYCOTIC_URL", "THYCOTIC_SECRET_SERVER_URL")
		user := firstVar(b.Vars, "SECRET_SERVER_USERNAME", "DELINEA_USERNAME", "THYCOTIC_USERNAME")
		pass := firstVar(b.Vars, "SECRET_SERVER_PASSWORD", "DELINEA_PASSWORD", "THYCOTIC_PASSWORD")
		if ep == "" || user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "delinea_secret_server",
			Fields: module.Fields{"username": user, "password": pass, "endpoint": ep},
			Secret: pass, Label: "SECRET_SERVER_PASSWORD"}}
	})
}

func delineaHarvest(ctx context.Context, c *recon.Client, base, token string) []module.Harvested {
	get := func(path string) []byte {
		req, _ := recon.NewRequest(ctx, http.MethodGet, base+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req, recon.CallOpts{Note: "delinea secret read (read-only)"})
		if err != nil || resp.DryRun || resp.Status >= 300 {
			return nil
		}
		return resp.Body
	}
	records, _ := jsonDecode(get("/api/v1/secrets?take=" + itoaSS(secretStoreCap)))["records"].([]any)
	var out []module.Harvested
	for _, rec := range records {
		m, _ := rec.(map[string]any)
		id, ok := m["id"].(float64)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		items, _ := jsonDecode(get("/api/v1/secrets/" + itoaSS(int(id))))["items"].([]any)
		for _, it := range items {
			im, _ := it.(map[string]any)
			val, _ := im["itemValue"].(string)
			isPw, _ := im["isPassword"].(bool)
			fn, _ := im["fieldName"].(string)
			if val == "" || (!isPw && !secretFieldName(fn)) {
				continue
			}
			out = append(out, module.Harvested{Label: "delinea:" + name + "/" + fn, Value: val})
			if len(out) >= secretStoreCap {
				return out
			}
		}
	}
	return out
}

// ---- Akeyless: access-id/key → token (token rides in the POST body) ----

type akeyless struct{ module.Base }

func (akeyless) Name() string { return "akeyless" }

func (m akeyless) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	body := jsonBody("access-id", f["access_id"], "access-key", f["access_key"], "access-type", "access_key")
	resp := m.post(ctx, c, f["endpoint"], "/auth", body, "akeyless auth (read-only token exchange)")
	if resp == nil {
		return module.Token{}, errors.New("akeyless: auth request failed")
	}
	if resp.DryRun {
		return module.Token{Bearer: "<dry-run-token>"}, nil
	}
	t, _ := jsonDecode(resp.Body)["token"].(string)
	if t == "" {
		return module.Token{}, errors.New("akeyless: auth returned no token")
	}
	return module.Token{Bearer: t}, nil
}

func (m akeyless) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{
		{Key: "reach", Value: "lists items and reads STATIC_SECRET values (POST /list-items, /get-secret-value) per the auth role's access rules", Flag: fmFlag},
	}
	if t.Bearer == "" || t.Bearer == "<dry-run-token>" {
		return out, nil
	}
	resp := m.post(ctx, c, f["endpoint"], "/list-items", jsonBody2("token", t.Bearer), "akeyless list-items (read-only)")
	if resp != nil && !resp.DryRun && resp.Status < 300 {
		if items, ok := jsonDecode(resp.Body)["items"].([]any); ok && len(items) > 0 {
			out = append([]module.Finding{{Key: "items", Value: itoaSS(len(items)), Flag: module.FlagInfo}}, out...)
		}
	}
	return out, nil
}

func (m akeyless) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "Akeyless — secret-store read (list-items / get-secret-value)"}
}

func (m akeyless) Harvest(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() || t.Bearer == "" {
		return nil, nil
	}
	items, ok := jsonDecode(okBody(m.post(ctx, c, f["endpoint"], "/list-items", jsonBody2("token", t.Bearer), "akeyless list-items (read-only)")))["items"].([]any)
	if !ok {
		return nil, nil
	}
	var names []string
	for _, it := range items {
		im, _ := it.(map[string]any)
		if tp, _ := im["item_type"].(string); tp != "STATIC_SECRET" {
			continue
		}
		if name, _ := im["item_name"].(string); name != "" {
			names = append(names, name)
		}
		if len(names) >= secretStoreCap {
			break
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	nb, _ := json.Marshal(map[string]any{"token": t.Bearer, "names": names})
	vals := jsonDecode(okBody(m.post(ctx, c, f["endpoint"], "/get-secret-value", nb, "akeyless get-secret-value (read-only)")))
	var out []module.Harvested
	for name, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, module.Harvested{Label: "akeyless:" + name, Value: s})
		}
	}
	return out, nil
}

func (akeyless) post(ctx context.Context, c *recon.Client, base, path string, body []byte, note string) *recon.Response {
	req, err := recon.NewRequest(ctx, http.MethodPost, base+path, body)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: note})
	if err != nil {
		return nil
	}
	return resp
}

// okBody returns a response's body only when it's a live, successful read.
func okBody(resp *recon.Response) []byte {
	if resp == nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	return resp.Body
}

func recognizeAkeyless(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	id := firstVar(b.Vars, "AKEYLESS_ACCESS_ID")
	key := firstVar(b.Vars, "AKEYLESS_ACCESS_KEY")
	if id == "" || key == "" {
		return nil
	}
	ep := resolveEndpoint(b, endpoint, "AKEYLESS_API_URL", "AKEYLESS_GATEWAY_URL", "AKEYLESS_URL")
	if ep == "" {
		ep = "https://api.akeyless.io"
	}
	return []recognize.Match{{Module: "akeyless",
		Fields: module.Fields{"access_id": id, "access_key": key, "endpoint": ep},
		Secret: key, Label: "AKEYLESS_ACCESS_KEY"}}
}

// secretFieldName reports whether a Delinea field name names a secret value.
func secretFieldName(fn string) bool {
	fn = strings.ToLower(fn)
	for _, s := range []string{"password", "key", "token", "secret", "connection", "private"} {
		if strings.Contains(fn, s) {
			return true
		}
	}
	return false
}

// jsonBody2 is jsonBody for a single pair (kept explicit for the token-only body).
func jsonBody2(k, v string) []byte { return jsonBody(k, v) }

func itoaSS(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
