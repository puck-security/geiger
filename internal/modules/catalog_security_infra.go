package modules

import (
	"context"
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

// Security platforms (read the whole security graph / logs) and PaaS deploy
// APIs (deploy = code execution + access to app secrets).

func init() {
	registerSumoLogic()
	registerLacework()
	registerWiz()
	registerTailscale()
	registerRender()
	registerRailway()
	registerFlyio()
}

// --- Sumo Logic: HTTP Basic accessId:accessKey, region host ---

func registerSumoLogic() {
	add("", r.HTTP{
		ModuleName: "sumologic", Endpoint: saasOnly("sumologic.com"), Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Basic, UserField: "access_id", PassField: "access_key"},
		Whoami:    r.GET("/api/v1/users?limit=1").CountArrayFlag("data", "users (PII)", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "search all ingested logs (routinely contain secrets, tokens, and PII) and manage collectors/users", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Sumo Logic — log search (secrets/PII) + collector admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "SUMO_ACCESS_ID", "SUMOLOGIC_ACCESS_ID", "SUMOLOGIC_ACCESSID")
		key := firstVar(b.Vars, "SUMO_ACCESS_KEY", "SUMOLOGIC_ACCESS_KEY", "SUMOLOGIC_ACCESSKEY")
		if id == "" || key == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "SUMO_URL", "SUMOLOGIC_URL", "SUMO_ENDPOINT")
		if ep == "" {
			ep = "https://api.sumologic.com"
		}
		return []recognize.Match{{Module: "sumologic", Fields: module.Fields{"access_id": id, "access_key": key, "endpoint": ep}, Secret: key, Label: "SUMOLOGIC_ACCESS_KEY"}}
	})
}

// --- Lacework: keyId + secret → temp token (X-LW-UAKS header) → bearer ---

func registerLacework() {
	add("", r.HTTP{
		ModuleName: "lacework", Endpoint: saasOnly("lacework.net"), Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			req, err := recon.NewRequest(ctx, http.MethodPost, f["endpoint"]+"/api/v2/access/tokens",
				[]byte(`{"keyId":`+jsonQuote(f["key_id"])+`,"expiryTime":3600}`))
			if err != nil {
				return module.Token{}, err
			}
			req.Header.Set("X-LW-UAKS", f["secret"])
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "Lacework token (read-only)"})
			if err != nil {
				return module.Token{}, err
			}
			if resp.DryRun {
				return module.Token{Bearer: "<dry-run-token>"}, nil
			}
			if resp.Status < 200 || resp.Status >= 300 {
				return module.Token{}, errStatus(resp.Status)
			}
			return module.Token{Bearer: jsonPath(resp.Body, "token")}, nil
		},
		Whoami:    r.GET("/api/v2/UserProfile").Field("account", "data.0.orgAccountName"),
		Static:    []module.Finding{{Key: "reach", Value: "read cloud security posture, compliance, alerts, and vulnerabilities across all connected cloud accounts; admin manages integrations", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Lacework — cloud security posture across connected accounts" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "LACEWORK_API_KEY", "LW_API_KEY")
		secret := firstVar(b.Vars, "LACEWORK_API_SECRET", "LW_API_SECRET")
		if key == "" || secret == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "LACEWORK_URL", "LW_URL")
		if ep == "" {
			if acct := firstVar(b.Vars, "LACEWORK_ACCOUNT", "LW_ACCOUNT"); acct != "" {
				ep = "https://" + acct + ".lacework.net"
			}
		}
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "lacework", Fields: module.Fields{"key_id": key, "secret": secret, "endpoint": ep}, Secret: secret, Label: "LACEWORK_API_SECRET"}}
	})
}

// --- Wiz: OAuth client_credentials → GraphQL API ---

func registerWiz() {
	add("", r.HTTP{
		ModuleName: "wiz", Endpoint: saasOnly("wiz.io"), Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			au := f["auth_url"]
			if au == "" {
				au = "https://auth.app.wiz.io/oauth/token"
			}
			return auth.ClientCredentials(ctx, c, au, f["client_id"], f["client_secret"], url.Values{"audience": {"wiz-api"}})
		},
		// A schema-agnostic GraphQL query validates the token + endpoint.
		Whoami: r.Call{Method: "POST", Path: "", ReadOnlyPOST: true,
			Body:   `{"query":"query{__typename}"}`,
			Fields: []r.Extract{{Key: "graphql", Path: "data.__typename"}}},
		Static:    []module.Finding{{Key: "reach", Value: "read the full cloud security graph — findings, exposures, identities, and stored secrets/keys across the environment", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Wiz — cloud security graph (findings, identities, secrets)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "WIZ_CLIENT_ID")
		secret := firstVar(b.Vars, "WIZ_CLIENT_SECRET")
		ep := resolveEndpoint(b, endpoint, "WIZ_API_URL", "WIZ_URL")
		if id == "" || secret == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "wiz",
			Fields: module.Fields{"client_id": id, "client_secret": secret, "endpoint": ep, "auth_url": firstVar(b.Vars, "WIZ_AUTH_URL")},
			Secret: secret, Label: "WIZ_CLIENT_SECRET"}}
	})
}

// --- Tailscale: API key (tskey-api-…) bearer ---

func registerTailscale() {
	add("", r.HTTP{
		ModuleName: "tailscale", Base: "https://api.tailscale.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/api/v2/tailnet/-/devices").CountArrayFlag("devices", "devices (network nodes)", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "manage the tailnet — read all devices, edit ACLs, and mint auth keys to enroll attacker-controlled nodes into the private network", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Tailscale — tailnet device/ACL admin + auth-key minting" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "TAILSCALE_API_KEY", "TS_API_KEY", "TAILSCALE_APIKEY")
		if tok == "" { // value-prefix: API keys are tskey-api-…
			for _, v := range b.Vars {
				if strings.HasPrefix(v, "tskey-api-") {
					tok = v
					break
				}
			}
		}
		if tok == "" {
			return nil
		}
		return []recognize.Match{{Module: "tailscale", Fields: module.Fields{"token": tok}, Secret: tok, Label: "TAILSCALE_API_KEY"}}
	})
}

// --- Render (PaaS): bearer; deploy = code execution + env secrets ---

func registerRender() {
	add("", r.HTTP{
		ModuleName: "render", Base: "https://api.render.com/v1", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/services?limit=1").FlagField("services", "0.service.id", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "trigger deploys (run arbitrary build/start commands) and read env-group secrets — code execution + secret access", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Render — deploy (code exec) + env-secret access" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "RENDER_API_KEY", "RENDER_TOKEN"); k != "" {
			return []recognize.Match{{Module: "render", Fields: module.Fields{"token": k}, Secret: k, Label: "RENDER_API_KEY"}}
		}
		return nil
	})
}

// --- Railway (PaaS): GraphQL bearer ---

func registerRailway() {
	add("", r.HTTP{
		ModuleName: "railway", Base: "https://backboard.railway.app", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "POST", Path: "/graphql/v2", ReadOnlyPOST: true,
			Body:   `{"query":"query{me{email}}"}`,
			Fields: []r.Extract{{Key: "user", Path: "data.me.email"}}},
		Static:    []module.Finding{{Key: "reach", Value: "deploy services (arbitrary code) and read project/service variables (secrets) — code execution + secret access", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Railway — deploy (code exec) + project-variable access" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "RAILWAY_TOKEN", "RAILWAY_API_TOKEN"); k != "" {
			return []recognize.Match{{Module: "railway", Fields: module.Fields{"token": k}, Secret: k, Label: "RAILWAY_TOKEN"}}
		}
		return nil
	})
}

// --- Fly.io (PaaS): GraphQL bearer ---

func registerFlyio() {
	add("", r.HTTP{
		ModuleName: "flyio", Base: "https://api.fly.io", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "POST", Path: "/graphql", ReadOnlyPOST: true,
			Body:   `{"query":"query{viewer{email}}"}`,
			Fields: []r.Extract{{Key: "user", Path: "data.viewer.email"}}},
		Static:    []module.Finding{{Key: "reach", Value: "deploy machines (run arbitrary containers) and read app secrets — code execution + secret access", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Fly.io — machine deploy (code exec) + app-secret access" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "FLYCTL_ACCESS_TOKEN"); k != "" {
			return []recognize.Match{{Module: "flyio", Fields: module.Fields{"token": k}, Secret: k, Label: "FLY_API_TOKEN"}}
		}
		return nil
	})
}
