package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Enterprise IdP / SaaS / secrets-store modules. These are the high-value
// systems a responder cares about when a dev laptop or CI secret is exposed:
// an IdP token is identity-takeover, a secrets-manager token drains everything
// downstream. Most have no gitleaks rule and opaque token shapes, so they're
// recognized by environment-variable name (and instance/tenant host).

// global API hosts (package vars so tests can point them at httptest)
var (
	confluentAPI = "https://api.confluent.cloud"
	jumpcloudAPI = "https://console.jumpcloud.com/api"
	dopplerAPI   = "https://api.doppler.com"
)

func init() {
	registerServiceNow()
	registerSailPoint()
	registerWorkday()
	registerConfluent()
	registerJumpCloud()
	registerDoppler()
	registerOnePassword()
	registerPingOne()
	registerCyberArkPVWA()
}

// ---- ServiceNow: instance-scoped, HTTP Basic service-account user:pass ----
func registerServiceNow() {
	add("", r.HTTP{
		ModuleName: "servicenow", Endpoint: saasOnly("service-now.com", "servicenow.com"), Base: "{endpoint}",
		Auth:   r.AuthSpec{Kind: r.Basic, UserField: "username", PassField: "password"},
		Accept: "application/json",
		Whoami: r.GET("/api/now/ui/user/current_user").
			Field("user", "result.user_name").Field("name", "result.name").Field("email", "result.email"),
		Static: []module.Finding{{Key: "reach", Value: "generic Table API can enumerate sys_user (org-wide PII) and any business table the account's roles allow", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, reg *module.Registry) []recognize.Match {
		inst := firstVar(b.Vars, "SERVICENOW_INSTANCE", "SN_INSTANCE")
		user := firstVar(b.Vars, "SERVICENOW_USERNAME", "SN_USERNAME", "SN_USER")
		pass := firstVar(b.Vars, "SERVICENOW_PASSWORD", "SN_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		base := endpoint
		if base == "" && inst != "" {
			base = serviceNowBase(inst)
		}
		if base == "" {
			return nil
		}
		return []recognize.Match{{Module: "servicenow",
			Fields: module.Fields{"endpoint": base, "username": user, "password": pass},
			Secret: pass, Label: "SERVICENOW_PASSWORD", Line: b.Lines["SERVICENOW_PASSWORD"]}}
	})
}

func serviceNowBase(inst string) string {
	inst = strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(inst, "https://"), "http://"), "/")
	if strings.Contains(inst, ".") {
		return "https://" + inst
	}
	return "https://" + inst + ".service-now.com"
}

// ---- SailPoint Identity Security Cloud: PAT client_credentials → bearer ----
func registerSailPoint() {
	add("", r.HTTP{
		ModuleName: "sailpoint", Endpoint: saasOnly("identitynow.com", "sailpoint.com"), Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.ClientCredentials(ctx, c, f["endpoint"]+"/oauth/token", f["client_id"], f["client_secret"], url.Values{})
		},
		Whoami: r.GET("/oauth/info").Field("user", "user_name").Field("org", "org").Field("pod", "pod").
			Signal(r.Signal{Path: "authorities", Contains: "ORG_ADMIN", Key: "privilege",
				Value: "ORG_ADMIN — read every identity, account, and connected source in the org", Flag: fmFlag}),
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "SAIL_CLIENT_ID", "SAILPOINT_CLIENT_ID")
		secret := firstVar(b.Vars, "SAIL_CLIENT_SECRET", "SAILPOINT_CLIENT_SECRET")
		if id == "" || secret == "" {
			return nil
		}
		base := firstVar(b.Vars, "SAIL_BASE_URL", "SAILPOINT_BASE_URL")
		if base == "" {
			if t := firstVar(b.Vars, "SAILPOINT_TENANT", "SAIL_TENANT"); t != "" {
				base = "https://" + t + ".api.identitynow.com"
			}
		}
		if endpoint != "" {
			base = endpoint
		}
		if base == "" {
			return nil
		}
		return []recognize.Match{{Module: "sailpoint",
			Fields: module.Fields{"endpoint": strings.TrimRight(base, "/"), "client_id": id, "client_secret": secret},
			Secret: secret, Label: "SAILPOINT_CLIENT_SECRET", Line: b.Lines["SAIL_CLIENT_SECRET"]}}
	})
}

// ---- Workday: ISU client_credentials → bearer; no clean whoami, probe workers ----
func registerWorkday() {
	add("", r.HTTP{
		ModuleName: "workday", Endpoint: saasOnly("workday.com", "myworkday.com"), Base: "{host}/ccx/api/v1/{tenant}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.ClientCredentials(ctx, c, f["host"]+"/ccx/oauth2/"+f["tenant"]+"/token", f["client_id"], f["client_secret"], url.Values{})
		},
		// Workday has no /me; /workers both validates the token and sizes reach.
		Whoami: r.GET("/workers?limit=1").CountFrom("total", "workers (full directory)"),
		Static: []module.Finding{{Key: "reach", Value: "read the worker directory — names, work email, title, org; PII/comp depending on granted scopes", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		host := firstVar(b.Vars, "WORKDAY_HOST", "WORKDAY_BASE_URL")
		tenant := firstVar(b.Vars, "WORKDAY_TENANT")
		id := firstVar(b.Vars, "WORKDAY_CLIENT_ID")
		secret := firstVar(b.Vars, "WORKDAY_CLIENT_SECRET")
		if host == "" || tenant == "" || id == "" || secret == "" {
			return nil
		}
		host = strings.TrimRight(host, "/")
		if !strings.HasPrefix(host, "http") {
			host = "https://" + host
		}
		return []recognize.Match{{Module: "workday",
			Fields: module.Fields{"host": host, "tenant": tenant, "client_id": id, "client_secret": secret},
			Secret: secret, Label: "WORKDAY_CLIENT_SECRET", Line: b.Lines["WORKDAY_CLIENT_SECRET"]}}
	})
}

// ---- Confluent Cloud: HTTP Basic api-key:secret, global host ----
func registerConfluent() {
	add("", r.HTTP{
		ModuleName: "confluent", Base: confluentAPI,
		Auth:   r.AuthSpec{Kind: r.Basic, UserField: "key", PassField: "secret"},
		Accept: "application/json",
		// No /me; api-keys reveals the owning principal and validates the key.
		Whoami: r.GET("/iam/v2/api-keys?page_size=1").Field("owner", "data.0.spec.owner.id").Field("owner type", "data.0.spec.owner.kind"),
		Calls: []r.Call{
			r.GET("/org/v2/environments").CountArrayFlag("data", "environments", warnFlag),
			r.GET("/iam/v2/service-accounts").CountArray("data", "service accounts"),
		},
		Static: []module.Finding{{Key: "reach", Value: "org-level Cloud API key — enumerate every environment, Kafka cluster, and identity in the org", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "CONFLUENT_CLOUD_API_KEY", "CONFLUENT_API_KEY")
		secret := firstVar(b.Vars, "CONFLUENT_CLOUD_API_SECRET", "CONFLUENT_API_SECRET")
		if key == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "confluent",
			Fields: module.Fields{"key": key, "secret": secret},
			Secret: secret, Label: "CONFLUENT_CLOUD_API_SECRET", Line: b.Lines["CONFLUENT_CLOUD_API_SECRET"]}}
	})
}

// ---- JumpCloud: x-api-key header, global host, full directory admin ----
func registerJumpCloud() {
	add("", r.HTTP{
		ModuleName: "jumpcloud", Base: jumpcloudAPI,
		Auth:   r.AuthSpec{Kind: r.Header, HeaderName: "x-api-key"},
		Accept: "application/json",
		// /systemusers validates the key and totalCount sizes the directory.
		Whoami: r.GET("/systemusers?limit=1").CountFrom("totalCount", "users (full directory)"),
		Calls:  []r.Call{r.GET("/systems?limit=1").CountFrom("totalCount", "managed systems")},
		Static: []module.Finding{{Key: "reach", Value: "org API key inherits the admin's rights — read every user, device, and group; can pivot to credential/MFA reset", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "JUMPCLOUD_API_KEY", "JC_API_KEY")
		if key == "" {
			return nil
		}
		return []recognize.Match{{Module: "jumpcloud",
			Fields: module.Fields{"token": key},
			Secret: key, Label: "JUMPCLOUD_API_KEY", Line: b.Lines["JUMPCLOUD_API_KEY"]}}
	})
}

// ---- Doppler: bearer token, secrets manager — recon + secret harvest ----
func registerDoppler() {
	add("", r.HTTP{
		ModuleName: "doppler", Base: dopplerAPI, Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v3/me").Field("token type", "type").Field("workplace", "workplace.name").Field("slug", "workplace.slug"),
		Calls:  []r.Call{r.GET("/v3/projects").CountArrayFlag("projects", "projects", warnFlag)},
		Static: []module.Finding{{Key: "reach", Value: "GET /v3/configs/config/secrets returns plaintext values — a personal/service-account token reads every secret across every project", Flag: fmFlag}},
		Harvest: func(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
			if !c.Live() || !c.Intrusive() {
				return nil, nil
			}
			return dopplerHarvest(ctx, c, f["token"]), nil
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "DOPPLER_TOKEN")
		// Also catch a bare dp.* token pasted on its own.
		if tok == "" && dopplerTokenRe.MatchString(strings.TrimSpace(b.Raw)) {
			tok = strings.TrimSpace(b.Raw)
		}
		if tok == "" || !strings.HasPrefix(tok, "dp.") {
			return nil
		}
		return []recognize.Match{{Module: "doppler",
			Fields: module.Fields{"token": tok},
			Secret: tok, Label: "DOPPLER_TOKEN", Line: b.Lines["DOPPLER_TOKEN"]}}
	})
}

// ---- 1Password Connect: bearer, secrets manager — recon + secret harvest ----
// 1Password service-account tokens (ops_...) are CLI/SDK-only (no plain REST),
// so we flag them offline rather than exercising them.
func registerOnePassword() {
	add("", r.HTTP{
		ModuleName: "onepassword_connect", Endpoint: selfHosted, Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		// No identity route; /v1/vaults both validates the token and sizes reach.
		Whoami: r.GET("/v1/vaults").CountArray("", "vaults"),
		Static: []module.Finding{{Key: "reach", Value: "GET /v1/vaults/{v}/items/{i} returns plaintext item fields — reads every secret in every vault the Connect token is scoped to", Flag: fmFlag}},
		Harvest: func(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
			if !c.Live() || !c.Intrusive() {
				return nil, nil
			}
			return opConnectHarvest(ctx, c, f["endpoint"], f["token"]), nil
		},
	}.Module())
	registerOnePasswordRecognizer()
}

func registerOnePasswordRecognizer() {
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		var out []recognize.Match
		if tok := firstVar(b.Vars, "OP_CONNECT_TOKEN"); tok != "" {
			host := firstVar(b.Vars, "OP_CONNECT_HOST")
			if endpoint != "" {
				host = endpoint
			}
			if host != "" {
				if !strings.HasPrefix(host, "http") {
					host = "http://" + host
				}
				out = append(out, recognize.Match{Module: "onepassword_connect",
					Fields: module.Fields{"endpoint": strings.TrimRight(host, "/"), "token": tok},
					Secret: tok, Label: "OP_CONNECT_TOKEN", Line: b.Lines["OP_CONNECT_TOKEN"]})
			}
		}
		// Service-account token: offline flag only (CLI/SDK transport, not REST).
		if sa := firstVar(b.Vars, "OP_SERVICE_ACCOUNT_TOKEN"); sa != "" || strings.HasPrefix(strings.TrimSpace(b.Raw), "ops_") {
			if sa == "" {
				sa = strings.TrimSpace(b.Raw)
			}
			out = append(out, recognize.Match{Module: "onepassword_sa",
				Fields: module.Fields{"token": sa},
				Secret: sa, Label: "OP_SERVICE_ACCOUNT_TOKEN", Line: b.Lines["OP_SERVICE_ACCOUNT_TOKEN"]})
		}
		return out
	})
	module.Register(onePasswordSA{})
}

// ---- PingOne: worker-app client_credentials → bearer, environment-scoped ----
func registerPingOne() {
	add("", r.HTTP{
		ModuleName: "pingone", Endpoint: saasOnly("pingone.com", "pingone.eu", "pingone.asia", "pingone.ca"), Base: "{api}/v1", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.ClientCredentials(ctx, c, f["auth"]+"/"+f["env"]+"/as/token", f["client_id"], f["client_secret"], url.Values{})
		},
		// The token is bound to its environment; read that env, then size the org.
		Whoami: r.GET("/environments/{env}").Field("environment", "name").Field("type", "type").Field("region", "region"),
		Calls: []r.Call{
			r.GET("/environments").CountArrayFlag("_embedded.environments", "reachable environments", warnFlag),
			r.GET("/environments/{env}/users?limit=1").CountFlag("count", "users (environment directory)", fmFlag),
		},
		Static: []module.Finding{{Key: "reach", Value: "admin worker token — read every user, group, and role across reachable environments; can reset passwords / MFA", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "PINGONE_CLIENT_ID")
		secret := firstVar(b.Vars, "PINGONE_CLIENT_SECRET")
		env := firstVar(b.Vars, "PINGONE_ENVIRONMENT_ID", "PINGONE_ENV_ID")
		if id == "" || secret == "" || env == "" {
			return nil
		}
		apiHost, authHost := pingoneHosts(firstVar(b.Vars, "PINGONE_REGION"))
		return []recognize.Match{{Module: "pingone",
			Fields: module.Fields{"api": apiHost, "auth": authHost, "env": env, "client_id": id, "client_secret": secret},
			Secret: secret, Label: "PINGONE_CLIENT_SECRET", Line: b.Lines["PINGONE_CLIENT_SECRET"]}}
	})
}

// pingoneHosts maps a PingOne region code to its API and auth hosts.
func pingoneHosts(region string) (api, authHost string) {
	suffix := "com"
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "eu", "europe":
		suffix = "eu"
	case "asia", "ap":
		suffix = "asia"
	case "ca", "canada":
		suffix = "ca"
	case "au", "australia", "com.au":
		suffix = "com.au"
	}
	return "https://api.pingone." + suffix, "https://auth.pingone." + suffix
}

// ---- CyberArk Privilege Cloud / PVWA: logon → raw session token ----
func registerCyberArkPVWA() {
	add("", r.HTTP{
		ModuleName: "cyberark_pvwa", Endpoint: selfHosted, Base: "{endpoint}/PasswordVault",
		Auth: r.AuthSpec{Kind: r.PreAuthed, RawAuth: true, ValuePrefix: ""},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return cyberArkLogon(ctx, c, f["endpoint"], f["username"], f["password"])
		},
		// No /whoami; Safes both validates the session and sizes reach.
		Whoami: r.GET("/API/Safes?limit=1").CountFrom("count", "safes (caller is a member of)"),
		Calls:  []r.Call{r.GET("/API/Accounts?limit=1").CountFlag("count", "privileged accounts", fmFlag)},
		Static: []module.Finding{{Key: "reach", Value: "POST /API/Accounts/{id}/Password/Retrieve returns the live privileged credential for every reachable account", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		user := firstVar(b.Vars, "CYBERARK_USERNAME", "PVWA_USERNAME")
		pass := firstVar(b.Vars, "CYBERARK_PASSWORD", "PVWA_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		base := endpoint
		if base == "" {
			base = firstVar(b.Vars, "PVWA_URL", "CYBERARK_URL", "PVWA_HOST")
			if base == "" {
				if t := firstVar(b.Vars, "CYBERARK_TENANT"); t != "" {
					base = "https://" + t + ".privilegecloud.cyberark.com"
				}
			}
		}
		if base == "" {
			return nil
		}
		if !strings.HasPrefix(base, "http") {
			base = "https://" + base
		}
		return []recognize.Match{{Module: "cyberark_pvwa",
			Fields: module.Fields{"endpoint": strings.TrimRight(base, "/"), "username": user, "password": pass},
			Secret: pass, Label: "CYBERARK_PASSWORD", Line: b.Lines["CYBERARK_PASSWORD"]}}
	})
}
