package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
)

// Simple bearer-token providers: GET a whoami/identity endpoint, then size
// reach with a count call. Each is a few lines of declarative recipe.
func init() {
	// ---- Infra / hosting ----
	add("digitalocean-pat", r.HTTP{
		ModuleName: "digitalocean", Base: "https://api.digitalocean.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v2/account").Field("email", "account.email").Field("status", "account.status").Field("team", "account.team.name"),
		Calls: []r.Call{
			r.GET("/v2/droplets").CountFrom("meta.total", "droplets"),
			r.GET("/v2/databases").CountArrayFlag("databases", "managed databases", warnFlag),
			r.GET("/v2/kubernetes/clusters").CountArray("kubernetes_clusters", "k8s clusters"),
			{Path: "/v2/account", Signals: []r.Signal{{Path: "account.email", Regex: ".+", Key: "reach",
				Value: "full account — create/snapshot droplets, read DB clusters & Spaces", Flag: warnFlag}}},
		},
	}.Module())
	add("digitalocean-access-token", r.HTTP{
		ModuleName: "digitalocean_oauth", Base: "https://api.digitalocean.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v2/account").Field("email", "account.email"),
	}.Module())

	add("heroku-api-key", r.HTTP{
		ModuleName: "heroku", Base: "https://api.heroku.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Accept: "application/vnd.heroku+json; version=3",
		Whoami: r.GET("/account").Field("email", "email").Field("id", "id"),
		Calls: []r.Call{
			r.GET("/apps").CountArray("", "apps"),
			{Path: "/account", Signals: []r.Signal{{Path: "email", Regex: ".+", Key: "config-vars", Value: "GET /apps/{id}/config-vars exposes downstream secrets", Flag: fmFlag}}},
		},
	}.Module())
	module.MapRule("heroku-api-key-v2", "heroku")

	add("linode-api-token", r.HTTP{ // gitleaks lacks a linode rule; recognized via env recognizer below
		ModuleName: "linode", Base: "https://api.linode.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v4/profile").Field("username", "username").Field("email", "email"),
		Calls: []r.Call{
			r.GET("/v4/linode/instances").CountFrom("results", "instances"),
			r.GET("/v4/object-storage/buckets").CountFlag("results", "object-storage buckets", warnFlag),
			r.GET("/v4/databases/instances").CountFlag("results", "managed databases", warnFlag),
		},
	}.Module())

	add("netlify-access-token", r.HTTP{
		ModuleName: "netlify", Base: "https://api.netlify.com/api/v1", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/user").Field("email", "email").Field("full_name", "full_name"),
		Calls: []r.Call{
			r.GET("/sites").CountArray("", "sites"),
			{Path: "/sites?per_page=1", Signals: []r.Signal{{Path: "0.id", Regex: ".+", Key: "build env",
				Value: "site build env vars (often secrets) readable; can deploy", Flag: fmFlag}}},
		},
	}.Module())

	add("", r.HTTP{
		ModuleName: "vercel", Base: "https://api.vercel.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v2/user").Field("user", "user.username").Field("email", "user.email"),
		Calls: []r.Call{
			r.GET("/v9/projects?limit=100").CountArrayFlag("projects", "projects", warnFlag),
			{Path: "/v9/projects?limit=1", Signals: []r.Signal{{Path: "projects.0.id", Regex: ".+", Key: "env vars",
				Value: "project env vars (often secrets) are readable via /v9/projects/{id}/env", Flag: fmFlag}}},
		},
	}.Module())

	add("fastly-api-token", r.HTTP{
		ModuleName: "fastly", Base: "https://api.fastly.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Fastly-Key"},
		Accept: "application/json",
		Whoami: r.GET("/current_user").Field("login", "login").Field("name", "name").FlagField("role", "role", warnFlag),
		Calls: []r.Call{
			r.GET("/service").CountArray("", "services"),
			{Path: "/service", Signals: []r.Signal{{Path: "0.id", Regex: ".+", Key: "config",
				Value: "can read/purge service config: backends, TLS, VCL, dictionaries", Flag: warnFlag}}},
		},
	}.Module())

	// ---- CI / CD / VCS ----
	add("buildkite", r.HTTP{ // recognized via env recognizer
		ModuleName: "buildkite", Base: "https://api.buildkite.com/v2", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/user").Field("name", "name").Field("email", "email"),
		Calls: []r.Call{
			r.GET("/organizations").CountArray("", "organizations"),
			{Path: "/organizations", Signals: []r.Signal{{Path: "0.slug", Regex: ".+", Key: "build logs",
				Value: "can read build logs & artifacts (frequently leak secrets)", Flag: warnFlag}}},
		},
	}.Module())

	add("", r.HTTP{
		ModuleName: "terraform_cloud", Base: "https://app.terraform.io/api/v2", Auth: r.AuthSpec{Kind: r.Bearer},
		Accept: "application/vnd.api+json",
		Whoami: r.GET("/account/details").Field("user", "data.attributes.username").Field("email", "data.attributes.email"),
		Calls: []r.Call{{Path: "/organizations", Signals: []r.Signal{
			{Path: "data.0.id", Regex: ".+", Key: "state-secrets", Value: "reading workspace state-versions exposes downstream secrets", Flag: fmFlag},
		}}},
	}.Module())

	// ---- Observability ----
	add("grafana-service-account-token", r.HTTP{
		ModuleName: "grafana", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "GET", Path: "/api/user",
			Fields: []r.Extract{{Key: "login", Path: "login"}, {Key: "email", Path: "email"}},
			Signals: []r.Signal{{Path: "isGrafanaAdmin", Contains: "true",
				Key: "server admin", Value: "Grafana server admin", Flag: fmFlag}}},
		Calls: []r.Call{
			{Path: "/api/org", Fields: []r.Extract{{Key: "org", Path: "name"}}},
			{Path: "/api/datasources", Signals: []r.Signal{{Path: "0.name", Regex: ".+", Key: "datasources", Value: "datasource connection details readable", Flag: fmFlag}}},
		},
	}.Module())
	module.MapRule("grafana-api-key", "grafana")
	module.MapRule("grafana-cloud-api-token", "grafana")

	add("sentry-org-token", r.HTTP{
		ModuleName: "sentry", Base: "https://sentry.io", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/api/0/").Field("user", "user.username"),
		Calls: []r.Call{
			r.GET("/api/0/organizations/").CountArray("", "organizations"),
			r.GET("/api/0/projects/").CountArray("", "projects"),
			{Path: "/api/0/projects/", Signals: []r.Signal{{Path: "0.slug", Regex: ".+", Key: "data",
				Value: "can read source maps, events & error payloads (often contain PII/tokens)", Flag: warnFlag}}},
		},
	}.Module())
	module.MapRule("sentry-access-token", "sentry")
	module.MapRule("sentry-user-token", "sentry")

	// ---- SaaS / productivity ----
	add("notion-api-token", r.HTTP{
		ModuleName: "notion", Base: "https://api.notion.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Headers: map[string]string{"Notion-Version": "2022-06-28"},
		Whoami:  r.GET("/v1/users/me").Field("name", "name").Field("type", "type").Field("workspace", "bot.workspace_name"),
		Calls: []r.Call{
			{Method: "POST", Path: "/v1/search", ReadOnlyPOST: true, Body: `{"page_size":100}`,
				Count:   &r.CountSpec{Key: "shared pages/dbs", Path: "results", ArrayLen: true, Flag: warnFlag},
				Signals: []r.Signal{{Path: "results.0.object", Regex: ".+", Key: "data", Value: "can read shared page & database content", Flag: warnFlag}}},
		},
	}.Module())

	add("asana-client-secret", r.HTTP{ // PAT recognized via env recognizer; secret rule mapped too
		ModuleName: "asana", Base: "https://app.asana.com/api/1.0", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/users/me").Field("name", "data.name").Field("email", "data.email"),
		Calls: []r.Call{
			r.GET("/workspaces").CountArray("data", "workspaces"),
			{Path: "/users/me", Signals: []r.Signal{{Path: "data.workspaces.0.gid", Regex: ".+", Key: "data",
				Value: "can read tasks, projects & attachments across workspaces", Flag: warnFlag}}},
		},
	}.Module())

	add("airtable-personnal-access-token", r.HTTP{
		ModuleName: "airtable", Base: "https://api.airtable.com/v0", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/meta/whoami").Field("user-id", "id").FlagField("scopes", "scopes", warnFlag),
		Calls:  []r.Call{r.GET("/meta/bases").CountArray("bases", "bases")},
	}.Module())
	module.MapRule("airtable-api-key", "airtable")

	add("hubspot-api-key", r.HTTP{
		ModuleName: "hubspot", Base: "https://api.hubapi.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/account-info/v3/details").Field("portal-id", "portalId").Field("account-type", "accountType"),
		Calls: []r.Call{
			r.GET("/crm/v3/objects/contacts?limit=1").FlagField("contacts (PII)", "results.0.id", fmFlag),
			r.GET("/crm/v3/objects/companies?limit=1").FlagField("companies", "results.0.id", warnFlag),
			r.GET("/crm/v3/objects/deals?limit=1").FlagField("deals (revenue data)", "results.0.id", warnFlag),
		},
	}.Module())

	add("dropbox-api-token", r.HTTP{
		ModuleName: "dropbox", Base: "https://api.dropboxapi.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "POST", Path: "/2/users/get_current_account", ReadOnlyPOST: true, Body: "null",
			Fields: []r.Extract{{Key: "name", Path: "name.display_name"}, {Key: "email", Path: "email"}}},
		Static: []module.Finding{{Key: "data", Value: "can read/download files in the account (files.content.read)", Flag: warnFlag}},
	}.Module())
	module.MapRule("dropbox-long-lived-api-token", "dropbox")
	module.MapRule("dropbox-short-lived-api-token", "dropbox")

	// ---- AI / LLM ----
	add("openai-api-key", r.HTTP{
		ModuleName: "openai", Base: "https://api.openai.com", Auth: r.AuthSpec{Kind: r.Bearer},
		// /v1/models validates the key (works for every key type). /v1/me is a
		// non-fatal enrichment — some key classes 401 on it, but the key is still
		// valid and useful, so its failure must not sink the whole result.
		Whoami: r.GET("/v1/models").CountArray("data", "models accessible"),
		Calls: []r.Call{
			r.Call{Method: "GET", Path: "/v1/me", Optional: true,
				Fields: []r.Extract{{Key: "name", Path: "name"}, {Key: "email", Path: "email"}, {Key: "org", Path: "orgs.data.0.name"}},
				Signals: []r.Signal{{Path: "orgs.data.0.role", Contains: "owner",
					Key: "org role", Value: "owner — can manage billing, members, and API keys", Flag: fmFlag}}},
		},
		Static: []module.Finding{{Key: "spend/quota", Value: "not readable without admin endpoints", Flag: cantFlag}},
	}.Module())

	add("anthropic-api-key", r.HTTP{
		ModuleName: "anthropic", Base: "https://api.anthropic.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "x-api-key"},
		Headers: map[string]string{"anthropic-version": "2023-06-01"},
		Whoami:  r.GET("/v1/models").CountArray("data", "models accessible"),
		Static:  []module.Finding{{Key: "spend/quota", Value: "needs admin endpoints", Flag: cantFlag}},
	}.Module())
	module.MapRule("anthropic-admin-api-key", "anthropic")

	add("cohere-api-token", r.HTTP{
		ModuleName: "cohere", Base: "https://api.cohere.ai", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v1/models").CountArray("models", "models"),
	}.Module())

	add("", r.HTTP{ // recognized via env recognizer (MISTRAL_API_KEY)
		ModuleName: "mistral", Base: "https://api.mistral.ai", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v1/models").CountArray("data", "models accessible"),
	}.Module())

	add("", r.HTTP{ // recognized via env recognizer (REPLICATE_API_TOKEN)
		ModuleName: "replicate", Base: "https://api.replicate.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v1/account").Field("username", "username").Field("type", "type"),
	}.Module())

	add("huggingface-access-token", r.HTTP{
		ModuleName: "huggingface", Base: "https://huggingface.co", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "GET", Path: "/api/whoami-v2",
			Fields: []r.Extract{{Key: "name", Path: "name"}, {Key: "type", Path: "type"}},
			Signals: []r.Signal{
				{Path: "auth.accessToken.role", Regex: "write|admin", Key: "token role",
					Value: "write/admin token — can push models & datasets (supply chain)", Flag: fmFlag},
				{Path: "orgs.0.name", Regex: ".+", Key: "orgs", Value: "member of orgs — access to private models/datasets", Flag: warnFlag},
			}},
	}.Module())
	module.MapRule("huggingface-organization-api-token", "huggingface")
}
