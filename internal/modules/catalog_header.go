package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
)

func init() {
	// ---- Payments / commerce ----
	add("stripe-access-token", r.HTTP{
		ModuleName: "stripe", Base: "https://api.stripe.com", Auth: r.AuthSpec{Kind: r.BasicKeyUser},
		Whoami: r.GET("/v1/account").Field("id", "id").Field("country", "country").
			FlagField("charges_enabled", "charges_enabled", warnFlag).Field("email", "email"),
		Calls: []r.Call{
			r.GET("/v1/balance").Field("livemode", "livemode"),
			r.GET("/v1/customers?limit=1").FlagField("customer-PII", "data.0.id", warnFlag),
		},
		Summarize: func(fs []module.Finding) string {
			for _, f := range fs {
				if f.Key == "customer-PII" {
					return "live key — real money + customer PII"
				}
			}
			return "Stripe key"
		},
	}.Module())

	add("square-access-token", r.HTTP{
		ModuleName: "square", Base: "https://connect.squareup.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Headers: map[string]string{"Square-Version": "2024-01-18"},
		Whoami:  r.GET("/v2/merchants").Field("merchant", "merchant.0.business_name").Field("country", "merchant.0.country"),
		Calls: []r.Call{
			r.GET("/v2/locations").CountArray("locations", "locations"),
			{Path: "/v2/customers?limit=1", Signals: []r.Signal{{Path: "customers.0.id", Regex: ".+", Key: "customer PII",
				Value: "can read customer names, emails, phone & payment history", Flag: fmFlag}}},
		},
	}.Module())

	add("shopify-access-token", r.HTTP{
		ModuleName: "shopify", Base: "https://{shop}.myshopify.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "X-Shopify-Access-Token"},
		Whoami: r.GET("/admin/api/2024-01/shop.json").Field("shop", "shop.name").Field("email", "shop.email").Field("plan", "shop.plan_name"),
		Calls: []r.Call{
			r.GET("/admin/api/2024-01/customers/count.json").CountFlag("count", "customers (PII)", fmFlag),
			r.GET("/admin/api/2024-01/orders/count.json").CountFlag("count", "orders", warnFlag),
			r.GET("/admin/api/2024-01/products/count.json").CountFrom("count", "products"),
		},
	}.Module())
	module.MapRule("shopify-custom-access-token", "shopify")
	module.MapRule("shopify-private-app-access-token", "shopify")

	// ---- Cloud / infra ----
	add("cloudflare-api-key", r.HTTP{
		ModuleName: "cloudflare", Base: "https://api.cloudflare.com/client/v4", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/user/tokens/verify").Field("token-status", "result.status").Field("token-id", "result.id"),
		// Blast radius (each call may 403 on a scoped token — geiger skips those):
		// reachable accounts, zones (DNS surface), and best-effort identity.
		Calls: []r.Call{
			r.GET("/accounts").CountFrom("result_info.total_count", "accounts"),
			r.GET("/zones").CountFrom("result_info.total_count", "zones"),
			r.GET("/user").Field("email", "result.email"),
		},
	}.Module())

	// ---- VCS / CI ----
	add("gitlab-pat", r.HTTP{
		ModuleName: "gitlab", Base: "https://gitlab.com/api/v4", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "PRIVATE-TOKEN"},
		Whoami: r.GET("/personal_access_tokens/self").FlagField("scopes", "scopes", fmFlag).Field("name", "name").Field("expires", "expires_at"),
		Calls:  []r.Call{r.GET("/user").Field("username", "username")},
	}.Module())
	for _, rule := range []string{"gitlab-pat-routable", "gitlab-deploy-token", "gitlab-feed-token", "gitlab-ptt", "gitlab-rrt"} {
		module.MapRule(rule, "gitlab")
	}
	add("gitlab-cicd-job-token", r.HTTP{
		ModuleName: "gitlab_ci_token", Base: "https://gitlab.com/api/v4", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "JOB-TOKEN"},
		Whoami: r.GET("/job").Field("job", "name"),
		Static: []module.Finding{{Key: "note", Value: "CI job token — short-lived, limited scope", Flag: infoFlag}},
	}.Module())

	add("circleci", r.HTTP{
		ModuleName: "circleci", Base: "https://circleci.com/api/v2", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Circle-Token"},
		Whoami: r.GET("/me").Field("login", "login").Field("name", "name"),
		Calls: []r.Call{
			r.GET("/me/collaborations").CountArray("", "orgs/projects"),
			{Path: "/me/collaborations", Signals: []r.Signal{{Path: "0.slug", Regex: ".+", Key: "ci access",
				Value: "can read build logs/artifacts & trigger pipelines (CI secrets exposure)", Flag: warnFlag}}},
		},
	}.Module())

	// ---- Observability ----
	add("", r.HTTP{
		ModuleName: "pagerduty", Base: "https://api.pagerduty.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Token token="},
		Accept: "application/vnd.pagerduty+json;version=2",
		Whoami: r.Call{Method: "GET", Path: "/users/me",
			Fields:  []r.Extract{{Key: "name", Path: "user.name"}, {Key: "email", Path: "user.email"}, {Key: "role", Path: "user.role"}},
			Signals: []r.Signal{{Path: "user.role", Regex: "owner|admin", Key: "privilege", Value: "account owner/admin", Flag: fmFlag}}},
		Calls: []r.Call{r.GET("/services").CountArray("services", "services")},
	}.Module())

	add("dynatrace-api-token", r.HTTP{
		ModuleName: "dynatrace", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Api-Token "},
		Whoami: r.GET("/api/v1/time").Field("server-time", ""),
	}.Module())

	add("honeycomb", r.HTTP{
		ModuleName: "honeycomb", Base: "https://api.honeycomb.io", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "X-Honeycomb-Team"},
		Whoami: r.GET("/1/auth").Field("team", "team.name").Field("environment", "environment.name").
			FlagField("api-key-access", "api_key_access.events", infoFlag),
		Calls: []r.Call{r.GET("/1/datasets").CountArray("", "datasets")},
	}.Module())

	// ---- Comms / email ----
	add("sendgrid-api-token", r.HTTP{
		ModuleName: "sendgrid", Base: "https://api.sendgrid.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/v3/scopes").FlagField("scopes", "scopes", warnFlag),
		Calls:  []r.Call{r.GET("/v3/user/profile").Field("username", "username")},
	}.Module())

	add("mailgun-private-api-token", r.HTTP{
		ModuleName: "mailgun", Base: "https://api.mailgun.net/v3", Auth: r.AuthSpec{Kind: r.Basic, UserField: "user", PassField: "token"},
		Whoami: r.GET("/domains").CountFrom("total_count", "sending domains"),
		Static: []module.Finding{{Key: "data", Value: "can read message events & stored messages (recipient PII)", Flag: warnFlag}},
	}.Module())

	add("", r.HTTP{ // recognized via env recognizer (POSTMARK_*_TOKEN)
		ModuleName: "postmark", Base: "https://api.postmarkapp.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "X-Postmark-Server-Token"},
		Accept: "application/json",
		Whoami: r.GET("/server").Field("server", "Name").Field("color", "Color"),
		Static: []module.Finding{{Key: "data", Value: "can read outbound message history (recipient PII); account token enumerates all servers", Flag: warnFlag}},
	}.Module())

	add("", r.HTTP{ // recognized via env recognizer (BREVO_API_KEY)
		ModuleName: "brevo", Base: "https://api.brevo.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "api-key"},
		Whoami: r.GET("/v3/account").Field("email", "email").Field("company", "companyName"),
		Calls:  []r.Call{r.GET("/v3/contacts?limit=1").CountFlag("count", "contacts (PII)", fmFlag)},
	}.Module())

	add("discord-api-token", r.HTTP{
		ModuleName: "discord_bot", Base: "https://discord.com/api/v10", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Bot "},
		Whoami: r.GET("/users/@me").Field("bot", "username").Field("id", "id"),
		Calls:  []r.Call{r.GET("/users/@me/guilds").CountArray("", "guilds")},
	}.Module())

	add("intercom", r.HTTP{
		ModuleName: "intercom", Base: "https://api.intercom.io", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/me").Field("email", "email").Field("app", "app.name"),
		Calls: []r.Call{
			r.GET("/contacts?per_page=1").CountFlag("total_count", "contacts (PII)", fmFlag),
			r.GET("/admins").CountArray("admins", "admins"),
		},
	}.Module())

	add("zendesk", r.HTTP{
		ModuleName: "zendesk", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "GET", Path: "/api/v2/users/me",
			Fields:  []r.Extract{{Key: "name", Path: "user.name"}, {Key: "role", Path: "user.role"}},
			Signals: []r.Signal{{Path: "user.role", Contains: "admin", Key: "privilege", Value: "Zendesk admin", Flag: fmFlag}}},
	}.Module())

	// ---- Secrets / identity ----
	add("vault-service-token", r.HTTP{
		ModuleName: "vault", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "X-Vault-Token"},
		Whoami: r.GET("/v1/auth/token/lookup-self").Field("display_name", "data.display_name").
			FlagField("policies", "data.policies", fmFlag).Field("ttl", "data.ttl"),
		Static: []module.Finding{{Key: "note", Value: "root/* policy = total compromise; any secret-engine read = secrets-store reach", Flag: infoFlag}},
	}.Module())
	module.MapRule("vault-batch-token", "vault")

	add("okta-access-token", r.HTTP{
		ModuleName: "okta", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "SSWS "},
		Whoami: r.GET("/api/v1/users/me").Field("login", "profile.login").Field("status", "status"),
		Static: []module.Finding{{Key: "note", Value: "SSWS inherits creating admin's rights; super_admin = IdP takeover", Flag: infoFlag}},
	}.Module())

	// ---- Data platforms ----
	add("databricks-api-token", r.HTTP{
		ModuleName: "databricks", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/api/2.0/preview/scim/v2/Me").Field("userName", "userName").Field("displayName", "displayName").
			Signal(r.Signal{Path: "groups.0.display", Contains: "admin", Key: "privilege", Value: "member of admins group", Flag: fmFlag}),
		Calls: []r.Call{
			r.GET("/api/2.0/clusters/list").CountArray("clusters", "clusters"),
			{Path: "/api/2.0/sql/warehouses", Signals: []r.Signal{{Path: "warehouses.0.id", Regex: ".+", Key: "data",
				Value: "SQL warehouses present — can query lakehouse tables", Flag: warnFlag}}},
		},
	}.Module())

	add("snyk-api-token", r.HTTP{
		ModuleName: "snyk", Base: "https://api.snyk.io", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "token "},
		Whoami: r.GET("/v1/user/me").Field("username", "username").Field("email", "email"),
		Calls:  []r.Call{r.GET("/v1/orgs").CountArray("orgs", "orgs")},
	}.Module())

	add("jfrog-api-key", r.HTTP{
		ModuleName: "jfrog", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Bearer "},
		Whoami: r.GET("/artifactory/api/system/ping").Field("status", ""),
		Static: []module.Finding{{Key: "note", Value: "package registry — publish rights are a supply-chain force multiplier", Flag: fmFlag}},
	}.Module())
	module.MapRule("jfrog-identity-token", "jfrog")
}
