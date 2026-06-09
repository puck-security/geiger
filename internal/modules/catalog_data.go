package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Data warehouses, CRM, and managed-database control planes. The blast radius
// is data (read/exfiltrate, and for service_role / ACCOUNTADMIN, modify) plus —
// for the management APIs — provisioning and minting new DB credentials.

func init() {
	registerSnowflake()
	registerSalesforce()
	registerSupabase()
	registerPlanetScale()
	registerNeon()
	registerAiven()
	registerUpstash()
	registerRedisCloud()
	registerPlaid()
}

// --- Snowflake: PAT/OAuth bearer; a fixed read-only SELECT proves identity ---

func registerSnowflake() {
	add("", r.HTTP{
		ModuleName: "snowflake", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Headers: map[string]string{"X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN"},
		// SELECT CURRENT_USER()/CURRENT_ROLE() is read-only by construction (a
		// fixed query), so it's an opted-in read POST like STS/k8s rules-review.
		Whoami: r.Call{Method: "POST", Path: "/api/v2/statements", ReadOnlyPOST: true,
			Body:    `{"statement":"SELECT CURRENT_USER(), CURRENT_ROLE()","timeout":60}`,
			Fields:  []r.Extract{{Key: "user", Path: "data.0.0"}, {Key: "role", Path: "data.0.1"}},
			Signals: []r.Signal{{Path: "data.0.1", Regex: "(?i)ACCOUNTADMIN|SECURITYADMIN|SYSADMIN", Key: "privilege", Value: "high-privilege role (account/security/sysadmin)", Flag: fmFlag}}},
		Static: []module.Finding{{Key: "reach", Value: "query and modify warehouses, databases, and schemas; ACCOUNTADMIN reaches the entire account (all data, users, network policies)", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "Snowflake — data-warehouse access (account-wide at ACCOUNTADMIN)"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "SNOWFLAKE_TOKEN", "SNOWFLAKE_PAT", "SNOWFLAKE_PROGRAMMATIC_ACCESS_TOKEN", "SNOWSQL_PWD")
		if tok == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "SNOWFLAKE_URL", "SNOWFLAKE_HOST")
		if ep == "" {
			if acct := firstVar(b.Vars, "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_ACCOUNT_IDENTIFIER"); acct != "" {
				ep = "https://" + acct + ".snowflakecomputing.com"
			}
		}
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "snowflake", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "SNOWFLAKE_TOKEN"}}
	})
}

// --- Salesforce: OAuth access token against the instance URL ---

func registerSalesforce() {
	add("", r.HTTP{
		ModuleName: "salesforce", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/services/oauth2/userinfo").Field("user", "preferred_username").Field("email", "email").Field("org", "organization_id"),
		Static:    []module.Finding{{Key: "reach", Value: "read/modify CRM objects the user can access (accounts, contacts, opportunities, cases) — customer PII; admin profiles reach setup & all data", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Salesforce — CRM object access (customer PII)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "SALESFORCE_ACCESS_TOKEN", "SF_ACCESS_TOKEN", "SALESFORCE_TOKEN")
		ep := resolveEndpoint(b, endpoint, "SALESFORCE_INSTANCE_URL", "SF_INSTANCE_URL", "SALESFORCE_URL")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "salesforce", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "SALESFORCE_ACCESS_TOKEN"}}
	})
}

// --- Supabase: service_role key (bypasses Row Level Security) ---

func registerSupabase() {
	add("", r.HTTP{
		ModuleName: "supabase", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Headers: map[string]string{"apikey": "{token}"},
		// The admin users endpoint only answers to a service_role key, so a 200
		// here both validates the key and confirms it bypasses RLS.
		Whoami:    r.GET("/auth/v1/admin/users?page=1&per_page=1").CountArrayFlag("users", "users (admin-readable)", fmFlag),
		Static:    []module.Finding{{Key: "reach", Value: "a service_role key bypasses Row Level Security — full read/write on every table plus auth-user administration", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Supabase service_role — RLS-bypass full DB + auth admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_KEY", "SUPABASE_KEY")
		ep := resolveEndpoint(b, endpoint, "SUPABASE_URL", "SUPABASE_PROJECT_URL")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "supabase", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "SUPABASE_SERVICE_ROLE_KEY"}}
	})
}

// --- PlanetScale: service token, sent as "Authorization: <id>:<token>" ---

func registerPlanetScale() {
	add("", r.HTTP{
		ModuleName: "planetscale", Base: "https://api.planetscale.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization"},
		Whoami:    r.GET("/v1/organizations").CountArrayFlag("data", "organizations", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "manage databases, branches, and production branch passwords — provision DB credentials and read schema", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "PlanetScale service token — database & branch admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "PLANETSCALE_SERVICE_TOKEN_ID", "PLANETSCALE_TOKEN_ID", "PSCALE_TOKEN_ID")
		tok := firstVar(b.Vars, "PLANETSCALE_SERVICE_TOKEN", "PLANETSCALE_TOKEN", "PSCALE_TOKEN")
		if id == "" || tok == "" {
			return nil
		}
		// PlanetScale auth header is the literal "<token-id>:<token>".
		return []recognize.Match{{Module: "planetscale", Fields: module.Fields{"token": id + ":" + tok}, Secret: tok, Label: "PLANETSCALE_SERVICE_TOKEN"}}
	})
}

// --- Neon (serverless Postgres) management API ---

func registerNeon() {
	add("", r.HTTP{
		ModuleName: "neon", Base: "https://console.neon.tech/api/v2", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/projects").CountArrayFlag("projects", "projects", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "manage Postgres projects/branches/roles and reset role passwords — provision DB credentials", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Neon API key — Postgres project & role admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "NEON_API_KEY", "NEON_TOKEN"); k != "" {
			return []recognize.Match{{Module: "neon", Fields: module.Fields{"token": k}, Secret: k, Label: "NEON_API_KEY"}}
		}
		return nil
	})
}

// --- Aiven (managed Kafka/PG/OpenSearch/…) ---

func registerAiven() {
	add("", r.HTTP{
		ModuleName: "aiven", Base: "https://api.aiven.io", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/v1/me").Field("user", "user.user"),
		Calls:     []r.Call{r.GET("/v1/project").CountArrayFlag("projects", "projects", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "manage services (Kafka, PostgreSQL, OpenSearch…) and read service URIs/credentials — data-plane access", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Aiven token — managed-service & credential admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "AIVEN_API_TOKEN", "AIVEN_TOKEN", "AIVEN_API_KEY"); k != "" {
			return []recognize.Match{{Module: "aiven", Fields: module.Fields{"token": k}, Secret: k, Label: "AIVEN_API_TOKEN"}}
		}
		return nil
	})
}

// --- Upstash (serverless Redis/Kafka/Vector) management API: Basic ---

func registerUpstash() {
	add("", r.HTTP{
		ModuleName: "upstash", Base: "https://api.upstash.com", Auth: r.AuthSpec{Kind: r.Basic, UserField: "username", PassField: "token"},
		Whoami:    r.GET("/v2/redis/databases").CountArrayFlag("", "redis databases", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "manage Redis/Kafka/Vector databases and read their REST tokens/endpoints — data-plane access", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Upstash management API — database & token admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		email := firstVar(b.Vars, "UPSTASH_EMAIL")
		key := firstVar(b.Vars, "UPSTASH_API_KEY", "UPSTASH_MANAGEMENT_API_KEY")
		if email == "" || key == "" {
			return nil
		}
		return []recognize.Match{{Module: "upstash", Fields: module.Fields{"username": email, "token": key}, Secret: key, Label: "UPSTASH_API_KEY"}}
	})
}

// --- Redis Cloud (Redis Enterprise Cloud) management API: dual header keys ---

func registerRedisCloud() {
	add("", r.HTTP{
		ModuleName: "redis_cloud", Base: "https://api.redislabs.com/v1", Auth: r.AuthSpec{Kind: r.None},
		Headers:   map[string]string{"x-api-key": "{account_key}", "x-api-secret-key": "{secret_key}"},
		Whoami:    r.GET("/subscriptions").FlagField("subscriptions", "subscriptions.0.id", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "manage subscriptions/databases and read connection details — provision and reach managed Redis", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Redis Cloud API — subscription & database admin" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		acct := firstVar(b.Vars, "REDISCLOUD_ACCOUNT_KEY", "REDIS_CLOUD_ACCOUNT_KEY", "REDISCLOUD_API_ACCOUNT_KEY")
		secret := firstVar(b.Vars, "REDISCLOUD_SECRET_KEY", "REDIS_CLOUD_SECRET_KEY", "REDISCLOUD_API_SECRET_KEY")
		if acct == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "redis_cloud", Fields: module.Fields{"account_key": acct, "secret_key": secret}, Secret: secret, Label: "REDISCLOUD_SECRET_KEY"}}
	})
}

// --- Plaid: client_id + secret (financial data via stored access tokens) ---

func plaidHost(env string) string {
	switch env {
	case "sandbox":
		return "https://sandbox.plaid.com"
	case "development":
		return "https://development.plaid.com"
	default:
		return "https://production.plaid.com"
	}
}

func registerPlaid() {
	add("", r.HTTP{
		ModuleName: "plaid", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.None},
		// /institutions/get requires valid client_id+secret, so it validates the
		// keys read-only without needing a linked-item access token.
		Whoami: r.Call{Method: "POST", Path: "/institutions/get", ReadOnlyPOST: true,
			Body:  `{"client_id":"{client_id}","secret":"{secret}","count":1,"offset":0,"country_codes":["US"]}`,
			Count: &r.CountSpec{Key: "institutions reachable", Path: "total", Flag: warnFlag}},
		Static:    []module.Finding{{Key: "reach", Value: "with a stored item access_token, read linked bank accounts, balances, and transactions — financial PII; production keys move money via transfer endpoints", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Plaid keys — bank-account data access (financial PII)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "PLAID_CLIENT_ID")
		secret := firstVar(b.Vars, "PLAID_SECRET")
		if id == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "plaid",
			Fields: module.Fields{"client_id": id, "secret": secret, "endpoint": plaidHost(firstVar(b.Vars, "PLAID_ENV", "PLAID_ENVIRONMENT"))},
			Secret: secret, Label: "PLAID_SECRET"}}
	})
}
