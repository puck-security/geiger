package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// ITSM / IAM / asset / database-control platforms. Mostly read-or-PII reach
// (warn), with PingFederate (federation-trust modification) and ClickHouse
// Cloud (service control) reaching force-multiplier territory.

func init() {
	registerJira()
	registerConfluence()
	registerIvanti()
	registerPingFederate()
	registerSnipeIT()
	registerClickHouseCloud()
	registerClickHouseSelfHosted()
}

// --- Jira (Atlassian Cloud): API token via HTTP Basic (email:token) ---

func registerJira() {
	add("", r.HTTP{
		ModuleName: "jira", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Basic, UserField: "email", PassField: "token"},
		Whoami: r.GET("/rest/api/3/myself").Field("account", "accountId").Field("user", "displayName").Field("email", "emailAddress"),
		Calls: []r.Call{
			r.GET("/rest/api/3/project/search").CountFlag("total", "projects", warnFlag),
			r.GET("/rest/api/3/users/search?maxResults=1").FlagField("user directory", "0.accountId", warnFlag),
		},
		Static: []module.Finding{{Key: "reach", Value: "read every issue and project plus the user directory (org PII); admin tokens edit workflows and configuration", Flag: warnFlag}},
		Summarize: func([]module.Finding) string {
			return "Jira (Atlassian Cloud) — full issue/project read + user-directory PII"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "JIRA_API_TOKEN", "ATLASSIAN_API_TOKEN", "JIRA_TOKEN")
		email := firstVar(b.Vars, "JIRA_EMAIL", "ATLASSIAN_EMAIL", "JIRA_USER", "JIRA_USERNAME")
		if tok == "" || email == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "JIRA_BASE_URL", "JIRA_URL", "ATLASSIAN_URL")
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "jira",
			Fields: module.Fields{"email": email, "token": tok, "endpoint": ep}, Secret: tok, Label: "JIRA_API_TOKEN"}}
	})
}

// --- Confluence (Atlassian Cloud): API token via HTTP Basic (email:token) ---
// Same account token as Jira reaches Confluence on the same site, so a shared
// ATLASSIAN_* credential triggers both recognizers — one token, two findings.

func registerConfluence() {
	add("", r.HTTP{
		ModuleName: "confluence", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Basic, UserField: "email", PassField: "token"},
		Whoami: r.GET("/wiki/rest/api/user/current").Field("account", "accountId").Field("user", "displayName").Field("email", "email"),
		Calls: []r.Call{
			r.GET("/wiki/rest/api/space?limit=100").CountFrom("size", "spaces"),
		},
		Static: []module.Finding{{Key: "reach", Value: "read every accessible space and page — internal docs, runbooks, and credentials teams paste in plaintext; admin tokens manage spaces and users", Flag: warnFlag}},
		Summarize: func([]module.Finding) string {
			return "Confluence (Atlassian Cloud) — full space/page read; pages often hold secrets"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "CONFLUENCE_API_TOKEN", "ATLASSIAN_API_TOKEN", "CONFLUENCE_TOKEN")
		email := firstVar(b.Vars, "CONFLUENCE_EMAIL", "ATLASSIAN_EMAIL", "CONFLUENCE_USER")
		if tok == "" || email == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "CONFLUENCE_BASE_URL", "CONFLUENCE_URL", "ATLASSIAN_URL")
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "confluence",
			Fields: module.Fields{"email": email, "token": tok, "endpoint": ep}, Secret: tok, Label: "CONFLUENCE_API_TOKEN"}}
	})
}

// --- Ivanti Neurons / ITSM: Authorization: rest_api_key=<key> ---

func registerIvanti() {
	add("", r.HTTP{
		ModuleName: "ivanti", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "rest_api_key="},
		Whoami:    r.GET("/api/odata/businessobject/employees?$top=1").FlagField("employees readable", "value.0.RecId", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "ITSM/CMDB CRUD — read incidents, configuration items, and employee PII; can run workflows", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Ivanti ITSM — incident/CMDB access + employee PII" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "IVANTI_API_KEY", "ISM_API_KEY", "IVANTI_REST_API_KEY")
		ep := resolveEndpoint(b, endpoint, "IVANTI_URL", "ISM_URL")
		if key == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "ivanti", Fields: module.Fields{"token": key, "endpoint": ep}, Secret: key, Label: "IVANTI_API_KEY"}}
	})
}

// --- PingFederate admin API: HTTP Basic + X-XSRF-Header ---

func registerPingFederate() {
	add("", r.HTTP{
		ModuleName: "pingfederate", Base: "{endpoint}/pf-admin-api/v1",
		Auth:    r.AuthSpec{Kind: r.Basic, UserField: "username", PassField: "password"},
		Headers: map[string]string{"X-XSRF-Header": "PingFederate"},
		Whoami:  r.GET("/version").Field("version", "version"),
		Calls: []r.Call{
			r.GET("/oauth/clients").CountArrayFlag("items", "oauth clients", warnFlag),
			r.GET("/idp/connections").CountArrayFlag("items", "idp connections", warnFlag),
		},
		Static: []module.Finding{{Key: "reach", Value: "read/modify OAuth clients and SP/IdP connections incl. signing keys — federation-trust takeover", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "PingFederate admin API — OAuth client & federation-trust control"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		user := firstVar(b.Vars, "PINGFEDERATE_USERNAME", "PF_ADMIN_USERNAME", "PINGFED_USERNAME")
		pass := firstVar(b.Vars, "PINGFEDERATE_PASSWORD", "PF_ADMIN_PASSWORD", "PINGFED_PASSWORD")
		ep := resolveEndpoint(b, endpoint, "PINGFEDERATE_URL", "PF_ADMIN_URL", "PINGFED_URL")
		if user == "" || pass == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "pingfederate", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "PINGFEDERATE_PASSWORD"}}
	})
}

// --- Snipe-IT: Bearer (personal API token, JWT) ---

func registerSnipeIT() {
	add("", r.HTTP{
		ModuleName: "snipeit", Base: "{endpoint}/api/v1", Accept: "application/json", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/hardware?limit=1").CountFlag("total", "assets", warnFlag),
		Calls:     []r.Call{r.GET("/users?limit=1").CountFlag("total", "users (PII)", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "full asset/license/user CRUD; user records carry employee PII", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Snipe-IT — asset/license inventory + user PII" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "SNIPEIT_API_TOKEN", "SNIPE_IT_TOKEN", "SNIPEIT_TOKEN")
		ep := resolveEndpoint(b, endpoint, "SNIPEIT_URL", "SNIPE_IT_URL", "SNIPEIT_BASE_URL")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "snipeit", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "SNIPEIT_API_TOKEN"}}
	})
}

// --- ClickHouse Cloud: control-plane key (Key ID + secret) via HTTP Basic ---

func registerClickHouseCloud() {
	add("", r.HTTP{
		ModuleName: "clickhouse_cloud", Base: "https://api.clickhouse.cloud/v1",
		Auth:      r.AuthSpec{Kind: r.Basic, UserField: "key", PassField: "secret"},
		Whoami:    r.GET("/organizations").Field("org", "result.0.name").CountArrayFlag("result", "organizations", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "an Admin Cloud key can provision/stop/scale services and manage keys/members — full service control (Developer keys are scoped lower)", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "ClickHouse Cloud API key — service & member control" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "CLICKHOUSE_KEY_ID", "CLICKHOUSE_CLOUD_KEY_ID", "CH_KEY_ID")
		secret := firstVar(b.Vars, "CLICKHOUSE_KEY_SECRET", "CLICKHOUSE_CLOUD_KEY_SECRET", "CH_KEY_SECRET")
		if key == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "clickhouse_cloud", Fields: module.Fields{"key": key, "secret": secret}, Secret: secret, Label: "CLICKHOUSE_KEY_SECRET"}}
	})
}

// --- ClickHouse self-hosted: SQL over HTTP via X-ClickHouse-User/-Key ---

func registerClickHouseSelfHosted() {
	add("", r.HTTP{
		ModuleName: "clickhouse_selfhosted", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.None},
		Headers:   map[string]string{"X-ClickHouse-User": "{username}", "X-ClickHouse-Key": "{password}"},
		Whoami:    r.GET("/?query=SELECT%20currentUser()%20FORMAT%20JSON").Field("user", "data.0.currentUser()"),
		Static:    []module.Finding{{Key: "reach", Value: "SQL over HTTP — read/modify data and manage users per the account's GRANTs", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "ClickHouse (self-hosted) — SQL data & user access" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		user := firstVar(b.Vars, "CLICKHOUSE_USER", "CH_USER")
		pass := firstVar(b.Vars, "CLICKHOUSE_PASSWORD", "CH_PASSWORD")
		ep := resolveEndpoint(b, endpoint, "CLICKHOUSE_HOST", "CLICKHOUSE_URL", "CH_HOST")
		if user == "" || pass == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "clickhouse_selfhosted", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "CLICKHOUSE_PASSWORD"}}
	})
}
