package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
)

func init() {
	// ---- Slack: auth.test (read-only) ----
	slack := r.HTTP{
		ModuleName: "slack", Base: "https://slack.com/api", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/auth.test").Field("workspace", "url").Field("team", "team").
			Field("user", "user").Field("bot-id", "bot_id"),
		Summarize: func(fs []module.Finding) string { return "valid Slack token — workspace reachable" },
	}.Module()
	for _, rule := range []string{
		"slack-bot-token", "slack-user-token", "slack-app-token", "slack-legacy-bot-token",
		"slack-legacy-token", "slack-legacy-workspace-token", "slack-config-access-token",
	} {
		module.MapRule(rule, "slack")
	}
	module.Register(slack)

	// ---- Telegram: token in URL path ----
	add("telegram-bot-api-token", r.HTTP{
		ModuleName: "telegram_bot", Base: "https://api.telegram.org/bot{token}", Auth: r.AuthSpec{Kind: r.None},
		Whoami: r.GET("/getMe").Field("username", "result.username").Field("bot-id", "result.id").Field("name", "result.first_name"),
	}.Module())

	// ---- New Relic: GraphQL (read-only query POST) ----
	add("new-relic-user-api-key", r.HTTP{
		ModuleName: "newrelic", Base: "https://api.newrelic.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "API-Key"},
		Whoami: r.Call{Method: "POST", Path: "/graphql", ReadOnlyPOST: true,
			Body:   `{"query":"{ actor { user { name email } accounts { id name } } }"}`,
			Fields: []r.Extract{{Key: "user", Path: "data.actor.user.name"}, {Key: "email", Path: "data.actor.user.email"}}},
	}.Module())
	module.MapRule("new-relic-user-api-id", "newrelic")

	// ---- Linear: GraphQL ----
	add("linear-api-key", r.HTTP{
		ModuleName: "linear", Base: "https://api.linear.app", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization"},
		Whoami: r.Call{Method: "POST", Path: "/graphql", ReadOnlyPOST: true,
			Body:   `{"query":"{ viewer { name email admin } organization { name urlKey } teams { nodes { id } } }"}`,
			Fields: []r.Extract{{Key: "user", Path: "data.viewer.name"}, {Key: "org", Path: "data.organization.name"}},
			Signals: []r.Signal{
				{Path: "data.viewer.admin", Contains: "true", Key: "privilege", Value: "workspace admin", Flag: fmFlag},
				{Path: "data.teams.nodes.0.id", Regex: ".+", Key: "data", Value: "can read all teams' issues & comments", Flag: warnFlag},
			}},
	}.Module())

	// ---- npm: whoami ----
	add("npm-access-token", r.HTTP{
		ModuleName: "npm", Base: "https://registry.npmjs.org", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/-/whoami").Field("username", "username"),
		Static: []module.Finding{{Key: "supply-chain", Value: "npm publish rights are a supply-chain force multiplier", Flag: fmFlag}},
	}.Module())

	// ---- RubyGems ----
	add("rubygems-api-token", r.HTTP{
		ModuleName: "rubygems", Base: "https://rubygems.org", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Authorization"},
		Whoami: r.GET("/api/v1/profile/me.json").Field("handle", "handle").Field("id", "id"),
		Static: []module.Finding{{Key: "supply-chain", Value: "gem push rights = supply-chain force multiplier", Flag: fmFlag}},
	}.Module())

	// ---- PyPI: macaroon, no read identity ----
	add("pypi-upload-token", r.HTTP{
		ModuleName: "pypi", Base: "https://upload.pypi.org", Auth: r.AuthSpec{Kind: r.None},
		Whoami: r.GET("/legacy/").Field("status", ""),
		Static: []module.Finding{{Key: "recon", Value: "upload-scoped macaroon — no read-only identity endpoint; decode caveats offline for project scope", Flag: cantFlag}},
	}.Module())

	// ---- DigitalOcean refresh / GitLab oauth already handled; Cloudflare global key ----
	add("cloudflare-global-api-key", r.HTTP{
		ModuleName: "cloudflare_global", Base: "https://api.cloudflare.com/client/v4", Auth: r.AuthSpec{Kind: r.None},
		Headers: map[string]string{"X-Auth-Key": "{token}", "X-Auth-Email": "{email}"},
		Whoami:  r.GET("/user").Field("email", "result.email").Field("id", "result.id"),
		Static:  []module.Finding{{Key: "note", Value: "legacy Global API Key = full account access", Flag: fmFlag}},
	}.Module())
}
