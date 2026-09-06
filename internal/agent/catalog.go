package agent

import "strings"

// The catalog types well-known MCP servers by what they REACH, not by what they
// are called. Entries are matched against the whole invocation (command + args)
// for stdio servers and against the host+path for remote ones, so a server is
// recognized however it is launched — npx, uvx, pipx, a docker image, a global
// binary, or a URL.
//
// Same shape as geiger's credential catalogs: an unmatched server is not a
// failure, it falls through to the argv/env heuristics in infer.go and, failing
// those, is reported as untyped rather than guessed at.

// entry is one catalog row. Match is a lowercase substring of the invocation
// that identifies the server; the first matching row wins, so rows are ordered
// most-specific first within a group.
type entry struct {
	match string
	caps  []Cap
	// scope names the corpus/system the caps apply to, when it is fixed by the
	// server's identity rather than by its arguments.
	scope string
	label string
}

// catalog is scanned in order. Keep the most specific match above any prefix it
// shares with another row.
var catalog = []entry{
	// ---- code execution: the strongest primitive ----
	{match: "server-shell", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "shell"},
	{match: "mcp-shell", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "shell"},
	{match: "shell-mcp", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "shell"},
	{match: "mcp-server-commands", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "command runner"},
	{match: "iterm-mcp", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "terminal"},
	{match: "desktop-commander", caps: []Cap{CapExec, CapFSRead, CapFSWrite}, label: "desktop commander"},
	{match: "code-sandbox", caps: []Cap{CapExec}, label: "code sandbox"},
	{match: "mcp-run-python", caps: []Cap{CapExec}, label: "python runner"},
	{match: "server-docker", caps: []Cap{CapExec, CapFSRead, CapFSWrite, CapDestructive}, label: "docker"},
	{match: "docker-mcp", caps: []Cap{CapExec, CapFSRead, CapFSWrite, CapDestructive}, label: "docker"},
	{match: "kubernetes-mcp", caps: []Cap{CapExec, CapCloudControl, CapSecretsRead, CapDestructive}, label: "kubernetes"},
	{match: "mcp-server-kubernetes", caps: []Cap{CapExec, CapCloudControl, CapSecretsRead, CapDestructive}, label: "kubernetes"},

	// ---- corpus search: bulk read across a document corpus ----
	{match: "mcp-atlassian", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapDataRead}, scope: "Confluence + Jira", label: "Atlassian"},
	{match: "server-confluence", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Confluence", label: "Confluence"},
	{match: "confluence-mcp", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Confluence", label: "Confluence"},
	{match: "server-jira", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Jira", label: "Jira"},
	{match: "jira-mcp", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Jira", label: "Jira"},
	{match: "server-slack", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapNetEgress}, scope: "Slack", label: "Slack"},
	{match: "slack-mcp", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapNetEgress}, scope: "Slack", label: "Slack"},
	{match: "notion", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Notion", label: "Notion"},
	{match: "server-google-drive", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Google Drive", label: "Google Drive"},
	{match: "gdrive", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Google Drive", label: "Google Drive"},
	{match: "sharepoint", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "SharePoint", label: "SharePoint"},
	{match: "microsoft-365", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapNetEgress}, scope: "Microsoft 365", label: "Microsoft 365"},
	{match: "server-gmail", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapNetEgress}, scope: "Gmail", label: "Gmail"},
	{match: "gmail-mcp", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapNetEgress}, scope: "Gmail", label: "Gmail"},
	{match: "linear", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Linear", label: "Linear"},
	{match: "zendesk", caps: []Cap{CapCorpusSearch, CapUntrustedIn}, scope: "Zendesk", label: "Zendesk"},
	{match: "servicenow", caps: []Cap{CapCorpusSearch, CapUntrustedIn, CapIdentityAdmin}, scope: "ServiceNow", label: "ServiceNow"},
	{match: "obsidian", caps: []Cap{CapCorpusSearch, CapFSRead}, scope: "Obsidian vault", label: "Obsidian"},
	{match: "elasticsearch", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "Elasticsearch", label: "Elasticsearch"},
	{match: "opensearch", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "OpenSearch", label: "OpenSearch"},

	// vector stores hold embedded copies of whatever corpus was indexed
	{match: "pinecone", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "Pinecone index", label: "Pinecone"},
	{match: "qdrant", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "Qdrant collection", label: "Qdrant"},
	{match: "chroma", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "Chroma collection", label: "Chroma"},
	{match: "weaviate", caps: []Cap{CapCorpusSearch, CapDataRead}, scope: "Weaviate", label: "Weaviate"},

	// ---- source control: corpus search AND supply-chain write ----
	{match: "github-mcp-server", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn, CapSecretsRead}, scope: "GitHub", label: "GitHub"},
	{match: "server-github", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn, CapSecretsRead}, scope: "GitHub", label: "GitHub"},
	{match: "githubcopilot.com/mcp", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn}, scope: "GitHub", label: "GitHub"},
	{match: "server-gitlab", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn, CapSecretsRead}, scope: "GitLab", label: "GitLab"},
	{match: "gitlab-mcp", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn, CapSecretsRead}, scope: "GitLab", label: "GitLab"},
	{match: "bitbucket", caps: []Cap{CapCorpusSearch, CapCodeWrite, CapUntrustedIn}, scope: "Bitbucket", label: "Bitbucket"},
	{match: "server-git", caps: []Cap{CapFSRead, CapFSWrite, CapCodeWrite}, label: "git"},

	// ---- secret stores: the edge into every other credential ----
	{match: "vault-mcp", caps: []Cap{CapSecretsRead}, scope: "HashiCorp Vault", label: "Vault"},
	{match: "mcp-vault", caps: []Cap{CapSecretsRead}, scope: "HashiCorp Vault", label: "Vault"},
	{match: "1password", caps: []Cap{CapSecretsRead}, scope: "1Password", label: "1Password"},
	{match: "onepassword", caps: []Cap{CapSecretsRead}, scope: "1Password", label: "1Password"},
	{match: "doppler", caps: []Cap{CapSecretsRead}, scope: "Doppler", label: "Doppler"},
	{match: "infisical", caps: []Cap{CapSecretsRead}, scope: "Infisical", label: "Infisical"},
	{match: "keyring", caps: []Cap{CapSecretsRead}, label: "OS keyring"},

	// ---- cloud control planes ----
	{match: "aws-mcp", caps: []Cap{CapCloudControl, CapSecretsRead, CapDataRead, CapDestructive}, scope: "AWS", label: "AWS"},
	{match: "mcp-server-aws", caps: []Cap{CapCloudControl, CapSecretsRead, CapDataRead, CapDestructive}, scope: "AWS", label: "AWS"},
	{match: "awslabs", caps: []Cap{CapCloudControl, CapSecretsRead, CapDataRead}, scope: "AWS", label: "AWS"},
	{match: "azure-mcp", caps: []Cap{CapCloudControl, CapSecretsRead, CapDataRead, CapDestructive}, scope: "Azure", label: "Azure"},
	{match: "gcp-mcp", caps: []Cap{CapCloudControl, CapSecretsRead, CapDataRead, CapDestructive}, scope: "GCP", label: "GCP"},
	{match: "cloudflare", caps: []Cap{CapCloudControl, CapSecretsRead}, scope: "Cloudflare", label: "Cloudflare"},
	{match: "terraform", caps: []Cap{CapCloudControl, CapSecretsRead, CapDestructive}, scope: "Terraform", label: "Terraform"},

	// ---- identity ----
	{match: "okta", caps: []Cap{CapIdentityAdmin, CapDataRead}, scope: "Okta", label: "Okta"},
	{match: "entra", caps: []Cap{CapIdentityAdmin, CapDataRead}, scope: "Entra ID", label: "Entra ID"},
	{match: "auth0", caps: []Cap{CapIdentityAdmin, CapDataRead}, scope: "Auth0", label: "Auth0"},

	// ---- databases: scoped private data, plus destructive SQL ----
	{match: "server-postgres", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "Postgres", label: "Postgres"},
	{match: "postgres-mcp", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "Postgres", label: "Postgres"},
	{match: "mysql-mcp", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "MySQL", label: "MySQL"},
	{match: "server-sqlite", caps: []Cap{CapDataRead, CapFSRead}, scope: "SQLite", label: "SQLite"},
	{match: "mongodb-mcp", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "MongoDB", label: "MongoDB"},
	{match: "snowflake", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "Snowflake", label: "Snowflake"},
	{match: "bigquery", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "BigQuery", label: "BigQuery"},
	{match: "databricks", caps: []Cap{CapDataRead, CapCorpusSearch, CapExec}, scope: "Databricks", label: "Databricks"},
	{match: "clickhouse", caps: []Cap{CapDataRead, CapCorpusSearch}, scope: "ClickHouse", label: "ClickHouse"},
	{match: "supabase", caps: []Cap{CapDataRead, CapCorpusSearch, CapSecretsRead}, scope: "Supabase", label: "Supabase"},

	// ---- untrusted ingress + egress ----
	{match: "server-fetch", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "fetch"},
	{match: "mcp-server-fetch", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "fetch"},
	{match: "server-puppeteer", caps: []Cap{CapUntrustedIn, CapNetEgress, CapExec}, label: "puppeteer"},
	{match: "playwright", caps: []Cap{CapUntrustedIn, CapNetEgress, CapExec}, label: "playwright"},
	{match: "browser-use", caps: []Cap{CapUntrustedIn, CapNetEgress, CapExec}, label: "browser"},
	{match: "server-brave-search", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "web search"},
	{match: "tavily", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "web search"},
	{match: "exa-mcp", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "web search"},
	{match: "firecrawl", caps: []Cap{CapUntrustedIn, CapNetEgress}, label: "web crawler"},
	{match: "server-sentry", caps: []Cap{CapUntrustedIn, CapDataRead}, scope: "Sentry", label: "Sentry"},
	{match: "sendgrid", caps: []Cap{CapNetEgress}, label: "mail send"},
	{match: "twilio", caps: []Cap{CapNetEgress}, label: "SMS/voice send"},
	{match: "discord", caps: []Cap{CapUntrustedIn, CapNetEgress}, scope: "Discord", label: "Discord"},

	// ---- filesystem (scope comes from argv; see infer.go) ----
	{match: "server-filesystem", caps: []Cap{CapFSRead, CapFSWrite}, label: "filesystem"},
	{match: "filesystem-mcp", caps: []Cap{CapFSRead, CapFSWrite}, label: "filesystem"},
	{match: "mcp-filesystem", caps: []Cap{CapFSRead, CapFSWrite}, label: "filesystem"},

	// ---- benign-by-design ----
	{match: "server-memory", caps: []Cap{CapDataRead}, label: "memory"},
	{match: "sequential-thinking", caps: nil, label: "sequential thinking"},
	{match: "server-time", caps: nil, label: "time"},
	{match: "server-everything", caps: []Cap{CapFSRead}, label: "reference server"},
	{match: "context7", caps: []Cap{CapUntrustedIn}, label: "docs lookup"},
}

// lookup returns the catalog entry for an invocation string, which the caller
// has already lowercased and joined (command + args, or host + path).
func lookup(invocation string) (entry, bool) {
	for _, e := range catalog {
		if strings.Contains(invocation, e.match) {
			return e, true
		}
	}
	return entry{}, false
}
