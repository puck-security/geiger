// Command coverage regenerates the credential-coverage table for the README
// from the live module registry. Names + reach are pulled from the registry
// (so new modules appear automatically); only the category grouping and the
// reach phrases for modules whose summary is built from live findings are
// curated below. Run: `go run ./tools/coverage` and paste the output into the
// README "### Coverage" section. Any module not placed in a group prints under
// "Uncategorized" so it's never silently dropped.
package main

import (
	"fmt"
	"sort"

	"github.com/puck-security/geiger/internal/module"
	_ "github.com/puck-security/geiger/internal/modules" // register the catalog
)

// groups define the category buckets and the display order within each.
var groups = []struct {
	title string
	names []string
}{
	{"Cloud & hosting", []string{
		"aws", "aws_sso", "aws_sso_registration", "gcp_service_account", "gcp_adc", "azure_msal",
		"digitalocean", "digitalocean_oauth", "linode", "cloudflare", "cloudflare_global", "fastly",
		"heroku", "render", "railway", "flyio", "netlify", "vercel", "tailscale", "terraform_cloud", "oci_config",
	}},
	{"Source control & packages", []string{
		"github_pat", "gitlab", "gitlab_ci_token", "jfrog", "docker_registry", "npm", "pypi", "rubygems",
	}},
	{"CI/CD & build", []string{"buildkite", "circleci"}},
	{"Databases & data platforms", []string{
		"db_connection_string", "snowflake", "databricks", "mongodb_atlas", "supabase", "planetscale",
		"neon", "aiven", "upstash", "redis_cloud", "clickhouse_cloud", "clickhouse_selfhosted", "plaid",
	}},
	{"AI / LLM & agentic", []string{
		"openai", "anthropic", "claude_code_oauth", "gemini", "azure_openai", "cohere", "mistral",
		"replicate", "huggingface", "groq", "together", "deepseek", "openrouter", "xai", "fireworks",
		"perplexity", "elevenlabs", "stability", "pinecone", "mcp_config", "ai_ide_store",
	}},
	{"Secrets managers & vaults", []string{
		"vault", "conjur", "cyberark_pvwa", "infisical", "akeyless", "delinea_secret_server", "doppler",
		"onepassword_connect", "onepassword_sa", "onepassword_secret_key", "bitwarden", "bitwarden_vault",
		"keepass_db", "vault_export_plaintext",
	}},
	{"Identity, SSO & directory", []string{
		"okta", "pingone", "pingfederate", "entra_sp", "jumpcloud", "sailpoint", "auth0", "duo", "workday",
	}},
	{"Endpoint, MDM, RMM & config-mgmt", []string{
		"ninjaone", "atera", "kandji", "jamf", "mosyle", "automox", "tanium", "ansible_awx",
		"puppet_enterprise", "saltstack", "fleet",
	}},
	{"Monitoring & observability", []string{
		"datadog", "newrelic", "grafana", "splunk", "sumologic", "dynatrace", "honeycomb", "sentry",
		"zabbix", "auvik", "manageengine_opmanager", "lacework", "wiz", "snyk",
	}},
	{"Backup & DR", []string{"veeam", "acronis", "cohesity", "netbackup", "commvault"}},
	{"ITSM, productivity & support", []string{
		"servicenow", "jira", "ivanti", "snipeit", "pagerduty", "linear", "asana", "notion", "zendesk", "intercom",
	}},
	{"Comms, email & SMS", []string{
		"slack", "discord_bot", "telegram_bot", "zoom", "twilio", "vonage", "sendgrid", "mailgun",
		"mailchimp", "postmark", "brevo",
	}},
	{"Payments, CRM & SaaS data", []string{
		"stripe", "square", "coinbase", "salesforce", "hubspot", "shopify", "klaviyo", "braze", "segment",
		"mixpanel", "amplitude", "customerio", "docusign", "dropbox", "box", "airtable", "algolia", "confluent",
	}},
	{"Local credential stores & keys", []string{
		"ssh_private_key", "kubeconfig", "firefox_logins", "jwt", "generic_secret", "needs_endpoint",
	}},
}

// reach fills in a one-line capability for modules whose registry summary is
// empty or too terse (their note summary is otherwise built from live findings).
var reach = map[string]string{
	"aws":                  "AWS account — IAM-scoped access across all AWS services",
	"github_pat":           "GitHub — repo read/write/admin, org membership, Actions",
	"docker_registry":      "container registry — pull/push images (supply-chain)",
	"db_connection_string": "direct DB data-plane (pg/mysql/mongo/redis/mssql/oracle/clickhouse/cassandra/sqlite)",
	"slack":                "Slack — messages, files, users per token scope",
	"stripe":               "Stripe — charges/customers/payouts (a live key moves money)",
	"twilio":               "Twilio — SMS/voice send (billed) + message logs (PII)",
	"gitlab":               "GitLab — repo/project access per token scope",
	"gitlab_ci_token":      "GitLab CI job token — pipeline-scoped repo/registry access",
	"jfrog":                "JFrog Artifactory — artifact read/write + package admin",
	"npm":                  "npm — publish/yank packages (supply-chain)",
	"pypi":                 "PyPI — publish packages (supply-chain)",
	"rubygems":             "RubyGems — publish gems (supply-chain)",
	"buildkite":            "Buildkite — pipelines + build-agent access",
	"circleci":             "CircleCI — pipelines + project env vars",
	"databricks":           "Databricks — workspace, jobs, notebooks, data",
	"openai":               "OpenAI — model access, files/fine-tunes; org-owner = key/billing admin",
	"anthropic":            "Anthropic — Claude model access (billed)",
	"cohere":               "Cohere — LLM API access (billed)",
	"mistral":              "Mistral — LLM API access (billed)",
	"replicate":            "Replicate — model runs (billed) + model access",
	"huggingface":          "Hugging Face — model/dataset access; write token can push",
	"vault":                "HashiCorp Vault — read secrets per policy",
	"cyberark_pvwa":        "CyberArk PVWA — privileged-account vault access",
	"doppler":              "Doppler — project config/secret access",
	"onepassword_connect":  "1Password Connect — vault item access via the Connect server",
	"okta":                 "Okta — directory, SSO apps, admin per scope",
	"pingone":              "PingOne — identity & SSO admin",
	"entra_sp":             "Microsoft Entra service principal — Graph/Azure per app roles",
	"jumpcloud":            "JumpCloud — directory, device & SSO admin",
	"sailpoint":            "SailPoint — identity governance (certs, provisioning)",
	"auth0":                "Auth0 — tenant management API (users, apps, rules)",
	"duo":                  "Duo — MFA admin API (bypass codes, user mgmt)",
	"workday":              "Workday — HR/finance records (PII)",
	"datadog":              "Datadog — metrics/logs/APM + monitor & key admin",
	"newrelic":             "New Relic — telemetry + account admin",
	"grafana":              "Grafana — dashboards/datasources; server-admin = full",
	"dynatrace":            "Dynatrace — observability data + config API",
	"honeycomb":            "Honeycomb — event data + query API",
	"sentry":               "Sentry — error events (may hold secrets/PII) + org admin",
	"snyk":                 "Snyk — code/dependency vuln data + org project access",
	"servicenow":           "ServiceNow — ITSM/CMDB records + workflows",
	"pagerduty":            "PagerDuty — on-call schedules + incident API",
	"linear":               "Linear — issues/projects + member data",
	"asana":                "Asana — tasks/projects + workspace members",
	"notion":               "Notion — workspace pages/databases (often secrets/PII)",
	"zendesk":              "Zendesk — support tickets (customer PII)",
	"intercom":             "Intercom — conversations & customer profiles (PII)",
	"discord_bot":          "Discord bot — guild/message access per intents",
	"telegram_bot":         "Telegram bot — send/read in its chats",
	"zoom":                 "Zoom — meetings, recordings, user admin (S2S OAuth)",
	"vonage":               "Vonage — SMS/voice send (billed)",
	"sendgrid":             "SendGrid — email send + template/contact access",
	"mailgun":              "Mailgun — email send + logs (recipient PII)",
	"mailchimp":            "Mailchimp — audience export (subscriber PII) + send",
	"postmark":             "Postmark — transactional email send + history",
	"brevo":                "Brevo — email/SMS + contact PII",
	"square":               "Square — payments + customer data (financial)",
	"hubspot":              "HubSpot — CRM contacts/deals (PII)",
	"shopify":              "Shopify — store orders/customers (PII) + admin",
	"docusign":             "DocuSign — envelopes/agreements (legal docs)",
	"dropbox":              "Dropbox — file access per scope",
	"box":                  "Box — file/folder access; admin = all content",
	"airtable":             "Airtable — base data (often PII/secrets)",
	"algolia":              "Algolia — search index read/write; admin key = full",
	"confluent":            "Confluent Cloud — Kafka cluster & topic admin",
	"linode":               "Linode — compute, storage, DNS account control",
	"cloudflare":           "Cloudflare — DNS/zones/Workers per token scope",
	"cloudflare_global":    "Cloudflare Global API Key — full account control",
	"fastly":               "Fastly — CDN config, edge purge/secrets",
	"netlify":              "Netlify — site deploy + build env vars",
	"vercel":               "Vercel — project deploy + env vars",
	"heroku":               "Heroku — app deploy + config-vars (downstream secrets)",
	"terraform_cloud":      "Terraform Cloud — workspace state & variables (often secrets)",
	"digitalocean":         "DigitalOcean — droplets, databases, Spaces, Kubernetes",
	"digitalocean_oauth":   "DigitalOcean OAuth — account API access",
}

func main() {
	dummy := []module.Finding{{Key: "reach", Value: "x", Flag: module.FlagInfo}}
	summary := map[string]string{}
	for _, m := range module.Default.All() {
		summary[m.Name()] = m.Summarize("x", dummy).Summary
	}
	placed := map[string]bool{}

	for _, g := range groups {
		fmt.Printf("\n**%s**\n\n| Credential / app | Reach |\n|---|---|\n", g.title)
		for _, n := range g.names {
			placed[n] = true
			fmt.Printf("| `%s` | %s |\n", n, reachOf(n, summary))
		}
	}

	// Anything registered but not placed in a group (e.g. a newly added module).
	var leftover []string
	for n := range summary {
		if !placed[n] {
			leftover = append(leftover, n)
		}
	}
	sort.Strings(leftover)
	if len(leftover) > 0 {
		fmt.Printf("\n**Uncategorized (add to a group in tools/coverage)**\n\n| Credential / app | Reach |\n|---|---|\n")
		for _, n := range leftover {
			fmt.Printf("| `%s` | %s |\n", n, reachOf(n, summary))
		}
	}
	fmt.Printf("\n_%d credential types_\n", len(summary))
}

func reachOf(name string, summary map[string]string) string {
	if r, ok := reach[name]; ok {
		return r
	}
	if s := summary[name]; s != "" {
		// trim a leading "<Name> — " so the table reads cleanly.
		return s
	}
	return "—"
}
