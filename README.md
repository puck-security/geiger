<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/geiger-lockup-dark.svg">
  <img alt="geiger" src="assets/geiger-lockup-light.svg" width="312">
</picture>

When a leaked credential turns up or a device is compromised, the critical question
is **is it still live, what does it reach, and how bad?** Your secret scanner might
have found the key but it won't answer that.

`geiger` does. Pipe credential-bearing text at it: it recognizes the credentials
inside, runs **read-only** recon with each, and prints what it is and what it can
reach — ranked by blast radius.

```
$ cat ~/.aws/credentials | geiger --live
[HIGH] aws …JV3Q (from ~/.aws/credentials: [default])
  identity : arn:aws:iam::1234567890:user/ci-deploy   (IAM user)
  account  : 1234567890
  alias    : acme-production   ⚠
  buckets  : 47 visible — incl. acme-prod-customer-backups   ⚠
  secrets  : can list 31 secrets   ⚠⚠ force multiplier
  → prod account + secrets access
```

Dual-use triage: an incident responder's *"how bad is this?"* and a pentester's
*"what does this key reach?"*. Read-only by construction and dry-run by default.

---

## Install

**Binary** — grab the archive for your OS/arch from [Releases](../../releases):

```sh
tar xzf geiger_*_linux_amd64.tar.gz && sudo mv geiger /usr/local/bin/
```

**Source** (Go 1.25+):

```sh
git clone https://github.com/puck-security/geiger && cd geiger
go build -o geiger ./cmd/geiger
```

---

## Tutorial

geiger doesn't touch anything on the network until you say so. Dry-run first 
(default): recognizes the credential and prints the read-only calls it *would*
make.

```sh
echo 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' | geiger
```

Add `--live` to actually run them and get the impact note:

```sh
echo 'GITHUB_TOKEN=ghp_...' | geiger --live
```

---

## How-to

```sh
# a file, stdin, or a cloud CLI's output
geiger --live .env
cat sso-cache.json | geiger --live
aws configure export-credentials | geiger --live

# the current environment
geiger --env --live

# a whole repo / dir (walked; results sorted by impact)
geiger --live ./leaked-repo

# a scanner's report — e.g. a TruffleHog sweep of a compromised laptop,
# exactly what supply-chain worms (Shai-Hulud) run; triage which creds reach prod
geiger --live --from-trufflehog trufflehog.json
geiger --live --from-gitleaks gitleaks-report.json

# rank by YOUR crown jewels (boost anything touching these to HIGH+)
geiger --live --context '1234567890,acme-prod,billing-service' ./repo

# self-hosted services need a host
echo 'VAULT_TOKEN=hvs....' | geiger --live --endpoint https://vault.internal:8200

# only what matters; save a clean artifact
geiger --live --min-severity high -o case-1234.txt ./repo

# OPSEC: identity call only; route egress through a proxy
geiger --live --min-footprint --proxy socks5://127.0.0.1:9050 .env

# machine-readable
geiger --live --json ./repo | jq .
```

**Go deeper — `--intrusive`** (still read-only): connects to databases (Postgres,
MySQL, MongoDB, Redis, SQL Server, Oracle, ClickHouse, Cassandra — fixed catalog
queries, read-only session), reads local SQLite/IDE stores in place, hits cluster
APIs, and **follows secrets-store reads** — draining Vault/Doppler/1Password/cloud
secret managers (AWS SM, GCP SM, Azure Key Vault) and recursively triaging each
extracted secret. The same fan-out a worm performs, so you see the *real* blast
radius.

```sh
geiger --live --intrusive .env
```

**SSH keys** — point it at a directory; it fingerprints each key (encrypted keys
are *locked*, not dead). `--ssh-correlate` lists candidate target hosts from
`~/.ssh/config`, `known_hosts`, and shell history.

```sh
geiger --ssh-correlate ~/.ssh
```

---

## Reference

### Flags

| Flag | Effect |
|---|---|
| *(stdin / files / dirs)* | input source; multiple files/dirs may be passed, and a directory is walked |
| `--live` | make read-only recon calls (default: dry-run) |
| `--intrusive` | connect to DBs / cluster APIs, read local stores, harvest downstream secrets (needs `--live`) |
| `--min-footprint` | identity call only; skip inventory fan-out |
| `--env` | read current environment variables |
| `--endpoint URL` | host/instance for self-hosted & set-shaped creds |
| `--proxy URL` | route HTTP recon via http/https/socks5 proxy |
| `--timeout DUR` | per-credential recon timeout (default `15s`) |
| `--concurrency N` | credentials reconned at once on `--live` (default `8`) |
| `--context TERMS` | comma-separated crown-jewel terms; a match raises tier |
| `--min-severity TIER` | only print findings at or above a tier (`critical`/`high`/`medium`/`low`/`info`/`dead`); `dead` is the floor, so `info` excludes dead and `high` keeps only critical+high |
| `-o, --output FILE` | write results to FILE instead of stdout (`0600`, color off; status stays on stderr) |
| `--json` | machine-readable output (NDJSON, one note per line) |
| `--stream` | print results as found (discovery order) instead of sorted by impact |
| `--only TYPES` / `--skip TYPES` | scope by module name or category (`databases`,`cloud`,`secrets`,`ai`,`vcs`,`kubernetes`,`identity`,`backup`,`endpoint`) |
| `--from-gitleaks F` / `--from-trufflehog F` | triage each finding in a scanner report |
| `--ssh-correlate` | SSH: read local hints for candidate target hosts |
| `--trace` | print the raw request + response of each call (secrets masked) |
| `--user-agent UA` | User-Agent for recon calls (default `geiger/<version>`) |
| `--color MODE` | `auto` (default, off when piped) / `always` / `never` |
| `-v` / `-q` | show planned/executed calls (and full finding detail) / quiet stderr |
| `--version` | print version |

### Tiers

`CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` · `DEAD` — a composite blast-radius
score (capability × reach × sensitivity), relative not absolute. `--context`
matches and force-multiplier capabilities force at least `HIGH`.

### What geiger reads — and what it can't

geiger triages a credential **you were handed**, or one **sitting on disk**.

- **In scope — on-disk / offline-readable.** API tokens, connection strings,
  cloud CLI caches (`~/.aws`, gcloud, MSAL), SSH keys, kubeconfigs, secrets-manager
  creds, MCP configs, AI-IDE plaintext token stores, password-manager *recovery
  material* (KeePass, encrypted Bitwarden — offline-crackable with the master
  password), plaintext exports, and Firefox saved logins (`logins.json` +
  `key4.db`), which decrypt offline when no primary password is set.
- **Out of scope — in-process / OS-bound.** Chromium passwords & cookies (wrapped
  by DPAPI / macOS Keychain / Secret Service), raw DPAPI blobs, the macOS
  Keychain, LSASS. Reading those means decrypting against a live OS session —
  credential *extraction from a host*, not triage of one. Not always a black and white line.

### Coverage

Recognition rides on [gitleaks](https://github.com/gitleaks/gitleaks)
(shape/checksum) plus geiger's own shape/env-name recognizers; an unrecognized
type is reported `unknown, not characterized`. Triage keys on capability — a
key that runs code, wipes devices, restores backups, or reads *other* secrets is
a force multiplier; a billed-usage API key is a warning.

<details>
<summary><b>Full coverage — 163 credential types</b> (regenerate with <code>go run ./tools/coverage</code>)</summary>

**Cloud & hosting**

| Credential / app | Reach |
|---|---|
| `aws` | AWS account — IAM-scoped access across all AWS services |
| `aws_sso` | active SSO session |
| `aws_sso_registration` | SSO client registration (no session) |
| `gcp_service_account` | GCP service account — exchanged a read-only token |
| `gcp_adc` | gcloud user credentials — delegated user access |
| `azure_msal` | Azure CLI session — Entra identity, refreshable headlessly |
| `digitalocean` | DigitalOcean — droplets, databases, Spaces, Kubernetes |
| `digitalocean_oauth` | DigitalOcean OAuth — account API access |
| `linode` | Linode — compute, storage, DNS account control |
| `cloudflare` | Cloudflare — DNS/zones/Workers per token scope |
| `cloudflare_global` | Cloudflare Global API Key — full account control |
| `fastly` | Fastly — CDN config, edge purge/secrets |
| `heroku` | Heroku — app deploy + config-vars (downstream secrets) |
| `render` | Render — deploy (code exec) + env-secret access |
| `railway` | Railway — deploy (code exec) + project-variable access |
| `flyio` | Fly.io — machine deploy (code exec) + app-secret access |
| `netlify` | Netlify — site deploy + build env vars |
| `vercel` | Vercel — project deploy + env vars |
| `tailscale` | Tailscale — tailnet device/ACL admin + auth-key minting |
| `terraform_cloud` | Terraform Cloud — workspace state & variables (often secrets) |
| `oci_config` | Oracle Cloud — API signing config (key_file referenced, not inline) |

**Source control & packages**

| Credential / app | Reach |
|---|---|
| `github_pat` | GitHub — repo read/write/admin, org membership, Actions |
| `gitlab` | GitLab — repo/project access per token scope |
| `gitlab_ci_token` | GitLab CI job token — pipeline-scoped repo/registry access |
| `jfrog` | JFrog Artifactory — artifact read/write + package admin |
| `docker_registry` | container registry — pull/push images (supply-chain) |
| `npm` | npm — publish/yank packages (supply-chain) |
| `pypi` | PyPI — publish packages (supply-chain) |
| `rubygems` | RubyGems — publish gems (supply-chain) |

**CI/CD & build**

| Credential / app | Reach |
|---|---|
| `buildkite` | Buildkite — pipelines + build-agent access |
| `circleci` | CircleCI — pipelines + project env vars |

**Databases & data platforms**

| Credential / app | Reach |
|---|---|
| `db_connection_string` | direct DB data-plane (pg/mysql/mongo/redis/mssql/oracle/clickhouse/cassandra/sqlite) |
| `snowflake` | Snowflake — data-warehouse access (account-wide at ACCOUNTADMIN) |
| `databricks` | Databricks — workspace, jobs, notebooks, data |
| `mongodb_atlas` | MongoDB Atlas service account — Admin API access to orgs/projects/clusters |
| `supabase` | Supabase service_role — RLS-bypass full DB + auth admin |
| `planetscale` | PlanetScale service token — database & branch admin |
| `neon` | Neon API key — Postgres project & role admin |
| `aiven` | Aiven token — managed-service & credential admin |
| `upstash` | Upstash management API — database & token admin |
| `redis_cloud` | Redis Cloud API — subscription & database admin |
| `clickhouse_cloud` | ClickHouse Cloud API key — service & member control |
| `clickhouse_selfhosted` | ClickHouse (self-hosted) — SQL data & user access |
| `plaid` | Plaid keys — bank-account data access (financial PII) |

**AI / LLM & agentic**

| Credential / app | Reach |
|---|---|
| `openai` | OpenAI — model access, files/fine-tunes; org-owner = key/billing admin |
| `anthropic` | Anthropic — Claude model access (billed) |
| `claude_code_oauth` | Claude Code / Claude subscription OAuth token — acts as the signed-in user |
| `gemini` | Google Gemini — generative API (billed usage) |
| `azure_openai` | Azure OpenAI — resource model access (billed usage) |
| `cohere` | Cohere — LLM API access (billed) |
| `mistral` | Mistral — LLM API access (billed) |
| `replicate` | Replicate — model runs (billed) + model access |
| `huggingface` | Hugging Face — model/dataset access; write token can push |
| `groq` / `together` / `deepseek` / `openrouter` / `xai` / `fireworks` | LLM API access (billed usage) |
| `perplexity` | Perplexity — LLM API (billed usage) |
| `elevenlabs` | ElevenLabs — voice API (billed usage + voice library) |
| `stability` | Stability AI — image API (billed usage) |
| `pinecone` | Pinecone — vector index read/write (embedded data) |
| `mcp_config` | MCP config — agent credential aggregator (extracts + re-triages embedded secrets) |
| `ai_ide_store` | AI-IDE token store (Cursor/VS Code `state.vscdb`, plaintext) |

**Secrets managers & vaults**

| Credential / app | Reach |
|---|---|
| `vault` | HashiCorp Vault — read secrets per policy |
| `conjur` | CyberArk Conjur — secrets-manager access (reads downstream secret values) |
| `cyberark_pvwa` | CyberArk PVWA — privileged-account vault access |
| `infisical` | Infisical — secret-store read across authorized projects |
| `akeyless` | Akeyless — secret-store read (list-items / get-secret-value) |
| `delinea_secret_server` | Delinea/Thycotic Secret Server — vaulted-secret read access |
| `doppler` | Doppler — project config/secret access |
| `onepassword_connect` | 1Password Connect — vault item access via the Connect server |
| `onepassword_sa` | 1Password service account — vault secret access (CLI/SDK only) |
| `onepassword_secret_key` | 1Password Secret Key — vault-unlock half; dangerous with the master password |
| `bitwarden` | Bitwarden API key — enumerates the vault (items encrypted without the master password) |
| `bitwarden_vault` | Bitwarden encrypted vault — offline-crackable with the master password |
| `keepass_db` | KeePass vault — offline-crackable to every secret with the master password |
| `vault_export_plaintext` | plaintext credential dump — full account takeover across every listed site |

**Identity, SSO & directory**

| Credential / app | Reach |
|---|---|
| `okta` | Okta — directory, SSO apps, admin per scope |
| `pingone` | PingOne — identity & SSO admin |
| `pingfederate` | PingFederate admin API — OAuth client & federation-trust control |
| `entra_sp` | Microsoft Entra service principal — Graph/Azure per app roles |
| `jumpcloud` | JumpCloud — directory, device & SSO admin |
| `sailpoint` | SailPoint — identity governance (certs, provisioning) |
| `auth0` | Auth0 — tenant management API (users, apps, rules) |
| `duo` | Duo — MFA admin API (bypass codes, user mgmt) |
| `workday` | Workday — HR/finance records (PII) |

**Endpoint, MDM, RMM & config-mgmt**

| Credential / app | Reach |
|---|---|
| `ninjaone` | NinjaOne RMM — script execution + remote control across endpoints |
| `atera` | Atera RMM/PSA — full agent & customer inventory |
| `kandji` | Kandji MDM — device inventory + remote lock/erase |
| `jamf` | Jamf Pro — script execution + MDM lock/wipe |
| `mosyle` | Mosyle MDM — device control incl. remote wipe/lock |
| `automox` | Automox — patch policies + worklet script execution across endpoints |
| `tanium` | Tanium — package deploy + action execution across endpoints |
| `ansible_awx` | Ansible AWX/Tower — playbook execution across managed hosts |
| `puppet_enterprise` | Puppet Enterprise — orchestrator task/plan execution on nodes |
| `saltstack` | SaltStack salt-api — arbitrary module execution across minions |
| `fleet` | Fleet (osquery) — live queries + script execution + MDM wipe |

**Monitoring, observability & security posture**

| Credential / app | Reach |
|---|---|
| `datadog` | Datadog — metrics/logs/APM + monitor & key admin |
| `newrelic` | New Relic — telemetry + account admin |
| `grafana` | Grafana — dashboards/datasources; server-admin = full |
| `splunk` | Splunk — search over all data + scripted-input command execution |
| `sumologic` | Sumo Logic — log search (secrets/PII) + collector admin |
| `dynatrace` | Dynatrace — observability data + config API |
| `honeycomb` | Honeycomb — event data + query API |
| `sentry` | Sentry — error events (may hold secrets/PII) + org admin |
| `zabbix` | Zabbix — global script execution on monitored hosts |
| `auvik` | Auvik — network topology & device inventory |
| `manageengine_opmanager` | ManageEngine OpManager — device management + workflow script execution |
| `lacework` | Lacework — cloud security posture across connected accounts |
| `wiz` | Wiz — cloud security graph (findings, identities, secrets) |
| `snyk` | Snyk — code/dependency vuln data + org project access |

**Backup & DR**

| Credential / app | Reach |
|---|---|
| `veeam` | Veeam Backup & Replication — job control + restores |
| `acronis` | Acronis Cyber Protect — backup/restore + agent control |
| `cohesity` | Cohesity — protection-job & restore control |
| `netbackup` | Veritas NetBackup — policy & restore control |
| `commvault` | Commvault — backup/restore + client management |

**ITSM, productivity & support**

| Credential / app | Reach |
|---|---|
| `servicenow` | ServiceNow — ITSM/CMDB records + workflows |
| `jira` | Jira (Atlassian Cloud) — full issue/project read + user-directory PII |
| `ivanti` | Ivanti ITSM — incident/CMDB access + employee PII |
| `snipeit` | Snipe-IT — asset/license inventory + user PII |
| `pagerduty` | PagerDuty — on-call schedules + incident API |
| `linear` | Linear — issues/projects + member data |
| `asana` | Asana — tasks/projects + workspace members |
| `notion` | Notion — workspace pages/databases (often secrets/PII) |
| `zendesk` | Zendesk — support tickets (customer PII) |
| `intercom` | Intercom — conversations & customer profiles (PII) |

**Comms, email & SMS**

| Credential / app | Reach |
|---|---|
| `slack` | Slack — messages, files, users per token scope |
| `discord_bot` | Discord bot — guild/message access per intents |
| `telegram_bot` | Telegram bot — send/read in its chats |
| `zoom` | Zoom — meetings, recordings, user admin (S2S OAuth) |
| `twilio` | Twilio — SMS/voice send (billed) + message logs (PII) |
| `vonage` | Vonage — SMS/voice send (billed) |
| `sendgrid` | SendGrid — email send + template/contact access |
| `mailgun` | Mailgun — email send + logs (recipient PII) |
| `mailchimp` | Mailchimp — audience export (subscriber PII) + send |
| `postmark` | Postmark — transactional email send + history |
| `brevo` | Brevo — email/SMS + contact PII |

**Payments, CRM & SaaS data**

| Credential / app | Reach |
|---|---|
| `stripe` | Stripe — charges/customers/payouts (a live key moves money) |
| `square` | Square — payments + customer data (financial) |
| `coinbase` | Coinbase — account access (financial; can move funds) |
| `salesforce` | Salesforce — CRM object access (customer PII) |
| `hubspot` | HubSpot — CRM contacts/deals (PII) |
| `shopify` | Shopify — store orders/customers (PII) + admin |
| `klaviyo` | Klaviyo — customer-profile export (PII) + campaign send |
| `braze` | Braze — message-send to all users + profile export (PII) |
| `segment` | Segment — customer event-pipeline access (behavioral PII) |
| `mixpanel` / `amplitude` | product-analytics data (behavioral PII) |
| `customerio` | Customer.io — messaging + customer data (PII) |
| `docusign` | DocuSign — envelopes/agreements (legal docs) |
| `dropbox` | Dropbox — file access per scope |
| `box` | Box — file/folder access; admin = all content |
| `airtable` | Airtable — base data (often PII/secrets) |
| `algolia` | Algolia — search index read/write; admin key = full |
| `confluent` | Confluent Cloud — Kafka cluster & topic admin |

**Local credential stores & keys**

| Credential / app | Reach |
|---|---|
| `ssh_private_key` | SSH private key — local fingerprint only |
| `kubeconfig` | kubeconfig — cluster credential |
| `firefox_logins` | Firefox saved logins — offline-decrypted when no primary password |
| `jwt` | decoded offline — map issuer to its provider for live recon |
| `generic_secret` | unrecognized credential (matched by name) |
| `needs_endpoint` | recognized — provide `--endpoint` to characterize |

Plus the dev-laptop / supply-chain on-disk stores read natively:
`~/.docker/config.json`, `~/.npmrc`, `~/.netrc`, `~/.git-credentials`, the `gh`
CLI `hosts.yml`, `~/.databrickscfg`, Snowflake `connections.toml`, the Terraform
CLI `credentials.tfrc.json`, `~/.vault-token`, Fly.io `config.yml`, `~/.oci/config`,
Terraform state, and AWS-INI / GCP-SSO-MSAL JSON caches.

Bug reports and PRs welcome.

</details>

### Output

A block per credential: a tier, a redacted title with the source location, never
the raw secret, labeled findings (`⚠` notable, `⚠⚠` force multiplier, `?`
can't-determine-read-only), and a one-line takeaway.

**For IR**, each finding leads with *where* and *when*: an `exposure` line
classifies the source — a **crash dump** (in-memory, persisted to disk, often
auto-uploaded — may have left the host), a VS Code **local-history snapshot**, an
IDE secret store, shell history, a log — and `source modified` / `validated live`
carry the file mtime and live-check timestamp. When a secret turns up in several
files, `also exposed in` groups them by class (`8 local-history snapshots; 7
crash dumps`) instead of listing paths (the full list expands under `-v` and in
`--json`).

With `-v` each planned call prints as a copy-pasteable `curl`. Triaging more than
one credential prints a closing **summary** — tier breakdown, rotate-first queue,
and follow-ups (secrets-store reach, what couldn't be characterized, anything
hidden by `--min-severity`). GitHub write/admin and org-admin are read from each
repo's `permissions` and `/user/memberships/orgs`, so they're reported even for
fine-grained PATs that expose no scopes.

**Drift resilience.** Beyond declared field paths, every response is scanned
heuristically (admin/owner indicators → force multiplier; a fallback identity +
count when the API shape changed), so a module stays useful as providers rename
fields. `--trace` shows the raw request/response (secrets masked).

---

## How it works

**Pipeline:** recognize → (authenticate) → recon → note. Recon runs the
identity/whoami call first, then a couple of count calls to size reach.

**Safety model**
- **Read-only by construction.** One client allows only `GET`/`HEAD` plus a short
  allowlist of read-only POSTs (STS `GetCallerIdentity`, k8s
  `SelfSubjectRulesReview`, the single OAuth token exchange). DB recon uses a
  read-only session and a fixed query allowlist. Local stores (SQLite, IDE
  `state.vscdb`, Firefox key4.db) open read-only. A guard test enforces this
  across every module.
- **Dry-run by default.** `--live` is required and always prints the destinations
  it hits (real provider APIs, and their audit logs).
- **Attribution.** Recon identifies itself as `geiger/<version>` — dual use beware, 
  no detection evasion; defenders can attribute the calls.
- **Secrets are not printed or stored.** Redacted everywhere; scrubbed from URLs,
  headers, and errors.
- **Untrusted-input hardening.** Refuses cloud-metadata targets (SSRF), sanitizes
  hostile API responses, strips file-referencing DSN options

**Principle: likely impact, not perfect impact.** 
geiger is triage, *not* deep cloud-privesc graphing (use PMapper/CloudFox/ScoutSuite/etc for that).

**Authorized use only.** geiger exercises live credentials — run it only on creds
you are entitled to triage.

---

## Contributing a module

Most providers are a few lines of declarative recipe:

```go
add("digitalocean-pat", recipe.HTTP{
    ModuleName: "digitalocean", Base: "https://api.digitalocean.com",
    Auth:   recipe.AuthSpec{Kind: recipe.Bearer},
    Whoami: recipe.GET("/v2/account").Field("email", "account.email"),
    Calls:  []recipe.Call{recipe.GET("/v2/droplets").CountFrom("meta.total", "droplets")},
}.Module())
```

Add an `httptest`-backed test, then `go run ./tools/coverage` to refresh the
coverage table above. Exotic signing (SigV4, RS256-JWT, Digest) implements the
`module.Module` interface directly with the `internal/sign` + `internal/auth`
helpers — see `internal/modules/` for examples.
