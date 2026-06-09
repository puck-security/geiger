<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/geiger-lockup-dark.svg">
  <img alt="geiger" src="assets/geiger-lockup-light.svg" width="312">
</picture>

**Detection tells you a key is real; geiger tells you whether it's dangerous.**

Pipe credential-bearing text at geiger. It recognizes the credentials inside,
runs read-only recon with each, and prints what it is and what it can reach.

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

Dual-use credential triage: a leaked-secret responder's "how bad is this?" and a
pentester's "what does this key reach?". Read-only by design, dry-run by default.

---

## Install

**Binary** — grab the archive for your OS/arch from [Releases](../../releases), then:

```sh
tar xzf geiger_*_linux_amd64.tar.gz && sudo mv geiger /usr/local/bin/
```

**Source** (Go 1.25+):

```sh
git clone https://github.com/puck-security/geiger && cd geiger
go build -o geiger ./cmd/geiger
```

---

## Tutorial — first run

geiger does nothing to the network until you say so. Start in dry-run (default):

```sh
echo 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' | geiger
```

It recognizes the token and prints the read-only calls it *would* make. Add
`--live` to actually run them and get the impact note:

```sh
echo 'GITHUB_TOKEN=ghp_...' | geiger --live
```

That's the whole loop: **dry-run to see the plan, `--live` to characterize.**

---

## How-to

**Triage a file or stdin**

```sh
geiger .env                       # a file
geiger --live .env
cat sso-cache.json | geiger --live
aws configure export-credentials | geiger --live
```

**Triage your current environment**

```sh
geiger --env --live
```

**Triage a whole repo / directory** (results sorted by impact)

```sh
geiger --live ./leaked-repo
```

**Triage a scanner's output**

```sh
geiger --live --from-gitleaks gitleaks-report.json
geiger --live --from-trufflehog trufflehog.json
```

TruffleHog over a home directory and git history is exactly what recent
supply-chain worms (Shai-Hulud) run on a compromised dev laptop — feed geiger
that same dump to triage which of the found secrets actually reach prod.

**Rank by *your* crown jewels** — boost anything touching these assets to HIGH+:

```sh
geiger --live --context '1234567890,acme-prod,billing-service' ./repo
```

**Stay quiet (OPSEC)** — identity call only, skip the inventory fan-out:

```sh
geiger --live --min-footprint .env
```

**Route egress through a proxy**

```sh
geiger --live --proxy socks5://127.0.0.1:9050 .env
```

**Go deeper (intrusive, read-only)** — connect to databases (PostgreSQL, MySQL,
MongoDB, Redis, SQL Server, Oracle, ClickHouse, Cassandra — fixed read-only
catalog queries; counts tables/keyspaces and flags sensitive ones), read local
SQLite files in place, hit cluster APIs, and follow secrets-store reads to
harvest + triage downstream creds. Cloud
secrets managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) are
drained read-only and each extracted secret is recursively triaged — the same
fan-out a supply-chain worm performs, so you see the *real* blast radius:

```sh
geiger --live --intrusive .env
```

**Supply a host for self-hosted services** (Vault, GitLab, Grafana, …)

```sh
echo 'VAULT_TOKEN=hvs....' | geiger --live --endpoint https://vault.internal:8200
```

**Machine-readable output**

```sh
geiger --live --json ./repo | jq .
```

**Triage SSH keys** — point it at the directory; it fingerprints each key.
Encrypted keys are reported as *locked* (not dead — still usable if the
passphrase is weak or loaded in `ssh-agent`). Add `--ssh-correlate` to also list
candidate target hosts from `~/.ssh/config`, `known_hosts`, and shell history.

```sh
geiger ~/.ssh
geiger --ssh-correlate ~/.ssh
```

---

## Reference

### Flags

| Flag | Effect |
|---|---|
| *(stdin / files / dirs)* | input source; multiple files/dirs may be passed, and a directory is walked |
| `--live` | make read-only recon calls (default: dry-run) |
| `--intrusive` | connect to DBs / cluster APIs, harvest downstream secrets (needs `--live`) |
| `--min-footprint` | identity call only; skip inventory fan-out |
| `--env` | read current environment variables |
| `--endpoint URL` | host/instance for self-hosted & set-shaped creds |
| `--proxy URL` | route HTTP recon via http/https/socks5 proxy |
| `--context TERMS` | comma-separated crown-jewel terms; a match raises tier |
| `--ssh-correlate` | SSH: read local hints for candidate target hosts |
| `--trace` | print the raw request + response of each call (secrets masked) |
| `--color MODE` | `auto` (default, off when piped) / `always` / `never` |
| `--from-gitleaks F` | triage each finding in a gitleaks JSON report |
| `--from-trufflehog F` | triage each finding in a TruffleHog v3 JSON report |
| `--json` | machine-readable output |
| `--stream` | print results as found (discovery order) instead of sorted by impact |
| `--only TYPES` | scope recon to module names or categories (`databases`,`cloud`,`secrets`,`ai`,`vcs`,`kubernetes`,`identity`,`backup`,`endpoint`) |
| `--skip TYPES` | exclude module names or categories from recon |
| `--user-agent UA` | User-Agent for recon calls (default `geiger/<version>`) |
| `-v` | show planned/executed calls |
| `-q` | quiet: suppress the stderr status header and progress line |
| `--version` | print version |

### Tiers

`CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO` · `DEAD` — a composite
blast-radius score (capability × reach × sensitivity), relative not absolute.
`--context` matches force at least `HIGH`.

### Coverage

~80 modules across AWS/GCP/Azure, GitHub/GitLab, Slack, Stripe, OpenAI/Anthropic,
Datadog, Vault, Snowflake, databases, Kubernetes, SSH, JWTs, and more —
including enterprise IdP / IGA / PAM and secrets managers: Okta, PingOne,
SailPoint, JumpCloud, ServiceNow, Workday, Duo, CyberArk (PVWA + Conjur),
Confluent, Doppler, and 1Password. Recognition rides on
[gitleaks](https://github.com/gitleaks/gitleaks) plus shape/env-name
recognizers; an unrecognized type is reported `unknown, not characterized`.

**Dev-laptop & supply-chain.** geiger also reads the local credential stores a
compromised laptop leaks — `~/.docker/config.json` (registry push = backdoored
image), `~/.npmrc`, `~/.netrc`, gcloud/`az` token caches, and Terraform state —
and can ingest a `--from-trufflehog`/`--from-gitleaks` scan of a home dir. Under
`--intrusive` it drains cloud and standalone secrets managers (AWS/GCP/Azure,
Conjur, Doppler, 1Password, Duo integration keys) and recursively triages every
secret it pulls, so you see the actual downstream blast radius. Structured stores are
parsed natively — AWS INI, GCP/SSO/MSAL JSON caches, and the gcloud SQLite
credential database (`~/.config/gcloud/credentials.db`).

**Password managers.** geiger triages what a leaked machine exposes. A 1Password
Secret Key (Emergency Kit), a KeePass `.kdbx`, and an encrypted Bitwarden vault
are flagged as *recovery material* — high-impact but honestly marked
can't-validate, since they need the master password (they're offline-crackable,
not read-only-exercisable). A **plaintext export** (unencrypted Bitwarden JSON,
LastPass/Dashlane CSV) is a cleartext credential dump: it's ranked accordingly
and each contained login is fanned out so any API key inside is recognized and
triaged on its own. A Bitwarden **API key** (`BW_CLIENTID`/`BW_CLIENTSECRET`) is
exercised read-only to size the vault and list org memberships — though items
stay encrypted without the master password. (Proton Pass and Apple iCloud
Keychain recovery is a passphrase/recovery key with no on-disk artifact to
fingerprint.)

**IT / endpoint / backup platforms.** geiger also triages the operational tokens
that grant remote control of a fleet — recognized by their conventional env-var
names (and `--endpoint` for self-hosted servers), since most have no distinctive
token shape. Coverage spans RMM/MDM/config-management (NinjaOne, Atera, Kandji,
Jamf, Mosyle, Automox, Tanium, Ansible/AWX, Puppet, SaltStack, Fleet), monitoring
(Zabbix, Splunk, Auvik, ManageEngine OpManager), backup/DR (Veeam, Acronis,
Cohesity, NetBackup, Commvault), and ITSM/IAM/asset/DB (Jira, Ivanti,
PingFederate, Snipe-IT, ClickHouse). The crucial signal is the *control*
capability: a credential that can **run scripts/commands across endpoints, wipe
devices, or restore/overwrite backups** is flagged a force multiplier — geiger
names that capability but, being read-only, never invokes it. (Not yet wired:
Chef and Backblaze B2 need bespoke request-signing/flows; MongoDB Atlas legacy
keys use HTTP Digest; StrongDM is gRPC-only; osquery and Spiceworks have no
exercisable API credential.)

**Data, SaaS & AI.** Beyond the cloud/VCS/SaaS catalog, geiger covers data
warehouses and managed databases (Snowflake, Salesforce, Supabase service_role,
PlanetScale, Neon, Aiven, Upstash, Redis Cloud, Plaid), security & PaaS (Sumo
Logic, Lacework, Wiz, Tailscale, Render, Railway, Fly.io), marketing/analytics
PII (Klaviyo, Braze — plus Segment/Mixpanel/Amplitude/Customer.io recognized and
flagged), and AI providers (Google Gemini, Azure OpenAI, Groq, Together,
DeepSeek, ElevenLabs, Stability, Pinecone, Perplexity, Coinbase). The triage
keys on *capability*: a service_role key (RLS bypass), a deploy token (code
execution), or a vector index (embedded proprietary data) is flagged a force
multiplier; an LLM key (billed usage) is a warning.

**More device-local stores.** On top of the cloud caches and dev-laptop files
above, geiger reads `~/.git-credentials` (plaintext VCS tokens), the `gh` CLI
`hosts.yml`, `~/.databrickscfg`, Snowflake `connections.toml`, the Terraform CLI
`credentials.tfrc.json`, `~/.vault-token`, Fly.io's `config.yml`, and `~/.oci/config`
— pairing the host with the token and routing to that service's module.

### Output

One block per credential: a tier, a redacted title with the source location
(`… (from .env:42: GITHUB_TOKEN)` — file and line where known), never the raw
secret, labeled findings (`⚠` notable, `⚠⚠` force multiplier, `?`
can't-determine-read-only), and a one-line takeaway. With `-v` (and in dry-run)
each planned call is printed as a copy-pasteable `curl` — swap the redacted
token for the real one to reproduce it. Triaging more than one credential prints
a closing **summary** — the tier breakdown, a rotate-first queue, and follow-up
actions (secrets-store reach, what couldn't be characterized). Output is colored
on a TTY and plain when piped, so redirects and `jq` stay clean.

For GitHub, write/admin access is read from each repo's `permissions` object and
org role from `/user/memberships/orgs` — so write/admin/org-admin are reported
even for fine-grained PATs that expose no scopes.

**Drift resilience.** Beyond each module's declared field paths, every response
is also scanned heuristically: admin/owner/root indicators (force multiplier),
emails/PII (warn), and — when the declared paths match nothing because the API
changed shape — a fallback identity and collection count. So a module keeps
returning *something* useful even as providers rename fields. Use `--trace` to
see the raw request/response (secrets masked) behind any finding.

---

## Explanation

**Pipeline:** recognize → (authenticate) → recon → note. Recon runs the
identity/whoami call first, then a couple of count calls to size reach.

**Safety model**
- **Read-only by construction.** One client allows only `GET`/`HEAD` plus a
  short allowlist of read-only POSTs (STS `GetCallerIdentity`, k8s
  `SelfSubjectRulesReview`, the single OAuth token exchange). DB recon uses a
  read-only session and a fixed query allowlist. A guard test enforces this
  across every module.
- **Dry-run by default.** Live calls hit real provider APIs (and their audit
  logs). `--live` is required; `--live` always prints the destinations it hit.
- **Honest attribution.** Recon identifies itself as `geiger/<version>` (override
  with `--user-agent`) — no detection evasion; defenders can attribute the calls.
- **Secrets never printed or stored.** Redacted everywhere, scrubbed from URLs,
  headers, and errors; nothing written to disk.
- **Untrusted-input hardening.** Refuses link-local targets (metadata SSRF),
  sanitizes hostile API responses, blocks MySQL `LOAD DATA LOCAL`.

**Principle: likely impact, not perfect impact.** A short honest note beats a
complete permission matrix. geiger is triage, *not* deep cloud-privesc graphing
(use PMapper/CloudFox/ScoutSuite for that).

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

Exotic signing (SigV4, RS256-JWT, Digest) implements the `module.Module`
interface directly using the `internal/sign` and `internal/auth` helpers. See
`internal/modules/` for examples; add an httptest fixture test.
