# How geiger works

**Pipeline:** recognize → (authenticate) → recon → note. Recon runs the
identity/whoami call first, then a couple of count calls to gauge how much the
credential reaches.

## Safety model

**Read-only.** One client allows only `GET` / `HEAD` plus a short allowlist of
read-only POSTs: STS `GetCallerIdentity`, k8s `SelfSubjectRulesReview`, and the
single OAuth token exchange. DB recon uses a read-only session and a fixed query
allowlist. Local stores (SQLite, IDE `state.vscdb`, Firefox `key4.db`) open
read-only. A guard test enforces this across every module.

**Dry-run by default.** `--live` is required and always prints the destinations it
hits (real provider APIs, and their audit logs).

**Attribution.** Recon identifies itself as `geiger/<version>`. This is dual-use,
so there is no detection evasion: defenders can attribute the calls.

**Secrets are not printed or stored.** They are redacted everywhere, and scrubbed
from URLs, headers, and errors.

**Untrusted-input hardening.** geiger refuses cloud-metadata targets (SSRF),
sanitizes hostile API responses, and strips file-referencing DSN options.

**Endpoint provenance.** A host read out of scanned data is untrusted: a planted
URL would otherwise aim a real credential at whoever planted it. Every module
declares where its credential may go, enforced centrally at recognition time. A
SaaS module is pinned to its vendor's domains, `--endpoint` outranks anything in
the file, and a violation degrades to "needs endpoint" instead of dialing.
Self-hosted services can live at any domain, so those are not pinned; their
destination is flagged in the note instead.

## What geiger does not do

geiger reports likely impact, not exact impact. It triages a credential; it does
not build a full cloud privilege-escalation graph. Use PMapper, CloudFox, or
ScoutSuite for that.

## Authorized use only

geiger exercises live credentials. Run it only on credentials you are entitled to
triage.
