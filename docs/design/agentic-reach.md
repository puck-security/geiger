# Agentic reach: triaging what an agent's tool chain can touch

**Status:** implemented (initial pass)
**Scope:** `internal/agent`, `internal/modules/mcp_config.go`, `--spawn-stdio`

---

## The problem

geiger triages credentials. An MCP config is currently triaged *as a credential
container*: `internal/modules/mcp_config.go` counts servers, pulls inline secrets
out of `env` / `headers` / `args`, and re-triages each through its real provider
module. When the file carries no inline secret, the note reads:

```
inline secrets: no inline credentials (servers auth via OS env or external)
```

…and the finding lands at INFO.

That is the wrong answer for the common case. Consider a config with no inline
secrets at all:

```json
{
  "mcpServers": {
    "fs":         { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"] },
    "shell":      { "command": "uvx", "args": ["mcp-server-shell"] },
    "confluence": { "command": "npx", "args": ["-y", "mcp-atlassian"], "env": { "CONFLUENCE_URL": "..." } },
    "github":     { "url": "https://api.githubcopilot.com/mcp/" }
  }
}
```

Every credential here is stored correctly — OS env, a keychain, an OAuth flow.
geiger says INFO. The truth is that this agent can read every file on the box,
run arbitrary commands, search the whole corporate wiki, and push code. The
credential hygiene is irrelevant to the blast radius.

**The unit of blast radius for an agentic system is the tool chain, not the
credential.** That is what this design adds.

## What this is not

This is not a graph product. There is no node/edge export, no path visualiser,
no cross-host correlation — that is a different tool with a different shape.
geiger stays triage: *how bad is this, in what order do I deal with it.* The
composition analysis here exists only to produce **force-multiplier findings**
on a surface, in the same vocabulary as every other geiger note.

It is also not a content scanner. Whether a tool *description* contains a hidden
prompt injection is well covered by Snyk `agent-scan` (née Invariant `mcp-scan`),
which reads the same config paths and does exactly that job. That analysis is
per-component and content-based; ours is compositional and capability-based.
They answer "is this component malicious." We answer "what does this surface
reach, and what does it escalate into." Running both is the right posture.

---

## 1. Capability primitives

Every tool reduces to a set of reach primitives. This vocabulary is the whole
design; everything downstream is bookkeeping over it.

| Primitive | Meaning |
|---|---|
| `exec` | runs commands on the host — shell, python eval, docker, k8s exec, CI trigger |
| `corpus-search` | **bulk search/read across a document store** — wiki, ticketing, chat, drive, mail, code search, vector store |
| `secrets-read` | reads a secret store, env, or keychain |
| `code-write` | VCS push / PR / package publish |
| `cloud-control` | cloud control plane |
| `destructive` | delete / wipe / terminate |
| `identity-admin` | IdP or directory writes |
| `fs-read` / `fs-write` | local filesystem — **carrying its root path** |
| `data-read` | scoped private data — a single record, a bounded table |
| `net-egress` | outbound to a URL the caller picks: fetch, webhook, mail send, chat post |
| `untrusted-in` | reads content an attacker can influence: web, GH issues, mail, tickets |

The table has no severity column on purpose. A capability line is inventory:
it says what the agent is wired to, and reading a config file cannot tell you
whether that is appropriate for the machine it is on. Severity comes from
section 4. See section 5.

### Why `corpus-search` is separated from `data-read`

Bulk read is the highest-yield move in a real engagement. "Give me every
credential in Confluence" is one tool call. The same shape works on Jira, Slack,
Notion, SharePoint, Drive, mail, GitHub code search, and any vector index —
stores that exist precisely because people put secrets in them.

Folding it into a generic `data-read` would lose that. Kept separate, it is the
private-data leg of the trifecta and the read leg of the bulk-read chain, and it
is what makes a wiki server plus a webhook server score differently from two
database servers.

### Scope is not decoration

`server-filesystem /` and `server-filesystem ./project` are the same package and
differ by two orders of magnitude in reach. Scope is extracted from `args` and
carried on the capability. It is the one thing in the capability list that does
carry weight on its own, because the file itself says which of the two it is.

---

## 2. Static typing (offline, always on)

No flag. When geiger's normal walk encounters an agent config, it types every
server without executing anything:

- **Catalog** — well-known servers keyed by npm/PyPI package, docker image,
  binary name, or remote host. Same shape as geiger's existing credential
  catalogs.
- **Heuristics**, which cover what the catalog does not:
  - `docker run -v /:/host` → `fs-read|fs-write` rooted at `/`
  - `npx -y <unpinned>` / `uvx <unpinned>` → capability is **unbounded**: the
    package is refetched at every launch, so today's typing has no shelf life
  - an `env` block passing `AWS_*`, `GITHUB_TOKEN`, `KUBECONFIG` → the server
    inherits that credential's blast radius, which geiger already computes
  - a DSN in `args` → routed to the existing `db_connection_string` module

Static typing reads the config, which is itself an observation: the arguments
say what the agent is wired to. What it cannot show is the exact tool list. See
§5 for how that difference is scored.

---

## 3. Live enumeration (`--live`)

### Remote servers

`tools/list`, `resources/list`, `prompts/list` are pure reads. They go through
`recon.CallOpts{ReadOnlyPOST: true}` alongside the existing STS/k8s carve-outs.
`tools/call` is never issued.

Version negotiation, because the wire protocol changed materially:

- **2026-07-28** is stateless. The `initialize`/`notifications/initialized`
  handshake is gone, `Mcp-Session-Id` is gone, and every request carries its
  version and client capabilities in `_meta`. Servers **MUST** implement
  `server/discover`. `Mcp-Method` and `Mcp-Name` headers are required on POSTs.
- **2025-06-18 / 2025-11-25** still require `initialize` + the initialized
  notification before any list call.

So the probe is: `server/discover` first; on failure fall back to the handshake.
Both paths converge on `tools/list`.

Two findings fall out that no static analysis can produce:

- **unauthenticated `tools/list` succeeds** — the server hands its entire tool
  surface to anyone who can route to it. No credential involved; the reach is
  simply available.
- **401 with `WWW-Authenticate`** — follow RFC 9728 protected-resource metadata
  to name the authorization server, i.e. *which* IdP actually gates this reach.

### Local stdio servers — `--spawn-stdio`

Spawning a stdio server **is code execution**. `npx -y whatever` taken from a
scanned config is arbitrary RCE against the operator running geiger, which is
strictly worse than anything `--intrusive` currently permits (connecting to a
database leaves a trail; this runs attacker-supplied argv).

It therefore gets its own flag rather than riding on `--intrusive`:

```
--spawn-stdio   execute local stdio MCP servers to enumerate their tools
                (requires --live; this RUNS the configured command)
```

Guarantees:

- never under dry-run, never without `--live`
- the exact argv is printed before the spawn and recorded in the audit trail
- a scrubbed environment, a hard timeout, killed process group on exit
- only `tools/list` is sent; the process is torn down immediately after

---

## 4. Composition chains

Findings on the surface note. Each is a property of the tool *union*, which is
why they cannot be produced one component at a time. This is also where severity
comes from — see section 5.

1. **Lethal trifecta** — `untrusted-in` ∧ (`corpus-search` | `secrets-read` |
   `data-read` | `fs-read`) ∧ (`net-egress` | `code-write`). One poisoned page,
   issue, or ticket is enough to make the agent leak what it can read. (Willison,
   2025.) *Force multiplier.*
2. **Bulk read plus a way out** — `corpus-search` ∧ (`net-egress` |
   `code-write`). Search the store, send the results out. Two tool calls, no
   exploit. Stands down when the trifecta already covers the same servers, so
   one fact is not counted twice. *Force multiplier.*
3. **Runs commands on this host** — any `exec` tool means agent reach = host
   reach = every credential on the host, including the other findings in the same
   run. *Force multiplier.*
4. **Reads a secret store** — `secrets-read` yields a credential, which geiger
   recursively triages. This is the existing `module.Harvester` contract; an MCP
   secrets server is a Harvester like Vault or Doppler, bounded by the same
   `maxHarvestDepth` / `maxHarvestBudget`. *Force multiplier.*
5. **No approval prompt** — Claude Code `permissions.allow`, Cline/Roo
   `alwaysAllow`, Cursor YOLO, `--dangerously-skip-permissions`. Modelled as a
   property of the whole surface, weighted by what is behind it: *force
   multiplier* when a chain above is present, *warn* when there is high reach
   without one, *info* otherwise.
6. **Untrusted content next to wide reach** — a low-trust server sharing a
   context window with a high-reach one can steer calls toward it. Whether a
   description is actually poisoned is a content question and `agent-scan`'s job.
   *Info.*
7. **Package fetched fresh at every start** — unpinned `npx -y` / `uvx` refetch
   at every launch, so the typing has no shelf life. *Info*, or *warn* when there
   is also no approval prompt in the path.

---

## 5. Scoring discipline

### Inventory is not severity

A config file says what an agent is wired to. It does not say whether that is
appropriate. A filesystem server scoped to a project directory is the normal
setup, and geiger cannot tell from the file whether the machine is a laptop or a
build runner. Scoring the inventory would put every developer with an MCP config
into the top tier, which makes the tier useless for triage.

So the capability list carries no weight. The census line is the one
informational finding; capability lines, server lines and the evidence caveat
are context. Weight is attached only where the file establishes something:

- a filesystem root that is broad (`/`, `$HOME`) rather than scoped — **warn**,
- a chain from section 4, where several capabilities meet in one context —
  **force multiplier** for the trifecta, bulk read plus a way out, an exec tool,
  and a secret store; **info** for shadowing and unpinned launchers,
- approval turned off, which removes the human from every chain at once — scaled
  to what is behind it, up to **force multiplier** when a chain is,
- a server observed answering with no credential, or reached over plaintext —
  facts a config cannot show, so they only appear under `--live`.

Read and write at the same broad path are one fact and are marked once. The
bulk-read chain stands down when the trifecta covers the same servers. Both
rules exist so that one fact moves the tier once.

The ladder this produces is pinned in `TestTierCalibration`:

| Surface | Tier |
|---|---|
| one filesystem server scoped to a project | INFO |
| working laptop: scoped project dir, local database, clock | INFO |
| filesystem server rooted at `/` | LOW |
| wiki server plus web fetch (the trifecta) | HIGH |
| broad filesystem + shell + vault + chat, prompts disabled | CRITICAL |

### Undetermined

A config is not a credential, and the difference decides when a tier is withheld.

For a credential, `Undetermined` means geiger could not establish the thing is
even live, so putting a tier on it would invent a severity. `score.TierFor`
enforces that: a force multiplier does not floor an `Undetermined` note at HIGH.

Here the config file **is** the observation. `server-filesystem /` in the
arguments is read off disk, and what it grants is not in doubt. Only the exact
tool list is, and that changes precision, not the class of reach.

Withholding a tier until enumeration would also make the common case useless.
Most servers are local, and enumerating those needs `--spawn-stdio`, which runs
third-party code and often cannot be run at all — so the default mode, the one
most people run, would report nothing.

So a surface that types cleanly is scored, and the note states where the reach
came from:

- **read from the config** → scored, with an `evidence` finding naming the
  config as the source and the flags that would confirm it.
- **enumerated under `--live`** → scored, with `evidence` reporting that every
  server reported its own tool list.
- **servers configured, nothing typed** → `Undetermined` → the note reads
  **UNKNOWN**. This is the case the flag was meant for: no catalog entry, no
  recognizable arguments, no tool list.

`--live` still earns its place. It replaces a claim about a package name with
what the server reports, and it is the only way to learn the things a config
cannot show: an unauthenticated tool surface, the authorization server behind a
401, and the real tool and resource counts.

`--context` crown-jewel matches still force HIGH, as everywhere else.

---

## 6. Shape

One `Note` per discovered **agent surface** (config file), not per server. The
surface is the unit the chains are defined over, and it avoids the
`recognize.dedupe` hazard — matches are keyed on `module + secret`, so N
secret-less per-server matches from one file would collapse into one.

Per-server breakdown lives in `Finding.Detail`, shown under `-v` and always
present in `--json`. Benign servers collapse into a count, mirroring how
`--browser` handles narrow extensions.

Discovery is an always-on upgrade to the existing walk rather than a mode flag:
point geiger at a repo, a home directory, or a config file and it types whatever
agent surface is there. Runtime layouts covered: Claude Code and Claude Desktop,
Cursor, VS Code, Windsurf, Cline/Roo/Kilo, Continue, Gemini CLI, Zed, Codex
(TOML), Goose (YAML).

`~/.claude.json` needs one extra step. It keeps a global `mcpServers` map and one
more for every directory the user has opened, under `projects.<dir>.mcpServers`,
and in practice that is where the servers are. Those maps are merged in, keyed
`<dir>/<name>` so two projects' servers stay apart and a finding says which
project it is about.

Non-MCP tool surface is inventoried alongside, because it is the same reach by a
different road:

- **hooks** — run shell on lifecycle events with *no model and no approval in the
  path*. Nothing else lists them; what the command does decides whether it
  matters, so the finding points at them without rating them
- **skills** and **subagents** — instructions the agent loads and follows

---

## 7. Sequencing

1. Capability typing of MCP configs — offline, no new flag.
2. Surface discovery across runtimes, plus hooks/skills/subagents.
3. Live enumeration; `--spawn-stdio`.
4. Composition chains.

---

## References

- [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) — stateless protocol, `server/discover`, required headers
- [Willison, *The lethal trifecta*](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [CSA — MCP tool poisoning and IDE auto-execution](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/)
- [Snyk `agent-scan` issue codes](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md) — the per-component analysis this deliberately does not duplicate
- [CrowdStrike — agentic tool chain attacks](https://www.crowdstrike.com/en-us/blog/how-agentic-tool-chain-attacks-threaten-ai-agent-security/)
