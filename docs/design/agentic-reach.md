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

| Primitive | Meaning | Flag |
|---|---|---|
| `exec` | runs code on the host — shell, python eval, docker, k8s exec, CI trigger | force multiplier |
| `corpus-search` | **bulk search/read across a document corpus** — wiki, ticketing, chat, drive, mail, code search, vector store | force multiplier |
| `secrets-read` | reads a secret store, env, or keychain | force multiplier |
| `code-write` | VCS push / PR / package publish | force multiplier |
| `cloud-control` | cloud control plane | force multiplier |
| `destructive` | delete / wipe / terminate | force multiplier |
| `identity-admin` | IdP or directory writes | force multiplier |
| `fs-read` / `fs-write` | local filesystem — **carrying its root scope** | scope-dependent |
| `data-read` | scoped private data — a single record, a bounded table | warn |
| `net-egress` | arbitrary outbound: fetch, webhook, mail send, chat post | warn |
| `untrusted-in` | ingests attacker-influenceable content: web, GH issues, mail, tickets | warn |

### Why `corpus-search` is separated from `data-read`

Bulk read is the highest-yield move in a real engagement, and it needs no
chaining to be an incident on its own. "Give me every credential in Confluence"
is one tool call. The same shape works on Jira, Slack, Notion, SharePoint, Drive,
mail, GitHub code search, and any vector index — corpora that exist precisely
because humans put secrets in them.

Folding that into a generic `data-read` would rank it `warn` and bury it. It is a
force multiplier in its own right, and the note says so in those terms:

> `corpus-search` — searches an entire document corpus in one call; the
> highest-yield agentic recon primitive (one query returns every secret a human
> ever pasted into the wiki)

### Scope is not decoration

`server-filesystem /` and `server-filesystem ./project` are the same package and
differ by two orders of magnitude in reach. Scope is extracted from `args` and
carried on the capability, and it is what decides whether `fs-read`/`fs-write`
score as a force multiplier or as `info`.

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

Static typing is an **assertion about a package name**, not an observation. See
§5.

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

Force-multiplier findings on the surface note. Each is a property of the tool
*union*, which is why they cannot be produced one component at a time.

1. **Corpus exfiltration** — `corpus-search` ∧ `net-egress`. Search the wiki,
   post the results out. Two tool calls, no exploit.
2. **Lethal trifecta** — `untrusted-in` ∧ (`corpus-search` | `secrets-read` |
   `data-read` | `fs-read`) ∧ (`net-egress` | `code-write`). The agent is one
   poisoned document away from exfiltrating private data. (Willison, 2025.)
3. **Exec closure** — any `exec` tool means agent reach = host reach = every
   credential on the host. The note says so explicitly and cross-references the
   other findings in the same run: an exec-capable server inherits their union.
4. **Credential laundering** — `secrets-read` yields a credential, which geiger
   recursively triages. This is the existing `module.Harvester` contract; an MCP
   secrets server is a Harvester like Vault or Doppler, bounded by the same
   `maxHarvestDepth` / `maxHarvestBudget`.
5. **Auto-approval collapse** — Claude Code `permissions.allow`, Cline/Roo
   `alwaysAllow`, Cursor YOLO, `--dangerously-skip-permissions`. Human-in-the-loop
   was the only mitigation on every chain above. Modelled as a **modifier on the
   whole surface**, not as its own finding.
6. **Unpinned supply chain** — unpinned `npx -y` / `uvx` fetch latest at every
   launch. Capability is unbounded and can change with no config change.
7. **Cross-server shadowing** — a low-trust server sharing a context window with
   a high-reach one can steer calls toward it. Reported as a composition edge;
   the description-content half of that analysis is left to `agent-scan`.

---

## 5. Scoring discipline

`score.TierFor` is explicit that a force multiplier must **not** floor an
`Undetermined` note at HIGH, because on an undetermined note the capability is
geiger's own claim about what a credential *would* reach — "invented severity in
a different costume."

Typing a server from its package name is exactly that kind of claim. So:

- **static typing only** → `Undetermined: true` → the note reads **UNKNOWN**,
  with the capability claim fully visible in the findings and `Reason` explaining
  that no tool list was observed.
- **`--live` enumeration succeeded** → observed → a real tier.

This is what gives `--live` a genuine job here instead of being a formality, and
it keeps the new subsystem inside the same honesty contract as the rest of
geiger. `--context` crown-jewel matches still force HIGH either way, because that
is operator input rather than geiger's guess.

The existing "multiple force multipliers compound" rule (`+20` for each beyond
the first) already performs the chain arithmetic; the chains above simply feed it
correctly-flagged findings.

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

Non-MCP tool surface is inventoried alongside, because it is the same reach by a
different road:

- **hooks** — run shell on lifecycle events with *no model in the loop at all*,
  which is strictly more reach than any MCP tool
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
