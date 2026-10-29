# Agentic reach

Point geiger at an agent config, a repo, or a home directory and it maps what the
agent's tool chain reaches. This runs by default. No flag is needed: it happens
when a config turns up in the walk.

The credential axis and the reach axis are separate. A config whose every secret
is stored properly — OS env, a keychain, an OAuth flow — can still wire the agent
to a filesystem server rooted at `/`, a shell server, and the corporate wiki.
Good credential hygiene does not bound any of that.

```sh
geiger ~/.claude.json                    # what this agent's tools reach
geiger ./repo                            # .mcp.json / .cursor / .vscode in a repo
geiger --live ~/.cursor/mcp.json         # enumerate remote servers' real tool lists
geiger --live --spawn-stdio ~/.claude    # + run local stdio servers to enumerate them
```

## Reach primitives

Each server is typed into reach primitives: `exec`, `corpus-search`,
`secrets-read`, `code-write`, `cloud-control`, `fs-read` / `fs-write` with their
root path, `data-read`, `net-egress`, `untrusted-in`, `destructive`,
`identity-admin`.

Bulk store search is its own primitive. "Give me every credential in Confluence"
is one tool call and a high-yield move in a real engagement, so folding it into a
generic "reads data" would hide it.

This list is inventory. It does not set a tier. A config file says what an agent
is wired to. It cannot say whether that is appropriate for the machine it is on,
and a filesystem server scoped to a project directory is a normal setup. An
ordinary developer laptop scores INFO.

## Compositions set the tier

The tier comes from the compositions: reach that exists only because the tools
share one context window. No per-component scanner can see this.

| Chain | Why it matters |
|---|---|
| lethal trifecta | untrusted content, private data, and a way out in one context — one poisoned page and the agent leaks what it can read |
| bulk read plus a way out | search the store, send the results. Two tool calls, no exploit |
| exec on this host | an `exec` tool makes the agent's reach the host's reach: every credential on the box, geiger's other findings in the same run included |
| reads a secret store | tool-chain access becomes credentials that outlive the session |
| shared context | a low-trust server sharing a context with a high-reach one |
| unpinned package | `npx -y` / `uvx` refetch at every launch, so the code that runs tomorrow need not be the code in the config |

Three more things the file itself establishes:

- A filesystem root that is the whole disk or home directory rather than a
  project.
- No approval prompt (`permissions.allow`, `alwaysAllow`, YOLO mode). This is
  scored as a property of the whole surface, because it removes the human from
  every chain at once.
- Under `--live` only: a server that answers with no credential (enumeration
  sends none, so the token in the config is not what gates it), or one reached
  over plaintext.

Hooks are inventoried too. They run shell on lifecycle events with no model and
no approval in that path, and nothing else lists them.

## Runtimes read

Claude Code and Claude Desktop, Cursor, VS Code, Windsurf, Cline/Roo/Kilo,
Continue, Gemini CLI, Zed, Codex, Goose.

## Where the reach came from

The note always says where the reach came from: read from the config (what these
packages are known to do) or reported by the servers themselves. A surface whose
servers type to nothing at all reads `UNKNOWN` rather than getting a severity
invented from a guess.

## The two flags split by transport

`--live` enumerates the remote servers' real tool lists over http (`tools/list`,
read-only; `tools/call` is never issued).

A local stdio server is only asked under `--spawn-stdio`, because asking it means
running the command in the config. This is a separate flag from `--intrusive` on
purpose: running an argv that came out of the scanned file is worse than anything
`--intrusive` permits. Each server line says which it is (`stdio <command>` or a
URL) and whether it was asked.

See [docs/design/agentic-reach.md](design/agentic-reach.md) for the design.
