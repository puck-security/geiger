# Agentic reach

Point geiger at an agent config, a repo, or a home directory and it maps what the
agent's tools can reach. This runs by default: no flag, it happens when a config
turns up in the walk.

The secrets in a config and what its tools can reach are two separate problems. A
config can store every secret correctly — OS env, a keychain, an OAuth flow — and
still wire the agent to a filesystem server rooted at `/`, a shell server, and the
corporate wiki. Good credential hygiene does not limit any of that.

```sh
geiger ~/.claude.json                    # what this agent's tools reach
geiger ./repo                            # .mcp.json / .cursor / .vscode in a repo
geiger --live ~/.cursor/mcp.json         # enumerate remote servers' real tool lists
geiger --live --spawn-stdio ~/.claude    # + run local stdio servers to enumerate them
```

## What each tool can do

geiger labels each server with the kinds of access it gives: `exec`,
`corpus-search`, `secrets-read`, `code-write`, `cloud-control`, `fs-read` /
`fs-write` with their root path, `data-read`, `net-egress`, `untrusted-in`,
`destructive`, `identity-admin`.

Bulk search of a store is tracked on its own. "Give me every credential in
Confluence" is one tool call and a high-yield move in a real engagement, so
folding it into a generic "reads data" would hide it.

This list is only an inventory; it does not set the severity. A config says what
an agent is wired to. It cannot say whether that is right for the machine it runs
on, and a filesystem server scoped to a project directory is a normal setup. An
ordinary developer laptop scores INFO.

## What makes a setup risky

The severity comes from combinations of tools, not from any single tool. These
combinations exist only because the tools share one context window, so a scanner
that checks one server at a time cannot see them.

| Combination | Why it matters |
|---|---|
| lethal trifecta | untrusted content, private data, and a way out in one context — one poisoned page and the agent leaks what it can read |
| bulk read plus a way out | search the store, send the results. Two tool calls, no exploit |
| exec on this host | an `exec` tool makes the agent's reach the host's reach: every credential on the box, geiger's other findings in the same run included |
| reads a secret store | tool-chain access becomes credentials that outlive the session |
| shared context | a low-trust server sharing a context with a high-reach one |
| unpinned package | `npx -y` / `uvx` refetch at every launch, so the code that runs tomorrow need not be the code in the config |

Three more things come from the config file itself:

- A filesystem root that is the whole disk or home directory, not a project.
- No approval prompt (`permissions.allow`, `alwaysAllow`, YOLO mode). This is
  scored against the whole surface, because it removes the human from every chain
  at once.
- Under `--live` only: a server that answers with no credential (enumeration
  sends none, so the token in the config is not what gates it), or one reached
  over plaintext.

Hooks are listed too. They run shell on lifecycle events with no model and no
approval in that path, and nothing else lists them.

## Which agent tools geiger reads

Claude Code and Claude Desktop, Cursor, VS Code, Windsurf, Cline/Roo/Kilo,
Continue, Gemini CLI, Zed, Codex, Goose.

## Where the reach information comes from

The note says where each reach came from: read from the config (what these
packages are known to do) or reported by the servers themselves. A surface whose
servers map to nothing at all reads `UNKNOWN`, rather than being given a severity
from a guess.

## --live and --spawn-stdio

`--live` lists the real tools of the remote servers over http (`tools/list`,
read-only; `tools/call` is never sent).

A local stdio server is only asked under `--spawn-stdio`, because asking it means
running the command in the config. That is a separate flag from `--intrusive` on
purpose: running a command that came out of the scanned file is worse than
anything `--intrusive` allows. Each server line says which it is (`stdio
<command>` or a URL) and whether it was asked.

See [the design doc](design/agentic-reach.md) for how this works internally.
