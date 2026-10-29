# Browser extensions

`--browser` models the impact of a malicious Chromium-family extension (Chrome,
Edge, Brave, Chromium, Vivaldi): a CursedChrome-style proxy, an infostealer, or a
sideloaded MV3 extension.

```sh
geiger --browser                    # score extensions + triage bundle
geiger --browser --live --intrusive # + session inventory + storage IOC grep
geiger --browser --all              # full inventory (incl. narrow/benign)
geiger --browser --json             # IOCs (extension id, hosts) for a SIEM
```

## What it scores

geiger scores each installed extension's permission union. `cookies` + broad host
access + request interception, script injection, or proxy means the extension can
read every site's session cookies and pivot through the browser. It flags
sideloaded or unpacked extensions, which are unsigned and not content-verified.

With `--live --intrusive` it also inventories the live sessions such an extension
would reach, from the Cookies store metadata (domains only — the values are
keychain-encrypted), ranked by blast radius with IdP/SSO sessions first.

## Responder triage bundle

An unsigned all-sites extension is capability-identical to a real CursedChrome, so
geiger does not guess intent. For each flagged sideloaded extension it builds a
triage bundle:

- install age
- UI surface
- dev-project markers
- the extension id
- a low-false-positive grep of its on-disk code for hardcoded remote hosts
  (websocket and public-IP endpoints), and under `--intrusive` its LevelDB
  storage as well

Use the remote hosts to check against egress and DNS logs. Everything is emitted
as IOCs in `--json` (`detail` arrays) for a SIEM.

By default only extensions with risky reach are shown. Narrow or benign ones are
collapsed into a count. `--all` lists every installed extension.
