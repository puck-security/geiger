package modules

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/agent"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// MCP (Model Context Protocol) configs wire an AI agent to its tools. geiger
// triages them on two axes, because they carry two different kinds of risk:
//
//   - As a credential aggregator. These files routinely carry the credentials
//     for those tools inline (server `env` blocks, remote-server auth `headers`,
//     or `args`). Each embedded secret is extracted and re-triaged through its
//     real provider module — including the env-name-only providers that JSON
//     key-flattening (mcpServers.x.env.MISTRAL_API_KEY) otherwise hides.
//
//   - As a tool chain. This is the axis that does NOT depend on the secrets: a
//     config whose every credential is stored correctly — OS env, a keychain, an
//     OAuth flow — can still wire the agent to a filesystem server rooted at /,
//     a shell server, and the corporate wiki. The credential hygiene is
//     irrelevant to that blast radius. internal/agent types each server's reach,
//     enumerates it read-only under --live, and reports the compositions (bulk
//     corpus read plus an egress channel, the lethal trifecta, exec closure)
//     that only exist because the tools share one context.
//
// See docs/design/agentic-reach.md.

func init() {
	module.Register(mcpConfig{})
	recognize.RegisterRecognizer(recognizeMCPConfig)
}

// surfaceField carries the parsed agent surface from the recognizer to Recon.
// Fields are strings, so the surface rides as JSON; pipeline's nonSecretField
// list keeps it out of the secret scrubber.
const surfaceField = "_surface"

// undeterminedKey and summaryKey are sentinel findings Summarize consumes into
// note fields rather than printing (same pattern as the Tailscale module —
// Summarize does not receive Fields, so module state rides through findings).
const (
	undeterminedKey = "_undetermined"
	summaryKey      = "_summary"
)

// mcpServers returns the server map from any of the known MCP config layouts.
func mcpServers(b parse.Blob) map[string]any {
	if b.JSON == nil {
		return nil
	}
	return agent.ServerMaps(b.JSON)
}

// mcpFilename reports whether a path is a known agent-runtime config. Every
// client agrees on the per-server shape and disagrees on where the file lives,
// so recognition is by filename plus the structural check in mcpServers.
func mcpFilename(file string) bool {
	base := strings.ToLower(filepath.Base(file))
	switch base {
	case "mcp.json", ".mcp.json", "claude_desktop_config.json", "cline_mcp_settings.json",
		"mcp_config.json", ".claude.json", "mcp_settings.json":
		return true
	}
	// settings.json is only an agent surface when it sits in an agent's
	// directory — a bare settings.json is far too common to claim on its name.
	if base == "settings.json" || base == "settings.local.json" {
		dir := strings.ToLower(filepath.ToSlash(filepath.Dir(file)))
		for _, marker := range []string{"/.claude", "/.cursor", "/.vscode", "/.gemini", "/zed", "/.continue"} {
			if strings.HasSuffix(dir, marker) {
				return true
			}
		}
	}
	return false
}

// agentSurfaceOnly reports whether a config has no MCP servers but still
// describes an agent's reach — a settings.json carrying hooks or blanket
// permission grants. Hooks run shell on lifecycle events with no model and no
// approval in the path, so such a file is a finding even with zero servers.
func agentSurfaceOnly(s agent.Surface) bool {
	return len(s.Hooks) > 0 || s.SkipPermissions || len(s.AllowRules) > 0
}

// embeddedSecret is one inline credential. value is the bare token (used for the
// provider match); raw is the exact string as it appears in the file (e.g.
// "Bearer <tok>") so the outer suppressor consumes the generic duplicate too.
type embeddedSecret struct{ server, name, value, raw string }

// stripBearer removes a leading auth scheme word ("Bearer "/"token ") so the
// bare token can be shape-matched.
func stripBearer(v string) string {
	for _, p := range []string{"Bearer ", "bearer ", "token ", "Token "} {
		if strings.HasPrefix(v, p) {
			return strings.TrimSpace(v[len(p):])
		}
	}
	return v
}

// tokensInArg splits a CLI arg on common separators so an inline secret in
// `args` (e.g. "--header=Authorization: Bearer sk-…", "KEY=sk-…") is surfaced —
// flattenJSON ignores arrays, so this is the only path that sees them.
func tokensInArg(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '=' || r == ':' || r == ' ' || r == ',' || r == '"' || r == '\''
	})
}

// credPrefixes are distinctive credential leaders. args extraction requires one
// (CLI args are full of flags/paths/package names that valueLooksSecret can't
// tell apart from secrets), so we only pull args tokens that unambiguously lead
// with a known credential shape.
var credPrefixes = []string{
	"sk-", "sk-ant-", "sk-or-", "xai-", "fw_", "pplx-", "hf_",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"xox", "AKIA", "ASIA", "AIza", "ya29.", "dop_v1_", "shpat_", "shpss_",
}

func hasStrongCredPrefix(v string) bool {
	for _, p := range credPrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// embeddableSecret gates an env/header value: a real-looking secret, but not a
// bare endpoint URL (a credential-bearing DSN like postgres://u:p@h keeps its
// "@" and is kept; a plain https://api.x endpoint is not a secret).
func embeddableSecret(v string) bool {
	if !valueLooksSecret(v) {
		return false
	}
	low := strings.ToLower(v)
	if (strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")) && !strings.Contains(v, "@") {
		return false
	}
	return true
}

func recognizeMCPConfig(b parse.Blob, endpoint string, reg *module.Registry) []recognize.Match {
	servers := mcpServers(b)
	if servers == nil && !mcpFilename(b.File) {
		return nil
	}

	// Type the tool chain. This is independent of the secrets below: it is what
	// the agent reaches, whether or not any credential sits in this file.
	surface := agent.ParseSurface(b.File, b.JSON)
	if len(surface.Servers) == 0 && !agentSurfaceOnly(surface) && servers == nil {
		return nil // an agent-shaped filename with nothing agent-shaped inside
	}

	embedded := embeddedSecrets(servers)
	blob, err := json.Marshal(surface)
	if err != nil {
		blob = nil
	}

	stdio, remote := 0, 0
	for _, srv := range surface.Servers {
		if srv.Transport == agent.TransportHTTP {
			remote++
		} else {
			stdio++
		}
	}
	matches := []recognize.Match{{
		Module: "mcp_config",
		Fields: module.Fields{
			surfaceField:   string(blob),
			"server_count": strconv.Itoa(len(surface.Servers)),
			"stdio_count":  strconv.Itoa(stdio),
			"remote_count": strconv.Itoa(remote),
			"secret_count": strconv.Itoa(len(embedded)),
		},
		Label: "agent surface [" + filepath.Base(b.File) + "]",
	}}
	for _, es := range embedded {
		matches = append(matches, retriageEmbedded(es, endpoint, reg)...)
	}
	return matches
}

// embeddedSecrets pulls every inline credential out of the server map.
func embeddedSecrets(servers map[string]any) []embeddedSecret {
	var embedded []embeddedSecret
	for name, v := range servers {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		if env, ok := m["env"].(map[string]any); ok {
			for k, ev := range env {
				if s, ok := ev.(string); ok && embeddableSecret(s) {
					embedded = append(embedded, embeddedSecret{name, k, s, s})
				}
			}
		}
		if hdrs, ok := m["headers"].(map[string]any); ok {
			for hk, hv := range hdrs {
				if s, ok := hv.(string); ok {
					if tok := stripBearer(s); embeddableSecret(tok) {
						embedded = append(embedded, embeddedSecret{name, hk, tok, s})
					}
				}
			}
		}
		if args, ok := m["args"].([]any); ok {
			for _, a := range args {
				if s, ok := a.(string); ok {
					for _, tok := range tokensInArg(s) {
						if hasStrongCredPrefix(tok) && valueLooksSecret(tok) {
							embedded = append(embedded, embeddedSecret{name, "args", tok, tok})
						}
					}
				}
			}
		}
	}
	return embedded
}

// retriageEmbedded routes one inline secret through the full recognizer set via
// a synthetic dotenv blob, so it lands on its real provider module (the env-var
// NAME drives env-name recognizers; the value drives shape/gitleaks). The blob
// has File=="" and is flat KEY=VALUE, so it cannot re-trigger recognizeMCPConfig.
func retriageEmbedded(es embeddedSecret, endpoint string, reg *module.Registry) []recognize.Match {
	syn := parse.Parse(es.name+"="+es.value+"\n", "")
	var out []recognize.Match
	for _, m := range recognize.Recognize(syn, endpoint, reg) {
		if m.Module == "mcp_config" { // defensive recursion guard
			continue
		}
		m.Secret = es.value // exact secret so the outer dedupe collapses gitleaks duplicates
		// Consume the raw file form too (e.g. "Bearer <tok>"), so the generic
		// recognizer's match on the un-stripped value is suppressed as a duplicate.
		if es.raw != "" && es.raw != es.value {
			if m.Fields == nil {
				m.Fields = module.Fields{}
			}
			m.Fields["_raw"] = es.raw
		}
		m.Label = "mcp " + es.server + " [" + es.name + "]"
		out = append(out, m)
	}
	return out
}

type mcpConfig struct{ module.Base }

func (mcpConfig) Name() string { return "mcp_config" }

// EndpointPolicy: an MCP server is deployable at any domain, and the URL in the
// config is the one the agent itself already trusts and calls. Pinning would
// break every legitimate deployment. The destination is instead made visible in
// the note (and in the audit trail) so a planted host is something an operator
// can SEE — which is the same treatment geiger gives Vault, GitLab, and every
// other self-hostable service.
func (mcpConfig) EndpointPolicy() module.EndpointPolicy {
	return module.EndpointPolicy{SelfHosted: true}
}

func (m mcpConfig) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	var surface agent.Surface
	if s := f[surfaceField]; s != "" {
		if err := json.Unmarshal([]byte(s), &surface); err != nil {
			return nil, err
		}
	}

	enumerate(ctx, c, &surface)

	out := surface.Findings()
	out = append(out, inlineSecretFindings(f)...)
	out = append(out, module.Finding{Key: summaryKey, Value: surface.Summary()})
	if !surface.Enumerated() && len(surface.Servers) > 0 {
		out = append(out, module.Finding{Key: undeterminedKey, Value: undeterminedReason(c)})
	}
	return out, nil
}

// enumerate asks each server what it actually exposes. Remote servers are an
// ordinary read-only HTTP call; local stdio servers are only run when the
// operator has separately opted in, because running them executes an argv that
// came out of the scanned file.
func enumerate(ctx context.Context, c *recon.Client, s *agent.Surface) {
	for i := range s.Servers {
		srv := &s.Servers[i]
		switch srv.Transport {
		case agent.TransportHTTP:
			if srv.URL == "" {
				srv.EnumErr = "remote server with no url"
				continue
			}
			agent.EnumerateRemote(ctx, c, srv)
		default:
			agent.EnumerateStdio(ctx, srv, agent.SpawnOptions{
				Permitted: c.SpawnStdio(),
				Live:      c.Live(),
			})
		}
	}
}

// undeterminedReason explains what would confirm the inferred reach, naming the
// flag that is actually missing rather than listing both every time.
func undeterminedReason(c *recon.Client) string {
	base := "reach inferred from server identity and arguments; no tool list observed — re-run with "
	switch {
	case !c.Live():
		return base + "--live to confirm it against what each server actually exposes"
	case !c.SpawnStdio():
		return base + "--spawn-stdio to enumerate local stdio servers (this RUNS each configured command)"
	}
	return base + "--live to confirm it against what each server actually exposes"
}

// inlineSecretFindings report the aggregator axis: credentials sitting in the
// file itself, each already extracted and triaged separately.
func inlineSecretFindings(f module.Fields) []module.Finding {
	n := f["secret_count"]
	if n == "" || n == "0" {
		return []module.Finding{{
			Key:   "inline secrets",
			Value: "no inline credentials — the servers authenticate via OS env, a keychain, or OAuth. This does NOT bound the reach above.",
			Flag:  module.FlagInfo,
		}}
	}
	return []module.Finding{
		{Key: "inline secrets", Value: n + " credential(s) embedded in this config — extracted and triaged separately below", Flag: fmFlag},
		{Key: "aggregator", Value: "plaintext agent config: each token here drives an autonomous agent across every tool the server exposes — one file, the agent's whole keyring", Flag: fmFlag},
	}
}

func (mcpConfig) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title}
	kept := fs[:0:0]
	summary := "agent tool chain — what the agent reaches through its MCP servers, hooks, and approval posture"
	for _, f := range fs {
		switch f.Key {
		case undeterminedKey:
			// Nothing was disproved and nothing was observed. The reach above is
			// what these packages are known to do, not what this deployment was
			// seen doing — score.TierFor reads that as UNKNOWN rather than
			// deriving a severity from geiger's own claim.
			n.Undetermined, n.Reason = true, f.Value
		case summaryKey:
			summary = f.Value
		default:
			kept = append(kept, f)
		}
	}
	n.Findings = kept
	n.Summary = summary
	return n
}
