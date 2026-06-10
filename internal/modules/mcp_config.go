package modules

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// MCP (Model Context Protocol) configs are plaintext JSON files that wire an AI
// agent to its tools — and routinely carry the credentials for those tools
// inline (server `env` blocks, remote-server auth `headers`, or `args`). A
// single such file is the agent's whole keyring: one token here drives an
// autonomous agent across every tool it touches. geiger recognizes the file,
// frames it as an aggregator, and re-triages each embedded secret through its
// real provider module — including the env-name-only providers that JSON
// key-flattening (mcpServers.x.env.MISTRAL_API_KEY) otherwise hides from firstVar.

func init() {
	module.Register(mcpConfig{})
	recognize.RegisterRecognizer(recognizeMCPConfig)
}

// mcpServers returns the server map from any of the known MCP config layouts.
func mcpServers(b parse.Blob) map[string]any {
	if b.JSON == nil {
		return nil
	}
	if s, ok := b.JSON["mcpServers"].(map[string]any); ok {
		return s
	}
	if s, ok := b.JSON["servers"].(map[string]any); ok { // VS Code .vscode/mcp.json
		return s
	}
	if mcp, ok := b.JSON["mcp"].(map[string]any); ok { // VS Code settings.json -> mcp.servers
		if s, ok := mcp["servers"].(map[string]any); ok {
			return s
		}
	}
	return nil
}

func mcpFilename(file string) bool {
	switch strings.ToLower(filepath.Base(file)) {
	case "mcp.json", ".mcp.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp_config.json":
		return true
	}
	return false
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
	var stdio, remote, plaintext int
	var embedded []embeddedSecret
	for name, v := range servers {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		isRemote := false
		if u, ok := m["url"].(string); ok {
			isRemote = true
			if strings.HasPrefix(strings.ToLower(u), "http://") {
				plaintext++
			}
		}
		if t, ok := m["type"].(string); ok && (t == "sse" || t == "http" || t == "streamable-http") {
			isRemote = true
		}
		if isRemote {
			remote++
		} else {
			stdio++
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

	matches := []recognize.Match{{
		Module: "mcp_config",
		Fields: module.Fields{
			"server_count":     strconv.Itoa(len(servers)),
			"stdio_count":      strconv.Itoa(stdio),
			"remote_count":     strconv.Itoa(remote),
			"plaintext_remote": strconv.Itoa(plaintext),
			"secret_count":     strconv.Itoa(len(embedded)),
		},
		Label: "mcp config [" + filepath.Base(b.File) + "]",
	}}
	for _, es := range embedded {
		matches = append(matches, retriageEmbedded(es, endpoint, reg)...)
	}
	return matches
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

func (mcpConfig) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{
		Key:   "servers",
		Value: f["server_count"] + " MCP server(s): " + f["stdio_count"] + " stdio, " + f["remote_count"] + " remote",
		Flag:  infoFlag,
	}}
	if n := f["secret_count"]; n != "" && n != "0" {
		out = append(out,
			module.Finding{Key: "inline secrets", Value: n + " credential(s) embedded in this config — extracted and triaged separately below", Flag: fmFlag},
			module.Finding{Key: "aggregator", Value: "plaintext MCP config: each token here drives an autonomous agent across every tool the server exposes — one file, the agent's whole keyring", Flag: fmFlag},
		)
	} else {
		out = append(out, module.Finding{Key: "inline secrets", Value: "no inline credentials (servers auth via OS env or external) — recognized as MCP config", Flag: infoFlag})
	}
	if p := f["plaintext_remote"]; p != "" && p != "0" {
		out = append(out, module.Finding{Key: "transport", Value: p + " remote server(s) over plaintext http:// — token sent in clear", Flag: warnFlag})
	}
	return out, nil
}

func (mcpConfig) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "MCP config — agent credential aggregator"}
}
