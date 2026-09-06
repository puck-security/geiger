package agent

import (
	"path/filepath"
	"sort"
	"strings"
)

// A Surface is one agent's configured tool chain: the servers it can call, the
// approval posture governing those calls, and the non-MCP tool surface (hooks,
// skills, subagents) that reaches the same places by a different road.
//
// The surface, not the server, is the unit of analysis. Every composition in
// chains.go — corpus read plus egress, the lethal trifecta, exec closure — is a
// property of the UNION of an agent's tools. A per-server view cannot see any of
// them, which is precisely the gap this package exists to close.

// Runtime names the agent client a surface was read from.
type Runtime string

// Surface is a parsed agent configuration.
type Surface struct {
	Runtime Runtime
	File    string
	Servers []Server
	// SkipPermissions records a runtime-wide bypass of the approval prompt
	// (Claude Code's dangerouslySkipPermissions, Cline/Roo YOLO mode). It is the
	// single most consequential setting in an agent config: it removes the human
	// from every chain at once.
	SkipPermissions bool
	// AllowRules are the runtime's blanket pre-approvals (Claude Code's
	// permissions.allow), which auto-approve matching tool calls.
	AllowRules []string
	// Hooks are shell commands the runtime runs on lifecycle events. They
	// execute with NO model in the loop at all, which is strictly more reach
	// than any MCP tool on the same surface.
	Hooks []Hook
	// Skills and Subagents are instruction sets the agent loads and follows.
	Skills    []string
	Subagents []string
}

// Hook is one lifecycle shell command.
type Hook struct {
	Event   string
	Command string
}

// Caps is the union of every server's reach — what the agent can touch through
// its tool chain as a whole.
func (s Surface) Caps() Caps {
	var out Caps
	for _, srv := range s.Servers {
		out = out.Merge(srv.Caps)
	}
	return out
}

// Enumerated reports whether any server's real tool list was observed. Until one
// was, every capability on the surface is geiger's claim about a package name,
// and the note must stay Undetermined.
func (s Surface) Enumerated() bool {
	for _, srv := range s.Servers {
		if srv.Enumerated {
			return true
		}
	}
	return false
}

// AutoApproved reports whether the surface's calls can proceed without a human:
// a runtime-wide bypass, a blanket allow rule, or per-server pre-approval.
func (s Surface) AutoApproved() bool {
	if s.SkipPermissions || len(s.AllowRules) > 0 {
		return true
	}
	for _, srv := range s.Servers {
		if len(srv.AutoApproved) > 0 {
			return true
		}
	}
	return false
}

// runtimeFor identifies the agent client from the config's filename and shape.
// The path is the strongest signal available offline, and every runtime below
// uses a distinctive one.
func runtimeFor(file string) Runtime {
	lower := strings.ToLower(filepath.ToSlash(file))
	base := filepath.Base(lower)
	switch {
	case strings.Contains(lower, "claude_desktop_config"):
		return "Claude Desktop"
	case base == ".claude.json", strings.Contains(lower, "/.claude/"), base == ".mcp.json":
		return "Claude Code"
	case strings.Contains(lower, "/.cursor/"), strings.Contains(lower, "\\.cursor\\"):
		return "Cursor"
	case strings.Contains(lower, "/.vscode/"), base == "mcp.json" && strings.Contains(lower, "vscode"):
		return "VS Code"
	case strings.Contains(lower, "windsurf"), strings.Contains(lower, "codeium"):
		return "Windsurf"
	case strings.Contains(lower, "cline_mcp_settings"):
		return "Cline"
	case strings.Contains(lower, "roo"), strings.Contains(lower, "kilo"):
		return "Roo/Kilo"
	case strings.Contains(lower, "/.continue/"):
		return "Continue"
	case strings.Contains(lower, "/.gemini/"):
		return "Gemini CLI"
	case strings.Contains(lower, "/.codex/"):
		return "Codex"
	case strings.Contains(lower, "goose"):
		return "Goose"
	case strings.Contains(lower, "zed"):
		return "Zed"
	case strings.Contains(lower, "opencode"), strings.Contains(lower, "openclaw"):
		return "OpenClaw"
	}
	return "MCP client"
}

// ServerMaps returns the server map from any known config layout. Clients agree
// on the per-server shape and disagree on where the map lives, so this is the
// only place the layouts differ.
func ServerMaps(root map[string]any) map[string]any {
	if root == nil {
		return nil
	}
	// Flat, top-level keys used by most clients.
	for _, k := range []string{"mcpServers", "servers", "mcp_servers", "context_servers"} {
		if m, ok := root[k].(map[string]any); ok {
			return m
		}
	}
	// Nested: VS Code settings.json (mcp.servers), Continue (experimental).
	for _, k := range []string{"mcp", "experimental"} {
		if outer, ok := root[k].(map[string]any); ok {
			for _, ik := range []string{"servers", "mcpServers"} {
				if m, ok := outer[ik].(map[string]any); ok {
					return m
				}
			}
		}
	}
	return nil
}

// ParseSurface builds a Surface from a decoded agent config. It is layout-aware
// but transport-agnostic: nothing here runs or dials anything.
func ParseSurface(file string, root map[string]any) Surface {
	s := Surface{Runtime: runtimeFor(file), File: file}
	for name, v := range ServerMaps(root) {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		s.Servers = append(s.Servers, parseServer(name, m))
	}
	sort.Slice(s.Servers, func(i, j int) bool { return s.Servers[i].Name < s.Servers[j].Name })
	s.SkipPermissions = skipPermissions(root)
	s.AllowRules = allowRules(root)
	s.Hooks = parseHooks(root)
	for i := range s.Servers {
		Type(&s.Servers[i])
	}
	return s
}

// parseServer reads one server entry. Values are read only for the shape they
// imply (a url means remote, an env block means inherited credentials); secret
// VALUES are left to mcp_config.go, which re-triages them through their real
// provider modules.
func parseServer(name string, m map[string]any) Server {
	srv := Server{Name: name, Transport: TransportStdio}
	if u, ok := m["url"].(string); ok && u != "" {
		srv.Transport, srv.URL = TransportHTTP, u
	}
	// An explicit type wins: a client may declare http/sse transport without a
	// url field (the endpoint then comes from elsewhere in the entry).
	if t, ok := m["type"].(string); ok {
		switch strings.ToLower(t) {
		case "sse", "http", "streamable-http", "streamablehttp", "remote":
			srv.Transport = TransportHTTP
		}
	}
	if c, ok := m["command"].(string); ok {
		srv.Command = c
	}
	if args, ok := m["args"].([]any); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				srv.Args = append(srv.Args, s)
			}
		}
	}
	if env, ok := m["env"].(map[string]any); ok {
		for k := range env {
			srv.EnvNames = append(srv.EnvNames, k)
		}
		sort.Strings(srv.EnvNames)
	}
	if h, ok := m["headers"].(map[string]any); ok {
		for k := range h {
			srv.HeaderNames = append(srv.HeaderNames, k)
		}
		sort.Strings(srv.HeaderNames)
	}
	// Per-server pre-approval. Cline/Roo/Kilo write alwaysAllow; several
	// clients use autoApprove for the same thing.
	for _, k := range []string{"alwaysAllow", "autoApprove", "auto_approve"} {
		switch v := m[k].(type) {
		case []any:
			for _, t := range v {
				if s, ok := t.(string); ok {
					srv.AutoApproved = append(srv.AutoApproved, s)
				}
			}
		case bool:
			if v {
				srv.AutoApproved = append(srv.AutoApproved, "*")
			}
		}
	}
	// A server explicitly disabled in the config is still configured — it can be
	// re-enabled with one click — but it is not currently reachable, so its
	// absence of approval matters less than its presence in the inventory.
	return srv
}

// skipPermissionKeys are the runtime-wide approval bypasses across clients.
var skipPermissionKeys = []string{
	"dangerouslySkipPermissions", "bypassPermissions", "yoloMode", "alwaysAllowExecute",
	"autoApprovalEnabled", "skipPermissions", "acceptAllEdits",
}

// skipPermissions finds a runtime-wide approval bypass anywhere in the config.
// Clients nest these under different parents (permissions, settings, security),
// so the search is by key name over a bounded depth rather than by fixed path.
func skipPermissions(root map[string]any) bool {
	found := false
	walkMap(root, 0, func(k string, v any) {
		b, ok := v.(bool)
		if !ok || !b {
			return
		}
		for _, want := range skipPermissionKeys {
			if strings.EqualFold(k, want) {
				found = true
			}
		}
	})
	return found
}

// allowRules collects blanket pre-approval rules (Claude Code's
// permissions.allow, and the equivalents other clients spell differently).
func allowRules(root map[string]any) []string {
	var out []string
	collect := func(v any) {
		list, ok := v.([]any)
		if !ok {
			return
		}
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	if p, ok := root["permissions"].(map[string]any); ok {
		collect(p["allow"])
	}
	collect(root["autoApprove"])
	collect(root["alwaysAllow"])
	sort.Strings(out)
	return out
}

// parseHooks inventories lifecycle shell commands. A hook is not a tool the
// model chooses to call — the runtime runs it on an event — so it is reach with
// no model and no approval in the path at all.
func parseHooks(root map[string]any) []Hook {
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	var out []Hook
	for event, v := range hooks {
		// Claude Code: hooks.<Event>[].hooks[].command
		matchers, ok := v.([]any)
		if !ok {
			// Some clients map an event straight to a command string.
			if s, ok := v.(string); ok && s != "" {
				out = append(out, Hook{Event: event, Command: s})
			}
			continue
		}
		for _, mv := range matchers {
			mm, ok := mv.(map[string]any)
			if !ok {
				continue
			}
			inner, ok := mm["hooks"].([]any)
			if !ok {
				if c, ok := mm["command"].(string); ok && c != "" {
					out = append(out, Hook{Event: event, Command: c})
				}
				continue
			}
			for _, hv := range inner {
				hm, ok := hv.(map[string]any)
				if !ok {
					continue
				}
				if c, ok := hm["command"].(string); ok && c != "" {
					out = append(out, Hook{Event: event, Command: c})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Event != out[j].Event {
			return out[i].Event < out[j].Event
		}
		return out[i].Command < out[j].Command
	})
	return out
}

// maxWalkDepth bounds the key search in a config of arbitrary nesting; agent
// configs are shallow, and an unbounded walk over attacker-supplied JSON is a
// denial-of-service surface geiger does not need.
const maxWalkDepth = 6

// walkMap visits every key/value pair in a nested map, depth-bounded.
func walkMap(m map[string]any, depth int, fn func(k string, v any)) {
	if depth > maxWalkDepth {
		return
	}
	for k, v := range m {
		fn(k, v)
		if child, ok := v.(map[string]any); ok {
			walkMap(child, depth+1, fn)
		}
	}
}
