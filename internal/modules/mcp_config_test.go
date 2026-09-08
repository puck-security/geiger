package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// A Claude-Desktop / Cursor-style mcp.json exercising the three paths that
// require re-triage: an env-name-only provider in env (mistral — the JSON-flatten
// blind spot), a remote server's Bearer auth header (openrouter), and a secret
// embedded in args (fireworks). NODE_ENV and the package-name arg must NOT match.
const mcpFixture = `{
  "mcpServers": {
    "tools": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "MISTRAL_API_KEY": "MistralKey1234567890abcdefGHIJKL",
        "NODE_ENV": "production",
        "API_BASE_URL": "https://api.example.com/v1"
      }
    },
    "remote": {
      "type": "sse",
      "url": "https://mcp.example.com/sse",
      "headers": { "Authorization": "Bearer sk-or-v1-feedface00000000feedface00000000" }
    },
    "argsleak": {
      "command": "uvx",
      "args": ["some-server", "--api-key=fw_realfireworkskey1234567890"]
    }
  }
}`

func TestMCPConfigRecognizesAndReTriages(t *testing.T) {
	b := parse.Parse(mcpFixture, "/home/u/.cursor/mcp.json")
	got := modulesOf(recognize.Recognize(b, "", module.Default))

	agg, ok := got["mcp_config"]
	if !ok {
		t.Fatal("mcp_config aggregator not recognized")
	}
	if agg.Fields["server_count"] != "3" {
		t.Errorf("server_count = %q, want 3", agg.Fields["server_count"])
	}
	if agg.Fields["secret_count"] == "0" || agg.Fields["secret_count"] == "" {
		t.Errorf("secret_count should be >0, got %q", agg.Fields["secret_count"])
	}

	// Each embedded secret routed to its real provider:
	for _, want := range []string{"mistral", "openrouter", "fireworks"} {
		if _, ok := got[want]; !ok {
			t.Errorf("embedded secret not re-triaged to %s: got modules %v", want, keysOf(got))
		}
	}
	// mistral is the key case — env-name-only provider nested under a dotted key
	// that firstVar would miss without the synthetic-blob re-triage.
	if got["mistral"].Secret != "MistralKey1234567890abcdefGHIJKL" {
		t.Errorf("mistral secret = %q", got["mistral"].Secret)
	}
	// NODE_ENV must not become a credential, and no generic dup of the gh token.
	if _, bad := got["generic_secret"]; bad {
		t.Errorf("a non-secret/duplicate leaked as generic_secret: %v", keysOf(got))
	}
}

func TestMCPConfigAggregatorFindings(t *testing.T) {
	b := parse.Parse(mcpFixture, "mcp.json")
	var agg recognize.Match
	for _, m := range recognize.Recognize(b, "", module.Default) {
		if m.Module == "mcp_config" {
			agg = m
		}
	}
	mod, _ := module.Default.ByName("mcp_config")
	fs, err := mod.Recon(context.Background(), recon.New(nil, false), module.Token{}, agg.Fields)
	if err != nil {
		t.Fatal(err)
	}
	idx := indexByKey(fs)
	if idx["aggregator"].Flag != module.FlagForceMultiplier {
		t.Errorf("aggregator should be a force multiplier: %+v", idx["aggregator"])
	}
	if idx["inline secrets"].Flag != module.FlagForceMultiplier {
		t.Errorf("inline secrets should be a force multiplier: %+v", idx["inline secrets"])
	}
	if mod.Summarize("t", fs).Invalid {
		t.Error("MCP config note must not be marked dead")
	}
}

func TestMCPConfigNoInlineSecrets(t *testing.T) {
	// servers that auth via OS env (value is ${VAR}) carry no inline credential.
	raw := `{"mcpServers":{"db":{"command":"x","env":{"PGPASSWORD":"${DB_PASS}"}}}}`
	b := parse.Parse(raw, "mcp.json")
	got := modulesOf(recognize.Recognize(b, "", module.Default))
	agg, ok := got["mcp_config"]
	if !ok {
		t.Fatal("mcp_config not recognized")
	}
	if agg.Fields["secret_count"] != "0" {
		t.Errorf("placeholder ${VAR} must not count as a secret: %q", agg.Fields["secret_count"])
	}
	mod, _ := module.Default.ByName("mcp_config")
	fs, _ := mod.Recon(context.Background(), recon.New(nil, false), module.Token{}, agg.Fields)
	if indexByKey(fs)["aggregator"].Flag == module.FlagForceMultiplier {
		t.Error("no inline secrets → should not flag as a force-multiplier aggregator")
	}
}

func keysOf(m map[string]recognize.Match) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The premise of the agentic-reach work: correct credential hygiene does not
// bound the blast radius. This config carries no secret at all and still wires
// the agent to the whole filesystem, the corporate wiki, and a way out.
func TestMCPConfigScoresReachWithoutAnySecret(t *testing.T) {
	raw := `{"mcpServers":{
		"fs":   {"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]},
		"wiki": {"command":"uvx","args":["mcp-atlassian"]},
		"chat": {"command":"npx","args":["-y","@modelcontextprotocol/server-slack"]}}}`
	b := parse.Parse(raw, "/home/u/.claude/settings.json")
	got := modulesOf(recognize.Recognize(b, "", module.Default))
	agg, ok := got["mcp_config"]
	if !ok {
		t.Fatal("mcp_config not recognized")
	}
	if agg.Fields["secret_count"] != "0" {
		t.Fatalf("fixture must carry no inline secret, got %q", agg.Fields["secret_count"])
	}

	mod, _ := module.Default.ByName("mcp_config")
	fs, err := mod.Recon(context.Background(), recon.New(nil, false), module.Token{}, agg.Fields)
	if err != nil {
		t.Fatal(err)
	}
	idx := indexByKey(fs)
	for _, key := range []string{"corpus-search", "fs-read", "fs-write", "chain: corpus exfiltration", "chain: lethal trifecta"} {
		f, ok := idx[key]
		if !ok {
			t.Errorf("missing finding %q — reach must be reported independently of secrets", key)
			continue
		}
		if f.Flag != module.FlagForceMultiplier {
			t.Errorf("%s flag = %v, want force multiplier", key, f.Flag)
		}
	}

	// The config types cleanly, so it is scored rather than withheld. The note
	// still has to say the reach came from the config and not from enumeration.
	n := mod.Summarize("t", fs)
	if n.Undetermined {
		t.Error("a surface typed from its config must be scored, not left Undetermined")
	}
	if n.Invalid {
		t.Error("an agent surface is never 'dead'")
	}
	if e, ok := findingFor(n.Findings, "evidence"); !ok {
		t.Error("the note must state how the reach was established")
	} else if !strings.Contains(e.Value, "typed from the config") {
		t.Errorf("evidence should name the config as the source: %q", e.Value)
	}
	// The sentinels must not leak into the printed findings.
	for _, f := range n.Findings {
		if strings.HasPrefix(f.Key, "_") {
			t.Errorf("internal sentinel %q leaked into the note", f.Key)
		}
	}
}

// A settings.json with no MCP servers at all is still an agent surface when it
// carries hooks: they run shell on lifecycle events with nothing in the path.
func TestMCPConfigRecognizesHookOnlySurface(t *testing.T) {
	raw := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"/opt/x.sh"}]}]}}`
	b := parse.Parse(raw, "/home/u/.claude/settings.json")
	got := modulesOf(recognize.Recognize(b, "", module.Default))
	if _, ok := got["mcp_config"]; !ok {
		t.Fatal("a hooks-only agent settings.json should be recognized")
	}
}

// A settings.json that is not an agent config must not be claimed on its name.
func TestMCPConfigIgnoresUnrelatedJSON(t *testing.T) {
	for _, f := range []string{"/srv/app/settings.json", "/etc/config.json"} {
		b := parse.Parse(`{"theme":"dark","fontSize":12}`, f)
		if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["mcp_config"]; ok {
			t.Errorf("%s is not an agent surface", f)
		}
	}
}

func findingFor(fs []module.Finding, key string) (module.Finding, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return module.Finding{}, false
}

// A config geiger cannot type at all is the case Undetermined exists for.
func TestMCPConfigUntypeableSurfaceIsUndetermined(t *testing.T) {
	b := parse.Parse(`{"mcpServers":{"mystery":{"command":"./unknown-binary"}}}`, "mcp.json")
	var agg recognize.Match
	for _, m := range recognize.Recognize(b, "", module.Default) {
		if m.Module == "mcp_config" {
			agg = m
		}
	}
	mod, _ := module.Default.ByName("mcp_config")
	fs, err := mod.Recon(context.Background(), recon.New(nil, false), module.Token{}, agg.Fields)
	if err != nil {
		t.Fatal(err)
	}
	n := mod.Summarize("t", fs)
	if !n.Undetermined {
		t.Error("a server with no identifiable reach must leave the note Undetermined")
	}
	if n.Reason == "" {
		t.Error("an Undetermined note must say why")
	}
}
