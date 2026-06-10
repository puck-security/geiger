package modules

import (
	"context"
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
