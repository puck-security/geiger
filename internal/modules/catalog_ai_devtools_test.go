package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestPrefixLLMRecognizedByShape(t *testing.T) {
	cases := map[string]string{ // value -> expected module
		"OPENROUTER_API_KEY=sk-or-v1-abcdef0123456789abcdef0123456789": "openrouter",
		"XAI_API_KEY=xai-abcdef0123456789ABCDEF0123":                   "xai",
		"FIREWORKS_API_KEY=fw_3aBcDeFgHiJkLmNoPqRs":                    "fireworks",
	}
	for line, want := range cases {
		b := parse.Parse(line+"\n", ".env")
		if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))[want]; !ok {
			t.Errorf("%q not recognized as %s", line, want)
		}
	}
	// value-shape only (no conventional env name) still routes by prefix
	b := parse.Parse("SOME_RANDOM_NAME=sk-or-v1-feedface00000000feedface00000000\n", ".env")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["openrouter"]; !ok {
		t.Error("sk-or- prefix should route to openrouter even under a non-standard env name")
	}
}

func TestAnthropicEnvNameFallback(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_API_KEY"} {
		b := parse.Parse(name+"=some-proxied-or-rotated-key-value-123\n", ".env")
		if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["anthropic"]; !ok {
			t.Errorf("%s should route to the anthropic module", name)
		}
	}
}

func TestClaudeCodeOAuthRecognized(t *testing.T) {
	// the plaintext ~/.claude/.credentials.json shape
	raw := `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123","refreshToken":"sk-ant-ort01-zyxwvutsrqponmlkjihgfedcba9876"}}`
	got := modulesOf(recognize.Recognize(parse.Parse(raw, ".credentials.json"), "", module.Default))
	m, ok := got["claude_code_oauth"]
	if !ok {
		t.Fatal("sk-ant-oat token not recognized as claude_code_oauth")
	}
	if m.Module != "claude_code_oauth" {
		t.Errorf("module = %q", m.Module)
	}
	// must NOT be misrouted to the x-api-key `anthropic` module
	if _, wrong := got["anthropic"]; wrong {
		t.Error("OAuth token must not be routed to the anthropic (x-api-key) module")
	}
}

func TestGitHubCopilotRoutesToGitHub(t *testing.T) {
	raw := `{"github.com:Iv1.abc123":{"user":"octocat","oauth_token":"gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}}`
	b := parse.Parse(raw, "/home/u/.config/github-copilot/apps.json")
	got := modulesOf(recognize.Recognize(b, "", module.Default))
	if _, ok := got["github_pat"]; !ok {
		t.Error("Copilot oauth_token should route to the github_pat module")
	}
}

func TestPrefixLLMWhoami(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-or-test" {
			t.Errorf("must Bearer-auth: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":[{"id":"gpt-4o"},{"id":"claude-3"}]}`)
	})
	got := driveModule(t, "openrouter", module.Fields{"token": "sk-or-test"}, mux)
	if got["models"].Value != "2" {
		t.Errorf("models count = %q", got["models"].Value)
	}
}
