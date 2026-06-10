package modules

import (
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Agentic-era LLM/dev-tool tokens beyond the core providers in catalog_ai.go /
// catalog_bearer.go. These are the credentials that increasingly drive
// autonomous agents — a single token now reaches a whole toolchain — so they
// belong in triage even when they carry no distinctive value shape.

func init() {
	// OpenAI-compatible inference hosts with a distinctive token prefix.
	registerPrefixLLM("openrouter", "https://openrouter.ai", "/api/v1/models", "sk-or-", []string{"OPENROUTER_API_KEY", "OPENROUTER_KEY"})
	registerPrefixLLM("xai", "https://api.x.ai", "/v1/models", "xai-", []string{"XAI_API_KEY", "GROK_API_KEY"})
	registerPrefixLLM("fireworks", "https://api.fireworks.ai/inference", "/v1/models", "fw_", []string{"FIREWORKS_API_KEY"})
	registerAnthropicEnv()
	registerClaudeCodeOAuth()
	recognize.RegisterRecognizer(recognizeGitHubCopilot)
}

// sortedVarKeys returns the blob's variable names in a stable order so prefix
// scans over the map are deterministic.
func sortedVarKeys(vars map[string]string) []string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// prefixMatches emits one match per distinct blob value carrying the given token
// prefix (and looking like a real secret). Used as the value-shape fallback when
// the env-name lookup misses.
func prefixMatches(b parse.Blob, modName, prefix string) []recognize.Match {
	seen := map[string]bool{}
	var out []recognize.Match
	for _, k := range sortedVarKeys(b.Vars) {
		v := b.Vars[k]
		if seen[v] || !strings.HasPrefix(v, prefix) || !valueLooksSecret(v) {
			continue
		}
		seen[v] = true
		out = append(out, recognize.Match{Module: modName, Fields: module.Fields{"token": v}, Secret: v, Label: k})
	}
	return out
}

// registerPrefixLLM registers an OpenAI-compatible bearer LLM module recognized
// by a distinctive token prefix OR a conventional env-var name. gitleaks has no
// rule for these prefixes, so the value-shape scan here is what catches them.
func registerPrefixLLM(name, base, modelsPath, prefix string, envNames []string) {
	add("", r.HTTP{
		ModuleName: name, Base: base, Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET(modelsPath).CountArrayFlag("data", "models", infoFlag),
		Static:    []module.Finding{{Key: "reach", Value: "call models on this account's billed quota; list fine-tunes and uploaded files", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return name + " — LLM API access (billed usage)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if tok := firstVar(b.Vars, envNames...); tok != "" {
			return []recognize.Match{{Module: name, Fields: module.Fields{"token": tok}, Secret: tok, Label: envNames[0]}}
		}
		return prefixMatches(b, name, prefix)
	})
}

// registerAnthropicEnv adds an env-name path to the existing `anthropic` module.
// gitleaks already shape-matches sk-ant-api03- keys; this catches an
// ANTHROPIC_API_KEY/CLAUDE_API_KEY whose value is a placeholder-shaped or
// proxied key that the shape rule misses.
func registerAnthropicEnv() {
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "ANTHROPIC_API_KEY", "CLAUDE_API_KEY"); k != "" {
			return []recognize.Match{{Module: "anthropic", Fields: module.Fields{"token": k}, Secret: k, Label: "ANTHROPIC_API_KEY"}}
		}
		return nil
	})
}

// registerClaudeCodeOAuth covers the Anthropic OAuth tokens (sk-ant-oat… access,
// sk-ant-ort… refresh) that authenticate Claude Code / a Claude.ai subscription
// — a DIFFERENT auth system from the x-api-key API (Bearer + an anthropic-beta
// header), so it must not be routed to the `anthropic` API module. Stored in
// plaintext at ~/.claude/.credentials.json on Linux (claudeAiOauth.accessToken).
func registerClaudeCodeOAuth() {
	add("", staticModule{name: "claude_code_oauth",
		summary: "Claude Code / Claude subscription OAuth token — acts as the signed-in user",
		findings: []module.Finding{
			{Key: "type", Value: "Anthropic OAuth token (sk-ant-oat/ort… — Claude Code / Claude.ai subscription auth, not an API key)", Flag: infoFlag},
			{Key: "reach", Value: "drives Claude Code as the logged-in user (agent runs within its tool permissions) billed to that account; a refresh token mints new access tokens", Flag: fmFlag},
			{Key: "validation", Value: "recognized by shape; not exercised (OAuth Bearer + anthropic-beta header, distinct from the x-api-key API)", Flag: cantFlag},
		}})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		var out []recognize.Match
		seen := map[string]bool{}
		for _, k := range sortedVarKeys(b.Vars) {
			v := b.Vars[k]
			if seen[v] {
				continue
			}
			if strings.HasPrefix(v, "sk-ant-oat") || strings.HasPrefix(v, "sk-ant-ort") {
				seen[v] = true
				out = append(out, recognize.Match{Module: "claude_code_oauth", Fields: module.Fields{"token": v}, Secret: v, Label: k})
			}
		}
		return out
	})
}

// recognizeGitHubCopilot extracts the GitHub OAuth token from a Copilot editor
// config (~/.config/github-copilot/apps.json or hosts.json) and routes it to the
// github_pat module — a Copilot token IS a GitHub OAuth token, so the real reach
// is GitHub access; the label carries the Copilot provenance.
func recognizeGitHubCopilot(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	f := strings.ToLower(b.File)
	if !strings.Contains(f, "github-copilot") && !strings.HasSuffix(f, "apps.json") && !strings.HasSuffix(f, "hosts.json") {
		return nil
	}
	var out []recognize.Match
	seen := map[string]bool{}
	for host, v := range b.JSON {
		m, _ := v.(map[string]any)
		if m == nil {
			continue
		}
		tok, _ := m["oauth_token"].(string)
		if tok == "" || seen[tok] || !valueLooksSecret(tok) {
			continue
		}
		seen[tok] = true
		out = append(out, recognize.Match{Module: "github_pat", Fields: module.Fields{"token": tok},
			Secret: tok, Label: "github copilot [" + host + "]"})
	}
	return out
}
