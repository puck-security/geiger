package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/score"
)

func oauthRun(t *testing.T, h http.HandlerFunc, tok string) ([]module.Finding, module.Note, *http.Request) {
	t.Helper()
	var seen *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen == nil { // keep the FIRST request: the identity call
			clone := *r
			seen = &clone
		}
		h(w, r)
	}))
	defer srv.Close()
	m := claudeCodeOAuthSpec(srv.URL).Module()
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": tok})
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	return fs, m.Summarize("claude_code_oauth …", fs), seen
}

// Exercising the token is the job. It must hit the OAuth identity endpoint with a
// Bearer — never a model request, which would bill the account and show in usage.
func TestClaudeOAuthLiveTokenIsExercised(t *testing.T) {
	fs, n, req := oauthRun(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"account":{"email_address":"a@b.com"},"organization":{"name":"Acme"}}`))
	}, "sk-ant-oat01-live")

	if req.URL.Path != "/api/oauth/profile" {
		t.Errorf("called %q, want /api/oauth/profile", req.URL.Path)
	}
	if req.Method != http.MethodGet {
		t.Errorf("method = %s, want GET (read-only)", req.Method)
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
		t.Errorf("Authorization = %q, want Bearer — the OAuth API, not x-api-key", req.Header.Get("Authorization"))
	}
	if got := indexByKey(fs)["account"].Value; got != "a@b.com" {
		t.Errorf("identity not extracted: %+v", fs)
	}
	if n.Undetermined {
		t.Error("an exercised token must not report undetermined")
	}
	// The capability is now backed by a real validation, so HIGH is earned.
	if got := score.TierFor(n, score.Context{}); got != score.TierHigh && got != score.TierCritical {
		t.Errorf("tier = %s, want at least HIGH", got)
	}
}

// 401: the token is dead. It must not keep its force-multiplier tier.
func TestClaudeOAuthDeadTokenIsDead(t *testing.T) {
	_, n, _ := oauthRun(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}, "sk-ant-oat01-dead")

	if got := score.TierFor(n, score.Context{}); got != score.TierDead {
		t.Errorf("tier = %s, want DEAD", got)
	}
}

// 403: authenticated but without the user:profile scope — the token is live.
func TestClaudeOAuthScopedTokenIsNotDead(t *testing.T) {
	_, n, _ := oauthRun(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, "sk-ant-oat01-scoped")

	if got := score.TierFor(n, score.Context{}); got == score.TierDead {
		t.Errorf("a 403 proves the credential authenticated; got DEAD: %+v", n.Findings)
	}
}

// Identity alone is existence, not reach: the token's model surface is what it
// can actually drive, so recon must size that too.
func TestClaudeOAuthCharacterizesModelReach(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/oauth/profile":
			_, _ = w.Write([]byte(`{"account":{"email_address":"a@b.com"}}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"claude-opus-5"},{"id":"claude-sonnet-5"},{"id":"claude-haiku-4-5"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	m := claudeCodeOAuthSpec(srv.URL).Module()
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "sk-ant-oat01-live"})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 || paths[1] != "/v1/models" {
		t.Fatalf("model surface never probed, called %v", paths)
	}
	if got := indexByKey(fs)["models reachable"].Value; got != "3" {
		t.Errorf("models reachable = %q, want 3: %+v", got, fs)
	}
}

// The Anthropic API requires anthropic-version; without it the calls do not
// behave. Missing it was why the model list came back empty against the real API.
func TestClaudeOAuthSendsRequiredVersionHeader(t *testing.T) {
	var versions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		versions = append(versions, r.Header.Get("Anthropic-Version"))
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	m := claudeCodeOAuthSpec(srv.URL).Module()
	if _, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	if len(versions) == 0 {
		t.Fatal("no calls made")
	}
	for i, v := range versions {
		if v != "2023-06-01" {
			t.Errorf("call %d sent anthropic-version %q, want 2023-06-01", i, v)
		}
	}
}

// An OAuth token that can read /v1/organizations/me holds the org:admin scope —
// it administers the organization, which far outranks driving Claude Code.
func TestClaudeOAuthOrgAdminIsAForceMultiplier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/organizations/me":
			_, _ = w.Write([]byte(`{"id":"org_123","type":"organization","name":"Acme"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	m := claudeCodeOAuthSpec(srv.URL).Module()
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}
	idx := indexByKey(fs)
	if idx["organization"].Value != "Acme" {
		t.Errorf("organization not extracted: %+v", fs)
	}
	if idx["org admin"].Flag != module.FlagForceMultiplier {
		t.Errorf("org:admin reach should be a force multiplier: %+v", idx["org admin"])
	}
}
