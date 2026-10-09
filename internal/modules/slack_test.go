package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func TestSlackTokenType(t *testing.T) {
	cases := map[string]string{
		"xoxb-123":  "bot token",
		"xoxp-123":  "user token",
		"xapp-1-A":  "app-level token",
		"xoxe-1-xy": "config/refresh token",
		"nope":      "token",
	}
	for in, want := range cases {
		if got := slackTokenType(in); got != want {
			t.Errorf("slackTokenType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSlackCapabilitiesGrouping(t *testing.T) {
	fs := slackCapabilities([]string{
		"admin", "admin.users:read", "chat:write", "search:read",
		"channels:history", "groups:history", "files:read", "users:read.email", "users:read",
	})
	byVal := func(sub string) *module.Finding {
		for i := range fs {
			if fs[i].Key == "capability" && strings.Contains(fs[i].Value, sub) {
				return &fs[i]
			}
		}
		return nil
	}
	if f := byVal("admin scopes (2)"); f == nil || f.Flag != module.FlagForceMultiplier {
		t.Errorf("admin grouping wrong: %+v", fs)
	}
	if f := byVal("chat:write"); f == nil || f.Flag != module.FlagForceMultiplier {
		t.Errorf("chat:write should be force multiplier: %+v", fs)
	}
	if f := byVal("search:read"); f == nil || f.Flag != module.FlagForceMultiplier {
		t.Errorf("search:read should be force multiplier: %+v", fs)
	}
	if f := byVal("read conversation history"); f == nil || f.Flag != module.FlagWarn {
		t.Errorf("history should warn: %+v", fs)
	}
	if f := byVal("read member emails"); f == nil || f.Flag != module.FlagWarn {
		t.Errorf("email scope should warn: %+v", fs)
	}
}

func TestSlackReconIdentityAndScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth.test") {
			w.Header().Set("X-OAuth-Scopes", "admin,chat:write,files:read,users:read.email,channels:history")
			_, _ = w.Write([]byte(`{"ok":true,"url":"https://acme.slack.com/","team":"Acme","user":"ci-bot","is_enterprise_install":true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	orig := slackAPIBase
	slackAPIBase = srv.URL
	defer func() { slackAPIBase = orig }()

	c := recon.New(srv.Client(), true) // not slack-intrusive
	fs, err := slackKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "xoxb-abc"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["type"].Value != "bot token" {
		t.Errorf("type = %q", got["type"].Value)
	}
	if !strings.Contains(got["workspace"].Value, "acme.slack.com") {
		t.Errorf("workspace = %q", got["workspace"].Value)
	}
	if got["enterprise"].Flag != module.FlagWarn {
		t.Errorf("enterprise install should warn")
	}
	// capability findings present even without --slack-intrusive (header is free)
	var fm int
	for _, f := range fs {
		if f.Key == "capability" && f.Flag == module.FlagForceMultiplier {
			fm++
		}
	}
	if fm < 2 { // admin + chat:write
		t.Errorf("expected admin+chat:write force multipliers, got %d: %+v", fm, fs)
	}
	note := slackKey{}.Summarize("t", fs)
	if note.Invalid || !strings.HasPrefix(note.Summary, "Slack token — ") {
		t.Errorf("summary = %q invalid=%v", note.Summary, note.Invalid)
	}
}

func TestSlackReconInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()
	orig := slackAPIBase
	slackAPIBase = srv.URL
	defer func() { slackAPIBase = orig }()

	c := recon.New(srv.Client(), true)
	fs, _ := slackKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "xoxb-dead"})
	note := slackKey{}.Summarize("t", fs)
	if !note.Invalid {
		t.Errorf("invalid token should produce invalid note: %+v", fs)
	}
}

func TestSlackIntrusiveReach(t *testing.T) {
	calls := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth.test", func(w http.ResponseWriter, r *http.Request) {
		calls["auth.test"] = true
		w.Header().Set("X-OAuth-Scopes", "channels:read,groups:read,users:read")
		_, _ = w.Write([]byte(`{"ok":true,"url":"https://acme.slack.com/","team":"Acme","user":"ci"}`))
	})
	mux.HandleFunc("/team.info", func(w http.ResponseWriter, r *http.Request) {
		calls["team.info"] = true
		_, _ = w.Write([]byte(`{"ok":true,"team":{"name":"Acme Inc","domain":"acme"}}`))
	})
	mux.HandleFunc("/users.list", func(w http.ResponseWriter, r *http.Request) {
		calls["users.list"] = true
		_, _ = w.Write([]byte(`{"ok":true,"members":[{"id":"U1"},{"id":"U2"}],"response_metadata":{"next_cursor":"more"}}`))
	})
	mux.HandleFunc("/conversations.list", func(w http.ResponseWriter, r *http.Request) {
		calls["conversations.list"] = true
		_, _ = w.Write([]byte(`{"ok":true,"channels":[{"is_private":true},{"is_private":false},{}]}`))
	})
	mux.HandleFunc("/files.list", func(w http.ResponseWriter, r *http.Request) {
		calls["files.list"] = true
		_, _ = w.Write([]byte(`{"ok":true,"paging":{"total":1234}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := slackAPIBase
	slackAPIBase = srv.URL
	defer func() { slackAPIBase = orig }()

	c := recon.New(srv.Client(), true)
	c.SetSlackIntrusive(true)
	fs, err := slackKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "xoxp-abc"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["workspace name"].Value != "Acme Inc (acme.slack.com)" {
		t.Errorf("workspace name = %q", got["workspace name"].Value)
	}
	if got["users"].Value != "2+ members visible" {
		t.Errorf("users = %q", got["users"].Value)
	}
	if got["channels"].Flag != module.FlagWarn || !strings.Contains(got["channels"].Value, "incl. 1 private") {
		t.Errorf("channels = %+v", got["channels"])
	}
	if !strings.Contains(got["files"].Value, "1234 files") {
		t.Errorf("files = %q", got["files"].Value)
	}
	for _, p := range []string{"team.info", "users.list", "conversations.list", "files.list"} {
		if !calls[p] {
			t.Errorf("expected %s to be called", p)
		}
	}
}

func TestSlackIntrusiveGate(t *testing.T) {
	deep := false
	mux := http.NewServeMux()
	mux.HandleFunc("/auth.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "users:read")
		_, _ = w.Write([]byte(`{"ok":true,"url":"https://acme.slack.com/","team":"Acme","user":"ci"}`))
	})
	for _, p := range []string{"/team.info", "/users.list", "/conversations.list", "/files.list"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			deep = true
			_, _ = w.Write([]byte(`{"ok":true}`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := slackAPIBase
	slackAPIBase = srv.URL
	defer func() { slackAPIBase = orig }()

	c := recon.New(srv.Client(), true) // intentionally NOT slack-intrusive
	_, _ = slackKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "xoxb-abc"})
	if deep {
		t.Error("deep Slack endpoints must not be called without --slack-intrusive")
	}
}

// The native Slack recognizer routes API-exercisable token prefixes to the slack
// module and supersedes the generic name/shape match, independent of gitleaks.
func TestSlackTokenRecognitionRoutesToModule(t *testing.T) {
	cases := []string{
		// Deliberately non-real structures (no numeric id groups) so secret
		// scanners don't flag them, while still matching the module's recognizer.
		"SLACK_TOKEN=xoxb-EXAMPLE-fake-bot-token-000000000000\n",
		"SLACK_TOKEN=xoxp-EXAMPLE-fake-user-token-00000000000\n",
		"SLACK_TOKEN=xapp-EXAMPLE-fake-app-token-0000000000\n",
	}
	for _, s := range cases {
		b := parse.Parse(s, "environment")
		ms := recognize.Recognize(b, "", module.Default)
		var slackSecret string
		for _, m := range ms {
			if m.Module == "slack" {
				slackSecret = m.Secret
			}
			if m.Module == "generic_secret" {
				t.Errorf("%q also surfaced generic_secret; slack recognizer should supersede it", s)
			}
		}
		want := strings.TrimSuffix(strings.TrimPrefix(s, "SLACK_TOKEN="), "\n")
		if slackSecret != want {
			t.Errorf("%q did not route full token to slack: got %q", s, slackSecret)
		}
	}
}
