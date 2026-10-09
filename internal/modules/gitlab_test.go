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

func TestGitlabTokenType(t *testing.T) {
	cases := map[string]string{
		"glpat-abc": "personal access token",
		"glptt-abc": "pipeline trigger token",
		"glrt-abc":  "runner token",
		"random":    "token",
	}
	for in, want := range cases {
		if got := gitlabTokenType(in); got != want {
			t.Errorf("gitlabTokenType(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGitlabForceScope(t *testing.T) {
	if !gitlabForceScope([]string{"read_repository", "api"}) {
		t.Error("api should be a force scope")
	}
	if gitlabForceScope([]string{"read_api", "read_repository"}) {
		t.Error("read-only scopes should not force")
	}
}

func TestGitlabScopesAndAdmin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"ci-bot","is_admin":true}`))
	})
	mux.HandleFunc("/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"deploy","scopes":["api","read_repository"],"expires_at":"2027-01-01"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := gitlabBase
	gitlabBase = srv.URL
	defer func() { gitlabBase = orig }()

	c := recon.New(srv.Client(), true) // not gitlab-intrusive
	fs, err := gitlabKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "glpat-abc"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["user"].Value != "ci-bot" {
		t.Errorf("user = %q", got["user"].Value)
	}
	if got["instance admin"].Flag != module.FlagForceMultiplier {
		t.Errorf("instance admin should be force multiplier: %+v", got["instance admin"])
	}
	if got["scopes"].Flag != module.FlagForceMultiplier || !strings.Contains(got["scopes"].Value, "api") {
		t.Errorf("scopes = %+v", got["scopes"])
	}
}

func TestGitlabIntrusiveReachAndVariableKeysOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"ci-bot"}`))
	})
	mux.HandleFunc("/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"scopes":["api"]}`))
	})
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("min_access_level") == "40" {
			w.Header().Set("X-Total", "3")
			_, _ = w.Write([]byte(`[{"id":7}]`))
			return
		}
		w.Header().Set("X-Total", "1234")
		_, _ = w.Write([]byte(`[{"id":1}]`))
	})
	mux.HandleFunc("/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total", "2")
		_, _ = w.Write([]byte(`[{"id":9}]`))
	})
	mux.HandleFunc("/projects/7/variables", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"key":"AWS_KEY","value":"SECRETVALUE1"},{"key":"DB_PW","value":"SECRETVALUE2"}]`))
	})
	mux.HandleFunc("/groups/9/variables", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"key":"NPM_TOKEN","value":"SECRETVALUE3"}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := gitlabBase
	gitlabBase = srv.URL
	defer func() { gitlabBase = orig }()

	c := recon.New(srv.Client(), true)
	c.SetGitLabIntrusive(true)
	fs, err := gitlabKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "glpat-abc"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["projects"].Value != "1234 accessible" {
		t.Errorf("projects = %q", got["projects"].Value)
	}
	if got["maintain projects"].Value != "3 (maintainer+)" {
		t.Errorf("maintain projects = %q", got["maintain projects"].Value)
	}
	if got["maintain groups"].Value != "2 (maintainer+)" {
		t.Errorf("maintain groups = %q", got["maintain groups"].Value)
	}
	pv := got["project ci variables"]
	if pv.Flag != module.FlagForceMultiplier || !strings.Contains(pv.Value, "AWS_KEY") {
		t.Errorf("project ci variables = %+v", pv)
	}
	if !strings.Contains(got["group ci variables"].Value, "NPM_TOKEN") {
		t.Errorf("group ci variables = %+v", got["group ci variables"])
	}
	// Variable VALUES must never be surfaced.
	for _, f := range fs {
		if strings.Contains(f.Value, "SECRETVALUE") {
			t.Errorf("variable value leaked into finding: %q", f.Value)
		}
	}
}

func TestGitlabIntrusiveGateOff(t *testing.T) {
	deep := false
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"username":"ci"}`)) })
	mux.HandleFunc("/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"scopes":["api"]}`)) })
	for _, p := range []string{"/projects", "/groups"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { deep = true; _, _ = w.Write([]byte(`[]`)) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := gitlabBase
	gitlabBase = srv.URL
	defer func() { gitlabBase = orig }()

	c := recon.New(srv.Client(), true) // not intrusive
	_, _ = gitlabKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "glpat-abc"})
	if deep {
		t.Error("deep GitLab endpoints must not be hit without --gitlab-intrusive")
	}
}

// Regression: a glpat- token from an env var must route to the gitlab module,
// not fall through to the generic name/shape matcher. The embedded gitleaks
// gitlab-pat rule captures only 20 body chars, so longer/newer tokens need the
// native prefix recognizer.
func TestGitlabTokenRecognitionRoutesToModule(t *testing.T) {
	cases := []string{
		"GITLAB_TOKEN=glpat-ABCDEFGHIJ1234567890\n",                                     // classic 20
		"GITLAB_TOKEN=glpat-A1b2C3d4E5f6G7h8I9j0kns0z\n",                                // longer body
		"GITLAB_TOKEN=glpat-01234567890123456789012345678901ABCns0z\n",                  // routable-length
		"GITLAB_TOKEN=glpat-ShJPowughot0rZuUuka82WM6MQpwOjEKdTo2ZzF3ba8.01.1701rns0a\n", // routable (dotted)
	}
	for _, s := range cases {
		b := parse.Parse(s, "environment")
		ms := recognize.Recognize(b, "", module.Default)
		var gitlabSecret string
		for _, m := range ms {
			if m.Module == "gitlab" {
				gitlabSecret = m.Secret
			}
			if m.Module == "generic_secret" {
				t.Errorf("%q also surfaced generic_secret; gitlab recognizer should supersede it", s)
			}
		}
		if gitlabSecret == "" {
			t.Errorf("%q did not route to gitlab module: %+v", s, ms)
			continue
		}
		want := strings.TrimSuffix(strings.TrimPrefix(s, "GITLAB_TOKEN="), "\n")
		if gitlabSecret != want {
			t.Errorf("gitlab token truncated: got %q want %q", gitlabSecret, want)
		}
	}
}
