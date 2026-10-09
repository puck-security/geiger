package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// roundTripTo rewrites api.github.com requests to the test server.
type rewriteTransport struct {
	base string
	rt   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = "http"
	r.URL.Host = t.base
	return t.rt.RoundTrip(r)
}

func githubClient(srv *httptest.Server) *recon.Client {
	host := srv.Listener.Addr().String()
	hc := &http.Client{Transport: rewriteTransport{base: host, rt: http.DefaultTransport}}
	return recon.New(hc, true)
}

func TestGithubClassicPATForceMultiplier(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, admin:org, workflow")
		_, _ = w.Write([]byte(`{"login":"octo-ci-bot","type":"User"}`))
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"full_name":"acme/web","permissions":{"admin":false,"push":true,"pull":true}},
			{"full_name":"acme/prod-infra","permissions":{"admin":true,"push":true,"pull":true}},
			{"full_name":"acme/docs","permissions":{"admin":false,"push":false,"pull":true}}
		]`))
	})
	mux.HandleFunc("/user/memberships/orgs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"role":"admin","organization":{"login":"acme"}},{"role":"member","organization":{"login":"other"}}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fs, err := githubPAT{}.Recon(context.Background(), githubClient(srv), module.Token{}, module.Fields{"token": "ghp_classic"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["user"].Value != "octo-ci-bot" {
		t.Errorf("user = %q", got["user"].Value)
	}
	if got["write access"].Value != "1 repos (push)" { // web only; prod-infra counted as admin
		t.Errorf("write access = %q", got["write access"].Value)
	}
	if got["repo admin"].Flag != module.FlagForceMultiplier || got["repo admin"].Value != "1 repos" {
		t.Errorf("repo admin = %+v", got["repo admin"])
	}
	if got["notable repos"].Value != "acme/prod-infra" {
		t.Errorf("notable repos = %q", got["notable repos"].Value)
	}
	if got["org admin"].Flag != module.FlagForceMultiplier || got["org admin"].Value != "acme" {
		t.Errorf("org admin = %+v", got["org admin"])
	}
}

func TestGithubFineGrainedInfersWriteWithoutScopes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"login":"fg-user","type":"User"}`))
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"full_name":"x/y","permissions":{"admin":false,"push":true,"pull":true}}]`))
	})
	mux.HandleFunc("/user/memberships/orgs", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fs, _ := githubPAT{}.Recon(context.Background(), githubClient(srv), module.Token{}, module.Fields{"token": "github_pat_xyz"})
	got := indexByKey(fs)
	if got["scopes"].Flag != module.FlagCantCharacterize {
		t.Errorf("fine-grained scopes should be CantCharacterize, got %v", got["scopes"].Flag)
	}
	// even without scopes, per-repo permissions reveal write access
	if got["write access"].Value != "1 repos (push)" {
		t.Errorf("fine-grained write not inferred: %+v", got["write access"])
	}
}

func indexByKey(fs []module.Finding) map[string]module.Finding {
	m := map[string]module.Finding{}
	for _, f := range fs {
		m[f.Key] = f
	}
	return m
}

func githubClientDeep(srv *httptest.Server) *recon.Client {
	c := githubClient(srv)
	c.SetGitHubIntrusive(true)
	return c
}

func TestGithubIntrusiveOrgAndRepoSecrets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, admin:org")
		_, _ = w.Write([]byte(`{"login":"ci-bot","type":"User"}`))
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"full_name":"acme/prod-infra","permissions":{"admin":true,"push":true,"pull":true}}]`))
	})
	mux.HandleFunc("/user/memberships/orgs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"role":"admin","organization":{"login":"acme"}}]`))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"login":"acme"}]`))
	})
	mux.HandleFunc("/orgs/acme/members", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://api.github.com/orgs/acme/members?per_page=1&page=42>; rel="last"`)
		_, _ = w.Write([]byte(`[{"login":"someone"}]`))
	})
	mux.HandleFunc("/orgs/acme/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":3,"secrets":[{"name":"AWS_KEY"},{"name":"DOCKER_PW"},{"name":"NPM_TOKEN"}]}`))
	})
	mux.HandleFunc("/repos/acme/prod-infra/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"DEPLOY_KEY"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fs, err := githubPAT{}.Recon(context.Background(), githubClientDeep(srv), module.Token{}, module.Fields{"token": "ghp_classic"})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["org members"].Value != "acme: 42 members" {
		t.Errorf("org members = %q", got["org members"].Value)
	}
	if got["org ci secrets"].Flag != module.FlagForceMultiplier || !strings.Contains(got["org ci secrets"].Value, "AWS_KEY") {
		t.Errorf("org ci secrets = %+v", got["org ci secrets"])
	}
	if got["repo ci secrets"].Flag != module.FlagForceMultiplier || !strings.Contains(got["repo ci secrets"].Value, "DEPLOY_KEY") {
		t.Errorf("repo ci secrets = %+v", got["repo ci secrets"])
	}
}

func TestGithubIntrusiveGateOff(t *testing.T) {
	hit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo")
		_, _ = w.Write([]byte(`{"login":"ci-bot","type":"User"}`))
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"full_name":"acme/x","permissions":{"admin":true,"push":true,"pull":true}}]`))
	})
	mux.HandleFunc("/user/memberships/orgs", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	for _, p := range []string{"/user/orgs", "/orgs/acme/actions/secrets", "/repos/acme/x/actions/secrets"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { hit = true; _, _ = w.Write([]byte(`{}`)) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, _ = githubPAT{}.Recon(context.Background(), githubClient(srv), module.Token{}, module.Fields{"token": "ghp_classic"})
	if hit {
		t.Error("deep GitHub endpoints must not be hit without --github-intrusive")
	}
}

func TestGithubInstallationReach(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":7,"repositories":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fs, _ := githubPAT{}.Recon(context.Background(), githubClientDeep(srv), module.Token{}, module.Fields{"token": "ghs_install"})
	got := indexByKey(fs)
	if got["installation reach"].Flag != module.FlagForceMultiplier || !strings.Contains(got["installation reach"].Value, "7 repositories") {
		t.Errorf("installation reach = %+v", got["installation reach"])
	}
}
