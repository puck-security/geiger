package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestK8sReconDetectsClusterAdmin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"gitVersion":"v1.29.2"}`))
	})
	mux.HandleFunc("/api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{},{},{}]}`))
	})
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("SelfSubjectRulesReview must be POST, got %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"status":{"resourceRules":[{"verbs":["*"],"resources":["*"]}]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fs, err := k8sRecon(context.Background(), true, true, srv.URL, "sa-token", "")
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["kubernetes"].Value != "v1.29.2" {
		t.Errorf("version = %q", got["kubernetes"].Value)
	}
	if got["namespaces"].Value != "3" {
		t.Errorf("namespaces = %q", got["namespaces"].Value)
	}
	if got["rbac reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("cluster-admin should be force multiplier, got %v: %q", got["rbac reach"].Flag, got["rbac reach"].Value)
	}
}

func TestDBAndK8sSkipWhenNotIntrusive(t *testing.T) {
	// dry-run, non-intrusive client: neither should make a live connection.
	c := recon.New(nil, false)

	dbFs, _ := dbConnString{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"dsn": "postgres://u:p@prod-db:5432/app"})
	if f := indexByKey(dbFs)["data access"]; f.Flag != module.FlagCantCharacterize {
		t.Errorf("DB should defer to offline note when not intrusive: %+v", f)
	}

	kFs, _ := kubeConfig{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"server": "https://prod-cluster", "token": "tok"})
	if f := indexByKey(kFs)["rbac reach"]; f.Flag != module.FlagCantCharacterize {
		t.Errorf("k8s should defer when not intrusive: %+v", f)
	}
}
