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

func TestVaultIntrusiveMountsAndCapabilities(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			t.Errorf("bad vault token header: %q", r.Header.Get("X-Vault-Token"))
		}
		_, _ = w.Write([]byte(`{"data":{"display_name":"token-ci","policies":["default","app-ro"],"ttl":3600}}`))
	})
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secret/":{"type":"kv"},"aws/":{"type":"aws"},"sys/":{"type":"system"},"cubbyhole/":{"type":"cubbyhole"}}}`))
	})
	mux.HandleFunc("/v1/sys/capabilities-self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"secret/":["read","list"],"aws/":["deny"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := recon.New(srv.Client(), true)
	c.SetVaultIntrusive(true)
	fs, err := vaultKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "tok", "endpoint": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["token"].Value != "token-ci" {
		t.Errorf("token = %q", got["token"].Value)
	}
	if got["mounts"].Flag != module.FlagWarn || !strings.Contains(got["mounts"].Value, "secret/") || strings.Contains(got["mounts"].Value, "sys/") {
		t.Errorf("mounts finding wrong: %+v", got["mounts"])
	}
	if got["secrets reach"].Flag != module.FlagForceMultiplier || !strings.Contains(got["secrets reach"].Value, "secret/") || strings.Contains(got["secrets reach"].Value, "aws/") {
		t.Errorf("secrets reach finding wrong: %+v", got["secrets reach"])
	}
}

func TestVaultRootPolicyForceMultiplier(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"display_name":"root","policies":["root"]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := recon.New(srv.Client(), true) // not vault-intrusive
	fs, _ := vaultKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "tok", "endpoint": srv.URL})
	got := indexByKey(fs)
	if got["policies"].Flag != module.FlagForceMultiplier {
		t.Errorf("root policy should be force multiplier: %+v", got["policies"])
	}
	if n := (vaultKey{}).Summarize("t", fs); !strings.Contains(n.Summary, "root") {
		t.Errorf("summary should flag root: %q", n.Summary)
	}
}

func TestVaultGateOff(t *testing.T) {
	deep := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"policies":["default"]}}`))
	})
	for _, p := range []string{"/v1/sys/mounts", "/v1/sys/capabilities-self"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { deep = true; _, _ = w.Write([]byte(`{}`)) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	_, _ = vaultKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "tok", "endpoint": srv.URL})
	if deep {
		t.Error("deep Vault endpoints must not be hit without --vault-intrusive")
	}
}
