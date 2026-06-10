package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestHeuristicPrivilegeAndIdentity(t *testing.T) {
	// declared path is wrong (drift); heuristics must still surface admin + identity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"account":{"login":"svc-bot","is_admin":true,"email":"svc@acme.com"}}`))
	}))
	defer srv.Close()
	m := HTTP{ModuleName: "d", Base: srv.URL, Auth: AuthSpec{Kind: Bearer},
		Whoami: GET("/x").Field("user", "wrong.path")}.Module() // path won't match
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{}, module.Fields{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]module.Finding{}
	for _, f := range fs {
		got[f.Key] = f
	}
	if got["privileged"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin not detected heuristically: %+v", fs)
	}
	if _, ok := got["PII"]; ok {
		t.Errorf("generic PII finding should no longer be emitted: %+v", fs)
	}
	if got["identity"].Value != "login=svc-bot" {
		t.Errorf("fallback identity wrong: %+v", got["identity"])
	}
}

func TestHeuristicQuietOnCleanResponse(t *testing.T) {
	r := scanJSON(map[string]any{"status": "ok", "count": float64(3)})
	if r.privileged || r.pii {
		t.Errorf("should be quiet: %+v", r)
	}
}
