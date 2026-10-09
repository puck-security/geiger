package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func fakeJWT(payload map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pb, _ := json.Marshal(payload)
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

func TestEntraAppPermFindings(t *testing.T) {
	fs := entraAppPermFindings([]string{"Directory.ReadWrite.All", "User.Read.All", "Application.ReadWrite.All"})
	if len(fs) != 1 || fs[0].Flag != module.FlagForceMultiplier {
		t.Fatalf("expected one force-multiplier finding, got %+v", fs)
	}
	if !strings.Contains(fs[0].Value, "Directory.ReadWrite.All") || !strings.Contains(fs[0].Value, "Application.ReadWrite.All") {
		t.Errorf("privileged perms missing: %q", fs[0].Value)
	}
	if strings.Contains(fs[0].Value, "User.Read.All") {
		t.Errorf("ordinary perm should not be in the privileged list: %q", fs[0].Value)
	}

	// no dangerous perms -> warn listing
	fs = entraAppPermFindings([]string{"User.Read.All"})
	if len(fs) != 1 || fs[0].Flag != module.FlagWarn {
		t.Errorf("ordinary perms should warn: %+v", fs)
	}
}

func TestEntraSPReconDecodesRolesAndRBAC(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	mux := http.NewServeMux()
	mux.HandleFunc("/"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		payload := map[string]any{"roles": []string{"Directory.ReadWrite.All"}, "oid": "sp-oid"}
		_, _ = w.Write([]byte(`{"access_token":"` + fakeJWT(payload) + `","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/organization", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"displayName":"Acme Corp","id":"tid"}]}`))
	})
	mux.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"sub-1"}]}`))
	})
	mux.HandleFunc("/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"properties":{"roleDefinitionId":"/x/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	orig := azureMSALEndpoints
	azureMSALEndpoints.TokenTmpl = srv.URL + "/%s/oauth2/v2.0/token"
	azureMSALEndpoints.Graph = srv.URL
	azureMSALEndpoints.ARM = srv.URL
	defer func() { azureMSALEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	c.SetAzureIntrusive(true)
	f := module.Fields{"tenant": tenant, "client_id": "cid", "client_secret": "sec"}
	tok, err := entraSP{}.Authenticate(context.Background(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := entraSP{}.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["app permissions"].Flag != module.FlagForceMultiplier || !strings.Contains(got["app permissions"].Value, "Directory.ReadWrite.All") {
		t.Errorf("app permissions finding wrong: %+v", got["app permissions"])
	}
	if got["tenant"].Value != "Acme Corp" {
		t.Errorf("tenant = %q", got["tenant"].Value)
	}
	if got["azure rbac"].Flag != module.FlagForceMultiplier || !strings.Contains(got["azure rbac"].Value, "Owner") {
		t.Errorf("azure rbac finding wrong: %+v", got["azure rbac"])
	}
}
