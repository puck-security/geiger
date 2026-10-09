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

func TestAzureImpactRolesAndRBAC(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	mux := http.NewServeMux()
	// Token endpoint: audience-specific tokens.
	mux.HandleFunc("/"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := "GRAPHTOKEN"
		if strings.Contains(r.Form.Get("scope"), "management.azure.com") {
			tok = "ARMTOKEN"
		}
		_, _ = w.Write([]byte(`{"access_token":"` + tok + `","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"user-oid-1"}`))
	})
	mux.HandleFunc("/me/memberOf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[
			{"@odata.type":"#microsoft.graph.directoryRole","displayName":"Global Administrator","roleTemplateId":"62e90394-69f5-4237-9190-012177145e10"},
			{"@odata.type":"#microsoft.graph.group","displayName":"All Staff"}
		]}`))
	})
	mux.HandleFunc("/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"subscriptionId":"sub-1"}]}`))
	})
	mux.HandleFunc("/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "user-oid-1") {
			t.Errorf("roleAssignments not filtered by principal: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"value":[
			{"properties":{"roleDefinitionId":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}
		]}`))
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
	fs := azureImpact(context.Background(), c, tenant, "clientid", "refreshtoken")
	got := indexByKey(fs)
	if er, ok := got["entra roles"]; !ok || er.Flag != module.FlagForceMultiplier || !strings.Contains(er.Value, "Global Administrator") {
		t.Errorf("entra roles finding wrong: %+v", got["entra roles"])
	}
	if rb, ok := got["azure rbac"]; !ok || rb.Flag != module.FlagForceMultiplier || !strings.Contains(rb.Value, "Owner") {
		t.Errorf("azure rbac finding wrong: %+v", got["azure rbac"])
	}
}

func TestAzureImpactGateOff(t *testing.T) {
	// azureImpact is only called from Recon under AzureIntrusive; here we confirm
	// Recon does not call it (no token minting) without the flag.
	minted := false
	const tenant = "11111111-2222-3333-4444-555555555555"
	mux := http.NewServeMux()
	mux.HandleFunc("/"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		minted = true
		_, _ = w.Write([]byte(`{"access_token":"X"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := azureMSALEndpoints
	azureMSALEndpoints.TokenTmpl = srv.URL + "/%s/oauth2/v2.0/token"
	azureMSALEndpoints.Graph = srv.URL
	azureMSALEndpoints.ARM = srv.URL
	defer func() { azureMSALEndpoints = orig }()

	c := recon.New(srv.Client(), true) // not azure-intrusive, not intrusive
	_, _ = azureMSAL{}.Recon(context.Background(), c, module.Token{},
		module.Fields{"refresh_token": "rt", "client_id": "cid", "tenant": tenant})
	if minted {
		t.Error("refresh token must not be redeemed without --azure-intrusive/--intrusive")
	}
}
