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

// intrusiveClient returns a live+intrusive client whose every request is
// rewritten to srv (so https module URLs land on the local test server).
func intrusiveClient(srv *httptest.Server) *recon.Client {
	hc := &http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}
	c := recon.New(hc, true)
	c.SetIntrusive(true)
	return c
}

func TestConfluentRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/iam/v2/api-keys", func(w http.ResponseWriter, r *http.Request) {
		if u, _, _ := r.BasicAuth(); u != "KEYID" {
			t.Errorf("expected basic user=KEYID, got %q", u)
		}
		respond(w, `{"data":[{"spec":{"owner":{"id":"sa-123","kind":"ServiceAccount"}}}]}`)
	})
	mux.HandleFunc("/org/v2/environments", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"env-a"},{"id":"env-b"}]}`)
	})
	mux.HandleFunc("/iam/v2/service-accounts", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"sa-123"}]}`)
	})
	got := driveModule(t, "confluent", module.Fields{"key": "KEYID", "secret": "SEKRET"}, mux)
	if got["owner"].Value != "sa-123" || got["owner type"].Value != "ServiceAccount" {
		t.Errorf("owner not extracted: %+v", got["owner"])
	}
	if got["environments"].Value != "2" {
		t.Errorf("environment count wrong: %+v", got["environments"])
	}
}

func TestJumpCloudRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/systemusers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "JCKEY" {
			t.Errorf("x-api-key not set: %q", r.Header.Get("x-api-key"))
		}
		respond(w, `{"totalCount":418,"results":[]}`)
	})
	mux.HandleFunc("/api/systems", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"totalCount":77,"results":[]}`)
	})
	got := driveModule(t, "jumpcloud", module.Fields{"token": "JCKEY"}, mux)
	if got["users (full directory)"].Value != "418" {
		t.Errorf("user count wrong: %+v", got)
	}
	if got["managed systems"].Value != "77" {
		t.Errorf("system count wrong: %+v", got)
	}
}

func TestSailPointExchangeAndOrgAdmin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("expected client_credentials, got %q", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"SPTOKEN","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/oauth/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SPTOKEN" {
			t.Errorf("whoami not using exchanged token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"user_name":"admin@acme","org":"acme","pod":"useast1","authorities":["ORG_ADMIN"]}`)
	})
	got := driveModule(t, "sailpoint", module.Fields{
		"endpoint": "https://acme.api.identitynow.com", "client_id": "cid", "client_secret": "csec"}, mux)
	if got["user"].Value != "admin@acme" || got["org"].Value != "acme" {
		t.Errorf("identity wrong: %+v", got)
	}
	if got["privilege"].Flag != module.FlagForceMultiplier {
		t.Errorf("ORG_ADMIN should raise a force-multiplier signal: %+v", got["privilege"])
	}
}

func TestPingOneExchangeAndEnv(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/env-123/as/token", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"access_token":"PINGTOK","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/v1/environments/env-123", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"name":"Production","type":"PRODUCTION","region":"EU"}`)
	})
	mux.HandleFunc("/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"_embedded":{"environments":[{"id":"env-123"},{"id":"env-456"}]}}`)
	})
	mux.HandleFunc("/v1/environments/env-123/users", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"count":1200,"_embedded":{"users":[]}}`)
	})
	got := driveModule(t, "pingone", module.Fields{
		"api": "https://api.pingone.eu", "auth": "https://auth.pingone.eu",
		"env": "env-123", "client_id": "cid", "client_secret": "csec"}, mux)
	if got["environment"].Value != "Production" {
		t.Errorf("env name wrong: %+v", got)
	}
	if got["users (environment directory)"].Value != "1200" || got["users (environment directory)"].Flag != module.FlagForceMultiplier {
		t.Errorf("user count/flag wrong: %+v", got["users (environment directory)"])
	}
}

func TestCyberArkPVWALogon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/PasswordVault/API/Auth/CyberArk/Logon", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `"SESSIONTOKEN123"`) // body is a quoted JSON string
	})
	mux.HandleFunc("/PasswordVault/API/Safes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SESSIONTOKEN123" {
			t.Errorf("expected raw session token (no Bearer), got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"count":12,"Safes":[]}`)
	})
	mux.HandleFunc("/PasswordVault/API/Accounts", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"count":340,"value":[]}`)
	})
	got := driveModule(t, "cyberark_pvwa", module.Fields{
		"endpoint": "https://acme.privilegecloud.cyberark.com", "username": "svc", "password": "pw"}, mux)
	if got["safes (caller is a member of)"].Value != "12" {
		t.Errorf("safe count wrong: %+v", got)
	}
	if got["privileged accounts"].Value != "340" {
		t.Errorf("account count wrong: %+v", got)
	}
}

func TestDopplerReconAndHarvest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/me", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"type":"service_account","workplace":{"name":"Acme","slug":"acme"}}`)
	})
	mux.HandleFunc("/v3/projects", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"projects":[{"slug":"backend"}]}`)
	})
	mux.HandleFunc("/v3/configs", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"configs":[{"name":"prd"}]}`)
	})
	mux.HandleFunc("/v3/configs/config/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dp.pt.tok" {
			t.Errorf("secrets read not using bearer: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"secrets":{"DB_URL":{"computed":"postgres://prod"},"API_KEY":{"computed":"sk_live_x"}}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// recon via driveModule (rewrites host)
	got := driveModule(t, "doppler", module.Fields{"token": "dp.pt.tok"}, mux)
	if got["workplace"].Value != "Acme" {
		t.Errorf("workplace wrong: %+v", got)
	}

	// harvest directly: point the global API host at the test server
	orig := dopplerAPI
	dopplerAPI = srv.URL
	defer func() { dopplerAPI = orig }()
	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)
	hv := dopplerHarvest(context.Background(), c, "dp.pt.tok")
	if len(hv) != 2 {
		t.Fatalf("expected 2 harvested secrets, got %d: %+v", len(hv), hv)
	}
	vals := map[string]bool{}
	for _, x := range hv {
		vals[x.Value] = true
	}
	if !vals["postgres://prod"] || !vals["sk_live_x"] {
		t.Errorf("plaintext secret values not harvested: %+v", hv)
	}
}

func TestOnePasswordConnectHarvest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"id":"vault1","name":"Prod"}]`)
	})
	mux.HandleFunc("/v1/vaults/vault1/items", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"id":"item1","title":"DB"}]`)
	})
	mux.HandleFunc("/v1/vaults/vault1/items/item1", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"title":"DB","fields":[{"label":"password","type":"CONCEALED","value":"hunter2"},{"label":"username","type":"STRING","value":"admin"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	c.SetIntrusive(true)

	hv := opConnectHarvest(context.Background(), c, srv.URL, "optoken")
	if len(hv) != 1 {
		t.Fatalf("expected 1 concealed field harvested, got %d: %+v", len(hv), hv)
	}
	if hv[0].Value != "hunter2" {
		t.Errorf("concealed value wrong: %+v", hv[0])
	}
}

func TestConjurFullFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/authn/acme/host%2Fmyapp/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "base64" {
			t.Errorf("authn missing Accept-Encoding base64: %q", r.Header.Get("Accept-Encoding"))
		}
		respond(w, "BASE64TOKEN")
	})
	mux.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != `Token token="BASE64TOKEN"` {
			t.Errorf("whoami auth header wrong: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"username":"host/myapp","account":"acme"}`)
	})
	mux.HandleFunc("/api/resources/acme", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("count") == "true" {
			respond(w, `{"count":9}`)
			return
		}
		respond(w, `[{"id":"acme:variable:db/password"},{"id":"acme:variable:api/key"}]`)
	})
	// secret ids contain "/", which gets %2F-escaped — match the whole subtree.
	mux.HandleFunc("/api/secrets/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `s3cr3t-`+strings.ReplaceAll(r.URL.Path, "/", "_"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := intrusiveClient(srv)

	f := module.Fields{"endpoint": "https://conjur.acme.com/api", "api_key": "APIKEY", "login": "host/myapp", "account": "acme"}
	m := conjur{}
	tok, err := m.Authenticate(context.Background(), c, f)
	if err != nil || tok.Bearer != "BASE64TOKEN" {
		t.Fatalf("authenticate failed: tok=%q err=%v", tok.Bearer, err)
	}
	fs, err := m.Recon(context.Background(), c, tok, f)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["role"].Value != "host/myapp" {
		t.Errorf("whoami role wrong: %+v", got["role"])
	}
	if got["secrets in reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("variable count should be a force multiplier: %+v", got["secrets in reach"])
	}
	hv, _ := m.Harvest(context.Background(), c, tok, f)
	if len(hv) != 2 {
		t.Fatalf("expected 2 harvested secrets, got %d: %+v", len(hv), hv)
	}
}

func TestDuoSigningAndHarvest(t *testing.T) {
	mux := http.NewServeMux()
	var sawAuth, sawDate bool
	mux.HandleFunc("/admin/v1/users", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "IKEY" && p != "" {
			sawAuth = true
		}
		sawDate = r.Header.Get("Date") != ""
		respond(w, `{"stat":"OK","response":[],"metadata":{"total_objects":501}}`)
	})
	mux.HandleFunc("/admin/v3/integrations", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"stat":"OK","metadata":{"total_objects":2},"response":[
			{"name":"VPN","integration_key":"DI1","secret_key":"skey-vpn"},
			{"name":"RDP","integration_key":"DI2","secret_key":"skey-rdp"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := intrusiveClient(srv)

	f := module.Fields{"host": "api-abc.duosecurity.com", "ikey": "IKEY", "skey": "SKEY"}
	m := duoAdmin{}
	fs, err := m.Recon(context.Background(), c, module.Token{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !sawAuth || !sawDate {
		t.Errorf("Duo request not signed: basic-auth=%v date=%v", sawAuth, sawDate)
	}
	got := indexByKey(fs)
	if got["users"].Value != "501" {
		t.Errorf("user count wrong: %+v", got["users"])
	}
	if got["integrations"].Flag != module.FlagForceMultiplier {
		t.Errorf("integrations should be a force multiplier: %+v", got["integrations"])
	}
	hv, _ := m.Harvest(context.Background(), c, module.Token{}, f)
	if len(hv) != 2 || hv[0].Value == "" {
		t.Fatalf("expected 2 harvested skeys, got %+v", hv)
	}
}

// sanity: the Duo canonical signature is deterministic for a fixed input.
func TestDuoCanonParams(t *testing.T) {
	got := duoCanonParams(map[string][]string{"limit": {"1"}, "offset": {"0"}})
	if got != "limit=1&offset=0" {
		t.Errorf("canonical params wrong: %q", got)
	}
	if duoEsc("a b") != "a%20b" {
		t.Errorf("space must encode as %%20, got %q", duoEsc("a b"))
	}
}
