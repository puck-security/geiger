package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// driveModule runs a registered module end-to-end (Authenticate + Recon)
// against a local test server, rewriting every outbound host to it. This
// exercises the real recipe — auth scheme, token exchange, field paths, flags —
// without hitting any live provider.
func driveModule(t *testing.T, name string, fields module.Fields, mux *http.ServeMux) map[string]module.Finding {
	t.Helper()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hc := &http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}
	c := recon.New(hc, true)
	mod, ok := module.Default.ByName(name)
	if !ok {
		t.Fatalf("module %q not registered", name)
	}
	ctx := context.Background()
	tok, err := mod.Authenticate(ctx, c, fields)
	if err != nil {
		t.Fatalf("%s authenticate: %v", name, err)
	}
	fs, err := mod.Recon(ctx, c, tok, fields)
	if err != nil {
		t.Fatalf("%s recon: %v", name, err)
	}
	return indexByKey(fs)
}

func respond(w http.ResponseWriter, body string) { _, _ = w.Write([]byte(body)) }

func TestZoomServerToServerOAuth(t *testing.T) {
	mux := http.NewServeMux()
	gotToken := false
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		gotToken = true
		if r.Method != http.MethodPost {
			t.Errorf("token exchange must POST")
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "account_credentials" {
			t.Errorf("wrong grant: %s", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"ZTKN","token_type":"bearer"}`)
	})
	mux.HandleFunc("/v2/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ZTKN" {
			t.Errorf("recon must use exchanged token, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"email":"a@b.com","type":2,"role_name":"Owner"}`)
	})
	mux.HandleFunc("/v2/users", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"total_records":50,"users":[{"id":"u1"}]}`)
	})
	got := driveModule(t, "zoom", module.Fields{"client_id": "c", "client_secret": "s", "account_id": "acc"}, mux)
	if !gotToken {
		t.Error("token endpoint not called")
	}
	if got["privilege"].Flag != module.FlagForceMultiplier {
		t.Errorf("Owner role should be force-multiplier: %+v", got["privilege"])
	}
	if got["users (PII)"].Value != "50" {
		t.Errorf("users count = %q", got["users (PII)"].Value)
	}
}

func TestVonageBalance(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/account/get-balance", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api_key") != "k" || r.URL.Query().Get("api_secret") != "s" {
			t.Errorf("creds not in query: %s", r.URL.RawQuery)
		}
		respond(w, `{"value":12.34,"autoReload":false}`)
	})
	got := driveModule(t, "vonage", module.Fields{"api_key": "k", "api_secret": "s"}, mux)
	if got["balance"].Value != "12.34" {
		t.Errorf("balance = %q", got["balance"].Value)
	}
	if got["reach"].Flag != module.FlagWarn {
		t.Errorf("reach note missing")
	}
}

func TestMailchimpDatacenterAndPII(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/3.0/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"account_name":"Acme","email":"o@acme.com","role":"owner"}`)
	})
	mux.HandleFunc("/3.0/lists", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"total_items":4}`)
	})
	got := driveModule(t, "mailchimp", module.Fields{"token": "abc-us21", "user": "geiger", "dc": "us21"}, mux)
	if got["account"].Value != "Acme" {
		t.Errorf("account = %q", got["account"].Value)
	}
	if got["audiences (subscriber PII)"].Flag != module.FlagForceMultiplier {
		t.Errorf("audiences PII flag wrong: %+v", got["audiences (subscriber PII)"])
	}
}

func TestBoxAdminRole(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/2.0/users/me", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"name":"Svc","login":"svc@acme.com","role":"admin"}`)
	})
	got := driveModule(t, "box", module.Fields{"token": "boxtok"}, mux)
	if got["privilege"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin role not flagged: %+v", got["privilege"])
	}
	if got["data"].Flag != module.FlagWarn {
		t.Errorf("data note missing")
	}
}

func TestDocuSignUserinfo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"name":"Signer","email":"s@acme.com","accounts":[{"account_name":"Acme Legal"}]}`)
	})
	got := driveModule(t, "docusign", module.Fields{"token": "dstok"}, mux)
	if got["account"].Value != "Acme Legal" {
		t.Errorf("account = %q", got["account"].Value)
	}
	if got["data"].Flag != module.FlagForceMultiplier {
		t.Errorf("legal-docs data should be force-multiplier")
	}
}

func TestDigitalOceanDataReach(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/account", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"account":{"email":"a@b.com","status":"active"}}`)
	})
	mux.HandleFunc("/v2/droplets", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"meta":{"total":7}}`) })
	mux.HandleFunc("/v2/databases", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"databases":[{"id":"a"},{"id":"b"}]}`) })
	mux.HandleFunc("/v2/kubernetes/clusters", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"kubernetes_clusters":[]}`) })
	got := driveModule(t, "digitalocean", module.Fields{"token": "dop"}, mux)
	if got["managed databases"].Value != "2" || got["managed databases"].Flag != module.FlagWarn {
		t.Errorf("managed databases wrong: %+v", got["managed databases"])
	}
}

func TestHuggingFaceWriteToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami-v2", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"name":"bot","type":"user","auth":{"accessToken":{"role":"write"}},"orgs":[{"name":"acme"}]}`)
	})
	got := driveModule(t, "huggingface", module.Fields{"token": "hf"}, mux)
	if got["token role"].Flag != module.FlagForceMultiplier {
		t.Errorf("write token not flagged: %+v", got["token role"])
	}
	if got["orgs"].Flag != module.FlagWarn {
		t.Errorf("orgs note missing")
	}
}

func TestHeuristicLiftsThinModule(t *testing.T) {
	// Even with no per-module signal, the heuristic scanner surfaces admin/PII
	// from a generic response — proving the drift safety net works in-catalog.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"login":"svc","email":"svc@acme.com","isGrafanaAdmin":true}`)
	})
	mux.HandleFunc("/api/org", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"name":"Main"}`) })
	mux.HandleFunc("/api/datasources", func(w http.ResponseWriter, r *http.Request) { respond(w, `[]`) })
	got := driveModule(t, "grafana", module.Fields{"token": "glsa", "endpoint": "https://grafana.example"}, mux)
	if got["server admin"].Flag != module.FlagForceMultiplier {
		t.Errorf("grafana admin not flagged: %+v", got["server admin"])
	}
	if got["PII"].Flag != module.FlagWarn {
		t.Errorf("heuristic PII not surfaced: %+v", got)
	}
}

func TestOpenAIMeFields(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"object":"user","id":"user-1","email":"jane@acme.com","name":"Jane Dev","orgs":{"object":"list","data":[{"id":"org-1","name":"Acme Inc","role":"owner","is_default":true}]}}`)
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}`)
	})
	got := driveModule(t, "openai", module.Fields{"token": "sk-x"}, mux)
	if got["name"].Value != "Jane Dev" {
		t.Errorf("name = %q", got["name"].Value)
	}
	if got["org"].Value != "Acme Inc" {
		t.Errorf("org = %q", got["org"].Value)
	}
	if got["org role"].Flag != module.FlagForceMultiplier {
		t.Errorf("owner role not flagged: %+v", got["org role"])
	}
	if got["models accessible"].Value != "2" {
		t.Errorf("models = %q", got["models accessible"].Value)
	}
}
