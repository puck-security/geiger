package modules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestZabbixTokenRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api_jsonrpc.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ZT" {
			t.Errorf("6.4 token must ride Authorization: Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"jsonrpc":"2.0","result":"57","id":1}`)
	})
	got := driveModule(t, "zabbix", module.Fields{"token": "ZT", "endpoint": "https://zbx.acme.com"}, mux)
	if got["hosts (in reach)"].Value != "57" {
		t.Errorf("host count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("script.execute should be fm: %+v", got["reach"])
	}
}

func TestZabbixLoginExchange(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api_jsonrpc.php", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "user.login") {
			respond(w, `{"jsonrpc":"2.0","result":"SESSIONTOK","id":1}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer SESSIONTOK" {
			t.Errorf("recon not using logged-in token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"jsonrpc":"2.0","result":"3","id":1}`)
	})
	got := driveModule(t, "zabbix", module.Fields{"username": "Admin", "password": "zabbix", "endpoint": "https://zbx.acme.com"}, mux)
	if got["hosts (in reach)"].Value != "3" {
		t.Errorf("login-path recon failed: %+v", got)
	}
}

func TestSplunkTokenRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/services/authentication/current-context", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SJWT" {
			t.Errorf("JWT token must use Bearer scheme, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"entry":[{"content":{"username":"admin","roles":["admin"]}}]}`)
	})
	mux.HandleFunc("/services/data/indexes", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"paging":{"total":12},"entry":[]}`)
	})
	got := driveModule(t, "splunk", module.Fields{"token": "SJWT", "endpoint": "https://splunk.acme.com:8089"}, mux)
	if got["user"].Value != "admin" || got["indexes"].Value != "12" {
		t.Errorf("splunk fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("scripted-input RCE should be fm: %+v", got["reach"])
	}
}

func TestSplunkLoginUsesSplunkScheme(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/services/auth/login", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"sessionKey":"SK123"}`)
	})
	mux.HandleFunc("/services/authentication/current-context", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Splunk SK123" {
			t.Errorf("session key must use the Splunk scheme, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"entry":[{"content":{"username":"svc"}}]}`)
	})
	mux.HandleFunc("/services/data/indexes", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"paging":{"total":1}}`) })
	got := driveModule(t, "splunk", module.Fields{"username": "svc", "password": "pw", "endpoint": "https://splunk.acme.com:8089"}, mux)
	if got["user"].Value != "svc" {
		t.Errorf("splunk login exchange failed: %+v", got)
	}
}

func TestAuvikRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/inventory/device/info", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ops@acme.com" || p != "AVK" {
			t.Errorf("auvik must use Basic email:key, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"data":[{"id":"dev-1","attributes":{}}]}`)
	})
	got := driveModule(t, "auvik", module.Fields{"username": "ops@acme.com", "token": "AVK", "endpoint": "https://auvikapi.us1.my.auvik.com"}, mux)
	if got["devices"].Value != "dev-1" {
		t.Errorf("auvik device not read: %+v", got)
	}
}

func TestManageEngineOpManagerRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/json/device/listDevices", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apiKey") != "OPM" {
			t.Errorf("apiKey must be in the query, got %q", r.URL.Query().Get("apiKey"))
		}
		respond(w, `[{"name":"r1"},{"name":"r2"},{"name":"r3"}]`)
	})
	got := driveModule(t, "manageengine_opmanager", module.Fields{"token": "OPM", "endpoint": "https://opm.acme.com:8443"}, mux)
	if got["devices"].Value != "3" {
		t.Errorf("device count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("workflow script reach should be fm: %+v", got["reach"])
	}
}

func TestMonitoringRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"zabbix token", "ZABBIX_URL=https://zbx.acme.com\nZABBIX_API_TOKEN=zt\n", "", "zabbix", "zt"},
		{"splunk token", "SPLUNK_URL=https://splunk:8089\nSPLUNK_TOKEN=st\n", "", "splunk", "st"},
		{"auvik", "AUVIK_USERNAME=a@b.com\nAUVIK_API_KEY=ak\nAUVIK_REGION=us1\n", "", "auvik", "ak"},
		{"manageengine via --endpoint", "OPMANAGER_API_KEY=ok\n", "https://opm.acme.com", "manageengine_opmanager", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.env, ".env")
			by := modulesOf(recognize.Recognize(b, tc.endpoint, module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
		})
	}
}
