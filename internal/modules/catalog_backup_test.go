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

func TestVeeamRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-version") == "" {
			t.Errorf("token request missing x-api-version")
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "password" {
			t.Errorf("grant = %q", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"VT","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/api/v1/serverInfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer VT" || r.Header.Get("x-api-version") == "" {
			t.Errorf("recon headers wrong: auth=%q ver=%q", r.Header.Get("Authorization"), r.Header.Get("x-api-version"))
		}
		respond(w, `{"name":"VBR-01","buildVersion":"12.1.0"}`)
	})
	mux.HandleFunc("/api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"pagination":{"total":8},"data":[]}`)
	})
	got := driveModule(t, "veeam", module.Fields{"username": "svc", "password": "pw", "endpoint": "https://vbr.acme.com:9419"}, mux)
	if got["server"].Value != "VBR-01" || got["backup jobs"].Value != "8" {
		t.Errorf("veeam fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("restore reach should be fm: %+v", got["reach"])
	}
}

func TestAcronisRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2/idp/token", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"access_token":"AT","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/api/2/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer AT" {
			t.Errorf("recon not using token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"login":"admin","contact":{"email":"a@acme.com"}}`)
	})
	mux.HandleFunc("/api/2/agents", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"items":[{"id":1},{"id":2}]}`) })
	got := driveModule(t, "acronis", module.Fields{"client_id": "c", "client_secret": "s", "endpoint": "https://eu-cloud.acronis.com"}, mux)
	if got["user"].Value != "admin" || got["agents"].Value != "2" {
		t.Errorf("acronis fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("restore reach should be fm: %+v", got["reach"])
	}
}

func TestCohesityRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/irisservices/api/v1/public/accessTokens", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"accessToken":"CT","tokenType":"Bearer","privileges":["REMOTE_RESTORE"]}`)
	})
	mux.HandleFunc("/irisservices/api/v1/public/sessionUser", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer CT" {
			t.Errorf("recon not using accessToken: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"username":"admin","domain":"LOCAL"}`)
	})
	mux.HandleFunc("/irisservices/api/v1/public/protectionJobs", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"id":1},{"id":2},{"id":3}]`)
	})
	got := driveModule(t, "cohesity", module.Fields{"username": "admin", "password": "pw", "endpoint": "https://cohesity.acme.com"}, mux)
	if got["user"].Value != "admin" || got["protection jobs"].Value != "3" {
		t.Errorf("cohesity fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("REMOTE_RESTORE reach should be fm: %+v", got["reach"])
	}
}

func TestNetBackupAPIKeyRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/netbackup/admin/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer NBKEY" {
			t.Errorf("api key must be Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":[{"id":"job-1"}]}`)
	})
	mux.HandleFunc("/netbackup/config/policies", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"p1"},{"id":"p2"}]}`)
	})
	got := driveModule(t, "netbackup", module.Fields{"token": "NBKEY", "endpoint": "https://nbu.acme.com:1556"}, mux)
	if got["policies"].Value != "2" {
		t.Errorf("policy count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("restore reach should be fm: %+v", got["reach"])
	}
}

func TestCommvaultLoginAndQSDK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/Login", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "cHc=") { // base64("pw")
			t.Errorf("password must be base64-encoded in the body, got %s", body)
		}
		respond(w, `{"token":"CVTOKEN","userGUID":"g1"}`)
	})
	mux.HandleFunc("/CommServ", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authtoken") != "QSDK CVTOKEN" {
			t.Errorf("token must ride Authtoken: QSDK, got %q", r.Header.Get("Authtoken"))
		}
		respond(w, `{"commcell":{"commCellName":"acme-cs"}}`)
	})
	mux.HandleFunc("/Client", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"clientProperties":[{"client":{}},{"client":{}}]}`)
	})
	got := driveModule(t, "commvault", module.Fields{"username": "admin", "password": "pw", "endpoint": "https://cv.acme.com"}, mux)
	if got["commcell"].Value != "acme-cs" || got["clients"].Value != "2" {
		t.Errorf("commvault fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("restore reach should be fm: %+v", got["reach"])
	}
}

func TestBackupRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"veeam", "VEEAM_URL=https://vbr:9419\nVEEAM_USERNAME=svc\nVEEAM_PASSWORD=pw\n", "", "veeam", "pw"},
		{"acronis", "ACRONIS_URL=https://eu.acronis.com\nACRONIS_CLIENT_ID=c\nACRONIS_CLIENT_SECRET=cs\n", "", "acronis", "cs"},
		{"cohesity", "COHESITY_CLUSTER=https://cohesity\nCOHESITY_USERNAME=admin\nCOHESITY_PASSWORD=pw\n", "", "cohesity", "pw"},
		{"netbackup apikey", "NETBACKUP_URL=https://nbu:1556\nNETBACKUP_API_KEY=k\n", "", "netbackup", "k"},
		{"commvault via --endpoint", "COMMVAULT_USERNAME=admin\nCOMMVAULT_PASSWORD=pw\n", "https://cv.acme.com", "commvault", "pw"},
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
