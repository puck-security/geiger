package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestJiraRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/api/3/myself", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "jane@acme.com" || p != "JTOK" {
			t.Errorf("jira must use Basic email:token, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"accountId":"5b","displayName":"Jane","emailAddress":"jane@acme.com"}`)
	})
	mux.HandleFunc("/rest/api/3/project/search", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"total":42,"values":[]}`)
	})
	mux.HandleFunc("/rest/api/3/users/search", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `[{"accountId":"u1"}]`)
	})
	got := driveModule(t, "jira", module.Fields{"email": "jane@acme.com", "token": "JTOK", "endpoint": "https://acme.atlassian.net"}, mux)
	if got["account"].Value != "5b" || got["projects"].Value != "42" {
		t.Errorf("jira fields wrong: %+v", got)
	}
}

func TestConfluenceRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wiki/rest/api/user/current", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "jane@acme.com" || p != "CTOK" {
			t.Errorf("confluence must use Basic email:token, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"accountId":"5b","displayName":"Jane","email":"jane@acme.com"}`)
	})
	mux.HandleFunc("/wiki/rest/api/space", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"results":[{"key":"DEV"},{"key":"OPS"}],"size":2}`)
	})
	got := driveModule(t, "confluence", module.Fields{"email": "jane@acme.com", "token": "CTOK", "endpoint": "https://acme.atlassian.net"}, mux)
	if got["account"].Value != "5b" || got["spaces"].Value != "2" {
		t.Errorf("confluence fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagWarn {
		t.Errorf("confluence reach should be warn: %+v", got["reach"])
	}
}

// One Atlassian Cloud API token reaches both products, so a shared ATLASSIAN_*
// credential must surface both a jira and a confluence finding.
func TestAtlassianSharedTokenHitsBoth(t *testing.T) {
	env := "ATLASSIAN_URL=https://acme.atlassian.net\nATLASSIAN_EMAIL=j@acme.com\nATLASSIAN_API_TOKEN=ATATTshared\n"
	by := modulesOf(recognize.Recognize(parse.Parse(env, ".env"), "", module.Default))
	for _, m := range []string{"jira", "confluence"} {
		if _, ok := by[m]; !ok {
			t.Errorf("shared Atlassian token should trigger %s: %+v", m, by)
		}
	}
}

func TestIvantiRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/odata/businessobject/employees", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "rest_api_key=IVK" {
			t.Errorf("ivanti auth header wrong: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"value":[{"RecId":"r1"}]}`)
	})
	got := driveModule(t, "ivanti", module.Fields{"token": "IVK", "endpoint": "https://ivanti.acme.com"}, mux)
	if got["reach"].Flag != module.FlagWarn {
		t.Errorf("ivanti reach should be warn: %+v", got["reach"])
	}
}

func TestPingFederateRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pf-admin-api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		if u, _, ok := r.BasicAuth(); !ok || u != "admin" {
			t.Errorf("pingfed must use Basic, got user=%q ok=%v", u, ok)
		}
		if r.Header.Get("X-XSRF-Header") != "PingFederate" {
			t.Errorf("missing X-XSRF-Header")
		}
		respond(w, `{"version":"11.3.0"}`)
	})
	mux.HandleFunc("/pf-admin-api/v1/oauth/clients", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"items":[{"clientId":"a"},{"clientId":"b"}]}`)
	})
	mux.HandleFunc("/pf-admin-api/v1/idp/connections", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"items":[]}`) })
	got := driveModule(t, "pingfederate", module.Fields{"username": "admin", "password": "pw", "endpoint": "https://pf.acme.com:9999"}, mux)
	if got["version"].Value != "11.3.0" || got["oauth clients"].Value != "2" {
		t.Errorf("pingfed fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("federation-trust reach should be fm: %+v", got["reach"])
	}
}

func TestSnipeITRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/hardware", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SNT" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"total":500,"rows":[]}`)
	})
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"total":50,"rows":[]}`) })
	got := driveModule(t, "snipeit", module.Fields{"token": "SNT", "endpoint": "https://assets.acme.com"}, mux)
	if got["assets"].Value != "500" || got["users (PII)"].Value != "50" {
		t.Errorf("snipeit fields wrong: %+v", got)
	}
}

func TestClickHouseCloudRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/organizations", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "KID" || p != "KSEC" {
			t.Errorf("clickhouse cloud must use Basic keyid:secret, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"result":[{"id":"o1","name":"Acme"}]}`)
	})
	got := driveModule(t, "clickhouse_cloud", module.Fields{"key": "KID", "secret": "KSEC"}, mux)
	if got["org"].Value != "Acme" || got["organizations"].Value != "1" {
		t.Errorf("clickhouse cloud fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin key reach should be fm: %+v", got["reach"])
	}
}

func TestClickHouseSelfHostedRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClickHouse-User") != "default" || r.Header.Get("X-ClickHouse-Key") != "chpw" {
			t.Errorf("clickhouse self-hosted headers wrong: %q / %q", r.Header.Get("X-ClickHouse-User"), r.Header.Get("X-ClickHouse-Key"))
		}
		respond(w, `{"data":[{"currentUser()":"default"}]}`)
	})
	got := driveModule(t, "clickhouse_selfhosted", module.Fields{"username": "default", "password": "chpw", "endpoint": "https://ch.acme.com:8443"}, mux)
	if got["user"].Value != "default" {
		t.Errorf("clickhouse self-hosted user wrong: %+v", got)
	}
}

func TestITSMIAMRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"jira", "JIRA_BASE_URL=https://acme.atlassian.net\nJIRA_EMAIL=j@acme.com\nJIRA_API_TOKEN=jt\n", "", "jira", "jt"},
		{"confluence", "CONFLUENCE_BASE_URL=https://acme.atlassian.net\nCONFLUENCE_EMAIL=j@acme.com\nCONFLUENCE_API_TOKEN=ct\n", "", "confluence", "ct"},
		{"confluence via --endpoint", "CONFLUENCE_EMAIL=j@acme.com\nCONFLUENCE_API_TOKEN=ct2\n", "https://acme.atlassian.net", "confluence", "ct2"},
		{"ivanti", "IVANTI_URL=https://ivanti.acme.com\nIVANTI_API_KEY=ik\n", "", "ivanti", "ik"},
		{"pingfederate", "PINGFEDERATE_URL=https://pf:9999\nPINGFEDERATE_USERNAME=a\nPINGFEDERATE_PASSWORD=pw\n", "", "pingfederate", "pw"},
		{"clickhouse cloud", "CLICKHOUSE_KEY_ID=kid\nCLICKHOUSE_KEY_SECRET=ksec\n", "", "clickhouse_cloud", "ksec"},
		{"snipeit via --endpoint", "SNIPEIT_API_TOKEN=st\n", "https://assets.acme.com", "snipeit", "st"},
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
