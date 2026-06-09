package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestNinjaOneRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant = %q", r.Form.Get("grant_type"))
		}
		respond(w, `{"access_token":"NJ","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/v2/organizations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer NJ" {
			t.Errorf("recon not using token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `[{"id":1,"name":"Acme"},{"id":2,"name":"Beta"}]`)
	})
	got := driveModule(t, "ninjaone", module.Fields{"client_id": "c", "client_secret": "s", "endpoint": "https://app.ninjarmm.com"}, mux)
	if got["first org"].Value != "Acme" || got["organizations"].Value != "2" {
		t.Errorf("org fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("RCE reach should be force multiplier: %+v", got["reach"])
	}
}

func TestAteraRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "AK" {
			t.Errorf("X-API-KEY not set: %q", r.Header.Get("X-API-KEY"))
		}
		respond(w, `{"totalItemCount":42,"items":[{"AgentID":1}]}`)
	})
	got := driveModule(t, "atera", module.Fields{"token": "AK"}, mux)
	if got["agents (managed endpoints)"].Value != "42" {
		t.Errorf("agent count wrong: %+v", got)
	}
}

func TestKandjiRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer KT" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `[{"device_id":"d1","device_name":"Mac-1"}]`)
	})
	got := driveModule(t, "kandji", module.Fields{"token": "KT", "endpoint": "https://acme.api.kandji.io"}, mux)
	if got["device"].Value != "Mac-1" {
		t.Errorf("device not read: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("wipe reach should be fm: %+v", got["reach"])
	}
}

func TestJamfOAuthRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"access_token":"JT","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/api/v1/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer JT" {
			t.Errorf("auth not bearer JT: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"account":{"username":"svc","privilegeSet":"ADMINISTRATOR"}}`)
	})
	mux.HandleFunc("/api/v1/computers-inventory", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"totalCount":120,"results":[]}`)
	})
	got := driveModule(t, "jamf", module.Fields{"client_id": "c", "client_secret": "s", "endpoint": "https://acme.jamfcloud.com"}, mux)
	if got["account"].Value != "svc" || got["computers"].Value != "120" {
		t.Errorf("jamf fields wrong: %+v", got)
	}
	if got["privilege"].Flag != module.FlagForceMultiplier || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin/wipe should be fm: %+v", got)
	}
}

func TestJamfBasicAuthLogin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "pw" {
			t.Errorf("token endpoint must use Basic auth, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `{"token":"JBASIC","expires":"2099-01-01T00:00:00Z"}`)
	})
	mux.HandleFunc("/api/v1/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer JBASIC" {
			t.Errorf("recon not using basic-derived token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"account":{"username":"svc"}}`)
	})
	mux.HandleFunc("/api/v1/computers-inventory", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"totalCount":1}`) })
	got := driveModule(t, "jamf", module.Fields{"username": "svc", "password": "pw", "endpoint": "https://acme.jamfcloud.com"}, mux)
	if got["account"].Value != "svc" {
		t.Errorf("basic-auth login failed: %+v", got)
	}
}

func TestMosyleRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/listdevices", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("listdevices should be POST")
		}
		respond(w, `{"devices":[{"deviceudid":"a"},{"deviceudid":"b"}]}`)
	})
	got := driveModule(t, "mosyle", module.Fields{"token": "MT"}, mux)
	if got["devices"].Value != "2" {
		t.Errorf("device count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("wipe reach should be fm: %+v", got["reach"])
	}
}

func TestAutomoxRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer AX" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"email":"ops@acme.com","id":1}`)
	})
	mux.HandleFunc("/api/servers", func(w http.ResponseWriter, r *http.Request) { respond(w, `[{"id":1}]`) })
	mux.HandleFunc("/api/orgs", func(w http.ResponseWriter, r *http.Request) { respond(w, `[{"id":1},{"id":2}]`) })
	got := driveModule(t, "automox", module.Fields{"token": "AX"}, mux)
	if got["user"].Value != "ops@acme.com" || got["orgs"].Value != "2" {
		t.Errorf("automox fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("worklet RCE should be fm: %+v", got["reach"])
	}
}

func TestTaniumRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/session/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("session") != "TS" {
			t.Errorf("token must ride the `session` header, got %q", r.Header.Get("session"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("must NOT use Authorization header")
		}
		respond(w, `{"data":{"name":"svc","id":1}}`)
	})
	mux.HandleFunc("/api/v2/computer_groups", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":1},{"id":2},{"id":3}]}`)
	})
	got := driveModule(t, "tanium", module.Fields{"token": "TS", "endpoint": "https://tanium.acme.com"}, mux)
	if got["user"].Value != "svc" || got["computer groups (targetable scope)"].Value != "3" {
		t.Errorf("tanium fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("action RCE should be fm: %+v", got["reach"])
	}
}

func TestAnsibleAWXRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/me/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"results":[{"username":"admin"}]}`)
	})
	mux.HandleFunc("/api/v2/inventories/", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"count":5}`) })
	mux.HandleFunc("/api/v2/job_templates/", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"count":9}`) })
	got := driveModule(t, "ansible_awx", module.Fields{"token": "AWX", "endpoint": "https://awx.acme.com"}, mux)
	if got["user"].Value != "admin" || got["job templates"].Value != "9" {
		t.Errorf("awx fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("playbook RCE should be fm: %+v", got["reach"])
	}
}

func TestPuppetTokenRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rbac-api/v1/users/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Authentication") != "PT" {
			t.Errorf("token must ride X-Authentication, got %q", r.Header.Get("X-Authentication"))
		}
		respond(w, `{"login":"svc","role_ids":[1,2]}`)
	})
	mux.HandleFunc("/classifier-api/v1/groups", func(w http.ResponseWriter, r *http.Request) { respond(w, `[{"id":"g1"}]`) })
	got := driveModule(t, "puppet_enterprise", module.Fields{"token": "PT", "endpoint": "https://pe.acme.com:4433"}, mux)
	if got["user"].Value != "svc" {
		t.Errorf("puppet user wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("task RCE should be fm: %+v", got["reach"])
	}
}

func TestSaltStackLoginAndExec(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("eauth") != "pam" || r.Form.Get("username") != "salt" {
			t.Errorf("login form wrong: %v", r.Form)
		}
		respond(w, `{"return":[{"token":"ST","perms":["@wheel"]}]}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "ST" {
			t.Errorf("token must ride X-Auth-Token, got %q", r.Header.Get("X-Auth-Token"))
		}
		respond(w, `{"clients":["local","local_async"],"return":"Welcome"}`)
	})
	got := driveModule(t, "saltstack", module.Fields{"username": "salt", "password": "pw", "endpoint": "https://salt.acme.com:8000"}, mux)
	if got["salt-api"].Value != "local" {
		t.Errorf("salt-api not validated: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("cmd.run RCE should be fm: %+v", got["reach"])
	}
}

func TestFleetTokenRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fleet/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer FT" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"user":{"email":"admin@acme.com","global_role":"admin"}}`)
	})
	mux.HandleFunc("/api/v1/fleet/hosts/count", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"count":1000}`) })
	got := driveModule(t, "fleet", module.Fields{"token": "FT", "endpoint": "https://fleet.acme.com"}, mux)
	if got["user"].Value != "admin@acme.com" || got["hosts"].Value != "1000" {
		t.Errorf("fleet fields wrong: %+v", got)
	}
	if got["privilege"].Flag != module.FlagForceMultiplier || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("admin + RCE/wipe should be fm: %+v", got)
	}
}

func TestFleetLoginExchange(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fleet/login", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"token":"FLOGIN","user":{"email":"a@b.com"}}`)
	})
	mux.HandleFunc("/api/v1/fleet/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer FLOGIN" {
			t.Errorf("recon not using logged-in token: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"user":{"email":"a@b.com","global_role":"observer"}}`)
	})
	mux.HandleFunc("/api/v1/fleet/hosts/count", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"count":3}`) })
	got := driveModule(t, "fleet", module.Fields{"username": "a@b.com", "password": "pw", "endpoint": "https://fleet.acme.com"}, mux)
	if got["user"].Value != "a@b.com" {
		t.Errorf("fleet login exchange failed: %+v", got)
	}
}

// --- recognizer behavior ---

func TestEndpointMgmtRecognizers(t *testing.T) {
	cases := []struct {
		name   string
		env    string
		module string
		secret string
	}{
		{"ninjaone set-shape", "NINJA_CLIENT_ID=cid\nNINJA_CLIENT_SECRET=csec\n", "ninjaone", "csec"},
		{"atera", "ATERA_API_KEY=ak123\n", "atera", "ak123"},
		{"automox", "AUTOMOX_API_KEY=ax123\n", "automox", "ax123"},
		{"jamf oauth", "JAMF_URL=https://acme.jamfcloud.com\nJAMF_CLIENT_ID=c\nJAMF_CLIENT_SECRET=cs\n", "jamf", "cs"},
		{"fleet token", "FLEET_URL=https://fleet.acme.com\nFLEET_API_TOKEN=ftok\n", "fleet", "ftok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.env, ".env")
			by := modulesOf(recognize.Recognize(b, "", module.Default))
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

func TestSelfHostedNeedsEndpoint(t *testing.T) {
	// Tanium has no shape and is self-hosted: a bare token with no host must NOT
	// be claimed (we'd have nowhere to send recon).
	b := parse.Parse("TANIUM_API_TOKEN=tok-abc\n", ".env")
	if _, ok := modulesOf(recognize.Recognize(b, "", module.Default))["tanium"]; ok {
		t.Errorf("tanium should not be recognized without an endpoint")
	}
	// With --endpoint it is.
	if _, ok := modulesOf(recognize.Recognize(b, "https://tanium.acme.com", module.Default))["tanium"]; !ok {
		t.Errorf("tanium should be recognized once --endpoint is supplied")
	}
}
