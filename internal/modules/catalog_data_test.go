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

func TestSnowflakeRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/statements", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SFPAT" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Snowflake-Authorization-Token-Type") == "" {
			t.Errorf("missing token-type header")
		}
		respond(w, `{"data":[["SVC_USER","ACCOUNTADMIN"]]}`)
	})
	got := driveModule(t, "snowflake", module.Fields{"token": "SFPAT", "endpoint": "https://acme.snowflakecomputing.com"}, mux)
	if got["user"].Value != "SVC_USER" || got["role"].Value != "ACCOUNTADMIN" {
		t.Errorf("snowflake identity wrong: %+v", got)
	}
	if got["privilege"].Flag != module.FlagForceMultiplier || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("ACCOUNTADMIN + reach should be fm: %+v", got)
	}
}

func TestSalesforceRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/services/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SFTOK" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"preferred_username":"ops@acme.com","email":"ops@acme.com","organization_id":"00Dxx0000001"}`)
	})
	got := driveModule(t, "salesforce", module.Fields{"token": "SFTOK", "endpoint": "https://acme.my.salesforce.com"}, mux)
	if got["user"].Value != "ops@acme.com" || got["org"].Value != "00Dxx0000001" {
		t.Errorf("salesforce fields wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("CRM PII reach should be fm: %+v", got["reach"])
	}
}

func TestSupabaseServiceRole(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/admin/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") != "SVCKEY" || r.Header.Get("Authorization") != "Bearer SVCKEY" {
			t.Errorf("supabase needs apikey + bearer: %q / %q", r.Header.Get("apikey"), r.Header.Get("Authorization"))
		}
		respond(w, `{"users":[{"id":"u1"}]}`)
	})
	got := driveModule(t, "supabase", module.Fields{"token": "SVCKEY", "endpoint": "https://abc.supabase.co"}, mux)
	if got["users (admin-readable)"].Flag != module.FlagForceMultiplier || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("service_role RLS-bypass should be fm: %+v", got)
	}
}

func TestPlanetScaleRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/organizations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "tid123:ptok456" {
			t.Errorf("planetscale auth header must be id:token, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":[{"id":"o1"}]}`)
	})
	got := driveModule(t, "planetscale", module.Fields{"token": "tid123:ptok456"}, mux)
	if got["organizations"].Value != "1" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("planetscale fields wrong: %+v", got)
	}
}

func TestNeonRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer NEONK" {
			t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"projects":[{"id":"p1"},{"id":"p2"}]}`)
	})
	got := driveModule(t, "neon", module.Fields{"token": "NEONK"}, mux)
	if got["projects"].Value != "2" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("neon fields wrong: %+v", got)
	}
}

func TestAivenRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"user":{"user":"ops@acme.com"}}`) })
	mux.HandleFunc("/v1/project", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"projects":[{"project_name":"prod"}]}`) })
	got := driveModule(t, "aiven", module.Fields{"token": "AIVENT"}, mux)
	if got["user"].Value != "ops@acme.com" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("aiven fields wrong: %+v", got)
	}
}

func TestUpstashRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/redis/databases", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ops@acme.com" || p != "UPK" {
			t.Errorf("upstash needs Basic email:key, got %q:%q ok=%v", u, p, ok)
		}
		respond(w, `[{"database_id":"d1"}]`)
	})
	got := driveModule(t, "upstash", module.Fields{"username": "ops@acme.com", "token": "UPK"}, mux)
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("upstash reach should be fm: %+v", got)
	}
}

func TestRedisCloudRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "ACCT" || r.Header.Get("x-api-secret-key") != "SEC" {
			t.Errorf("redis cloud dual-key headers wrong: %q / %q", r.Header.Get("x-api-key"), r.Header.Get("x-api-secret-key"))
		}
		respond(w, `{"subscriptions":[{"id":101}]}`)
	})
	got := driveModule(t, "redis_cloud", module.Fields{"account_key": "ACCT", "secret_key": "SEC"}, mux)
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("redis cloud reach should be fm: %+v", got)
	}
}

func TestPlaidRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/institutions/get", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"client_id":"cid"`) || !strings.Contains(string(body), `"secret":"sek"`) {
			t.Errorf("plaid creds must be in the body, got %s", body)
		}
		respond(w, `{"total":11000,"institutions":[{"institution_id":"ins_1"}]}`)
	})
	got := driveModule(t, "plaid", module.Fields{"client_id": "cid", "secret": "sek", "endpoint": "https://production.plaid.com"}, mux)
	if got["institutions reachable"].Value != "11000" {
		t.Errorf("plaid institution count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("financial PII reach should be fm: %+v", got["reach"])
	}
}

func TestDataRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"snowflake (account→host)", "SNOWFLAKE_ACCOUNT=acme-xy12345\nSNOWFLAKE_TOKEN=pat123\n", "", "snowflake", "pat123"},
		{"salesforce", "SALESFORCE_INSTANCE_URL=https://acme.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00Dtok\n", "", "salesforce", "00Dtok"},
		{"supabase", "SUPABASE_URL=https://abc.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=svckey\n", "", "supabase", "svckey"},
		{"planetscale (id:token)", "PLANETSCALE_SERVICE_TOKEN_ID=tid\nPLANETSCALE_SERVICE_TOKEN=ptok\n", "", "planetscale", "ptok"},
		{"neon", "NEON_API_KEY=napi_x\n", "", "neon", "napi_x"},
		{"aiven", "AIVEN_API_TOKEN=avn_x\n", "", "aiven", "avn_x"},
		{"upstash", "UPSTASH_EMAIL=a@b.com\nUPSTASH_API_KEY=upk\n", "", "upstash", "upk"},
		{"redis cloud", "REDISCLOUD_ACCOUNT_KEY=ak\nREDISCLOUD_SECRET_KEY=sk\n", "", "redis_cloud", "sk"},
		{"plaid", "PLAID_CLIENT_ID=cid\nPLAID_SECRET=sek\nPLAID_ENV=sandbox\n", "", "plaid", "sek"},
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
