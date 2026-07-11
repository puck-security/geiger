package modules

import (
	"net/http"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// a syntactically valid three-segment token (prefix.id.secret); secret is exactly
// 64 alphanumerics, id within 8..128.
var (
	dtID     = strings.Repeat("B", 24)
	dtSecret = strings.Repeat("A", 64)
	dtAPITok = "dt0c01." + dtID + "." + dtSecret // classic API token / PAT
	dtPlatTk = "dt0s16." + dtID + "." + dtSecret // 3rd-gen platform token
)

func TestDynatraceRecognizer(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		wantModule   string // "" = expect neither dynatrace nor needs_endpoint
		wantEndpoint string
		wantTenant   string
	}{
		{"token + live tenant", dtAPITok + " https://qxz71834.live.dynatrace.com/api", "dynatrace",
			"https://qxz71834.live.dynatrace.com", "qxz71834.live.dynatrace.com"},
		{"prod apps normalized to live", dtAPITok + " mwk52907.apps.dynatrace.com", "dynatrace",
			"https://mwk52907.live.dynatrace.com", "mwk52907.apps.dynatrace.com"},
		{"dev apps label dropped", dtAPITok + " tnv38115.dev.apps.dynatracelabs.com", "dynatrace",
			"https://tnv38115.dev.dynatracelabs.com", "tnv38115.dev.apps.dynatracelabs.com"},
		{"dev host unchanged", dtAPITok + " tnv38115.dev.dynatracelabs.com", "dynatrace",
			"https://tnv38115.dev.dynatracelabs.com", "tnv38115.dev.dynatracelabs.com"},
		{"platform token recognized", dtPlatTk + " https://qxz71834.live.dynatrace.com", "dynatrace",
			"https://qxz71834.live.dynatrace.com", "qxz71834.live.dynatrace.com"},
		{"token via env vars", "DT_API_TOKEN=" + dtAPITok + "\nDT_ENV_URL=https://jrb64200.live.dynatrace.com\n", "dynatrace",
			"https://jrb64200.live.dynatrace.com", ""},
		{"token without tenant", dtAPITok + "\n", "needs_endpoint", "", ""},
		{"two-segment client id ignored", "dt0s02." + dtID + "\n", "", "", ""},
		{"short secret ignored", "dt0c01." + dtID + "." + strings.Repeat("A", 32) + "\n", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.raw, "test.env"), "", module.Default))
			for k := range by {
				if strings.HasPrefix(k, "__unknown__") {
					t.Errorf("leftover generic hit %q should be suppressed by our recognizer", k)
				}
			}
			if tc.wantModule == "" {
				if _, ok := by["dynatrace"]; ok {
					t.Errorf("must not recognize as dynatrace: %+v", by)
				}
				if _, ok := by["needs_endpoint"]; ok {
					t.Errorf("must not emit needs_endpoint: %+v", by)
				}
				return
			}
			m, ok := by[tc.wantModule]
			if !ok {
				t.Fatalf("not recognized as %s: %+v", tc.wantModule, by)
			}
			if m.Secret != dtAPITok && m.Secret != dtPlatTk {
				t.Errorf("secret = %q", m.Secret)
			}
			if tc.wantEndpoint != "" && m.Fields["endpoint"] != tc.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", m.Fields["endpoint"], tc.wantEndpoint)
			}
			if tc.wantTenant != "" && m.Fields["tenant"] != tc.wantTenant {
				t.Errorf("tenant = %q, want %q", m.Fields["tenant"], tc.wantTenant)
			}
		})
	}
}

func TestDynatraceAPIHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"qxz71834.live.dynatrace.com", "qxz71834.live.dynatrace.com"},             // classic API, unchanged
		{"mwk52907.apps.dynatrace.com", "mwk52907.live.dynatrace.com"},             // prod 3rd-gen → classic
		{"tnv38115.dev.apps.dynatracelabs.com", "tnv38115.dev.dynatracelabs.com"},  // dev 3rd-gen → classic
		{"tnv38115.sprint.dynatracelabs.com", "tnv38115.sprint.dynatracelabs.com"}, // qualifier preserved
	}
	for _, tc := range cases {
		if got := dynatraceAPIHost(tc.in); got != tc.want {
			t.Errorf("dynatraceAPIHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func dtReconMux(t *testing.T, status int, body string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/apiTokens/lookup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("lookup must POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Api-Token dttok" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
		respond(w, body)
	})
	return mux
}

func dtDrive(t *testing.T, status int, body string) map[string]module.Finding {
	return driveModule(t, "dynatrace",
		module.Fields{"token": "dttok", "endpoint": "https://qxz71834.live.dynatrace.com"},
		dtReconMux(t, status, body))
}

func TestDynatraceReconPrivilegeScope(t *testing.T) {
	got := dtDrive(t, 200, `{"name":"ci","owner":"joe@acme.com","personalAccessToken":false,`+
		`"lastUsedIpAddress":"1.2.3.4","scopes":["apiTokens.write","entities.read"]}`)
	if got["privilege"].Flag != module.FlagForceMultiplier {
		t.Errorf("takeover scope must be a force multiplier: %+v", got["privilege"])
	}
	if got["owner"].Value != "joe@acme.com" {
		t.Errorf("owner = %q", got["owner"].Value)
	}
	if got["last used IP"].Value != "1.2.3.4" {
		t.Errorf("last used IP = %q", got["last used IP"].Value)
	}
}

func TestDynatraceReconSensitiveReadIsMediumNotHigh(t *testing.T) {
	// Bulk sensitive read (logs) → exposure warn (MEDIUM), NOT a force multiplier.
	got := dtDrive(t, 200, `{"name":"ro","owner":"a@b.com","scopes":["logs.read"]}`)
	if got["exposure"].Flag != module.FlagWarn {
		t.Errorf("logs.read should be an exposure warn: %+v", got["exposure"])
	}
	if _, ok := got["privilege"]; ok {
		t.Errorf("sensitive read must NOT be a force multiplier: %+v", got["privilege"])
	}
}

func TestDynatraceReconIngestIsIntegrity(t *testing.T) {
	// A valid write/ingest token (the live BMO case) must outrank read-only: it
	// gets an integrity warn but not a force multiplier → MEDIUM, not LOW.
	got := dtDrive(t, 200, `{"name":"ai-obs","owner":"a@b.com","scopes":["metrics.ingest","logs.ingest"]}`)
	if got["integrity"].Flag != module.FlagWarn {
		t.Errorf("ingest scope should be an integrity warn: %+v", got["integrity"])
	}
	if _, ok := got["privilege"]; ok {
		t.Errorf("ingest must NOT be a force multiplier: %+v", got["privilege"])
	}
}

func TestDynatraceReconCredentialVaultReadStaysLow(t *testing.T) {
	// credentialVault.read returns metadata only (no secret material) → recon.
	// It must not fire ANY severity signal (LOW baseline). Guards against a future
	// edit silently re-promoting it based on the scary name.
	got := dtDrive(t, 200, `{"name":"ro","owner":"a@b.com","scopes":["credentialVault.read"]}`)
	for _, k := range []string{"privilege", "exposure", "integrity"} {
		if _, ok := got[k]; ok {
			t.Errorf("credentialVault.read must not fire %q (metadata-only recon): %+v", k, got[k])
		}
	}
}

func TestDynatraceReconTrivialWriteStaysLow(t *testing.T) {
	// Curated, not blanket: a trivial write (slo.write) must not be flagged as
	// integrity — it falls to the LOW baseline.
	got := dtDrive(t, 200, `{"name":"ro","owner":"a@b.com","scopes":["slo.write"]}`)
	for _, k := range []string{"privilege", "exposure", "integrity"} {
		if _, ok := got[k]; ok {
			t.Errorf("trivial write slo.write must not fire %q: %+v", k, got[k])
		}
	}
}

func TestDynatraceReconReadOnlyStaysLow(t *testing.T) {
	got := dtDrive(t, 200, `{"name":"ro","owner":"a@b.com","scopes":["entities.read"]}`)
	for _, k := range []string{"privilege", "exposure", "integrity"} {
		if _, ok := got[k]; ok {
			t.Errorf("read-only token must not be flagged %q: %+v", k, got[k])
		}
	}
	if got["scopes"].Value != "entities.read" {
		t.Errorf("scopes = %q", got["scopes"].Value)
	}
	if len(got) == 0 {
		t.Error("read-only token should still produce findings (not dead)")
	}
}

func TestDynatraceReconInvalidToken(t *testing.T) {
	// 401 on the lookup (dead/expired/invalid) → no findings → Summarize marks DEAD.
	got := dtDrive(t, 401, `{"error":{"code":401,"message":"Token is invalid"}}`)
	if len(got) != 0 {
		t.Errorf("401 must yield no findings (DEAD), got %+v", got)
	}
}

func TestDynatraceReconValidButScoped(t *testing.T) {
	// 403 = valid platform token lacking apiTokens.read to introspect itself.
	got := dtDrive(t, 403, `{"error":{"code":403,"message":"Token is missing required scope"}}`)
	if got["authenticated"].Flag != module.FlagWarn {
		t.Errorf("403 should report an accepted-but-scoped credential, not dead: %+v", got)
	}
}
