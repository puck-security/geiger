package modules

import (
	"net/http"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

const (
	workosKey      = "sk_test_a2V5XzAxSFpYQU1QTEUwUkVDT05LRVkwMDAwMDE=" // body decodes to "key_..."
	workosClientID = "client_01KV5WJNT7TTMGVEY0EXAMPLE0"
)

func matchByModule(ms []recognize.Match, name string) *recognize.Match {
	for i := range ms {
		if ms[i].Module == name {
			return &ms[i]
		}
	}
	return nil
}

func TestWorkOSRecognizerVarName(t *testing.T) {
	b := parse.Parse("WORKOS_CLIENT_ID="+workosClientID+"\nWORKOS_API_KEY="+workosKey+"\n", ".env")
	matches := recognize.Recognize(b, "", module.Default)
	wm := matchByModule(matches, "workos")
	if wm == nil {
		t.Fatalf("workos not recognized: %+v", matches)
	}
	if wm.Fields["token"] != workosKey {
		t.Errorf("token = %q", wm.Fields["token"])
	}
	if wm.Fields["client_id"] != workosClientID {
		t.Errorf("client_id = %q", wm.Fields["client_id"])
	}
}

func TestWorkOSRecognizerOddClientIDVar(t *testing.T) {
	// Next.js AuthKit convention: NEXT_PUBLIC_WORKOS_CLIENT_ID.
	b := parse.Parse("NEXT_PUBLIC_WORKOS_CLIENT_ID="+workosClientID+"\nWORKOS_API_KEY="+workosKey+"\n", ".env")
	matches := recognize.Recognize(b, "", module.Default)
	wm := matchByModule(matches, "workos")
	if wm == nil || wm.Fields["client_id"] != workosClientID {
		t.Fatalf("client_id from NEXT_PUBLIC var not carried: %+v", wm)
	}
}

func TestWorkOSRecognizerStructural(t *testing.T) {
	// Bare tokens in source — no WORKOS_* var names.
	raw := "const apiKey = \"" + workosKey + "\";\nconst clientId = \"" + workosClientID + "\";\n"
	b := parse.Parse(raw, "config.js")
	matches := recognize.Recognize(b, "", module.Default)
	wm := matchByModule(matches, "workos")
	if wm == nil {
		t.Fatalf("workos not recognized structurally: %+v", matches)
	}
	if wm.Fields["token"] != workosKey {
		t.Errorf("token = %q", wm.Fields["token"])
	}
	if wm.Fields["client_id"] != workosClientID {
		t.Errorf("client_id = %q", wm.Fields["client_id"])
	}
}

func TestWorkOSRecognizerStructuralLive(t *testing.T) {
	// The recognizer must also claim the sk_live_ arm, not just sk_test_.
	liveKey := strings.Replace(workosKey, "sk_test_", "sk_live_", 1)
	b := parse.Parse("const k = \""+liveKey+"\";\n", "config.js")
	matches := recognize.Recognize(b, "", module.Default)
	wm := matchByModule(matches, "workos")
	if wm == nil {
		t.Fatalf("sk_live_ structural match missed: %+v", matches)
	}
	if wm.Fields["token"] != liveKey {
		t.Errorf("token = %q", wm.Fields["token"])
	}
}

func TestWorkOSRecognizerIgnoresRealStripe(t *testing.T) {
	b := parse.Parse("STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n", ".env")
	matches := recognize.Recognize(b, "", module.Default)
	if matchByModule(matches, "workos") != nil {
		t.Errorf("real Stripe key wrongly claimed as workos: %+v", matches)
	}
	if matchByModule(matches, "stripe") == nil {
		t.Errorf("stripe should still be recognized: %+v", matches)
	}
}

func TestWorkOSRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/organizations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk_live_KEY" {
			t.Errorf("workos must use Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"data":[{"id":"org_1","name":"Acme"}],"list_metadata":{}}`)
	})
	mux.HandleFunc("/sso/connections", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"conn_1"}],"list_metadata":{}}`)
	})
	mux.HandleFunc("/directories", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"dir_1"}],"list_metadata":{}}`)
	})
	mux.HandleFunc("/directory_users", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"du_1"}],"list_metadata":{}}`)
	})
	mux.HandleFunc("/user_management/users", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":[{"id":"user_1"}],"list_metadata":{}}`)
	})
	got := driveModule(t, "workos", module.Fields{"token": "sk_live_KEY", "client_id": "client_x"}, mux)
	if got["org"].Value != "Acme" {
		t.Errorf("org = %q", got["org"].Value)
	}
	if got["sso-connections"].Flag != module.FlagForceMultiplier {
		t.Errorf("sso-connections should be force-multiplier: %+v", got["sso-connections"])
	}
	if got["directory-PII"].Flag != module.FlagWarn {
		t.Errorf("directory-PII should be warn: %+v", got["directory-PII"])
	}
	if got["user-PII"].Flag != module.FlagWarn {
		t.Errorf("user-PII should be warn: %+v", got["user-PII"])
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("static reach should be force-multiplier: %+v", got["reach"])
	}
}
