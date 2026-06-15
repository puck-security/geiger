package modules

import (
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
