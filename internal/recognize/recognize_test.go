package recognize

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
)

func TestGitleaksRoutesStripeToModule(t *testing.T) {
	reg := module.NewRegistry()
	reg.MapRule("stripe-access-token", "stripe")

	b := parse.Parse("STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n", ".env")
	matches := Recognize(b, "", reg)

	var found *Match
	for i := range matches {
		if matches[i].Module == "stripe" {
			found = &matches[i]
		}
	}
	if found == nil {
		t.Fatalf("stripe not recognized; got %+v", matches)
	}
	if found.Fields["token"] != "sk_live_4eC39HqLyjWDarjtT1zdp7dc" {
		t.Errorf("token field = %q", found.Fields["token"])
	}
	if found.Label != "STRIPE_SECRET_KEY" {
		t.Errorf("label = %q (want var name)", found.Label)
	}
}

func TestCustomRecognizerRuns(t *testing.T) {
	reg := module.NewRegistry()
	RegisterRecognizer(func(b parse.Blob, endpoint string, reg *module.Registry) []Match {
		if b.Vars["MY_SET_ID"] != "" && b.Vars["MY_SET_SECRET"] != "" {
			return []Match{{Module: "myset", Fields: module.Fields{
				"id": b.Vars["MY_SET_ID"], "secret": b.Vars["MY_SET_SECRET"],
			}, Secret: b.Vars["MY_SET_SECRET"]}}
		}
		return nil
	})
	b := parse.Parse("MY_SET_ID=abc\nMY_SET_SECRET=xyz\n", ".env")
	matches := Recognize(b, "", reg)
	ok := false
	for _, m := range matches {
		if m.Module == "myset" && m.Fields["id"] == "abc" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("custom recognizer didn't fire: %+v", matches)
	}
}
