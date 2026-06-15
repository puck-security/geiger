package recognize

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
)

// TestWorkOSKeyShapeWouldMisattributeToStripe is the precondition guard for the
// modules-package TestWorkOSSuppressesStripeMisattribution: it proves the WorkOS
// key fixture genuinely trips the gitleaks stripe-access-token rule. The WorkOS
// recognizer lives in the modules package and is NOT registered in this test
// binary, so here the key routes to stripe with nothing to suppress it. If
// gitleaks rules ever stop flagging this shape, this fails loudly — signalling
// that the modules suppression test has gone vacuous. Keep the literal in sync
// with modules.workosKey.
func TestWorkOSKeyShapeWouldMisattributeToStripe(t *testing.T) {
	reg := module.NewRegistry()
	reg.MapRule("stripe-access-token", "stripe")
	const workosKey = "sk_test_a2V5XzAxSFpYQU1QTEUwUkVDT05LRVkwMDAwMDAx" // == modules.workosKey
	b := parse.Parse("WORKOS_API_KEY="+workosKey+"\n", ".env")
	matches := Recognize(b, "", reg)
	if m := findByModule(matches, "stripe"); m == nil {
		t.Fatalf("gitleaks must flag the WorkOS key shape as stripe (else the modules suppression test is vacuous); got %+v", matches)
	}
	if findByModule(matches, "workos") != nil {
		t.Fatalf("workos recognizer must not be registered in the recognize test binary: %+v", matches)
	}
}

func findByModule(ms []Match, name string) *Match {
	for i := range ms {
		if ms[i].Module == name {
			return &ms[i]
		}
	}
	return nil
}

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

func TestSuppressOverriddenContainment(t *testing.T) {
	// gitleaks may capture only a prefix of the full token (e.g. up to a '+'/'/'
	// in a WorkOS base64 body), so suppression must be by containment.
	in := []Match{
		{Module: "stripe", Secret: "sk_test_PREFIX"},
		{Module: "workos", Secret: "sk_test_PREFIXtail==", Overrides: []string{"stripe"}},
	}
	out := suppressOverridden(in)
	for _, m := range out {
		if m.Module == "stripe" {
			t.Fatalf("stripe should be dropped by override: %+v", out)
		}
	}
	if len(out) != 1 || out[0].Module != "workos" {
		t.Fatalf("workos override should survive: %+v", out)
	}
}

func TestSuppressOverriddenIgnoresSelf(t *testing.T) {
	// A match listing its own module in Overrides must not delete itself.
	in := []Match{
		{Module: "vendorx", Secret: "abc", Overrides: []string{"vendorx"}},
	}
	out := suppressOverridden(in)
	if len(out) != 1 || out[0].Module != "vendorx" {
		t.Fatalf("self-override must not drop the match: %+v", out)
	}
}

func TestSuppressOverriddenEndToEnd(t *testing.T) {
	reg := module.NewRegistry()
	reg.MapRule("stripe-access-token", "stripe")
	RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []Match {
		if v := b.Vars["FAKE_OVERRIDE_KEY"]; v != "" {
			return []Match{{Module: "vendorx", Secret: v,
				Fields: module.Fields{"token": v}, Overrides: []string{"stripe"}}}
		}
		return nil
	})
	b := parse.Parse("FAKE_OVERRIDE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n", ".env")
	matches := Recognize(b, "", reg)
	for _, m := range matches {
		if m.Module == "stripe" {
			t.Fatalf("stripe should be suppressed by vendorx: %+v", matches)
		}
	}
	ok := false
	for _, m := range matches {
		if m.Module == "vendorx" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("vendorx override missing: %+v", matches)
	}
}
