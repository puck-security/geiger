package score

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

// A credential geiger tried and could not characterize must say so rather than
// deriving a severity from descriptive findings that demonstrate no access.
func TestUndeterminedReportsUnknown(t *testing.T) {
	n := module.Note{
		Undetermined: true,
		Reason:       "host unreachable",
		Findings: []module.Finding{
			{Key: "engine", Value: "mysql", Flag: module.FlagInfo},
			{Key: "host", Value: "db.prod", Flag: module.FlagWarn},
			{Key: "user", Value: "app", Flag: module.FlagInfo},
			{Key: "database", Value: "orders", Flag: module.FlagInfo},
		},
	}
	// Those findings would otherwise total enough to read as MEDIUM.
	if got := BlastRadius(n, Context{}); got < 30 {
		t.Fatalf("premise wrong: score %d would not have been MEDIUM anyway", got)
	}
	if got := TierFor(n, Context{}); got != TierUnknown {
		t.Errorf("tier = %s, want %s", got, TierUnknown)
	}
}

// A named capability is evidence of reach and outranks "we could not tell".
func TestForceMultiplierOutranksUndetermined(t *testing.T) {
	n := module.Note{
		Undetermined: true,
		Findings:     []module.Finding{{Key: "admin", Value: "yes", Flag: module.FlagForceMultiplier}},
	}
	if got := TierFor(n, Context{}); got != TierHigh && got != TierCritical {
		t.Errorf("tier = %s, want at least HIGH", got)
	}
}

// So does an operator's crown-jewel match.
func TestContextHitOutranksUndetermined(t *testing.T) {
	n := module.Note{
		Undetermined: true,
		Findings:     []module.Finding{{Key: "account", Value: "acme-prod", Flag: module.FlagInfo}},
	}
	ctx := Context{Terms: []string{"acme-prod"}}
	if !ctx.Matches(n) {
		t.Fatal("premise wrong: context should match")
	}
	if got := TierFor(n, ctx); got == TierUnknown {
		t.Error("a crown-jewel match must outrank undetermined")
	}
}

// Proven dead beats undetermined: nothing was disproved in the UNKNOWN case.
func TestInvalidStillWinsOverUndetermined(t *testing.T) {
	n := module.Note{Invalid: true, Undetermined: true}
	if got := TierFor(n, Context{}); got != TierDead {
		t.Errorf("tier = %s, want DEAD", got)
	}
}

// UNKNOWN sits above DEAD and below INFO, so --min-severity info excludes it
// but the default view shows it.
func TestUnknownRanksBetweenDeadAndInfo(t *testing.T) {
	if Rank(TierDead) >= Rank(TierUnknown) || Rank(TierUnknown) >= Rank(TierInfo) {
		t.Errorf("ranks: dead=%d unknown=%d info=%d", Rank(TierDead), Rank(TierUnknown), Rank(TierInfo))
	}
	if Rank(TierInfo) >= Rank(TierLow) || Rank(TierLow) >= Rank(TierMedium) {
		t.Error("renumbering broke the existing order")
	}
}

func TestParseUnknownTier(t *testing.T) {
	for _, s := range []string{"unknown", "UNKNOWN", " Unknown "} {
		got, ok := ParseTier(s)
		if !ok || got != TierUnknown {
			t.Errorf("ParseTier(%q) = %v, %v", s, got, ok)
		}
	}
}
