package score

import (
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func note(invalid bool, fs ...module.Finding) module.Note {
	return module.Note{Title: "t", Invalid: invalid, Findings: fs}
}

func TestInvalidIsDead(t *testing.T) {
	if got := TierFor(note(true), Context{}); got != TierDead {
		t.Errorf("invalid tier = %s", got)
	}
}

func TestForceMultiplierOutranksInfo(t *testing.T) {
	hi := note(false, module.Finding{Key: "secrets", Value: "can list 31 secrets", Flag: module.FlagForceMultiplier})
	lo := note(false, module.Finding{Key: "user", Value: "bob", Flag: module.FlagInfo})
	if BlastRadius(hi, Context{}) <= BlastRadius(lo, Context{}) {
		t.Errorf("force-multiplier should outscore info: hi=%d lo=%d", BlastRadius(hi, Context{}), BlastRadius(lo, Context{}))
	}
}

func TestReachIncreasesScore(t *testing.T) {
	small := note(false, module.Finding{Key: "repos", Value: "~3", Flag: module.FlagInfo})
	big := note(false, module.Finding{Key: "repos", Value: "~3120", Flag: module.FlagInfo})
	if BlastRadius(big, Context{}) <= BlastRadius(small, Context{}) {
		t.Errorf("larger reach should score higher")
	}
}

func TestContextForcesHigh(t *testing.T) {
	n := note(false, module.Finding{Key: "account", Value: "1234567890", Flag: module.FlagInfo})
	base := TierFor(n, Context{})
	withCtx := TierFor(n, Context{Terms: []string{"1234567890"}})
	if base == TierCritical || base == TierHigh {
		t.Skip("base already high")
	}
	if withCtx != TierHigh && withCtx != TierCritical {
		t.Errorf("crown-jewel context should lift tier, got %s", withCtx)
	}
}

func TestCompoundingForceMultipliers(t *testing.T) {
	one := note(false, module.Finding{Flag: module.FlagForceMultiplier})
	two := note(false,
		module.Finding{Flag: module.FlagForceMultiplier},
		module.Finding{Flag: module.FlagForceMultiplier})
	if BlastRadius(two, Context{}) <= 2*40 {
		t.Errorf("multiple force multipliers should compound: %d", BlastRadius(two, Context{}))
	}
	_ = one
}

func TestReachBonusIgnoresDatesAndVersions(t *testing.T) {
	// dates/versions/IDs must not inflate the score as if they were reach counts.
	for _, v := range []string{"2099-01-01 00:00Z  (live)", "8.0.36", "user-1234567", "arn:aws:iam::123456789012:user/x"} {
		if reachBonus(v) != 0 {
			t.Errorf("reachBonus(%q) = %d, want 0 (not a count)", v, reachBonus(v))
		}
	}
	// versions/ports in descriptive text must not be read as reach
	for _, v := range []string{"version 5432", "port 6379", "v8.0 build 41"} {
		if reachBonus(v) != 0 {
			t.Errorf("reachBonus(%q) = %d, want 0 (version/port, not reach)", v, reachBonus(v))
		}
	}
	// real counts still score
	for _, v := range []string{"~312", "47 visible", "can list 31 secrets", "3120"} {
		if reachBonus(v) == 0 {
			t.Errorf("reachBonus(%q) = 0, want >0 (real count)", v)
		}
	}
}

func TestSingleForceMultiplierFloorsHigh(t *testing.T) {
	// A single named high-impact capability (e.g. device wipe) must rank at least
	// HIGH even when reach can't be sized — not MEDIUM.
	n := note(false, module.Finding{Key: "capability", Value: "remote device wipe across the fleet", Flag: module.FlagForceMultiplier})
	if got := TierFor(n, Context{}); got != TierHigh && got != TierCritical {
		t.Errorf("single force-multiplier tier = %s, want >= HIGH", got)
	}
}

func TestFlagNoneIsWeightless(t *testing.T) {
	// FlagNone marks a context line — where else the credential sits, which hosts
	// it might target. It describes surroundings, not proven reach, so it must not
	// move the score by any route: not the flag weight, not the reach bonus, not
	// the sensitivity tags. An SSH key nobody accepted stays LOW when
	// --ssh-correlate adds candidate hosts, so it can't outrank a live key.
	base := note(false,
		module.Finding{Key: "type", Value: "ssh-ed25519", Flag: module.FlagInfo},
		module.Finding{Key: "fingerprint", Value: "SHA256:abc", Flag: module.FlagInfo},
		module.Finding{Key: "host acceptance", Value: "not accepted by GitHub/GitLab/Bitbucket", Flag: module.FlagInfo})
	ctxLines := []module.Finding{
		{Key: "candidate targets", Value: "bastion.example.com  (from local ~/.ssh + history — not confirmed)", Flag: module.FlagNone},
		{Key: "candidate targets", Value: "prod-db.corp, admin.corp  (not confirmed)", Flag: module.FlagNone}, // sensitivity words
		{Key: "candidate targets", Value: "reached 4200 hosts", Flag: module.FlagNone},                        // reach-looking count
	}
	want := BlastRadius(base, Context{})
	if TierFor(base, Context{}) != TierLow {
		t.Fatalf("baseline tier = %s, want LOW (test premise)", TierFor(base, Context{}))
	}
	for _, f := range ctxLines {
		n := note(false, append(append([]module.Finding{}, base.Findings...), f)...)
		if got := BlastRadius(n, Context{}); got != want {
			t.Errorf("context line %q changed the score: %d, want %d", f.Value, got, want)
		}
		if got := TierFor(n, Context{}); got != TierLow {
			t.Errorf("context line %q changed the tier: %s, want LOW", f.Value, got)
		}
	}
}

func TestParseTierAndRank(t *testing.T) {
	cases := map[string]Tier{"critical": TierCritical, "CRIT": TierCritical, "High": TierHigh, "med": TierMedium, "low": TierLow, "info": TierInfo, "dead": TierDead}
	for in, want := range cases {
		got, ok := ParseTier(in)
		if !ok || got != want {
			t.Errorf("ParseTier(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := ParseTier("bogus"); ok {
		t.Error("ParseTier should reject an unknown tier")
	}
	// strict severity ordering, DEAD is the floor
	ladder := []Tier{TierCritical, TierHigh, TierMedium, TierLow, TierInfo, TierDead}
	for i := 1; i < len(ladder); i++ {
		if Rank(ladder[i-1]) <= Rank(ladder[i]) {
			t.Errorf("tier ranks not strictly descending at %s/%s", ladder[i-1], ladder[i])
		}
	}
}
