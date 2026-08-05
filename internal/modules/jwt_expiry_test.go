package modules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/score"
)

func summarizeJWT(t *testing.T, claims map[string]any) module.Note {
	t.Helper()
	tok := makeJWT(claims)
	fs, err := genericJWT{}.Recon(context.Background(), recon.New(nil, false), module.Token{}, module.Fields{"token": tok})
	if err != nil {
		t.Fatal(err)
	}
	return genericJWT{}.Summarize("jwt …test", fs)
}

func jwtClaims(exp any) map[string]any {
	c := map[string]any{
		"iss":   "https://auth.example.com",
		"sub":   "user-123",
		"aud":   "api",
		"scope": "read write",
	}
	if exp != nil {
		c["exp"] = exp
	}
	return c
}

// An expired JWT provably cannot authenticate — geiger knows this offline,
// without a live call — so it is a dead credential, not a finding to rotate.
func TestExpiredJWTIsDead(t *testing.T) {
	n := summarizeJWT(t, jwtClaims(float64(time.Now().Add(-time.Hour).Unix())))
	if !n.Invalid {
		t.Fatalf("expired JWT should be invalid, got %+v", n)
	}
	if !strings.Contains(n.Reason, "expired") {
		t.Errorf("reason should say it expired, got %q", n.Reason)
	}
	if got := score.TierFor(n, score.Context{}); got != score.TierDead {
		t.Errorf("tier = %s, want %s", got, score.TierDead)
	}
	if got := score.BlastRadius(n, score.Context{}); got != 0 {
		t.Errorf("score = %d, want 0", got)
	}
}

// The bug this replaces: expiry carried FlagWarn (+18) and liveness FlagInfo
// (+4), so an expired token outscored an identical live one. A live JWT is the
// usable case and must always rank above an expired one.
func TestLiveJWTOutranksExpired(t *testing.T) {
	live := summarizeJWT(t, jwtClaims(float64(time.Now().Add(24*time.Hour).Unix())))
	expired := summarizeJWT(t, jwtClaims(float64(time.Now().Add(-time.Hour).Unix())))

	if live.Invalid {
		t.Fatalf("live JWT should not be invalid: %+v", live)
	}
	ls := score.BlastRadius(live, score.Context{})
	es := score.BlastRadius(expired, score.Context{})
	if ls <= es {
		t.Errorf("live scored %d, expired scored %d — live must rank higher", ls, es)
	}
	// Tier is asserted only as "not dead": the module's own findings are one input,
	// and a real scan adds exposure/timeline context on top that lifts it further.
	if got := score.TierFor(live, score.Context{}); got == score.TierDead {
		t.Errorf("live tier = %s (score %d)", got, ls)
	}
	got := indexByKey(live.Findings)
	if got["expires"].Flag != module.FlagWarn {
		t.Errorf("an unexpired bearer token is the usable case and should warn, got flag %v", got["expires"].Flag)
	}
	if !strings.Contains(got["expires"].Value, "live") {
		t.Errorf("expires = %q, want it marked live", got["expires"].Value)
	}
}

// A JWT with no exp claim can't be proven expired, so it stays a live finding.
func TestJWTWithoutExpiryIsNotDead(t *testing.T) {
	n := summarizeJWT(t, jwtClaims(nil))
	if n.Invalid {
		t.Fatalf("JWT without exp should not be marked dead: %+v", n)
	}
	if indexByKey(n.Findings)["expires"].Key != "" {
		t.Errorf("no exp claim should produce no expires finding")
	}
}

// An undecodable JWT keeps its own reason rather than being reported as expired.
func TestUndecodableJWTKeepsItsReason(t *testing.T) {
	n := genericJWT{}.Summarize("jwt …test", nil)
	if !n.Invalid {
		t.Fatal("empty findings should be invalid")
	}
	if strings.Contains(n.Reason, "expired") {
		t.Errorf("reason = %q, should not claim expiry", n.Reason)
	}
}
