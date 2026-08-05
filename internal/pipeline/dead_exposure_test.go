package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/note"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/score"
)

// A dead credential in a log file still indicts the logging pipeline: a token
// reached a log, and the next one through may be live. The exposure survives
// even though the credential itself scores zero.
func TestDeadCredentialKeepsExposure(t *testing.T) {
	res := Result{Note: module.Note{Title: "jwt …AAAA", Invalid: true, Reason: "expired 2020-09-13"}}
	annotateContext(&res, parse.Blob{File: "/srv/app/app.log"}, Options{})

	var exposure *module.Finding
	for i, f := range res.Note.Findings {
		if f.Key == module.ExposureKey {
			exposure = &res.Note.Findings[i]
		}
	}
	if exposure == nil {
		t.Fatalf("dead note lost its exposure: %+v", res.Note.Findings)
	}
	if !strings.Contains(exposure.Value, "log file") {
		t.Errorf("exposure = %q", exposure.Value)
	}
	// Still dead, still scores zero — this is context, not impact.
	if got := score.TierFor(res.Note, score.Context{}); got != score.TierDead {
		t.Errorf("tier = %s, want DEAD", got)
	}
	if got := score.BlastRadius(res.Note, score.Context{}); got != 0 {
		t.Errorf("score = %d, want 0", got)
	}
}

// Only the exposure survives. A dead note's own detail was deliberately
// suppressed and must not come back with it.
func TestDeadCredentialGainsOnlyExposure(t *testing.T) {
	res := Result{Note: module.Note{
		Title: "jwt …AAAA", Invalid: true, Reason: "expired",
		Findings: []module.Finding{{Key: "subject", Value: "user-123", Flag: module.FlagInfo}},
	}}
	annotateContext(&res, parse.Blob{File: "/srv/app/app.log"}, Options{})

	rendered := note.Text(res.Note)
	if !strings.Contains(rendered, "log file") {
		t.Errorf("exposure should be shown for a dead note:\n%s", rendered)
	}
	if strings.Contains(rendered, "user-123") {
		t.Errorf("a dead note's own detail should stay suppressed:\n%s", rendered)
	}
	if !strings.Contains(rendered, "invalid") {
		t.Errorf("reason line missing:\n%s", rendered)
	}
}

// An ordinary file has no exposure class, so a dead credential found there gains
// nothing — the classifier is what keeps this from becoming noise.
func TestDeadCredentialInOrdinaryFileGainsNothing(t *testing.T) {
	res := Result{Note: module.Note{Title: "jwt …AAAA", Invalid: true, Reason: "expired"}}
	annotateContext(&res, parse.Blob{File: "/srv/app/.env"}, Options{})
	if len(res.Note.Findings) != 0 {
		t.Errorf("want no findings for an ordinary path, got %+v", res.Note.Findings)
	}
}

// A live credential's context must be unchanged by this.
func TestLiveCredentialStillGetsFullContext(t *testing.T) {
	res := Result{Note: module.Note{Title: "jwt …AAAA"}}
	b := parse.Blob{File: "/srv/app/app.log"}
	b.ModTime = testTime()
	annotateContext(&res, b, Options{})
	keys := map[string]bool{}
	for _, f := range res.Note.Findings {
		keys[f.Key] = true
	}
	if !keys[module.ExposureKey] || !keys["source modified"] {
		t.Errorf("live note lost context: %+v", res.Note.Findings)
	}
}

func testTime() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
