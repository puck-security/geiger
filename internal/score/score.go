// Package score derives a relative blast-radius score and tier for a Note.
//
// The score is composed from the intrinsic signals Geiger already collects —
// capability class (flags), reach (counts), and sensitivity tags (prod/pii/…) —
// because without externally-supplied context that is the most honest ranking
// available. Supplying a context (crown-jewel account IDs, prod hosts, critical
// repos) boosts matching findings: intrinsic signal ranks relative danger,
// context ranks danger to *you*.
package score

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Tier is a coarse, honest bucket (we deliberately avoid a fake-precise 0-100).
type Tier string

const (
	TierCritical Tier = "CRITICAL"
	TierHigh     Tier = "HIGH"
	TierMedium   Tier = "MEDIUM"
	TierLow      Tier = "LOW"
	TierInfo     Tier = "INFO"
	TierDead     Tier = "DEAD"
)

// Context is optional operator-supplied criticality: substrings whose presence
// in a finding marks the credential as touching a crown-jewel asset.
type Context struct {
	Terms []string // e.g. account IDs, prod hostnames, critical repo names
}

// Matches reports whether any context term appears in the note.
func (c Context) Matches(n module.Note) bool {
	if len(c.Terms) == 0 {
		return false
	}
	hay := strings.ToLower(n.Title)
	for _, f := range n.Findings {
		hay += "\n" + strings.ToLower(f.Value)
	}
	for _, t := range c.Terms {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && strings.Contains(hay, t) {
			return true
		}
	}
	return false
}

var sensitiveRe = regexp.MustCompile(`(?i)\b(prod|production|pii|customer|backup|admin|root|secret)\b`)

// countRe matches a standalone count (optionally ~-prefixed) bounded by
// whitespace/start/end, so dates (2099-01-01), versions (8.0.36), ports, and
// IDs embedded with -, :, ., / separators are NOT mistaken for blast radius.
var countRe = regexp.MustCompile(`(?:^|\s)~?(\d[\d,]*)(?:\s|$)`)

// notReachRe matches a number that follows a reach-irrelevant word (a version,
// port, release, etc.), so "version 5432" / "port 6379" aren't read as reach
// even though the number is whitespace-bounded.
var notReachRe = regexp.MustCompile(`(?i)\b(version|port|release|build|revision|rev)\s+~?\d`)

// BlastRadius returns a relative score (0 = dead/invalid). Higher is worse.
func BlastRadius(n module.Note, ctx Context) int {
	if n.Invalid {
		return 0
	}
	s := 0
	forceMultipliers := 0
	for _, f := range n.Findings {
		switch f.Flag {
		case module.FlagForceMultiplier:
			forceMultipliers++
			s += 40
		case module.FlagWarn:
			s += 18
		case module.FlagInfo:
			s += 4
		case module.FlagCantCharacterize:
			s += 2
		}
		// reach: a count in the value is a blast-surface proxy (log-ish, capped).
		if n := reachBonus(f.Value); n > 0 {
			s += n
		}
		// sensitivity tags in the value.
		if sensitiveRe.MatchString(f.Value) {
			s += 10
		}
	}
	// multiple force multipliers compound (chained admin/secrets/assume).
	if forceMultipliers > 1 {
		s += 20 * (forceMultipliers - 1)
	}
	// operator-supplied crown-jewel context is the strongest single signal.
	if ctx.Matches(n) {
		s += 100
	}
	return s
}

// reachBonus extracts a leading count from a finding value and maps it to a
// small capped bonus (10→+4, 100→+8, 1000→+12, 10k+→+16).
func reachBonus(val string) int {
	if notReachRe.MatchString(val) {
		return 0 // a version/port number, not a reach count
	}
	m := countRe.FindStringSubmatch(val)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", ""))
	if err != nil || n < 5 {
		return 0
	}
	switch {
	case n >= 10000:
		return 16
	case n >= 1000:
		return 12
	case n >= 100:
		return 8
	default:
		return 4
	}
}

// TierFor maps a score to a tier. Context matches force at least HIGH, and a
// single force-multiplier finding (a named high-impact capability — RCE, wipe,
// full-DB, RLS-bypass) also floors at HIGH: such a capability should never rank
// merely MEDIUM just because reach couldn't be sized.
func TierFor(n module.Note, ctx Context) Tier {
	if n.Invalid {
		return TierDead
	}
	s := BlastRadius(n, ctx)
	ctxHit := ctx.Matches(n)
	fm := hasForceMultiplier(n)
	switch {
	case s >= 120 || (ctxHit && s >= 60):
		return TierCritical
	case s >= 60 || ctxHit || fm:
		return TierHigh
	case s >= 30:
		return TierMedium
	case s >= 12:
		return TierLow
	default:
		return TierInfo
	}
}

func hasForceMultiplier(n module.Note) bool {
	for _, f := range n.Findings {
		if f.Flag == module.FlagForceMultiplier {
			return true
		}
	}
	return false
}
