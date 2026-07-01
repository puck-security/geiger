// Package note renders a module's Note for the terminal or as JSON.
package note

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/puck-security/geiger/internal/color"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/score"
)

// Sanitize neutralizes control/ANSI sequences and caps length on any string
// that may originate from untrusted input (a hostile API response or a
// malicious variable name), so it can't hijack the terminal. Exported for
// callers that print note-derived text outside Text/JSON (e.g. the summary).
func Sanitize(s string) string { return sanitize(s) }

// sanitize neutralizes control/ANSI sequences and caps length on any string
// that may originate from an untrusted upstream response, so a hostile endpoint
// can't hijack the operator's terminal or flood the output.
func sanitize(s string) string {
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r == unicode.ReplacementChar:
			continue
		case unicode.IsControl(r):
			continue // drop ESC, BEL, other C0/C1 controls
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

const (
	warnMark  = "⚠"
	flagMark  = "⚠⚠" // force multiplier
	questMark = "?"  // can't characterize
)

// Text renders a Note as the short human-readable block (summarized: a
// finding's Detail expansion is omitted).
func Text(n module.Note) string { return text(n, false) }

// TextVerbose renders a Note and expands each finding's Detail (e.g. the full
// list of files a secret was also found in) as indented lines beneath it.
func TextVerbose(n module.Note) string { return text(n, true) }

func text(n module.Note, verbose bool) string {
	var b strings.Builder
	b.WriteString(sanitize(n.Title))
	b.WriteString("\n")
	if n.Invalid {
		fmt.Fprintf(&b, "  invalid : %s\n", sanitize(orDash(n.Reason, "credential not live")))
		return b.String()
	}
	// align keys
	w := 0
	for _, f := range n.Findings {
		if len(f.Key) > w {
			w = len(f.Key)
		}
	}
	for _, f := range n.Findings {
		mark := markFor(f.Flag)
		line := fmt.Sprintf("  %-*s : %s", w, sanitize(f.Key), sanitize(f.Value))
		if mark != "" {
			line += "   " + mark
		}
		b.WriteString(line)
		b.WriteString("\n")
		if verbose {
			for _, d := range f.Detail {
				fmt.Fprintf(&b, "  %-*s   - %s\n", w, "", sanitize(d))
			}
		}
	}
	if n.Summary != "" {
		fmt.Fprintf(&b, "  → %s\n", sanitize(n.Summary))
	}
	return b.String()
}

func markFor(fl module.FlagLevel) string {
	switch fl {
	case module.FlagWarn:
		return color.Warn(warnMark)
	case module.FlagForceMultiplier:
		return color.Force(flagMark + " force multiplier")
	case module.FlagCantCharacterize:
		return color.Cant(questMark + " can't determine with read-only access")
	default:
		return ""
	}
}

func orDash(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		if alt != "" {
			return alt
		}
		return "-"
	}
	return s
}

// jsonNote is the machine-readable shape.
type jsonNote struct {
	Title    string        `json:"title"`
	Tier     string        `json:"tier"`
	Score    int           `json:"score"`
	Invalid  bool          `json:"invalid"`
	Reason   string        `json:"reason,omitempty"`
	Summary  string        `json:"summary,omitempty"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Key    string   `json:"key"`
	Value  string   `json:"value"`
	Flag   string   `json:"flag"`
	Detail []string `json:"detail,omitempty"`
}

func flagName(fl module.FlagLevel) string {
	switch fl {
	case module.FlagInfo:
		return "info"
	case module.FlagWarn:
		return "warn"
	case module.FlagForceMultiplier:
		return "force_multiplier"
	case module.FlagCantCharacterize:
		return "cant_characterize"
	default:
		return "none"
	}
}

// JSON renders a Note as a JSON object. The blast-radius tier and score are
// computed here (from the same score.Context the text renderer uses) so the
// machine shape is self-contained and downstream consumers don't re-derive them.
func JSON(n module.Note, ctx score.Context) string {
	jn := jsonNote{Title: sanitize(n.Title), Tier: string(score.TierFor(n, ctx)), Score: score.BlastRadius(n, ctx), Invalid: n.Invalid, Reason: sanitize(n.Reason), Summary: sanitize(n.Summary), Findings: []jsonFinding{}}
	for _, f := range n.Findings {
		var detail []string
		for _, d := range f.Detail {
			detail = append(detail, sanitize(d))
		}
		jn.Findings = append(jn.Findings, jsonFinding{Key: sanitize(f.Key), Value: sanitize(f.Value), Flag: flagName(f.Flag), Detail: detail})
	}
	out, _ := json.Marshal(jn)
	return string(out)
}
