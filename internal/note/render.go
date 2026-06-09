// Package note renders a module's Note for the terminal or as JSON.
package note

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/puck-security/geiger/internal/color"
	"github.com/puck-security/geiger/internal/module"
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

// Text renders a Note as the short human-readable block.
func Text(n module.Note) string {
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
	Invalid  bool          `json:"invalid"`
	Reason   string        `json:"reason,omitempty"`
	Summary  string        `json:"summary,omitempty"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Flag  string `json:"flag"`
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

// JSON renders a Note as a JSON object.
func JSON(n module.Note) string {
	jn := jsonNote{Title: sanitize(n.Title), Invalid: n.Invalid, Reason: sanitize(n.Reason), Summary: sanitize(n.Summary), Findings: []jsonFinding{}}
	for _, f := range n.Findings {
		jn.Findings = append(jn.Findings, jsonFinding{Key: sanitize(f.Key), Value: sanitize(f.Value), Flag: flagName(f.Flag)})
	}
	out, _ := json.Marshal(jn)
	return string(out)
}
