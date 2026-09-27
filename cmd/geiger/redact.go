package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/color"
	"github.com/puck-security/geiger/internal/pipeline"
)

// redactRefused explains why the redact mode cannot run with the given input,
// or returns "" when it can. It rewrites files it read itself, so every input
// that is not a path on disk is refused rather than guessed at.
func (c config) redactRefused() string {
	if c.confirmRedact && !c.redact {
		return "--confirm-redact needs --dangerous-redact"
	}
	if c.replacements != "" && !c.redact {
		return "--redact-replacements needs --dangerous-redact"
	}
	if !c.redact {
		return ""
	}
	switch {
	case c.useEnv, c.useMetadata, c.browser:
		return "--dangerous-redact rewrites files; it cannot take --env, --metadata, or --browser"
	case c.fromGitleaks != "", c.fromTrufflehog != "", c.fromNuclei != "", c.fromKingfisher != "":
		return "--dangerous-redact rewrites the files it scanned itself; it cannot take a scanner report"
	case c.stream:
		return "--dangerous-redact needs the whole result set; drop --stream"
	case len(c.args) == 0:
		return "--dangerous-redact needs a file or directory to rewrite; stdin has no file"
	}
	for _, a := range c.args {
		if pipeline.LooksLikeGitleaks(a) {
			return "--dangerous-redact rewrites the files it scanned itself; " + a + " is a scanner report"
		}
	}
	return ""
}

// runRedact replaces the findings report: it plans which files hold the
// secrets behind results, prints the plan, and with --confirm-redact rewrites
// them. Returns the exit code.
func runRedact(stdout, stderr io.Writer, results []pipeline.Result, bt *pipeline.Batch, c config) int {
	plan := pipeline.PlanRedaction(results, bt.Locations)
	if len(results) == 0 && !c.asJSON {
		fmt.Fprintln(stderr, "geiger: no credentials recognized; nothing to redact.")
		return 0
	}
	code := 0
	if c.confirmRedact {
		if _, failed := plan.Apply(); failed > 0 {
			code = 1
		}
	}
	var repl replacementsReport
	if c.replacements != "" {
		repl.Path = c.replacements
		if c.confirmRedact {
			n, multi, err := plan.WriteReplacements(c.replacements)
			repl.Entries, repl.Multiline, repl.Written = n, multi, err == nil
			if err != nil {
				repl.Err = err.Error()
				code = 1
			}
		} else {
			repl.Entries, repl.Multiline = plan.Replacements()
		}
	}
	if c.asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(redactJSON{Mode: redactMode(c), Plan: plan, Replacements: repl})
		return code
	}
	printRedactReport(stdout, plan, repl, c)
	return code
}

type replacementsReport struct {
	Path      string `json:"path,omitempty"`
	Entries   int    `json:"entries"`
	Multiline int    `json:"multiline_skipped"`
	Written   bool   `json:"written"`
	Err       string `json:"error,omitempty"`
}

type redactJSON struct {
	Mode         string             `json:"mode"`
	Plan         *pipeline.Plan     `json:"plan"`
	Replacements replacementsReport `json:"replacements,omitempty"`
}

func redactMode(c config) string {
	if c.confirmRedact {
		return "rewrite"
	}
	return "plan"
}

// printRedactReport renders the plan (or the rewrite result) for a person. The
// files that are plain text swaps come first. Anything that is not a plain
// text swap is called out under a warning so it is not mistaken for done.
func printRedactReport(w io.Writer, p *pipeline.Plan, repl replacementsReport, c config) {
	verb := "would rewrite"
	if c.confirmRedact {
		verb = "rewrote"
	}
	fmt.Fprintf(w, "%s %d file(s) holding %d distinct secret(s)\n", verb, len(p.Files), p.Secrets)
	for _, f := range p.Files {
		line := fmt.Sprintf("  %s  %s", f.Path, formSummary(f))
		switch {
		case f.Err != "":
			line += "  " + color.Force("FAILED: "+f.Err)
		case f.Encoded > 0:
			line += "  " + color.Warn("base64 value: the file will no longer decode")
		}
		fmt.Fprintln(w, line)
		printChanges(w, f.Changes)
	}
	if repl.Path != "" {
		state := "would write"
		if repl.Written {
			state = "wrote"
		} else if repl.Err != "" {
			state = color.Force("FAILED (" + repl.Err + ") writing")
		}
		fmt.Fprintf(w, "%s %s: %d replacement(s) for git filter-repo --replace-text", state, repl.Path, repl.Entries)
		if repl.Multiline > 0 {
			fmt.Fprintf(w, " (%d multi-line value(s) left out)", repl.Multiline)
		}
		fmt.Fprintln(w)
	}

	if n := len(p.Skipped); n > 0 || p.Encoded() > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, color.Warn("WARNING: not everything is a plain text swap."))
		if p.Encoded() > 0 {
			fmt.Fprintf(w, "  %d file(s) hold a value only as base64. The placeholder does not decode; the consumer of that file will error until the value is replaced.\n", p.Encoded())
		}
		if n > 0 {
			fmt.Fprintf(w, "  %d location(s) cannot be rewritten:\n", n)
			for _, g := range groupSkips(p.Skipped) {
				fmt.Fprintf(w, "    %s (%d)\n", g.reason, len(g.items))
				for _, l := range g.locations() {
					fmt.Fprintf(w, "      %s  %s\n", l.path, color.Dim(strings.Join(l.tails, ", ")))
				}
			}
		}
	}

	fmt.Fprintln(w)
	switch {
	case !c.confirmRedact:
		fmt.Fprintln(w, "Nothing was written. Re-run with --confirm-redact to rewrite the files above.")
		fmt.Fprintln(w, "There is no undo and no backup: a backup would hold the secrets again.")
	default:
		fmt.Fprintln(w, "Redaction does not revoke anything. Rotate every credential above.")
	}
}

// printChanges lists each value in a file: the line it sat on, the module that
// recognized it, where it came from, the masked tail, and the form found. This
// is the record of what changed, so it is always printed, not only under -v.
func printChanges(w io.Writer, changes []pipeline.ValueChange) {
	modW, whereW := 0, 0
	rows := make([][3]string, len(changes))
	for i, ch := range changes {
		where := ch.Label
		if ch.Field != "" {
			where += " [" + ch.Field + "]"
		}
		rows[i] = [3]string{lineRef(ch.Line), ch.Module, where}
		modW = max(modW, len(ch.Module))
		whereW = max(whereW, len(where))
	}
	for i, ch := range changes {
		fmt.Fprintf(w, "    %4s  %-*s  %-*s  %s  %s\n", rows[i][0], modW, rows[i][1], whereW, rows[i][2], color.Dim(ch.Tail), ch.Form)
	}
}

func lineRef(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(":%d", n)
}

func formSummary(f *pipeline.FileChange) string {
	var parts []string
	if f.Plain > 0 {
		parts = append(parts, fmt.Sprintf("%d plain", f.Plain))
	}
	if f.Escaped > 0 {
		parts = append(parts, fmt.Sprintf("%d json-escaped", f.Escaped))
	}
	if f.Encoded > 0 {
		parts = append(parts, fmt.Sprintf("%d base64", f.Encoded))
	}
	return strings.Join(parts, ", ")
}

type skipGroup struct {
	reason string
	items  []pipeline.Skip
}

type skipLocation struct {
	path  string
	tails []string
}

// locations folds a group's skips to one line per location, since a file with
// several values in it is one thing to deal with, not several.
func (g *skipGroup) locations() []skipLocation {
	var out []skipLocation
	for _, s := range g.items {
		tail := strings.TrimSpace(s.Label + " " + s.Secret)
		if n := len(out); n > 0 && out[n-1].path == s.Location {
			out[n-1].tails = append(out[n-1].tails, tail)
			continue
		}
		out = append(out, skipLocation{path: s.Location, tails: []string{tail}})
	}
	return out
}

// groupSkips gathers skips by reason, largest group first, locations sorted.
func groupSkips(skips []pipeline.Skip) []*skipGroup {
	byReason := map[string]*skipGroup{}
	var order []*skipGroup
	for _, s := range skips {
		g := byReason[s.Reason]
		if g == nil {
			g = &skipGroup{reason: s.Reason}
			byReason[s.Reason] = g
			order = append(order, g)
		}
		g.items = append(g.items, s)
	}
	for _, g := range order {
		sort.Slice(g.items, func(i, j int) bool {
			if g.items[i].Location != g.items[j].Location {
				return g.items[i].Location < g.items[j].Location
			}
			return g.items[i].Secret < g.items[j].Secret
		})
	}
	sort.SliceStable(order, func(i, j int) bool { return len(order[i].items) > len(order[j].items) })
	return order
}
