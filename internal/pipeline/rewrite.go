package pipeline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/redact"
)

// Placeholder is what a redacted value becomes. See redact.Placeholder.
const Placeholder = redact.Placeholder

// FileChange is one file the redact mode rewrites, with a count of the secrets
// found in it by form. Plain and Escaped are text swaps that leave the file
// meaning the same minus the value. Encoded means the value sits in the file
// as base64: the swap leaves a value that no longer decodes, so the file's
// consumer sees an error rather than a blank credential.
type FileChange struct {
	Path    string `json:"path"`
	Plain   int    `json:"plain"`
	Escaped int    `json:"escaped"`
	Encoded int    `json:"encoded"`
	// Changes lists each value the file holds: what it is, where it sat, its
	// masked tail, and the form it was found in. Never the value itself.
	Changes []ValueChange `json:"changes"`
	Written bool          `json:"written"`
	Err     string        `json:"error,omitempty"`
	mode    os.FileMode   // preserved on rewrite
	secrets []string      // values to replace, every form
}

// ValueChange is one value in one file, described without the value.
type ValueChange struct {
	Module string `json:"module"`
	Label  string `json:"label"`           // where the match came from, e.g. ".env: GITHUB_TOKEN"
	Field  string `json:"field,omitempty"` // the module's field name for a set-shaped credential
	Line   int    `json:"line,omitempty"`  // 1-based line in the file the note names; 0 elsewhere
	Tail   string `json:"tail"`            // masked value, for correlation with the report
	Form   string `json:"form"`            // plain, json-escaped, or base64
}

// Skip is one location the redact mode cannot rewrite, with the reason.
type Skip struct {
	Location string `json:"location"`
	Module   string `json:"module,omitempty"`
	Label    string `json:"label,omitempty"`
	Secret   string `json:"secret"` // masked tail, for correlation with the report
	Reason   string `json:"reason"`
}

// Plan is what the redact mode would change. Build it with PlanRedaction,
// show it, and only then Apply it.
type Plan struct {
	Files   []*FileChange `json:"files"`
	Skipped []Skip        `json:"skipped"`
	// Secrets counts the distinct values behind the results, rewritable or not.
	Secrets int `json:"secrets"`

	all []string // every distinct secret, for WriteReplacements
}

// Encoded reports how many files hold a secret only in an encoded form.
func (p *Plan) Encoded() int {
	n := 0
	for _, f := range p.Files {
		if f.Encoded > 0 {
			n++
		}
	}
	return n
}

// PlanRedaction works out which files hold the secrets behind results and in
// which form. locate returns every source a result's secret was seen in (the
// note's file plus the deduplicated repeats); a batch's Locations method fits.
// Nothing is written.
func PlanRedaction(results []Result, locate func(Result) []string) *Plan {
	p := &Plan{}
	files := map[string]*FileChange{}
	contents := map[string]string{}
	unreadable := map[string]string{}
	seenSecret := map[string]bool{}
	for _, r := range results {
		for _, s := range r.Secrets {
			if !seenSecret[s.Value] {
				seenSecret[s.Value] = true
				p.all = append(p.all, s.Value)
			}
		}
		if len(r.Secrets) == 0 && r.secret == "" {
			continue // a surface note (an agent config, a token store): no value of its own
		}
		for i, loc := range locate(r) {
			primary := i == 0
			if len(r.Secrets) == 0 {
				p.skip(loc, r, SecretValue{Value: r.secret}, "value too short to replace safely")
				continue
			}
			if reason, ok := unreadable[loc]; ok {
				p.skipAll(loc, r, reason)
				continue
			}
			content, ok := contents[loc]
			if !ok {
				var reason string
				content, reason = readForRewrite(loc)
				if reason != "" {
					unreadable[loc] = reason
					p.skipAll(loc, r, reason)
					continue
				}
				contents[loc] = content
			}
			fc := files[loc]
			if fc == nil {
				fc = &FileChange{Path: loc}
				files[loc] = fc
				p.Files = append(p.Files, fc)
			}
			// Longest first, so a container (a DSN, an auth blob) is found
			// before the value inside it is judged absent.
			for _, s := range longestFirst(r.Secrets) {
				fc.note(content, r, s, primary, p)
			}
		}
	}
	p.Secrets = len(p.all)
	// A file none of whose values were found is not a change.
	kept := p.Files[:0]
	for _, fc := range p.Files {
		if len(fc.secrets) > 0 {
			kept = append(kept, fc)
		}
	}
	p.Files = kept
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Path < p.Files[j].Path })
	for _, fc := range p.Files {
		if fi, err := os.Lstat(fc.Path); err == nil {
			fc.mode = fi.Mode().Perm()
		}
	}
	return p
}

// note records secret s against the file if content holds it in any form. A
// value absent from the primary location is reported; one absent from a
// repeat location is not, since only the dedup secret is known to be there.
func (fc *FileChange) note(content string, r Result, sv SecretValue, primary bool, p *Plan) {
	s := sv.Value
	if slices.Contains(fc.secrets, s) {
		return
	}
	var form string
	switch {
	case strings.Contains(content, s):
		fc.Plain++
		form = "plain"
	case containsAny(content, []string{jsonEscaped(s)}):
		fc.Escaped++
		form = "json-escaped"
	case containsAny(content, base64Forms(s)):
		fc.Encoded++
		form = "base64"
	default:
		if primary && !containedInFound(s, fc.secrets, content) {
			p.skip(fc.Path, r, sv, "value not present in the file as text; it was transformed before geiger saw it")
		}
		return
	}
	fc.secrets = append(fc.secrets, s)
	line := 0
	if primary {
		line = r.Note.Line
	}
	fc.Changes = append(fc.Changes, ValueChange{
		Module: r.Note.Module, Label: r.label, Field: sv.Field, Line: line,
		Tail: redact.Secret(s), Form: form,
	})
}

// containedInFound reports whether s is part of a longer secret already found
// in content, such as a password inside a connection string. Replacing the
// longer value redacts the shorter one too.
func containedInFound(s string, found []string, content string) bool {
	for _, f := range found {
		if len(f) <= len(s) || !strings.Contains(content, f) {
			continue
		}
		if strings.Contains(f, s) {
			return true
		}
		// A docker auth blob is base64("user:password"): the password is
		// inside it once decoded, and replacing the blob redacts it.
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if dec, err := enc.DecodeString(f); err == nil && bytes.Contains(dec, []byte(s)) {
				return true
			}
		}
	}
	return false
}

func (p *Plan) skip(loc string, r Result, sv SecretValue, reason string) {
	label := r.label
	if sv.Field != "" {
		label += " " + sv.Field
	}
	p.Skipped = append(p.Skipped, Skip{
		Location: loc, Module: r.Note.Module, Label: strings.TrimSpace(label),
		Secret: redact.Secret(sv.Value), Reason: reason,
	})
}

func (p *Plan) skipAll(loc string, r Result, reason string) {
	for _, s := range r.Secrets {
		p.skip(loc, r, s, reason)
	}
}

var gitHistoryLabel = regexp.MustCompile(`@[0-9a-f]{7,40}$`)

// readForRewrite reads a location for rewriting, or explains why it cannot be
// rewritten. Only an existing regular text file qualifies; every other label a
// source can carry is classified so the report says what to do instead.
func readForRewrite(loc string) (content, reason string) {
	fi, err := os.Lstat(loc)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return "", "symlink, not followed; its target is rewritten if it was scanned as a file"
	case err == nil && !fi.Mode().IsRegular():
		return "", "not a regular file"
	case err == nil && fi.Size() > maxFileSize:
		return "", "file larger than the scan cap"
	case err == nil:
		data, err := os.ReadFile(loc)
		if err != nil {
			return "", "unreadable: " + err.Error()
		}
		if bytes.HasPrefix(data, []byte("SQLite format 3")) {
			return "", "SQLite store; the value lives in a database page, not text"
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return "", "binary file"
		}
		return string(data), ""
	case strings.Contains(loc, "::"):
		return "", "archive member; extract, redact, and repack the archive"
	case gitHistoryLabel.MatchString(loc):
		return "", "git history; rewrite it with git filter-repo (see --redact-replacements)"
	case strings.HasPrefix(loc, "harvested via "):
		return "", "harvested from a store, not read from a text file; rotate it there"
	case loc == "stdin" || loc == "environment":
		return "", "not a file"
	default:
		return "", "not a local file"
	}
}

// Apply rewrites every planned file. Each is re-read, so a file that changed
// since the plan is rewritten from its current content, and any planned value
// no longer in it is reported. Writes are atomic: a temp file in the same
// directory takes the original mode and is renamed over it. No copy of the
// original is kept, since a backup would hold the secrets again.
func (p *Plan) Apply() (written, failed int) {
	for _, fc := range p.Files {
		if err := fc.apply(); err != nil {
			fc.Err = err.Error()
			failed++
			continue
		}
		fc.Written = true
		written++
	}
	return written, failed
}

func (fc *FileChange) apply() error {
	content, reason := readForRewrite(fc.Path)
	if reason != "" {
		return fmt.Errorf("%s", reason)
	}
	out := Rewrite(content, fc.secrets)
	if out == content {
		return fmt.Errorf("no planned value found; the file changed since the plan")
	}
	dir, base := filepath.Split(fc.Path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".geiger-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.WriteString(out); err != nil {
		return cleanup(err)
	}
	mode := fc.mode
	if mode == 0 {
		mode = 0o600
	}
	if err := tmp.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, fc.Path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Rewrite replaces every form of every secret in content with Placeholder.
// Longer values go first, so a connection string is replaced whole before the
// password inside it would be.
func Rewrite(content string, secrets []string) string {
	for _, s := range longestFirst(secrets) {
		forms := append([]string{s, jsonEscaped(s)}, base64Forms(s)...)
		for _, f := range forms {
			if f != "" && f != Placeholder {
				content = strings.ReplaceAll(content, f, Placeholder)
			}
		}
	}
	return content
}

func longestFirst[T string | SecretValue](secrets []T) []T {
	sorted := append([]T(nil), secrets...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(valueOf(sorted[i])) > len(valueOf(sorted[j])) })
	return sorted
}

func valueOf[T string | SecretValue](v T) string {
	switch x := any(v).(type) {
	case string:
		return x
	case SecretValue:
		return x.Value
	}
	return ""
}

// WriteReplacements writes a git filter-repo --replace-text file: one
// "literal:<secret>==>REDACTED-BY-GEIGER" line per distinct secret, mode 0600.
// filter-repo reads the file a line at a time, so a value with a newline in it
// (a PEM key) cannot be expressed; those are counted in multiline and left out.
func (p *Plan) WriteReplacements(path string) (n, multiline int, err error) {
	var buf strings.Builder
	for _, s := range p.all {
		if strings.ContainsAny(s, "\r\n") {
			multiline++
			continue
		}
		fmt.Fprintf(&buf, "literal:%s==>%s\n", s, Placeholder)
		n++
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		return 0, 0, err
	}
	return n, multiline, nil
}

// Replacements counts what WriteReplacements would write, without writing.
func (p *Plan) Replacements() (n, multiline int) {
	for _, s := range p.all {
		if strings.ContainsAny(s, "\r\n") {
			multiline++
		} else {
			n++
		}
	}
	return n, multiline
}

// jsonEscaped is s as it sits inside a JSON string, without the quotes. A key
// with newlines is stored as \n; a slash may be stored as \/ by some writers,
// which this does not cover.
func jsonEscaped(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return ""
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	out = strings.TrimPrefix(strings.TrimSuffix(out, `"`), `"`)
	if out == s {
		return ""
	}
	return out
}

// base64Forms lists the encodings a value may be stored under: padded and
// unpadded standard base64. A value that is itself base64 (a docker auth
// blob) is covered by the plain form.
func base64Forms(s string) []string {
	return []string{
		base64.StdEncoding.EncodeToString([]byte(s)),
		base64.RawStdEncoding.EncodeToString([]byte(s)),
	}
}

func containsAny(content string, subs []string) bool {
	for _, s := range subs {
		if s != "" && strings.Contains(content, s) {
			return true
		}
	}
	return false
}
