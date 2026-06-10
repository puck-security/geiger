package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gmodule "github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/pipeline"
	"github.com/puck-security/geiger/internal/score"
)

func captureRun(statusOn bool, c config) (stdout, stderr string, code int) {
	var out, errb bytes.Buffer
	code = run(&out, &errb, statusOn, c)
	return out.String(), errb.String(), code
}

// The central guarantee: stdout is byte-identical whether or not the stderr
// status line is on, so progress/header never leak into a pipe or --json.
func TestStatusNeverLeaksToStdout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.env"),
		[]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	off, offErr, code1 := captureRun(false, config{colorMode: "never", args: []string{dir}})
	on, onErr, code2 := captureRun(true, config{colorMode: "never", args: []string{dir}})

	if code1 != 0 || code2 != 0 {
		t.Fatalf("non-zero exit: %d / %d", code1, code2)
	}
	if off == "" {
		t.Fatal("expected stdout output")
	}
	if off != on {
		t.Errorf("stdout differs when the status line is toggled — it must not:\n--- status off ---\n%q\n--- status on ---\n%q", off, on)
	}
	// The header lands on stderr regardless (it's not the transient line)…
	if !strings.Contains(offErr, "geiger "+version) {
		t.Errorf("header missing from stderr: %q", offErr)
	}
	// …while the carriage-return progress line appears ONLY when enabled.
	if strings.Contains(offErr, "\r") {
		t.Errorf("progress line leaked with status off: %q", offErr)
	}
	if !strings.Contains(onErr, "triaging") {
		t.Errorf("expected a progress line on stderr with status on: %q", onErr)
	}
}

// --quiet silences all stderr status (header + progress); stdout is unchanged.
func TestQuietSilencesStderr(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.env"),
		[]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	loud, _, _ := captureRun(false, config{colorMode: "never", args: []string{dir}})
	quiet, quietErr, _ := captureRun(false, config{colorMode: "never", quiet: true, args: []string{dir}})
	if strings.TrimSpace(quietErr) != "" {
		t.Errorf("-q should produce no stderr, got %q", quietErr)
	}
	if loud != quiet {
		t.Errorf("-q changed stdout (it must not): %q vs %q", loud, quiet)
	}
}

// --stream prints the same set of results as the sorted default (only ordering
// differs), and still emits the closing summary.
func TestStreamMatchesSortedResultSet(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "creds.env"),
		[]byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nGITHUB_TOKEN=ghp_0123456789abcdefABCDEF0123456789abcd\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	sorted, _, _ := captureRun(false, config{colorMode: "never", args: []string{dir}})
	streamed, _, _ := captureRun(false, config{colorMode: "never", stream: true, args: []string{dir}})

	if !strings.Contains(streamed, "── summary ──") {
		t.Errorf("stream mode dropped the summary: %q", streamed)
	}
	// Same credentials surface in both modes (compare the set of title lines).
	if titleSet(sorted) != titleSet(streamed) {
		t.Errorf("stream and sorted disagree on which credentials were found:\nsorted=%q\nstream=%q", sorted, streamed)
	}
}

func titleSet(out string) string {
	var titles []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "[") { // a result header line
			titles = append(titles, line)
		}
	}
	// order-independent comparison
	seen := map[string]bool{}
	for _, ti := range titles {
		seen[ti] = true
	}
	var keys []string
	for k := range seen {
		keys = append(keys, k)
	}
	// stable join
	return strings.Join(sortedStrings(keys), "\n")
}

func sortedStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
	return s
}

const awsCreds = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMultiPathMergesSources(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.env", awsCreds)
	b := writeFile(t, dir, "b.env", "STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n")
	out, _, code := captureRun(false, config{colorMode: "never", args: []string{a, b}})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, "] aws ") || !strings.Contains(out, "] stripe ") {
		t.Errorf("both files should be triaged in one run:\n%s", out)
	}
}

func TestOnlyScopesRecon(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "creds.env", awsCreds+"DATABASE_URL=postgres://u:p@db.example.com:5432/app\n")

	all, _, _ := captureRun(false, config{colorMode: "never", args: []string{dir}})
	if !strings.Contains(all, "] aws ") || !strings.Contains(all, "db_connection_string") {
		t.Fatalf("baseline should have both aws + db:\n%s", all)
	}
	only, _, _ := captureRun(false, config{colorMode: "never", only: "databases", args: []string{dir}})
	if strings.Contains(only, "] aws ") {
		t.Errorf("--only databases must skip the AWS cred:\n%s", only)
	}
	if !strings.Contains(only, "db_connection_string") {
		t.Errorf("--only databases must keep the DB cred:\n%s", only)
	}
}

func TestSkipExcludesRecon(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "creds.env", awsCreds+"DATABASE_URL=postgres://u:p@db.example.com:5432/app\n")
	out, _, _ := captureRun(false, config{colorMode: "never", skip: "databases", args: []string{dir}})
	if strings.Contains(out, "db_connection_string") {
		t.Errorf("--skip databases must drop the DB cred:\n%s", out)
	}
	if !strings.Contains(out, "] aws ") {
		t.Errorf("--skip databases must keep the AWS cred:\n%s", out)
	}
}

func TestIntrusiveDeepenHint(t *testing.T) {
	dir := t.TempDir()
	// A DB connection string under --live (no --intrusive) self-declares it needs
	// --intrusive — and must NOT make any network call to do so.
	writeFile(t, dir, "db.env", "DATABASE_URL=postgres://u:p@db.example.com:5432/app\n")
	_, errOut, _ := captureRun(false, config{colorMode: "never", live: true, args: []string{dir}})
	if !strings.Contains(errOut, "go deeper with --intrusive") {
		t.Errorf("expected a deepen hint on stderr: %q", errOut)
	}
	if !strings.Contains(errOut, "--only databases") {
		t.Errorf("hint should scope to the databases category: %q", errOut)
	}
	_, errOut2, _ := captureRun(false, config{colorMode: "never", live: true, intrusive: true, args: []string{dir}})
	if strings.Contains(errOut2, "go deeper") {
		t.Errorf("no hint expected with --intrusive already set: %q", errOut2)
	}
}

func TestMinSeverityShowResult(t *testing.T) {
	ctx := score.Context{}
	hi := pipeline.Result{Note: gmodule.Note{Findings: []gmodule.Finding{{Flag: gmodule.FlagForceMultiplier}}}} // HIGH (fm floor)
	info := pipeline.Result{Note: gmodule.Note{Findings: []gmodule.Finding{{Flag: gmodule.FlagInfo}}}}          // INFO
	dead := pipeline.Result{Note: gmodule.Note{Invalid: true}}                                                  // DEAD
	hiOnly := config{minSeverity: "high", minSevRank: score.Rank(score.TierHigh)}
	if !hiOnly.showResult(hi, ctx) {
		t.Error("force-multiplier (HIGH) must pass --min-severity=high")
	}
	if hiOnly.showResult(info, ctx) || hiOnly.showResult(dead, ctx) {
		t.Error("INFO and DEAD must be hidden by --min-severity=high")
	}
	// "exclude dead" via --min-severity=info: info shows, dead hidden.
	infoUp := config{minSeverity: "info", minSevRank: score.Rank(score.TierInfo)}
	if !infoUp.showResult(info, ctx) || infoUp.showResult(dead, ctx) {
		t.Error("--min-severity=info should show INFO but hide DEAD")
	}
	// no flag → show everything, including dead.
	if !(config{}).showResult(dead, ctx) {
		t.Error("no --min-severity must show all (incl DEAD)")
	}
}

func TestMinSeverityInvalidExits(t *testing.T) {
	_, errOut, code := captureRun(false, config{colorMode: "never", minSeverity: "bogus", args: []string{t.TempDir()}})
	if code != 2 {
		t.Errorf("invalid --min-severity should exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "invalid --min-severity") {
		t.Errorf("expected an error message, got: %q", errOut)
	}
}

func TestOutputToFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.env", "GITHUB_TOKEN=ghp_0123456789abcdefABCDEF0123456789abcd\n")
	outPath := filepath.Join(dir, "report.txt")
	stdoutCap, stderrCap, code := captureRun(false, config{colorMode: "always", output: outPath, args: []string{dir}})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(stdoutCap) != "" {
		t.Errorf("with -o, results must not also go to stdout: %q", stdoutCap)
	}
	if !strings.Contains(stderrCap, "results written to "+outPath) {
		t.Errorf("expected a stderr confirmation: %q", stderrCap)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "github_pat") {
		t.Errorf("output file missing the result:\n%s", body)
	}
	if strings.Contains(body, "\x1b[") {
		t.Errorf("output file must not contain ANSI color codes (got --color always):\n%q", body)
	}
	if fi, _ := os.Stat(outPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("output file perms = %v, want 0600", fi.Mode().Perm())
	}
}
