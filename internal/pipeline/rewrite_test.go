package pipeline

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recognize"
)

func writeFixture(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func result(file, secret string, more ...string) Result {
	r := Result{Note: module.Note{File: file, Module: "m", Line: 1}, secret: secret, label: "L"}
	for _, v := range append([]string{secret}, more...) {
		r.Secrets = append(r.Secrets, SecretValue{Value: v})
	}
	return r
}

func fileLocs(r Result) []string { return []string{r.Note.File} }

const (
	tok = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----"
	pw  = "s3cretpassw0rd"
	dsn = "postgres://app:" + pw + "@db.example.com:5432/app"
)

func TestPlanFindsEachForm(t *testing.T) {
	dir := t.TempDir()
	env := writeFixture(t, dir, ".env", "TOKEN="+tok+"\nDATABASE_URL="+dsn+"\n", 0o600)
	js := writeFixture(t, dir, "sa.json", `{"private_key":"`+strings.ReplaceAll(pem, "\n", `\n`)+`"}`, 0o644)
	auth := base64.StdEncoding.EncodeToString([]byte("deploy:" + pw))
	docker := writeFixture(t, dir, "config.json", `{"auths":{"r":{"auth":"`+auth+`"}}}`, 0o600)
	kube := writeFixture(t, dir, "kube.yaml", "client-key-data: "+base64.StdEncoding.EncodeToString([]byte(pem))+"\n", 0o600)

	p := PlanRedaction([]Result{
		result(env, tok),
		result(env, pw, dsn), // password is inside the DSN: covered, not a miss
		result(js, pem),
		result(docker, pw, auth), // password is inside the decoded blob: covered
		result(kube, pem),
	}, fileLocs)

	if len(p.Skipped) != 0 {
		t.Fatalf("nothing should be skipped: %+v", p.Skipped)
	}
	// The password is a literal hit of its own inside the DSN, so .env counts 3.
	want := map[string][3]int{env: {3, 0, 0}, js: {0, 1, 0}, docker: {1, 0, 0}, kube: {0, 0, 1}}
	if len(p.Files) != len(want) {
		t.Fatalf("files: got %d want %d", len(p.Files), len(want))
	}
	for _, f := range p.Files {
		w := want[f.Path]
		if got := [3]int{f.Plain, f.Escaped, f.Encoded}; got != w {
			t.Errorf("%s: forms %v want %v", filepath.Base(f.Path), got, w)
		}
		for _, ch := range f.Changes {
			if len(ch.Tail) > 12 || strings.Contains(ch.Tail, tok) {
				t.Errorf("Tail must be masked, got %q", ch.Tail)
			}
			if ch.Module != "m" || ch.Label != "L" || ch.Line != 1 || ch.Form == "" {
				t.Errorf("change lacks provenance: %+v", ch)
			}
		}
	}
	if p.Encoded() != 1 {
		t.Errorf("one file holds a value only as base64, got %d", p.Encoded())
	}
	if p.Secrets != 5 {
		t.Errorf("distinct secrets: got %d want 5", p.Secrets)
	}
}

func TestApplyRewritesInPlaceAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	env := writeFixture(t, dir, ".env", "TOKEN="+tok+"\nDATABASE_URL="+dsn+"\nOTHER=keep\n", 0o600)
	js := writeFixture(t, dir, "sa.json", `{"private_key":"`+strings.ReplaceAll(pem, "\n", `\n`)+`","id":"x"}`, 0o644)
	kube := writeFixture(t, dir, "kube.yaml", "client-key-data: "+base64.StdEncoding.EncodeToString([]byte(pem))+"\n", 0o600)

	p := PlanRedaction([]Result{result(env, tok), result(env, dsn, pw), result(js, pem), result(kube, pem)}, fileLocs)
	written, failed := p.Apply()
	if written != 3 || failed != 0 {
		t.Fatalf("written %d failed %d: %+v", written, failed, p.Files)
	}
	got, _ := os.ReadFile(env)
	if want := "TOKEN=" + Placeholder + "\nDATABASE_URL=" + Placeholder + "\nOTHER=keep\n"; string(got) != want {
		t.Errorf(".env:\n%s", got)
	}
	got, _ = os.ReadFile(js)
	if want := `{"private_key":"` + Placeholder + `","id":"x"}`; string(got) != want {
		t.Errorf("sa.json:\n%s", got)
	}
	got, _ = os.ReadFile(kube)
	if want := "client-key-data: " + Placeholder + "\n"; string(got) != want {
		t.Errorf("kube.yaml:\n%s", got)
	}
	for path, mode := range map[string]os.FileMode{env: 0o600, js: 0o644} {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %o want %o", filepath.Base(path), fi.Mode().Perm(), mode)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.geiger-*")); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
	// A second plan over the rewritten tree finds nothing to do.
	again := PlanRedaction([]Result{result(env, tok)}, fileLocs)
	if len(again.Files) != 0 || len(again.Skipped) != 1 {
		t.Errorf("rewritten file should report the value as absent: files=%d skipped=%+v", len(again.Files), again.Skipped)
	}
}

func TestPlanSkipsWhatItCannotRewrite(t *testing.T) {
	dir := t.TempDir()
	env := writeFixture(t, dir, ".env", "TOKEN="+tok+"\n", 0o600)
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(env, link); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	bin := writeFixture(t, dir, "blob.bin", "abc\x00"+tok, 0o600)
	db := writeFixture(t, dir, "state.vscdb", "SQLite format 3\x00"+tok, 0o600)
	transformed := writeFixture(t, dir, "enc.txt", "TOKEN=urlencoded%2Bvalue\n", 0o600)

	cases := []struct {
		loc, reason string
	}{
		{link, "symlink"},
		{bin, "binary"},
		{db, "SQLite"},
		{transformed, "not present"},
		{filepath.Join(dir, "repo", "config.yml") + "@0123abc", "git history"},
		{filepath.Join(dir, "host.tar.gz") + "::etc/app.env", "archive"},
		{"harvested via vault: secret/app", "harvested"},
		{"stdin", "not a file"},
		{filepath.Join(dir, "gone.env"), "not a local file"},
	}
	var rs []Result
	for _, c := range cases {
		rs = append(rs, result(c.loc, tok))
	}
	rs = append(rs, Result{Note: module.Note{File: env}, secret: "short"})                      // too short to replace
	rs = append(rs, Result{Note: module.Note{File: env}})                                       // a surface note: no value
	rs = append(rs, Result{Note: module.Note{File: env}, Secrets: []SecretValue{{Value: tok}}}) // still rewritable

	p := PlanRedaction(rs, fileLocs)
	if len(p.Files) != 1 || p.Files[0].Path != env {
		t.Fatalf("only the plain file is rewritable: %+v", p.Files)
	}
	byLoc := map[string]string{}
	for _, s := range p.Skipped {
		byLoc[s.Location] = s.Reason
		if s.Secret == tok {
			t.Errorf("skip carries the raw secret: %+v", s)
		}
	}
	for _, c := range cases {
		if !strings.Contains(byLoc[c.loc], c.reason) {
			t.Errorf("%s: reason %q want it to mention %q", c.loc, byLoc[c.loc], c.reason)
		}
	}
	if !strings.Contains(byLoc[env], "too short") {
		t.Errorf("short secret: %q", byLoc[env])
	}
	if n := len(p.Skipped); n != len(cases)+1 {
		t.Errorf("skips: got %d want %d (%+v)", n, len(cases)+1, p.Skipped)
	}
	if got, _ := os.ReadFile(env); !strings.Contains(string(got), tok) {
		t.Error("plan must not write")
	}
}

func TestRepeatLocationsAreRewrittenWithoutMissReports(t *testing.T) {
	dir := t.TempDir()
	a := writeFixture(t, dir, "a.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", 0o600)
	b := writeFixture(t, dir, "b.env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", 0o600)
	r := result(a, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE")
	p := PlanRedaction([]Result{r}, func(Result) []string { return []string{a, b} })
	if len(p.Skipped) != 0 {
		t.Errorf("the key id is absent from the repeat only; no miss expected: %+v", p.Skipped)
	}
	if len(p.Files) != 2 {
		t.Fatalf("both locations planned: %+v", p.Files)
	}
	p.Apply()
	for _, path := range []string{a, b} {
		got, _ := os.ReadFile(path)
		if strings.Contains(string(got), "EXAMPLE") {
			t.Errorf("%s not rewritten:\n%s", filepath.Base(path), got)
		}
	}
}

func TestApplyRefusesAFileThatChangedSincePlan(t *testing.T) {
	dir := t.TempDir()
	env := writeFixture(t, dir, ".env", "TOKEN="+tok+"\n", 0o600)
	p := PlanRedaction([]Result{result(env, tok)}, fileLocs)
	writeFixture(t, dir, ".env", "TOKEN=rotated-already-1234\n", 0o600)
	written, failed := p.Apply()
	if written != 0 || failed != 1 || p.Files[0].Err == "" {
		t.Errorf("written %d failed %d err %q", written, failed, p.Files[0].Err)
	}
	if got, _ := os.ReadFile(env); string(got) != "TOKEN=rotated-already-1234\n" {
		t.Errorf("file must be untouched:\n%s", got)
	}
}

func TestRewriteReplacesLongestFirst(t *testing.T) {
	in := "DSN=" + dsn + " PW=" + pw + " B64=" + base64.StdEncoding.EncodeToString([]byte(pw))
	got := Rewrite(in, []string{pw, dsn})
	want := "DSN=" + Placeholder + " PW=" + Placeholder + " B64=" + Placeholder
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestWriteReplacementsSkipsMultilineAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	env := writeFixture(t, dir, ".env", "TOKEN="+tok+"\n", 0o600)
	p := PlanRedaction([]Result{result(env, tok), result(dir+"/k@0123abc", pem)}, fileLocs)
	if n, multi := p.Replacements(); n != 1 || multi != 1 {
		t.Errorf("count: %d/%d", n, multi)
	}
	out := filepath.Join(dir, "repl.txt")
	n, multi, err := p.WriteReplacements(out)
	if err != nil || n != 1 || multi != 1 {
		t.Fatalf("n=%d multi=%d err=%v", n, multi, err)
	}
	got, _ := os.ReadFile(out)
	if want := "literal:" + tok + "==>" + Placeholder + "\n"; string(got) != want {
		t.Errorf("replacements:\n%s", got)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o want 0600", fi.Mode().Perm())
	}
}

func TestSecretValuesLeaveOutLocatorsAndShortValues(t *testing.T) {
	m := matchWith("aws", "AKIAIOSFODNN7EXAMPLE", map[string]string{
		"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region": "us-east-1", "username": "deploy-bot-account", "_rule": "aws-access-token",
		"secret_fields": "gh GITHUB_TOKEN", "password": "short",
	})
	got := secretValues(m)
	want := []SecretValue{{"AKIAIOSFODNN7EXAMPLE", "access_key"}, {"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "secret_key"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func matchWith(mod, secret string, fields map[string]string) recognize.Match {
	return recognize.Match{Module: mod, Secret: secret, Fields: module.Fields(fields)}
}
