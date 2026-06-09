package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/score"
)

func TestSortBySeverity(t *testing.T) {
	mk := func(flag module.FlagLevel, invalid bool) Result {
		return Result{Note: module.Note{Invalid: invalid, Findings: []module.Finding{{Flag: flag}}}}
	}
	rs := []Result{
		mk(module.FlagInfo, false),
		mk(module.FlagNone, true), // invalid → last
		mk(module.FlagForceMultiplier, false),
		mk(module.FlagWarn, false),
	}
	SortBySeverity(rs, score.Context{})
	if rs[0].Note.Findings[0].Flag != module.FlagForceMultiplier {
		t.Errorf("force-multiplier should sort first, got %v", rs[0].Note.Findings[0].Flag)
	}
	if !rs[len(rs)-1].Note.Invalid {
		t.Errorf("invalid should sort last")
	}
}

func TestFromGitleaks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.json")
	report := `[{"RuleID":"stripe-access-token","Secret":"sk_live_abc","File":"app/.env"},
	            {"RuleID":"x","Secret":"","File":"empty"}]`
	if err := os.WriteFile(p, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromGitleaks(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 { // empty secret skipped
		t.Fatalf("expected 1 source, got %d", len(srcs))
	}
	if srcs[0].Label != "app/.env" || srcs[0].Blob.Raw != "sk_live_abc" {
		t.Errorf("unexpected source: %+v", srcs[0])
	}
}

func TestFromTrufflehog(t *testing.T) {
	dir := t.TempDir()
	// TruffleHog v3 default output is newline-delimited JSON, one finding/line.
	ndjson := `{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Filesystem":{"file":"/home/u/.aws/credentials","line":3}}}}
{"DetectorName":"Github","Raw":"ghp_xxx","SourceMetadata":{"Data":{"Git":{"file":"src/app.go","line":42}}}}
{"DetectorName":"Empty","Raw":"","RawV2":""}
not json, ignore me`
	p := filepath.Join(dir, "th.json")
	if err := os.WriteFile(p, []byte(ndjson), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromTrufflehog(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 { // empty-secret finding and junk line skipped
		t.Fatalf("expected 2 sources, got %d: %+v", len(srcs), srcs)
	}
	if srcs[0].Label != "/home/u/.aws/credentials" || srcs[0].Blob.Raw != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("filesystem finding wrong: %+v", srcs[0])
	}
	if srcs[0].Blob.Lines["AKIAIOSFODNN7EXAMPLE"] != 3 {
		t.Errorf("line number not carried: %+v", srcs[0].Blob.Lines)
	}
	if srcs[1].Label != "src/app.go" { // falls back to Git metadata
		t.Errorf("git finding label wrong: %+v", srcs[1])
	}
}

func TestFromTrufflehogJSONArray(t *testing.T) {
	dir := t.TempDir()
	arr := `[{"DetectorName":"Stripe","RawV2":"sk_live_fromv2"}]`
	p := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(p, []byte(arr), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromTrufflehog(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || srcs[0].Blob.Raw != "sk_live_fromv2" {
		t.Fatalf("RawV2 fallback / array parse failed: %+v", srcs)
	}
}

func TestWalkDirSkipsNoiseDirs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "junk.js"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("A=B"), 0o600)
	srcs, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range srcs {
		if filepath.Base(filepath.Dir(s.Label)) == "node_modules" {
			t.Errorf("node_modules should be skipped: %s", s.Label)
		}
	}
	found := false
	for _, s := range srcs {
		if filepath.Base(s.Label) == ".env" {
			found = true
		}
	}
	if !found {
		t.Error(".env not walked")
	}
}

func TestWalkDirSkipsDependencyTreesAndLockfiles(t *testing.T) {
	dir := t.TempDir()
	// a python virtualenv dist-info tree (the reported false-positive source)
	rec := filepath.Join(dir, ".venv", "lib", "python3.12", "site-packages", "packaging-26.0.dist-info")
	os.MkdirAll(rec, 0o755)
	os.WriteFile(filepath.Join(rec, "RECORD"), []byte("packaging/_tokenizer.py,sha256=AAAA1111bbbb2222,5421\n"), 0o600)
	// lockfiles full of integrity hashes
	os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(`integrity sha512-deadbeef`), 0o600)
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte("mod h1:abcdef="), 0o600)
	// a real secret-bearing file that must still be walked
	os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN=s3cr3tValue123"), 0o600)

	srcs, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range srcs {
		base := filepath.Base(s.Label)
		if base == "RECORD" || base == "yarn.lock" || base == "go.sum" {
			t.Errorf("noise file should be skipped: %s", s.Label)
		}
		if filepath.Base(filepath.Dir(s.Label)) == "site-packages" {
			t.Errorf("site-packages should be skipped: %s", s.Label)
		}
	}
	var found bool
	for _, s := range srcs {
		if filepath.Base(s.Label) == ".env" {
			found = true
		}
	}
	if !found {
		t.Error(".env not walked")
	}
}

func TestLooksLikeGitleaks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.json")
	os.WriteFile(p, []byte(`[{"RuleID":"x","Secret":"y"}]`), 0o600)
	if !LooksLikeGitleaks(p) {
		t.Error("should detect gitleaks report")
	}
	p2 := filepath.Join(dir, "other.json")
	os.WriteFile(p2, []byte(`{"foo":"bar"}`), 0o600)
	if LooksLikeGitleaks(p2) {
		t.Error("non-gitleaks json misdetected")
	}
}
