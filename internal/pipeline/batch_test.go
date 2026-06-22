package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
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

func TestFromNuclei(t *testing.T) {
	dir := t.TempDir()
	// nuclei -j / -jsonl emits one result object per line. Two extractable
	// values, an all-blank extracted-results to skip, and a junk line to ignore.
	ndjson := `{"template-id":"exposed-env","matched-at":"https://victim.example/.env","extracted-results":["AKIAIOSFODNN7EXAMPLE"]}
{"template-id":"phpinfo","matched-at":"https://victim.example/phpinfo.php","extracted-results":["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}
{"template-id":"empty","matched-at":"https://victim.example/x","extracted-results":["",""]}
not json, ignore me`
	p := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(p, []byte(ndjson), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromNuclei(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 { // two real values; blank values and junk line skipped
		t.Fatalf("expected 2 sources, got %d: %+v", len(srcs), srcs)
	}
	// label = matched-at URL (the provenance that drives title/dedup/exposure),
	// raw = the literal extracted value (geiger re-types it downstream).
	if srcs[0].Label != "https://victim.example/.env" || srcs[0].Blob.Raw != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("unexpected source: %+v", srcs[0])
	}
}

func TestFromNucleiArrayAndFallbackLabel(t *testing.T) {
	dir := t.TempDir()
	// JSON-array form; matched-at absent → label falls back to nuclei:<template-id>.
	arr := `[{"template-id":"some-detector","extracted-results":["sk_live_fallbacklabel"]}]`
	p := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(p, []byte(arr), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromNuclei(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 1 || srcs[0].Blob.Raw != "sk_live_fallbacklabel" {
		t.Fatalf("array parse failed: %+v", srcs)
	}
	if srcs[0].Label != "nuclei:some-detector" {
		t.Errorf("expected nuclei:template-id fallback label, got %q", srcs[0].Label)
	}
}

func TestFromNucleiCorrelatesAcrossURLs(t *testing.T) {
	// The same key extracted from two exposed URLs should collapse to one
	// reconned finding that records both locations — the "one prod key exposed at
	// N URLs" signal — and the matched-at URLs drive the internet-exposed-endpoint
	// exposure class (both on the kept finding and in the "also exposed in" rollup).
	const sec = "nuclei-corr-token-abc123xyz"
	reg := module.NewRegistry()
	reg.Register(fakeBearer{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if b.Raw == sec {
			return []recognize.Match{{Module: "fake", Fields: module.Fields{"token": sec}, Secret: sec, Label: "nuclei"}}
		}
		return nil
	})
	dir := t.TempDir()
	ndjson := `{"template-id":"exposed-env","matched-at":"https://a.example/.env","extracted-results":["` + sec + `"]}
{"template-id":"exposed-env","matched-at":"https://b.example/backup.env","extracted-results":["` + sec + `"]}`
	p := filepath.Join(dir, "nuclei.jsonl")
	if err := os.WriteFile(p, []byte(ndjson), 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromNuclei(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(srcs))
	}
	// Run sequentially on one Batch so dedup state is shared and the first URL is
	// the kept finding (deterministic), matching TestBatchDedupesSecretAcrossSources.
	bt := NewBatch(reg, Options{Live: false})
	var all []Result
	for _, s := range srcs {
		all = append(all, bt.Run(s.Blob)...)
	}
	bt.AnnotateDuplicates(all)

	kept, exposed, correlated := 0, false, false
	for _, r := range all {
		if r.secret != sec {
			continue
		}
		kept++
		for _, f := range r.Note.Findings {
			if f.Key == "exposure" && strings.Contains(f.Value, "served over HTTP") {
				exposed = true
			}
			if f.Key == "also exposed in" && strings.Contains(f.Value, "internet-exposed endpoint") && len(f.Detail) == 1 {
				correlated = true
			}
		}
	}
	if kept != 1 {
		t.Fatalf("same key at 2 URLs should recon once, got %d", kept)
	}
	if !exposed {
		t.Errorf("kept result missing internet-exposed-endpoint exposure finding: %+v", all)
	}
	if !correlated {
		t.Errorf("kept result not correlated with the other URL: %+v", all)
	}
}

func TestFromNucleiIngestsResponseBody(t *testing.T) {
	// nuclei's JSON carries the full response body. Ingesting it (not just the
	// flat extracted-results) lets geiger's parsers reassemble multi-field
	// credentials — here an AWS access-key + secret-key pair the bare array,
	// which only carries the access key, can't represent.
	dir := t.TempDir()
	body := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	rec := map[string]any{
		"template-id":       "exposed-dotenv",
		"matched-at":        "https://victim.example/.env",
		"extracted-results": []string{"AKIAIOSFODNN7EXAMPLE"}, // nuclei only got the key
		"response":          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body,
	}
	line, _ := json.Marshal(rec)
	p := filepath.Join(dir, "n.jsonl")
	if err := os.WriteFile(p, line, 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromNuclei(p)
	if err != nil {
		t.Fatal(err)
	}
	// The body is a superset of the bare key, so the bare value is not re-emitted.
	if len(srcs) != 1 {
		t.Fatalf("expected 1 (body) source, got %d: %+v", len(srcs), srcs)
	}
	if srcs[0].Label != "https://victim.example/.env" {
		t.Errorf("label should be the matched-at URL, got %q", srcs[0].Label)
	}
	v := srcs[0].Blob.Vars
	if v["AWS_ACCESS_KEY_ID"] != "AKIAIOSFODNN7EXAMPLE" || v["AWS_SECRET_ACCESS_KEY"] == "" {
		t.Errorf("response body not parsed into a full AWS pair: %+v", v)
	}
}

func TestFromNucleiKeepsNonBodyExtracted(t *testing.T) {
	// A value extracted from a part other than the body (so not present in the
	// body) must still be ingested alongside the body source.
	dir := t.TempDir()
	body := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	rec := map[string]any{
		"template-id":       "x",
		"matched-at":        "https://victim.example/.env",
		"extracted-results": []string{"AKIAIOSFODNN7EXAMPLE", "ghp_headertokennotinbody000000000000000"},
		"response":          "HTTP/1.1 200 OK\r\n\r\n" + body,
	}
	line, _ := json.Marshal(rec)
	p := filepath.Join(dir, "n.jsonl")
	if err := os.WriteFile(p, line, 0o600); err != nil {
		t.Fatal(err)
	}
	srcs, err := FromNuclei(p)
	if err != nil {
		t.Fatal(err)
	}
	// body source + the one extracted value that isn't in the body.
	if len(srcs) != 2 {
		t.Fatalf("expected body source + 1 non-body value, got %d: %+v", len(srcs), srcs)
	}
	if srcs[1].Blob.Raw != "ghp_headertokennotinbody000000000000000" {
		t.Errorf("non-body extracted value not kept: %+v", srcs[1])
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

func TestWalkDirPicksUpIDEConfigs(t *testing.T) {
	dir := t.TempDir()
	vsc := filepath.Join(dir, ".vscode")
	if err := os.MkdirAll(vsc, 0o755); err != nil {
		t.Fatal(err)
	}
	// .vscode is skipped wholesale, but its mcp.json must still be walked.
	if err := os.WriteFile(filepath.Join(vsc, "mcp.json"), []byte(`{"servers":{"x":{"command":"y"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// settings.json (no mcpServers) must NOT be pulled out of the skipped dir.
	if err := os.WriteFile(filepath.Join(vsc, "settings.json"), []byte(`{"editor.fontSize":12}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srcs, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, s := range srcs {
		seen[filepath.Base(s.Label)] = true
	}
	if !seen["mcp.json"] {
		t.Error(".vscode/mcp.json should be walked despite the dir skip")
	}
	if seen["settings.json"] {
		t.Error("settings.json (no mcpServers) must not be pulled from a skipped IDE dir")
	}
}

func TestWalkDirReadsLargeVSCDBByHeader(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, 9<<20) // over the 8MB cap
	copy(big, []byte("SQLite format 3\x00"))
	if err := os.WriteFile(filepath.Join(dir, "state.vscdb"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	srcs, _ := WalkDir(dir, nil)
	var found *Source
	for i := range srcs {
		if filepath.Base(srcs[i].Label) == "state.vscdb" {
			found = &srcs[i]
		}
	}
	if found == nil {
		t.Fatal("large state.vscdb should be picked up by header despite the size cap")
	}
	if len(found.Blob.Raw) > 64 {
		t.Errorf("vscdb blob should carry only a header, got %d bytes", len(found.Blob.Raw))
	}
}
