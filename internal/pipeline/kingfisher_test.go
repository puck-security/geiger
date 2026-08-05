package pipeline

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	_ "github.com/puck-security/geiger/internal/modules" // register the catalog
)

const kfSecret = "AKIAIOSFODNN7EXAMPLE"

func kfRecord(secret, path, fp string, line int) string {
	return `{"rule":{"name":"AWS Access Key ID","id":"kingfisher.aws.1"},` +
		`"finding":{"snippet":"` + secret + `","fingerprint":"` + fp + `","confidence":"high",` +
		`"entropy":"3.5","validation":{"status":"Active","response":"ok"},"language":"env",` +
		`"line":` + itoa(line) + `,"column_start":1,"column_end":20,"path":"` + path + `"}}`
}

func writeReport(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kf.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --format jsonl emits one finding record per line.
func TestFromKingfisherJSONL(t *testing.T) {
	body := kfRecord(kfSecret, "/srv/app/.env", "12345678901234567890", 3) + "\n" +
		kfRecord("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "/srv/app/deploy.sh", "999", 7) + "\n"
	got, err := FromKingfisher(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 sources, got %d", len(got))
	}
	if got[0].Label != "/srv/app/.env" {
		t.Errorf("label = %s", got[0].Label)
	}
	if got[0].Blob.Fingerprint != "12345678901234567890" {
		t.Errorf("fingerprint = %q, want it carried verbatim", got[0].Blob.Fingerprint)
	}
	if got[0].Blob.Lines[kfSecret] != 3 {
		t.Errorf("line = %d, want 3", got[0].Blob.Lines[kfSecret])
	}
}

// --format json emits an envelope (one per repo scanned) with a findings array.
func TestFromKingfisherEnvelope(t *testing.T) {
	body := `{"findings":[` + kfRecord(kfSecret, "/a/.env", "42", 1) + `],"metadata":{"generated_at":"now","scan_timestamp":"now"}}`
	got, err := FromKingfisher(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Blob.Fingerprint != "42" {
		t.Fatalf("got %+v", got)
	}
}

// Several envelopes concatenated is still valid JSONL for their own viewer, so
// it has to be valid input here too.
func TestFromKingfisherMultipleEnvelopes(t *testing.T) {
	body := `{"findings":[` + kfRecord(kfSecret, "/a/.env", "1", 1) + `]}` + "\n" +
		`{"findings":[` + kfRecord("ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "/b/.env", "2", 1) + `]}` + "\n"
	got, err := FromKingfisher(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 sources, got %d", len(got))
	}
}

// jsonl_format appends an {"access_map": …} line. geiger does its own
// blast-radius work, so that line must be skipped rather than parsed as a
// finding with an empty secret.
func TestFromKingfisherSkipsAccessMapLine(t *testing.T) {
	body := kfRecord(kfSecret, "/a/.env", "7", 1) + "\n" +
		`{"access_map":[{"provider":"aws","account":"1234","groups":[]}]}` + "\n"
	got, err := FromKingfisher(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 source, got %d: %+v", len(got), got)
	}
}

// --redact swaps every secret for a one-way hash. There is nothing to triage, so
// say why instead of reporting an empty run.
func TestFromKingfisherRejectsRedactedReport(t *testing.T) {
	hash := strings.Repeat("a1b2c3d4", 8) // 64 hex chars
	body := kfRecord(hash, "/a/.env", "7", 1) + "\n"
	_, err := FromKingfisher(writeReport(t, body))
	if err == nil {
		t.Fatal("want an error naming --redact")
	}
	if !strings.Contains(err.Error(), "redact") {
		t.Errorf("error should point at --redact, got: %v", err)
	}
}

// The common mistake is handing over the wrong file. Fail loudly.
func TestFromKingfisherRejectsNonReport(t *testing.T) {
	_, err := FromKingfisher(writeReport(t, "just some text\nnot json at all\n"))
	if err == nil {
		t.Fatal("want an error for non-Kingfisher input")
	}
	if !strings.Contains(err.Error(), "not a Kingfisher report") {
		t.Errorf("unclear error: %v", err)
	}
}

// A clean scan is a legitimate result, not an error.
func TestFromKingfisherEmptyReportIsNotAnError(t *testing.T) {
	got, err := FromKingfisher(writeReport(t, `{"findings":[]}`))
	if err != nil {
		t.Fatalf("empty report should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no sources, got %d", len(got))
	}
}

// A finding with no path still has to be triageable — the rule id names it.
func TestFromKingfisherFallsBackToRuleIDLabel(t *testing.T) {
	got, err := FromKingfisher(writeReport(t, kfRecord(kfSecret, "", "5", 0)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Label != "kingfisher:kingfisher.aws.1" {
		t.Fatalf("label = %q", got[0].Label)
	}
}

// A scanner report hands geiger one secret per blob, so recognize always computes
// line 1. The number that matters is where the secret sits in the real file, which
// the report carries — it must reach the finding, not be overwritten by the blob's
// own line.
func TestKingfisherLineSurvivesTriage(t *testing.T) {
	jwt := makeTestJWT()
	body := `{"rule":{"name":"JWT","id":"kingfisher.jwt.1"},"finding":{"snippet":"` + jwt +
		`","fingerprint":"77","confidence":"high","entropy":"5","validation":{"status":"Active","response":""},` +
		`"language":"yaml","line":42,"column_start":1,"column_end":9,"path":"/srv/app/config.yaml"}}`
	srcs, err := FromKingfisher(writeReport(t, body))
	if err != nil {
		t.Fatal(err)
	}
	results := RunSources(srcs, defaultRegistry(), Options{})
	if len(results) == 0 {
		t.Fatal("JWT should be recognized")
	}
	n := results[0].Note
	if n.Line != 42 {
		t.Errorf("Note.Line = %d, want the report's line 42", n.Line)
	}
	if n.File != "/srv/app/config.yaml" {
		t.Errorf("Note.File = %q", n.File)
	}
	if n.Fingerprint != "77" {
		t.Errorf("Note.Fingerprint = %q, want it carried to the note", n.Fingerprint)
	}
	if !strings.Contains(n.Title, ":42") {
		t.Errorf("title should name the real line: %q", n.Title)
	}
}

func makeTestJWT() string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.example.com","sub":"svc","aud":"api","exp":4102444800}`))
	return hdr + "." + pl + ".AAAAAAAAAAAAAAAAAAAAAAA"
}

func defaultRegistry() *module.Registry { return module.Default }
