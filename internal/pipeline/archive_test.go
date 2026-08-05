package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCred = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

func writeZip(t *testing.T, path string, members map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Sorted for a deterministic archive; map order would otherwise vary.
	for _, name := range sortedKeys(members) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(members[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tarGzBytes(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, name := range sortedKeys(members) {
		body := members[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func labelSet(srcs []Source) map[string]string {
	out := map[string]string{}
	for _, s := range srcs {
		out[s.Label] = s.Blob.Raw
	}
	return out
}

func TestZipMembersBecomeSources(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "host.zip")
	writeZip(t, zp, map[string]string{
		"home/.env":       testCred,
		"home/notes.txt":  "nothing here\n",
		"home/logo.png":   "\x89PNG\r\n\x1a\n binary",
		"home/yarn.lock":  "lockfile noise\n",
		"home/sub/x.conf": "TOKEN=abc\n",
	})

	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := labelSet(got)
	wantEnv := zp + "::home/.env"
	if labels[wantEnv] != testCred {
		t.Errorf("member %s missing or wrong content: %q", wantEnv, labels[wantEnv])
	}
	if _, ok := labels[zp+"::home/sub/x.conf"]; !ok {
		t.Errorf("nested member not extracted; got %v", sortedKeys(labels))
	}
	// The same noise filter that applies on disk applies inside the container.
	for _, skipped := range []string{zp + "::home/logo.png", zp + "::home/yarn.lock"} {
		if _, ok := labels[skipped]; ok {
			t.Errorf("%s should have been skipped as noise", skipped)
		}
	}
}

func TestTarGzMembersBecomeSources(t *testing.T) {
	dir := t.TempDir()
	tp := filepath.Join(dir, "dotfiles.tar.gz")
	if err := os.WriteFile(tp, tarGzBytes(t, map[string]string{
		"dotfiles/.env":     testCred,
		"dotfiles/.bashrc":  "export PATH=/usr/bin\n",
		"dotfiles/data.bin": "\x00\x01\x02",
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	labels := labelSet(got)
	if labels[tp+"::dotfiles/.env"] != testCred {
		t.Errorf("tar.gz member missing; got %v", sortedKeys(labels))
	}
}

// A lone .gz is a compressed file, not a container — it yields one Source, and
// the label drops the .gz so the finding names the real file.
func TestGzipSingleFileBecomesOneSource(t *testing.T) {
	dir := t.TempDir()
	gp := filepath.Join(dir, "access.log.gz")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(testCred)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gp, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 source, got %d: %v", len(got), sortedKeys(labelSet(got)))
	}
	if want := filepath.Join(dir, "access.log"); got[0].Label != want {
		t.Errorf("label = %s, want %s", got[0].Label, want)
	}
	if got[0].Blob.Raw != testCred {
		t.Errorf("content = %q", got[0].Blob.Raw)
	}
}

// An archive inside an archive is opened, but only to maxArchiveDepth — a chain
// of nested containers is a cheap way to make a scanner do unbounded work.
func TestNestedArchiveStopsAtDepthLimit(t *testing.T) {
	dir := t.TempDir()
	inner := tarGzBytes(t, map[string]string{"deep/.env": testCred})
	mid := tarGzBytes(t, map[string]string{"mid/inner.tar.gz": string(inner)})
	outer := filepath.Join(dir, "outer.tar.gz")
	if err := os.WriteFile(outer, tarGzBytes(t, map[string]string{"outer/mid.tar.gz": string(mid)}), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// depth 0 = outer, 1 = mid, 2 = inner: the innermost .env is the last thing
	// still in budget, and nothing below it may be opened.
	labels := labelSet(got)
	found := false
	for l := range labels {
		if strings.HasSuffix(l, "deep/.env") {
			found = true
		}
		if strings.Count(l, "::") > maxArchiveDepth+1 {
			t.Errorf("expanded past the depth limit: %s", l)
		}
	}
	if !found {
		t.Errorf("member at the depth limit should still be read; got %v", sortedKeys(labels))
	}
}

// A decompression bomb is small on disk and enormous in memory. The member cap
// must stop the expansion regardless of how well it compresses.
func TestArchiveMemberCapStopsExpansion(t *testing.T) {
	members := map[string]string{}
	for i := range maxArchiveMembers + 500 {
		members[fmt.Sprintf("f%05d.env", i)] = testCred
	}
	dir := t.TempDir()
	zp := filepath.Join(dir, "many.zip")
	writeZip(t, zp, members)

	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxArchiveMembers {
		t.Errorf("expanded %d members, cap is %d", len(got), maxArchiveMembers)
	}
	if len(got) == 0 {
		t.Error("cap should bound the expansion, not prevent it")
	}
}

// A member that decompresses past the total byte budget must not be buffered.
func TestArchiveByteBudgetStopsExpansion(t *testing.T) {
	big := strings.Repeat("A", 4<<20) // 4MB each, compresses to almost nothing
	members := map[string]string{}
	for i := range 80 { // 320MB decompressed, over the 256MB budget
		members[fmt.Sprintf("big%02d.txt", i)] = big
	}
	dir := t.TempDir()
	zp := filepath.Join(dir, "bomb.zip")
	writeZip(t, zp, members)

	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, s := range got {
		total += int64(len(s.Blob.Raw))
	}
	if total > maxArchiveBytes {
		t.Errorf("expanded %d bytes, budget is %d", total, maxArchiveBytes)
	}
}

// Member paths come from the archive and are not trustworthy. Nothing is written
// to disk, but a traversing name must not produce a label that reads as a real
// path outside the archive.
func TestTraversingMemberNameIsCleaned(t *testing.T) {
	dir := t.TempDir()
	tp := filepath.Join(dir, "evil.tar.gz")
	if err := os.WriteFile(tp, tarGzBytes(t, map[string]string{
		"../../../../etc/shadow": testCred,
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if strings.Contains(s.Label, "..") {
			t.Errorf("label keeps a traversal: %s", s.Label)
		}
		if !strings.HasPrefix(s.Label, tp+"::") {
			t.Errorf("label escapes the archive: %s", s.Label)
		}
	}
}

// Archives are expanded through the same worker pool as everything else, so the
// order guarantee has to survive them.
func TestArchiveExpansionKeepsWalkOrder(t *testing.T) {
	dir := t.TempDir()
	for i := range 12 {
		p := filepath.Join(dir, fmt.Sprintf("a%02d.tar.gz", i))
		if err := os.WriteFile(p, tarGzBytes(t, map[string]string{
			fmt.Sprintf("m%02d/.env", i):   testCred,
			fmt.Sprintf("m%02d/b.conf", i): "TOKEN=b\n",
		}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := labels(first)
	if len(want) != 24 {
		t.Fatalf("want 24 sources, got %d", len(want))
	}
	for run := range 8 {
		got, err := WalkDir(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range labels(got) {
			if l != want[i] {
				t.Fatalf("run %d: source %d is %s, want %s", run, i, l, want[i])
			}
		}
	}
}

// A file named directly on the command line goes through SourcesFromArchive, not
// the walk — being handed the archive itself is the common IR case.
func TestSourcesFromArchiveHandlesDirectFile(t *testing.T) {
	dir := t.TempDir()
	tp := filepath.Join(dir, "host.tar.gz")
	if err := os.WriteFile(tp, tarGzBytes(t, map[string]string{"home/.env": testCred}), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := SourcesFromArchive(tp)
	if !ok {
		t.Fatal("archive not handled")
	}
	if len(got) != 1 || got[0].Label != tp+"::home/.env" {
		t.Fatalf("got %v", labels(got))
	}
}

// A file whose name says archive but whose bytes are not one must be reported as
// unhandled, so the caller still reads it as ordinary text.
func TestSourcesFromArchiveDeclinesNonArchive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notreally.gz")
	if err := os.WriteFile(p, []byte(testCred), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := SourcesFromArchive(p); ok {
		t.Error("plain text named .gz should not be handled as an archive")
	}
}
