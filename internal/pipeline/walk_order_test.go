package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// WalkDir reads files through a worker pool, so the order it returns them in is
// the one thing that could drift with scheduling. It must not: the batch dedupes
// a secret to its first sighting, so a varying order would change which file is
// reported as the primary location of a secret found in several places.
func TestWalkDirOrderIsStableAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	for i := range 60 {
		sub := filepath.Join(dir, fmt.Sprintf("d%02d", i%7))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(sub, fmt.Sprintf("f%02d.env", i))
		if err := os.WriteFile(p, fmt.Appendf(nil, "TOKEN=value-%d\n", i), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	first, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 60 {
		t.Fatalf("want 60 sources, got %d", len(first))
	}
	want := labels(first)
	for run := range 12 {
		got, err := WalkDir(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range labels(got) {
			if l != want[i] {
				t.Fatalf("run %d: source %d is %s, want %s — walk order is not deterministic", run, i, l, want[i])
			}
		}
	}
}

// The pool must not drop or duplicate a file, and every Source must carry the
// content of its own path (a slot mix-up would pair a label with another file's
// blob, mislabelling every finding from it).
func TestWalkDirPairsEachLabelWithItsOwnContent(t *testing.T) {
	dir := t.TempDir()
	for i := range 40 {
		p := filepath.Join(dir, fmt.Sprintf("f%02d.env", i))
		if err := os.WriteFile(p, fmt.Appendf(nil, "TOKEN=value-%d\n", i), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 40 {
		t.Fatalf("want 40 sources, got %d", len(got))
	}
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s.Label] {
			t.Fatalf("%s returned twice", s.Label)
		}
		seen[s.Label] = true
		var i int
		if _, err := fmt.Sscanf(filepath.Base(s.Label), "f%d.env", &i); err != nil {
			t.Fatalf("unexpected label %s", s.Label)
		}
		if want := fmt.Sprintf("value-%d", i); s.Blob.Vars["TOKEN"] != want {
			t.Errorf("%s: TOKEN=%q, want %q", s.Label, s.Blob.Vars["TOKEN"], want)
		}
	}
}

// The progress callback runs from worker goroutines. It is serialized, so a
// caller may write to a terminal from it, and it must report each loaded file
// exactly once with a monotonically increasing count.
func TestWalkDirProgressIsSerializedAndMonotonic(t *testing.T) {
	dir := t.TempDir()
	for i := range 50 {
		p := filepath.Join(dir, fmt.Sprintf("f%02d.env", i))
		if err := os.WriteFile(p, []byte("TOKEN=v\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var counts []int
	got, err := WalkDir(dir, func(n int) { counts = append(counts, n) }) // unsynchronized on purpose: -race proves the callback is serialized
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != len(got) {
		t.Fatalf("progress fired %d times for %d sources", len(counts), len(got))
	}
	for i, c := range counts {
		if c != i+1 {
			t.Fatalf("progress %d reported count %d, want %d", i, c, i+1)
		}
	}
}

func labels(srcs []Source) []string {
	out := make([]string, len(srcs))
	for i, s := range srcs {
		out[i] = s.Label
	}
	return out
}
