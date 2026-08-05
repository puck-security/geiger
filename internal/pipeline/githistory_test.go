package pipeline

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const gitCred = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

// newRepo builds a repository whose history holds a credential that is no longer
// in the working tree — the case --git-history exists for.
func newRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		// -c overrides beat any global config (a global gitignore would otherwise
		// silently drop the fixture and the test would pass for the wrong reason).
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-q", ".")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")

	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "creds.ini"), []byte(gitCred), 0o644); err != nil {
		t.Fatal(err)
	}
	// A lockfile in history must stay filtered, exactly as on disk.
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte("TOKEN=abcdef123456\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "config/creds.ini", "yarn.lock")
	run("commit", "-qm", "oops")
	run("rm", "-q", "config/creds.ini", "yarn.lock")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-qm", "remove secret")
	return dir
}

func TestGitHistoryFindsDeletedCredential(t *testing.T) {
	dir := newRepo(t)

	// Precondition: the walk alone finds nothing, or this proves nothing.
	tree, err := WalkDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range tree {
		if strings.Contains(s.Blob.Raw, "AKIAIOSFODNN7EXAMPLE") {
			t.Fatalf("fixture wrong: credential still in the working tree at %s", s.Label)
		}
	}

	got, err := GitHistorySources(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found *Source
	for i, s := range got {
		if strings.Contains(s.Blob.Raw, "AKIAIOSFODNN7EXAMPLE") {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatalf("deleted credential not recovered from history; got %d blobs", len(got))
	}
	if !strings.Contains(found.Label, "config/creds.ini@") {
		t.Errorf("label should name the path and the object: %s", found.Label)
	}
}

// The label has to classify as git history so the responder is told the value is
// recoverable from the repo even though it is gone from the tree.
func TestGitHistoryLabelClassifiesAsHistory(t *testing.T) {
	class, note, flag := classifyExposure("/repo/config/creds.ini@6f491d7")
	if class != "git history" {
		t.Fatalf("class = %q, want %q", class, "git history")
	}
	if !strings.Contains(note, "recoverable") {
		t.Errorf("note = %q", note)
	}
	if flag == 0 {
		t.Error("git history should not be a bare info finding")
	}
}

// A plain path must not be mistaken for a history blob.
func TestOrdinaryPathIsNotGitHistory(t *testing.T) {
	for _, p := range []string{"/repo/.env", "/repo/a@b.txt", "/repo/x@notahex"} {
		if class, _, _ := classifyExposure(p); class == "git history" {
			t.Errorf("%s misclassified as git history", p)
		}
	}
}

// The on-disk noise filter applies to history too — a lockfile full of hashes is
// as much false-positive fuel in a past commit as in the tree.
func TestGitHistorySkipsNoiseFiles(t *testing.T) {
	dir := newRepo(t)
	got, err := GitHistorySources(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if strings.Contains(s.Label, "yarn.lock") {
			t.Errorf("lockfile should be filtered from history: %s", s.Label)
		}
	}
}

func TestGitHistoryRejectsNonRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	_, err := GitHistorySources(t.TempDir(), nil)
	if err == nil {
		t.Fatal("want an error for a non-repository")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("unclear error: %v", err)
	}
}

// The progress callback must fire once per blob actually turned into a Source.
func TestGitHistoryProgressCounts(t *testing.T) {
	dir := newRepo(t)
	var counts []int
	got, err := GitHistorySources(dir, func(n int) { counts = append(counts, n) })
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != len(got) {
		t.Errorf("progress fired %d times for %d sources", len(counts), len(got))
	}
	for i, c := range counts {
		if c != i+1 {
			t.Fatalf("progress %d reported %d", i, c)
		}
	}
}
