package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/parse"
)

// Git history limits. A repository's history is unbounded and mostly
// uninteresting, so the sweep is capped the same way archive expansion is.
const (
	maxGitObjects = 20000     // blobs read per repository
	maxGitBytes   = 512 << 20 // total blob bytes read
	gitTimeout    = 10 * 60   // seconds; a large repo is slow, a hung git is worse
	shortSHALen   = 7
)

// IsGitRepo reports whether dir is inside a git working tree.
func IsGitRepo(dir string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// GitHistorySources yields a Source per blob reachable from any ref, so a
// credential that was committed and later deleted still surfaces. The working
// tree is walked separately; a value present in both dedupes to one finding with
// the other location rolled up, which is exactly the signal you want — "removed
// from the tree, still in history".
//
// This is opt-in: history is unbounded, and reading all of it would change the
// cost of pointing geiger at a repo.
func GitHistorySources(dir string, onFile func(scanned int)) ([]Source, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("--git-history needs the git binary on PATH: %w", err)
	}
	if !IsGitRepo(dir) {
		return nil, fmt.Errorf("--git-history: %s is not a git repository", dir)
	}
	objs, err := gitObjects(dir)
	if err != nil {
		return nil, err
	}
	return gitBlobSources(dir, objs, onFile)
}

// gitObject is one candidate blob: its id and the path it was committed under.
type gitObject struct {
	sha  string
	path string
}

// gitObjects lists every named object reachable from any ref. Trees and commits
// come back too and are filtered out by cat-file's type header later; what is
// filtered here is the noise geiger already refuses on disk, and repeats of the
// same blob under several paths (identical content, one triage).
func gitObjects(dir string) ([]gitObject, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout*1e9)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-list", "--objects", "--all")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var objs []gitObject
	seen := map[string]bool{}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		sha, path, ok := strings.Cut(sc.Text(), " ")
		if !ok || path == "" {
			continue // a commit or tag: no path, nothing to scan
		}
		if seen[sha] || skipFile(filepath.Base(path)) {
			continue
		}
		seen[sha] = true
		objs = append(objs, gitObject{sha: sha, path: path})
		if len(objs) >= maxGitObjects {
			break
		}
	}
	// The pipe may still be filling; stop git rather than draining a huge history.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return objs, nil
}

// gitBlobSources streams the listed objects through one `git cat-file --batch`
// and parses each blob. One process for the whole set: a process per object
// would dominate the runtime on any real repository.
func gitBlobSources(dir string, objs []gitObject, onFile func(int)) ([]Source, error) {
	if len(objs) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout*1e9)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		for _, o := range objs {
			if _, err := io.WriteString(stdin, o.sha+"\n"); err != nil {
				return
			}
		}
	}()

	byPath := make(map[string]string, len(objs))
	for _, o := range objs {
		byPath[o.sha] = o.path
	}

	var (
		out     []Source
		total   int64
		scanned int
	)
	r := bufio.NewReaderSize(stdout, 128*1024)
	for range objs {
		header, err := r.ReadString('\n')
		if err != nil {
			break
		}
		sha, typ, size, ok := parseBatchHeader(header)
		if !ok {
			break // desynchronized; stop rather than misattribute content
		}
		// Every object's bytes must be consumed even when skipped, or the stream
		// desynchronizes and every later blob is attributed to the wrong path.
		data, err := readExactly(r, size)
		if err != nil {
			break
		}
		if typ != "blob" || size == 0 || size > maxFileSize || total+size > maxGitBytes {
			continue
		}
		total += size
		label := gitLabel(dir, byPath[sha], sha)
		out = append(out, Source{Label: label, Blob: parse.Parse(string(data), label)})
		scanned++
		if onFile != nil {
			onFile(scanned)
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return out, nil
}

// parseBatchHeader reads cat-file's "<sha> <type> <size>" line. A missing object
// answers "<sha> missing", which has no size and ends the exchange for that id.
func parseBatchHeader(line string) (sha, typ string, size int64, ok bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 3 {
		return "", "", 0, false
	}
	n, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return "", "", 0, false
	}
	return f[0], f[1], n, true
}

// readExactly consumes size bytes plus cat-file's trailing newline.
func readExactly(r *bufio.Reader, size int64) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	if _, err := r.Discard(1); err != nil { // trailing LF
		return nil, err
	}
	return buf, nil
}

// gitLabel names a historical blob "<repo path>@<short sha>", which classifies as
// git history and tells a responder the value is recoverable from the repo even
// if it is gone from the tree.
func gitLabel(dir, path, sha string) string {
	if len(sha) > shortSHALen {
		sha = sha[:shortSHALen]
	}
	return filepath.Join(dir, path) + "@" + sha
}
