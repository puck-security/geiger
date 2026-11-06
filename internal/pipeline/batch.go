package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/score"
)

const (
	maxFileSize      = 8 << 20  // cap on one blob handed to the parsers
	largeFileWindow  = 4 << 20  // window size when scanning a file above the cap
	largeFileOverlap = 64 << 10 // overlap between windows so a boundary secret isn't split
	binarySniffBytes = 8 << 10  // bytes inspected to decide if a file is binary
)

// Source is one parsed input plus where it came from (for batch reporting).
type Source struct {
	Label string
	Blob  parse.Blob
}

// WalkConfig tunes a directory walk.
type WalkConfig struct {
	// ScanBinary includes files whose content looks binary. Off by default: a
	// tree of executables and media is noise and slow, so binaries are scanned
	// only when the operator asks for it. A file named directly on the command
	// line is always read — this applies to files discovered by the walk.
	ScanBinary bool
}

// WalkDirSeq streams a Source per regular file under dir, reading and parsing
// each file only when the consumer pulls it. The whole tree is never held in
// memory at once, so memory stays flat no matter how large the tree is. It
// skips the obvious dependency / cache / build directories and generated noise
// files (see skipDir/skipFile): a vendored dependency tree or a lockfile full
// of hashes is pure false-positive fuel.
//
// A file over maxFileSize is scanned in overlapping windows, not skipped, so a
// large log or memory dump is still covered without being read whole. A file
// whose content looks binary is skipped unless cfg.ScanBinary is set. onFile,
// if non-nil, is called with the running count of yielded sources.
func WalkDirSeq(dir string, cfg WalkConfig, onFile func(n int)) iter.Seq[Source] {
	return func(yield func(Source) bool) {
		n := 0
		emit := func(s Source) bool {
			n++
			if onFile != nil {
				onFile(n)
			}
			return yield(s)
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				if skipDir(d.Name()) && path != dir {
					// IDE dirs are noise, but the agentic config inside them is not:
					// pull just the known MCP config before skipping the rest.
					if ideConfigDir(d.Name()) {
						for _, p := range ideConfigPaths(path) {
							if !loadFileSeq(p, cfg, emit) {
								return filepath.SkipAll
							}
						}
					}
					return filepath.SkipDir
				}
				return nil
			}
			if skipFile(d.Name()) {
				return nil
			}
			if !loadFileSeq(path, cfg, emit) {
				return filepath.SkipAll
			}
			return nil
		})
	}
}

// WalkDir collects WalkDirSeq into a slice with the default config. It is a
// convenience for tests and callers that want the whole result at once; the
// scanning path uses WalkDirSeq so it never materializes the tree.
func WalkDir(dir string) ([]Source, error) {
	var out []Source
	for s := range WalkDirSeq(dir, WalkConfig{}, nil) {
		out = append(out, s)
	}
	return out, nil
}

// loadConcurrency is the worker count for reading and parsing files. The work is
// a syscall wait per file plus a CPU-bound parse, so a pool sized to the
// machine (rather than 1) overlaps the two instead of serializing them.
func loadConcurrency(n int) int {
	if n <= 1 {
		return 1
	}
	c := runtime.NumCPU()
	if c > maxLoadWorkers {
		c = maxLoadWorkers
	}
	if c < 2 {
		c = 2
	}
	if c > n {
		c = n
	}
	return c
}

const maxLoadWorkers = 16

// loadFileSeq reads and parses one path and yields its Source(s): one for a
// normal file, several for an archive (each member) or a large file (each
// window). It yields nothing for a file that should be skipped. It returns the
// consumer's verdict — false means stop the whole walk — so a caller can honor
// an early break.
//
// An AI-IDE token store (state.vscdb) is a known high-value target, identified
// by its SQLite header without slurping the whole multi-MB binary. An archive is
// read past the per-file cap and expanded, each member triaged in its own right.
// A file over the cap is scanned in windows rather than skipped. A file whose
// content looks binary is skipped unless cfg.ScanBinary is set.
func loadFileSeq(path string, cfg WalkConfig, yield func(Source) bool) bool {
	if isIDEStore(filepath.Base(path)) {
		hdr, err := readHead(path, 64)
		if err != nil || !strings.HasPrefix(hdr, "SQLite format 3") {
			return true
		}
		return yield(newSource(path, hdr, fileModTime(path)))
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return true // skip devices, pipes, sockets, broken symlinks
	}
	if looksLikeArchive(path) {
		if fi.Size() > maxArchiveBytes {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		for _, s := range archiveSources(path, data) {
			s.Blob.ModTime = fi.ModTime()
			if !yield(s) {
				return false
			}
		}
		return true
	}
	if fi.Size() <= maxFileSize {
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if !cfg.ScanBinary && looksBinary(data) {
			return true
		}
		return yield(newSource(path, string(data), fi.ModTime()))
	}
	return scanLargeFile(path, fi.ModTime(), cfg, yield)
}

// scanLargeFile scans a file above the per-blob cap in overlapping windows, so a
// big log or memory dump is covered without being read whole. Only one window is
// resident at a time. The overlap carries the tail of each window into the next
// so a secret straddling a boundary is still matched; the duplicate hit in the
// overlap is collapsed by the batch's secret dedupe. Structured parsing (JSON,
// INI) is best-effort on a partial window; raw secret recognition still runs.
func scanLargeFile(path string, mod time.Time, cfg WalkConfig, yield func(Source) bool) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	var carry []byte // tail of the previous window, prepended for overlap
	checked := false
	for {
		buf := make([]byte, largeFileWindow)
		n, err := io.ReadFull(f, buf)
		if n == 0 {
			return true
		}
		chunk := buf[:n]
		if !checked {
			if !cfg.ScanBinary && looksBinary(chunk) {
				return true
			}
			checked = true
		}
		window := chunk
		if len(carry) > 0 {
			window = make([]byte, 0, len(carry)+n)
			window = append(window, carry...)
			window = append(window, chunk...)
		}
		if !yield(newSource(path, string(window), mod)) {
			return false
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return true // last (short) window
		}
		if err != nil {
			return true
		}
		if len(window) > largeFileOverlap {
			carry = append([]byte(nil), window[len(window)-largeFileOverlap:]...)
		} else {
			carry = append([]byte(nil), window...)
		}
	}
}

// looksBinary reports whether a leading sample contains a NUL byte, git's
// heuristic for a binary file.
func looksBinary(b []byte) bool {
	if len(b) > binarySniffBytes {
		b = b[:binarySniffBytes]
	}
	return bytes.IndexByte(b, 0) >= 0
}

func newSource(path, raw string, mod time.Time) Source {
	b := parse.Parse(raw, path)
	b.ModTime = mod
	return Source{Label: path, Blob: b}
}

func fileModTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func isIDEStore(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".vscdb") }

func ideConfigDir(name string) bool { return name == ".vscode" || name == ".idea" }

// ideConfigPaths shallow-scans a skipped IDE dir for the MCP config it may hold
// (mcp.json by name, or any .json that declares an "mcpServers" map), so a repo
// scan still surfaces project-level agent credentials without descending into
// the rest of the editor noise.
func ideConfigPaths(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") || skipFile(name) {
			continue
		}
		if strings.EqualFold(name, "mcp.json") {
			out = append(out, filepath.Join(dir, name))
			continue
		}
		if hd, err := readHead(filepath.Join(dir, name), 8192); err == nil && strings.Contains(hd, "\"mcpServers\"") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out
}

// readHead returns up to n bytes from the start of a file.
func readHead(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}
	return string(buf[:m]), nil
}

// skipDir reports whether a directory is dependency/cache/build noise we should
// not descend into. Matches an exact name or a known suffix (e.g. *.dist-info).
func skipDir(name string) bool {
	switch name {
	// VCS / IDE / tooling
	case ".git", ".svn", ".hg", ".idea", ".vscode", ".vs":
		return true
	// JS / web dependencies & build output
	case "node_modules", "bower_components", ".pnpm-store", ".yarn",
		".next", ".nuxt", ".svelte-kit", ".angular", ".parcel-cache":
		return true
	// Python virtualenvs & caches
	case "site-packages", "__pycache__", ".venv", "venv", "virtualenv", "virtenv",
		".tox", ".nox", ".eggs", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".ipynb_checkpoints":
		return true
	// Go / Rust / JVM / Ruby / package caches
	case "vendor", "target", ".gradle", ".m2", ".cargo", ".rustup", ".npm",
		".nuget", ".ivy2", ".cache", ".bundle":
		return true
	// IaC / build artifacts
	case ".terraform", "dist", "build", "out", "coverage", "__snapshots__",
		"Pods", "DerivedData":
		return true
	}
	// Python package metadata dirs: foo-1.2.dist-info / foo.egg-info
	if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
		return true
	}
	return false
}

// skipFile reports whether a file is generated/lock/binary noise — full of
// hashes and integrity digests that masquerade as credential-shaped values.
func skipFile(name string) bool {
	switch name {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
		"poetry.lock", "Pipfile.lock", "Cargo.lock", "Gemfile.lock", "composer.lock",
		"go.sum", "flake.lock", "uv.lock", "pdm.lock",
		// Python dist-info members (in case the dir wasn't skipped).
		"RECORD", "WHEEL", "INSTALLER", "METADATA", "top_level.txt":
		return true
	}
	switch ext := strings.ToLower(filepath.Ext(name)); ext {
	case ".lock",
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp", ".svg",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".pyc", ".pyo", ".class", ".o", ".a", ".so", ".dylib", ".dll", ".wasm",
		// Archive formats are NOT listed here — they are containers, and their
		// members are triaged individually (see archive.go).
		".pdf", ".mp3", ".mp4", ".mov", ".avi", ".webm":
		return true
	case ".map":
		return true // source maps
	}
	// minified bundles: foo.min.js, foo.min.css
	if strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css") {
		return true
	}
	return false
}

// gitleaksFinding is the subset of a gitleaks JSON report we consume.
type gitleaksFinding struct {
	RuleID string `json:"RuleID"`
	Secret string `json:"Secret"`
	File   string `json:"File"`
}

// nucleiFinding is the subset of a nuclei JSONL result we consume. nuclei's
// detection templates locate where a secret leaks (an exposed /.env, phpinfo,
// instance metadata) and pull the literal value(s) into extracted-results;
// geiger re-types and validates each value itself. We also consume the raw
// response body when present: it's a superset of extracted-results and lets
// geiger's parsers reassemble multi-field credentials (an AWS key+secret pair, a
// ~/.aws/credentials INI, a connection string) that the flat value array can't.
type nucleiFinding struct {
	TemplateID       string   `json:"template-id"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Response         string   `json:"response"`
}

// nucleiBody returns the body of nuclei's raw `response` field (status line +
// headers + blank line + body). Returns "" when there's no body, so the caller
// falls back to the extracted values.
func nucleiBody(raw string) string {
	if _, body, ok := strings.Cut(raw, "\r\n\r\n"); ok {
		return body
	}
	if _, body, ok := strings.Cut(raw, "\n\n"); ok {
		return body
	}
	return "" // no header/body separator — nothing reliable to ingest
}

// trufflehogFinding is the subset of a TruffleHog v3 JSON finding we consume.
// TruffleHog emits newline-delimited JSON (one object per line).
type trufflehogFinding struct {
	DetectorName   string `json:"DetectorName"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
			Git struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// FromTrufflehog ingests a TruffleHog v3 JSON report (newline-delimited, the
// default `trufflehog ... --json` output, or a JSON array) and yields one
// Source per verified/unverified finding. TruffleHog over a home dir + git
// history is exactly what supply-chain malware runs, so this lets a responder
// triage that same dump.
func FromTrufflehog(path string) ([]Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []trufflehogFinding
	if json.Unmarshal(data, &findings) != nil {
		// fall back to newline-delimited JSON
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var f trufflehogFinding
			if json.Unmarshal([]byte(line), &f) == nil {
				findings = append(findings, f)
			}
		}
	}
	var out []Source
	for _, f := range findings {
		secret := f.Raw
		if secret == "" {
			secret = f.RawV2
		}
		if secret == "" {
			continue
		}
		file := f.SourceMetadata.Data.Filesystem.File
		line := f.SourceMetadata.Data.Filesystem.Line
		if file == "" {
			file = f.SourceMetadata.Data.Git.File
			line = f.SourceMetadata.Data.Git.Line
		}
		label := file
		if label == "" {
			label = "trufflehog:" + f.DetectorName
		}
		b := parse.Parse(secret, label)
		if line > 0 {
			b.Lines[secret] = line // best-effort line carry-through
		}
		out = append(out, Source{Label: label, Blob: b})
	}
	return out, nil
}

// FromNuclei ingests nuclei JSONL output (the `-j`/`-jsonl` stream, or a JSON
// array) and yields one Source per extracted credential value. nuclei casts the
// wide net — its templates extract any value that *looks* like a secret from an
// exposed endpoint — and geiger is the authority: each value flows through the
// same recognizer as every other source, so over-matches that aren't real
// credentials are dropped here. path "-" reads stdin, so the intended use is a
// streaming pipe (`nuclei … -j | geiger --from-nuclei - --live`) that never
// lands secrets on disk. The matched-at URL becomes the Source label, which
// drives the title provenance ("from https://host/.env"), the cross-source
// dedup/"also exposed in" rollup (one key exposed at many URLs collapses to one
// finding), and the internet-exposed-endpoint exposure class.
func FromNuclei(path string) ([]Source, error) {
	var data []byte
	if path == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20)) // cap at 32 MiB
		if err != nil {
			return nil, err
		}
		data = b
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = b
	}
	var findings []nucleiFinding
	arrayOK := json.Unmarshal(data, &findings) == nil
	sawObj := false
	if !arrayOK {
		// fall back to newline-delimited JSON (the default -j stream)
		findings = findings[:0]
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			sawObj = true
			var f nucleiFinding
			if json.Unmarshal([]byte(line), &f) == nil {
				findings = append(findings, f)
			}
		}
	}
	// Guard the common mistake: piping nuclei WITHOUT -j. Its human output (lines
	// like "[template-id] [http] ...") isn't JSON, so we'd otherwise silently find
	// nothing. A real `nuclei -j` run with no hits yields empty input, which is a
	// legitimate "nothing found" — so only error on non-empty, non-JSON input.
	if len(findings) == 0 && !arrayOK && !sawObj && strings.TrimSpace(string(data)) != "" {
		return nil, fmt.Errorf("--from-nuclei: input is not nuclei JSON — run nuclei with -j (e.g. `nuclei … -t templates/ -j | geiger --from-nuclei -`)")
	}
	var out []Source
	for _, f := range findings {
		label := f.MatchedAt
		if label == "" {
			label = "nuclei:" + f.TemplateID
		}
		// Prefer the full response body: it's a superset of extracted-results and
		// lets geiger reassemble multi-field credentials. Then add only those
		// extracted values not already in the body (e.g. a value a template pulled
		// from a response header). When there's no body, fall back to the values.
		if body := nucleiBody(f.Response); strings.TrimSpace(body) != "" {
			out = append(out, Source{Label: label, Blob: parse.Parse(body, label)})
			for _, v := range f.ExtractedResults {
				if v = strings.TrimSpace(v); v != "" && !strings.Contains(body, v) {
					out = append(out, Source{Label: label, Blob: parse.Parse(v, label)})
				}
			}
			continue
		}
		for _, v := range f.ExtractedResults {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, Source{Label: label, Blob: parse.Parse(v, label)})
			}
		}
	}
	return out, nil
}

// FromGitleaks ingests a gitleaks JSON report and yields one Source per
// finding, so a prior scanner run can feed Geiger's triage directly.
func FromGitleaks(path string) ([]Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, err
	}
	var out []Source
	for _, f := range findings {
		if f.Secret == "" {
			continue
		}
		label := f.File
		if label == "" {
			label = "gitleaks:" + f.RuleID
		}
		out = append(out, Source{Label: label, Blob: parse.Parse(f.Secret, label)})
	}
	return out, nil
}

// ResultFromNote wraps a pre-built Note (e.g. from the browser scanner, which
// produces capability/blast-radius findings rather than recognized credentials)
// as a Result so it flows through the same sort/tier/print path.
func ResultFromNote(n module.Note) Result { return Result{Note: n} }

// SortBySeverity orders results by composite blast-radius score so the highest-
// impact (and any crown-jewel context match) surface first, invalids last.
func SortBySeverity(rs []Result, ctx score.Context) {
	sort.SliceStable(rs, func(i, j int) bool {
		return score.BlastRadius(rs[i].Note, ctx) > score.BlastRadius(rs[j].Note, ctx)
	})
}

// RunSources runs the pipeline over many sources sharing one dedupe state (so a
// credential present in several files is reconned once) through a bounded worker
// pool. Results are annotated with the other files each secret appeared in.
func RunSources(srcs []Source, reg *module.Registry, opts Options) []Result {
	bt := NewBatch(reg, opts)
	all := bt.RunConcurrent(srcs, nil, nil)
	bt.AnnotateDuplicates(all)
	return all
}

// LooksLikeGitleaks reports whether a file is probably a gitleaks JSON report.
func LooksLikeGitleaks(path string) bool {
	if !strings.HasSuffix(path, ".json") {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), `"RuleID"`)
}
