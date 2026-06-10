package pipeline

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/score"
)

const maxFileSize = 8 << 20 // 8 MB

// Source is one parsed input plus where it came from (for batch reporting).
type Source struct {
	Label string
	Blob  parse.Blob
}

// WalkDir returns a Source per regular file under dir, skipping the obvious
// dependency / cache / build directories and generated noise files. IR works in
// volume: point Geiger at a tree of leaked files and triage them all — but a
// vendored dependency tree or a lockfile full of hashes is pure false-positive
// fuel, so we don't descend into it. onFile, if non-nil, is called with the
// running count of accepted files after each is added, for progress reporting.
func WalkDir(dir string, onFile func(scanned int)) ([]Source, error) {
	var out []Source
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != dir {
				// IDE dirs are noise, but the agentic config inside them is not:
				// pull just the known MCP config before skipping the rest.
				if ideConfigDir(d.Name()) {
					addIDEConfigs(path, &out, onFile)
				}
				return filepath.SkipDir
			}
			return nil
		}
		addFile(path, d.Name(), &out, onFile)
		return nil
	})
	return out, err
}

// addFile reads one regular file and appends a Source. Generated/lock/binary
// noise is skipped, and a file over the size cap is skipped — UNLESS it's an
// AI-IDE token store (state.vscdb), a known high-value target identified by its
// SQLite header without slurping the whole multi-MB binary.
func addFile(path, name string, out *[]Source, onFile func(int)) {
	if skipFile(name) {
		return
	}
	if isIDEStore(name) {
		hdr, err := readHead(path, 64)
		if err != nil || !strings.HasPrefix(hdr, "SQLite format 3") {
			return
		}
		appendSource(out, path, hdr, fileModTime(path), onFile)
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxFileSize {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	appendSource(out, path, string(data), fi.ModTime(), onFile)
}

func appendSource(out *[]Source, path, raw string, mod time.Time, onFile func(int)) {
	b := parse.Parse(raw, path)
	b.ModTime = mod
	*out = append(*out, Source{Label: path, Blob: b})
	if onFile != nil {
		onFile(len(*out))
	}
}

func fileModTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

func isIDEStore(name string) bool { return strings.HasSuffix(strings.ToLower(name), ".vscdb") }

func ideConfigDir(name string) bool { return name == ".vscode" || name == ".idea" }

// addIDEConfigs shallow-scans a skipped IDE dir for the MCP config it may hold
// (mcp.json by name, or any .json that declares an "mcpServers" map), so a repo
// scan still surfaces project-level agent credentials without descending into
// the rest of the editor noise.
func addIDEConfigs(dir string, out *[]Source, onFile func(int)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		if strings.EqualFold(name, "mcp.json") {
			addFile(filepath.Join(dir, name), name, out, onFile)
			continue
		}
		if hd, err := readHead(filepath.Join(dir, name), 8192); err == nil && strings.Contains(hd, "\"mcpServers\"") {
			addFile(filepath.Join(dir, name), name, out, onFile)
		}
	}
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
		".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
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
		for _, line := range strings.Split(string(data), "\n") {
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
