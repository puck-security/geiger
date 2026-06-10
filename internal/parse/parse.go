// Package parse turns raw input (a file, stdin, or the environment) into a Blob:
// the original text plus a flattened key/value view and any structured form
// (JSON object, INI sections). Recognizers consume the Blob.
package parse

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
)

// INISection is one [section] of an INI file with its keys.
type INISection struct {
	Name string
	Keys map[string]string
}

// Blob is the parsed view of one input source.
type Blob struct {
	Raw     string
	File    string
	Kind    module.SourceKind
	ModTime time.Time         // source file mtime (zero if unknown: stdin/env/harvested)
	Vars    map[string]string // flattened key=value (env, dotenv, all INI keys)
	Lines   map[string]int    // 1-based source line per variable name (when known)
	JSON    map[string]any    // populated if the whole blob is a JSON object
	INI     []INISection
}

// Parse detects the format of raw and returns a Blob. fileHint (a path or
// label) refines detection (e.g. ".npmrc", "credentials").
func Parse(raw, fileHint string) Blob {
	b := Blob{Raw: raw, File: fileHint, Vars: map[string]string{}, Lines: map[string]int{}, Kind: module.SourceFile}
	trimmed := strings.TrimSpace(raw)

	// Binary SQLite (e.g. an AI-IDE token store, state.vscdb): keep only the magic
	// header so a recognizer can identify it by path, but don't KV/JSON-parse
	// binary pages or let the raw scan scrape plaintext tokens out of them — that
	// read is gated behind --live --intrusive and done via the file path.
	if strings.HasPrefix(raw, "SQLite format 3") {
		if len(b.Raw) > 16 {
			b.Raw = b.Raw[:16]
		}
		return b
	}

	// Binary content (cert/revocation stores like Firefox's data.safe.bin, .bin
	// blobs, anything that slipped the walker's extension filter): a NUL byte means
	// it isn't text. Don't KV/JSON/INI-parse it — that turns binary noise into
	// bogus "variables" that the name-based recognizers (generic_secret, env-name)
	// then flag as credentials. Keep Raw so the precise, checksum-anchored gitleaks
	// rules can still scan it; they don't false-positive on cert strings.
	if strings.IndexByte(raw, 0) >= 0 {
		return b
	}

	// JSON object (SA key, SSO cache, docker config, ADC).
	if strings.HasPrefix(trimmed, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			b.JSON = obj
			b.Kind = module.SourceJSON
			flattenJSON("", obj, b.Vars)
			return b
		}
	}

	// INI (AWS credentials/config, .pypirc) — has [section] headers.
	if hasINISection(raw) {
		b.INI = parseINI(raw, b.Lines)
		b.Kind = module.SourceINI
		for _, s := range b.INI {
			for k, v := range s.Keys {
				b.Vars[k] = v
				b.Vars[s.Name+"."+k] = v
			}
		}
		return b
	}

	// dotenv / env-style KEY=VALUE.
	parseKV(raw, b.Vars, b.Lines)
	if len(b.Vars) > 0 {
		b.Kind = module.SourceDotenv
	}
	return b
}

// FromEnv builds a Blob from a list of "KEY=VALUE" strings (os.Environ()).
func FromEnv(environ []string) Blob {
	b := Blob{File: "environment", Kind: module.SourceEnv, Vars: map[string]string{}}
	var sb strings.Builder
	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		b.Vars[k] = v
		sb.WriteString(e)
		sb.WriteString("\n")
	}
	b.Raw = sb.String()
	return b
}

func hasINISection(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") && len(l) > 2 {
			return true
		}
	}
	return false
}

func parseINI(raw string, lines map[string]int) []INISection {
	var sections []INISection
	cur := INISection{Name: "default", Keys: map[string]string{}}
	have := false
	flush := func() {
		if have || len(cur.Keys) > 0 {
			sections = append(sections, cur)
		}
	}
	for i, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			flush()
			name := strings.TrimSpace(l[1 : len(l)-1])
			name = strings.TrimPrefix(name, "profile ")
			cur = INISection{Name: name, Keys: map[string]string{}}
			have = true
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			key := strings.TrimSpace(k)
			cur.Keys[key] = strings.TrimSpace(v)
			if lines != nil {
				lines[key] = i + 1
				lines[cur.Name+"."+key] = i + 1
			}
		}
	}
	flush()
	return sections
}

func parseKV(raw string, out map[string]string, lines map[string]int) {
	for i, line := range strings.Split(raw, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		l = strings.TrimPrefix(l, "export ")
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if k != "" {
			out[k] = v
			if lines != nil {
				lines[k] = i + 1
			}
		}
	}
}

func flattenJSON(prefix string, obj map[string]any, out map[string]string) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			flattenJSON(key, t, out)
		case string:
			out[key] = t
		}
	}
}
