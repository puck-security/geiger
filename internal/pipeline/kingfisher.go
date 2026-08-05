package pipeline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/parse"
)

// Kingfisher writes an envelope per line (`--format json`) or a bare finding
// record per line (`--format jsonl`), so both shapes have to be accepted. A
// JSONL stream can also carry a trailing {"access_map": …} object that is not a
// finding — geiger does its own blast-radius work, so that line is skipped.
type kingfisherEnvelope struct {
	Findings []kingfisherRecord `json:"findings"`
}

type kingfisherRecord struct {
	Rule struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"rule"`
	Finding struct {
		Snippet     string `json:"snippet"`
		Fingerprint string `json:"fingerprint"`
		// Older/other emitters spell it out; accept either.
		FindingFingerprint string `json:"finding_fingerprint"`
		Line               int    `json:"line"`
		Path               string `json:"path"`
		Validation         struct {
			Status string `json:"status"`
		} `json:"validation"`
	} `json:"finding"`
}

func (r kingfisherRecord) fingerprint() string {
	if r.Finding.Fingerprint != "" {
		return r.Finding.Fingerprint
	}
	return r.Finding.FindingFingerprint
}

// redactedRe matches the one-way hash --redact substitutes for the secret. Such
// a report cannot be triaged: geiger needs the value to authenticate with.
var redactedRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FromKingfisher ingests a Kingfisher report (JSON envelope, JSONL records, or a
// JSON array) and yields one Source per finding. path "-" reads stdin, so the
// intended use is a streaming pipe that never lands secrets on disk.
//
// Kingfisher's own fingerprint rides along on each Source: geiger cannot
// recompute it (it hashes the matched bytes with the origin label and the byte
// offsets, which don't survive re-typing) so it is carried verbatim, letting
// Kingfisher's viewer line geiger's findings up with its own.
func FromKingfisher(path string) ([]Source, error) {
	data, err := readReport(path)
	if err != nil {
		return nil, err
	}
	recs, sawJSON := parseKingfisher(data)
	if len(recs) == 0 {
		// An empty but valid report is a legitimate "nothing found"; anything else
		// is the wrong file or the wrong flag, and should say so rather than
		// silently triaging nothing.
		if !sawJSON && strings.TrimSpace(string(data)) != "" {
			return nil, fmt.Errorf("--from-kingfisher: input is not a Kingfisher report — run kingfisher with --format json (or jsonl)")
		}
		return nil, nil
	}

	var out []Source
	redacted := 0
	for _, r := range recs {
		secret := strings.TrimSpace(r.Finding.Snippet)
		if secret == "" {
			continue
		}
		if redactedRe.MatchString(secret) {
			redacted++
			continue
		}
		label := r.Finding.Path
		if label == "" {
			label = "kingfisher:" + r.Rule.ID
		}
		b := parse.Parse(secret, label)
		b.Fingerprint = r.fingerprint()
		if r.Finding.Line > 0 {
			b.Lines[secret] = r.Finding.Line
		}
		out = append(out, Source{Label: label, Blob: b})
	}
	// Every value being a hash means the report was produced with --redact. There
	// is nothing to triage, and saying so beats reporting zero findings.
	if len(out) == 0 && redacted > 0 {
		return nil, fmt.Errorf("--from-kingfisher: all %d finding(s) are redacted — geiger needs the secret value; re-run kingfisher without --redact", redacted)
	}
	return out, nil
}

// parseKingfisher accepts the envelope-per-line, record-per-line, and JSON-array
// shapes. It reports whether any JSON object was seen at all, so the caller can
// tell "valid report, no findings" from "this isn't a Kingfisher report".
func parseKingfisher(data []byte) (recs []kingfisherRecord, sawJSON bool) {
	// A whole-document envelope, or an array of records.
	var env kingfisherEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.Findings != nil {
		return env.Findings, true
	}
	var arr []kingfisherRecord
	if err := json.Unmarshal(data, &arr); err == nil {
		return keepFindings(arr), true
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		sawJSON = true
		// An envelope on this line (--format json emits one per repo scanned).
		var e kingfisherEnvelope
		if err := json.Unmarshal([]byte(line), &e); err == nil && e.Findings != nil {
			recs = append(recs, e.Findings...)
			continue
		}
		var r kingfisherRecord
		if err := json.Unmarshal([]byte(line), &r); err == nil {
			recs = append(recs, keepFindings([]kingfisherRecord{r})...)
		}
	}
	return recs, sawJSON
}

// keepFindings drops objects that unmarshalled without being findings — most
// notably the {"access_map": …} line jsonl_format appends.
func keepFindings(in []kingfisherRecord) []kingfisherRecord {
	out := in[:0]
	for _, r := range in {
		if r.Finding.Snippet != "" {
			out = append(out, r)
		}
	}
	return out
}

// readReport reads a report file, or stdin when path is "-".
func readReport(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 32<<20)) // cap at 32 MiB
	}
	return os.ReadFile(path)
}
