package note

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/score"
)

func parseSARIF(t *testing.T, s string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return doc
}

func firstRun(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", doc["runs"])
	}
	return runs[0].(map[string]any)
}

func results(t *testing.T, doc map[string]any) []any {
	t.Helper()
	rs, _ := firstRun(t, doc)["results"].([]any)
	return rs
}

func TestSARIFDocumentShape(t *testing.T) {
	notes := []module.Note{{
		Title: "aws …MPLE (from .env: AWS_ACCESS_KEY_ID)", Module: "aws", File: ".env", Line: 3,
		Summary:  "prod account",
		Findings: []module.Finding{{Key: "identity", Value: "arn:aws:iam::1:user/x", Flag: module.FlagInfo}},
	}}
	doc := parseSARIF(t, SARIF(notes, score.Context{}, "1.8.0"))

	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if _, ok := doc["$schema"].(string); !ok {
		t.Error("$schema missing")
	}
	driver := firstRun(t, doc)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "geiger" || driver["version"] != "1.8.0" {
		t.Errorf("driver = %v", driver)
	}
	rs := results(t, doc)
	if len(rs) != 1 {
		t.Fatalf("want 1 result, got %d", len(rs))
	}
	r := rs[0].(map[string]any)
	if r["ruleId"] != "aws" {
		t.Errorf("ruleId = %v", r["ruleId"])
	}
	loc := r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if got := loc["artifactLocation"].(map[string]any)["uri"]; got != ".env" {
		t.Errorf("uri = %v, want the relative path unchanged", got)
	}
	if got := loc["region"].(map[string]any)["startLine"]; got != float64(3) {
		t.Errorf("startLine = %v", got)
	}
}

// SARIF has four levels and geiger has six tiers, so level is lossy by
// construction — the real tier and score must survive in properties.
func TestSARIFLevelMappingAndTierPreserved(t *testing.T) {
	cases := []struct {
		name      string
		note      module.Note
		wantLevel string
		wantTier  score.Tier
	}{
		{"dead", module.Note{Module: "jwt", Invalid: true, Reason: "expired"}, "none", score.TierDead},
		{"force multiplier floors at high", module.Note{Module: "aws", Findings: []module.Finding{
			{Key: "admin", Value: "yes", Flag: module.FlagForceMultiplier},
		}}, "error", score.TierHigh},
		{"info", module.Note{Module: "x", Findings: []module.Finding{
			{Key: "a", Value: "b", Flag: module.FlagInfo},
		}}, "note", score.TierInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := parseSARIF(t, SARIF([]module.Note{tc.note}, score.Context{}, "v"))
			r := results(t, doc)[0].(map[string]any)
			if r["level"] != tc.wantLevel {
				t.Errorf("level = %v, want %s", r["level"], tc.wantLevel)
			}
			props := r["properties"].(map[string]any)
			if got := score.TierFor(tc.note, score.Context{}); got != tc.wantTier {
				t.Fatalf("test premise wrong: tier is %s, expected %s", got, tc.wantTier)
			}
			if props["tier"] != string(tc.wantTier) {
				t.Errorf("properties.tier = %v, want %s", props["tier"], tc.wantTier)
			}
			if _, ok := props["score"]; !ok {
				t.Error("properties.score missing")
			}
		})
	}
}

// Every result points at a rule in the table, and a credential type appearing
// many times contributes one rule — a viewer groups by rule.
func TestSARIFRulesAreDedupedAndIndexed(t *testing.T) {
	notes := []module.Note{
		{Module: "aws", Title: "a"}, {Module: "github", Title: "b"}, {Module: "aws", Title: "c"},
	}
	doc := parseSARIF(t, SARIF(notes, score.Context{}, "v"))
	driver := firstRun(t, doc)["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules for 3 results, got %d", len(rules))
	}
	for _, raw := range results(t, doc) {
		r := raw.(map[string]any)
		idx := int(r["ruleIndex"].(float64))
		if idx < 0 || idx >= len(rules) {
			t.Fatalf("ruleIndex %d out of range", idx)
		}
		if got := rules[idx].(map[string]any)["id"]; got != r["ruleId"] {
			t.Errorf("ruleIndex %d points at %v, but ruleId is %v", idx, got, r["ruleId"])
		}
	}
}

// Force multipliers are the named high-impact capabilities; a viewer should be
// able to read what a credential unlocks without walking every finding.
func TestSARIFCapabilitiesListed(t *testing.T) {
	n := module.Note{Module: "aws", Findings: []module.Finding{
		{Key: "secrets manager", Value: "readable", Flag: module.FlagForceMultiplier},
		{Key: "region", Value: "us-east-1", Flag: module.FlagInfo},
		{Key: "iam admin", Value: "yes", Flag: module.FlagForceMultiplier},
	}}
	doc := parseSARIF(t, SARIF([]module.Note{n}, score.Context{}, "v"))
	props := results(t, doc)[0].(map[string]any)["properties"].(map[string]any)
	caps, ok := props["capabilities"].([]any)
	if !ok || len(caps) != 2 {
		t.Fatalf("capabilities = %v, want the 2 force multipliers", props["capabilities"])
	}
	if caps[0] != "secrets manager" || caps[1] != "iam admin" {
		t.Errorf("capabilities = %v", caps)
	}
	if len(props["findings"].([]any)) != 3 {
		t.Error("all findings should still be carried")
	}
}

// A bare absolute path is not a URI; code-scanning consumers reject or mis-root
// it. URLs pass through, relative paths stay relative.
func TestSARIFArtifactURIForms(t *testing.T) {
	cases := []struct{ file, want string }{
		{".env", ".env"},
		{"./config/.env", "config/.env"},
		{"/home/u/.aws/credentials", "file:///home/u/.aws/credentials"},
		{"https://host/.env", "https://host/.env"},
		{"/tmp/host.tar.gz::home/.env", "file:///tmp/host.tar.gz::home/.env"},
	}
	for _, tc := range cases {
		doc := parseSARIF(t, SARIF([]module.Note{{Module: "m", File: tc.file}}, score.Context{}, "v"))
		r := results(t, doc)[0].(map[string]any)
		got := r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
		if got != tc.want {
			t.Errorf("%s -> %v, want %s", tc.file, got, tc.want)
		}
	}
}

// A note with no source (an env or harvested credential) still has to produce a
// valid result — SARIF allows a result with no location, but not a broken one.
func TestSARIFResultWithoutLocation(t *testing.T) {
	doc := parseSARIF(t, SARIF([]module.Note{{Module: "m", Title: "t"}}, score.Context{}, "v"))
	r := results(t, doc)[0].(map[string]any)
	if _, ok := r["locations"]; ok {
		t.Errorf("expected no locations key, got %v", r["locations"])
	}
	if r["ruleId"] != "m" {
		t.Errorf("ruleId = %v", r["ruleId"])
	}
}

func TestSARIFEmptyRunIsValid(t *testing.T) {
	s := SARIF(nil, score.Context{}, "v")
	doc := parseSARIF(t, s)
	if len(results(t, doc)) != 0 {
		t.Error("want no results")
	}
	// Empty collections must serialize as [] rather than null: a consumer that
	// iterates results without a nil check should not break on a clean scan.
	if !strings.Contains(s, `"results":[]`) || !strings.Contains(s, `"rules":[]`) {
		t.Errorf("empty arrays should not serialize as null: %s", s)
	}
}
