package note

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/score"
)

// SARIF 2.1.0 export. NDJSON stays geiger's canonical machine format — this is
// an interop shape, so that blast-radius output lands in a triage UI a team
// already runs (Kingfisher's viewer imports SARIF) and in GitHub code scanning
// without a bespoke integration.
//
// SARIF's level enum has four values and geiger has six tiers, so level is a
// lossy projection and the real tier travels in properties alongside the score.
// A consumer that understands geiger reads properties; one that doesn't still
// gets a sensible severity.

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifText        `json:"shortDescription"`
	Properties       map[string]any   `json:"properties,omitempty"`
	DefaultConfig    *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel projects a tier onto SARIF's four-value enum. The tier itself is
// preserved in result properties, so this collapse loses nothing a geiger-aware
// consumer needs.
func sarifLevel(t score.Tier) string {
	switch t {
	case score.TierCritical, score.TierHigh:
		return "error"
	case score.TierMedium:
		return "warning"
	case score.TierLow, score.TierInfo:
		return "note"
	default: // dead
		return "none"
	}
}

// SARIF renders notes as one SARIF 2.1.0 document. Unlike the NDJSON path, which
// emits a line per note as it goes, SARIF is a single document with a rules
// table, so every note has to be in hand before anything is written.
func SARIF(notes []module.Note, ctx score.Context, version string) string {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "geiger",
			InformationURI: "https://github.com/puck-security/geiger",
			Version:        version,
			Rules:          []sarifRule{},
		}},
		Results: []sarifResult{},
	}
	ruleIndex := map[string]int{}

	for _, n := range notes {
		id := n.Module
		if id == "" {
			id = "unknown"
		}
		idx, ok := ruleIndex[id]
		if !ok {
			idx = len(run.Tool.Driver.Rules)
			ruleIndex[id] = idx
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               id,
				Name:             id,
				ShortDescription: sarifText{Text: "credential type: " + id},
			})
		}
		tier := score.TierFor(n, ctx)
		res := sarifResult{
			RuleID:     id,
			RuleIndex:  idx,
			Level:      sarifLevel(tier),
			Message:    sarifText{Text: sanitize(messageFor(n))},
			Properties: resultProperties(n, tier, ctx),
		}
		if loc := locationFor(n); loc != nil {
			res.Locations = []sarifLocation{*loc}
		}
		run.Results = append(run.Results, res)
	}

	out, err := json.Marshal(sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: []sarifRun{run}})
	if err != nil {
		return ""
	}
	return string(out)
}

// messageFor is the human-readable one-liner: the summary when there is one, the
// reason when the credential is dead, and the title as a fallback.
func messageFor(n module.Note) string {
	switch {
	case n.Invalid && n.Reason != "":
		return n.Title + " — " + n.Reason
	case n.Summary != "":
		return n.Title + " — " + n.Summary
	default:
		return n.Title
	}
}

// resultProperties carries everything SARIF's own schema has no room for: the
// real tier, the blast-radius score, and each finding with its flag — which is
// where reach, capabilities and the downstream chain already live.
func resultProperties(n module.Note, tier score.Tier, ctx score.Context) map[string]any {
	props := map[string]any{
		"tier":  string(tier),
		"score": score.BlastRadius(n, ctx),
	}
	if n.Invalid {
		props["invalid"] = true
	}
	if n.Reason != "" {
		props["reason"] = sanitize(n.Reason)
	}
	if n.Summary != "" {
		props["summary"] = sanitize(n.Summary)
	}
	findings := make([]map[string]any, 0, len(n.Findings))
	var capabilities []string
	for _, f := range n.Findings {
		jf := map[string]any{
			"key":   sanitize(f.Key),
			"value": sanitize(f.Value),
			"flag":  flagName(f.Flag),
		}
		if len(f.Detail) > 0 {
			det := make([]string, 0, len(f.Detail))
			for _, d := range f.Detail {
				det = append(det, sanitize(d))
			}
			jf["detail"] = det
		}
		findings = append(findings, jf)
		// A force multiplier is a named high-impact capability (admin, RCE,
		// secrets-store read); surfacing them as a flat list means a viewer can
		// show what the credential unlocks without walking every finding.
		if f.Flag == module.FlagForceMultiplier {
			capabilities = append(capabilities, sanitize(f.Key))
		}
	}
	props["findings"] = findings
	if len(capabilities) > 0 {
		props["capabilities"] = capabilities
	}
	return props
}

// locationFor maps a note's source to a SARIF artifact location. A source may be
// a path, a URL (a nuclei finding), an archive member, or a synthetic label like
// "environment"; SARIF wants a URI, so anything that isn't already one is
// encoded as a relative path rather than being dropped.
func locationFor(n module.Note) *sarifLocation {
	if n.File == "" {
		return nil
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: artifactURI(n.File)},
	}}
	if n.Line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: n.Line}
	}
	return &loc
}

func artifactURI(file string) string {
	if u, err := url.Parse(file); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return file // a nuclei finding already carries the URL it leaked from
	}
	clean := sanitize(strings.TrimPrefix(file, "./"))
	// A bare absolute path is not a URI. Code-scanning consumers reject or
	// mis-root it, so give it a scheme; a relative path is left alone, which is
	// what those consumers want when geiger runs at the repo root.
	if strings.HasPrefix(clean, "/") {
		return (&url.URL{Scheme: "file", Path: clean}).String()
	}
	return clean
}
