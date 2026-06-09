package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// vaultLike recognizes VAULT_FAKE and harvests one downstream secret whose value
// is a token recognized by a second module.
type vaultLike struct{ module.Base }

func (vaultLike) Name() string { return "vault_fake" }
func (vaultLike) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{{Key: "policies", Value: "root", Flag: module.FlagForceMultiplier}}, nil
}
func (vaultLike) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs}
}
func (vaultLike) Harvest(_ context.Context, c *recon.Client, _ module.Token, _ module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	return []module.Harvested{{Label: "secret/db", Value: "DOWNSTREAM_TOKEN_abc123xyz4567"}}, nil
}

type downstream struct{ module.Base }

func (downstream) Name() string { return "downstream_fake" }
func (downstream) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{{Key: "id", Value: "child-cred"}}, nil
}
func (downstream) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs}
}

func harvestReg() *module.Registry {
	reg := module.NewRegistry()
	reg.Register(vaultLike{})
	reg.Register(downstream{})
	return reg
}

func init() {
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["VAULT_FAKE"]; v != "" {
			return []recognize.Match{{Module: "vault_fake", Fields: module.Fields{"token": v}, Secret: v, Label: "VAULT_FAKE"}}
		}
		if strings.Contains(b.Raw, "DOWNSTREAM_TOKEN_") {
			return []recognize.Match{{Module: "downstream_fake", Fields: module.Fields{"token": b.Raw}, Secret: b.Raw, Label: "harvested"}}
		}
		return nil
	})
}

func TestHarvestRecursesWhenIntrusive(t *testing.T) {
	b := parse.Parse("VAULT_FAKE=hvs.rootrootroot12345\n", ".env")
	results := Run(b, harvestReg(), Options{Live: true, Intrusive: true})

	var parent, child bool
	for _, r := range results {
		if strings.Contains(r.Note.Title, "vault_fake") {
			parent = true
		}
		if strings.Contains(r.Note.Title, "downstream_fake") {
			child = true
			if !strings.Contains(r.Note.Title, "harvested via") {
				t.Errorf("child not attributed to harvest: %q", r.Note.Title)
			}
		}
	}
	if !parent || !child {
		t.Fatalf("expected parent and harvested child; parent=%v child=%v (%d results)", parent, child, len(results))
	}
}

func TestHarvestGatedOffWithoutIntrusive(t *testing.T) {
	b := parse.Parse("VAULT_FAKE=hvs.rootrootroot12345\n", ".env")
	results := Run(b, harvestReg(), Options{Live: true, Intrusive: false})
	for _, r := range results {
		if strings.Contains(r.Note.Title, "downstream_fake") {
			t.Errorf("harvest must not run without --intrusive")
		}
	}
}
