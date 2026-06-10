package modules

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/puck-security/geiger/internal/dbrecon"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// AI-native IDEs (Cursor, VS Code + extensions) keep OAuth tokens and API keys
// in a plaintext SQLite key/value store, state.vscdb (ItemTable), with no
// isolation between extensions and secrets — reintroducing the failure mode the
// browser world spent a decade fixing. geiger recognizes the store and, under
// --live --intrusive, reads its credential keys and re-triages the plaintext
// tokens through their real provider modules. No OS-keychain decryption.

func init() {
	module.Register(aiIDEStore{})
	recognize.RegisterRecognizer(recognizeVSCDB)
}

// recognizeVSCDB matches a VS Code / Cursor state.vscdb. It requires the SQLite
// magic header in the bytes the walker actually read, so a crafted scanner-import
// finding (whose Raw is a secret string, not a real on-disk SQLite) can't steer
// an --intrusive read at an arbitrary host path.
func recognizeVSCDB(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.HasSuffix(strings.ToLower(b.File), ".vscdb") {
		return nil
	}
	if !strings.HasPrefix(b.Raw, "SQLite format 3") {
		return nil
	}
	return []recognize.Match{{
		Module: "ai_ide_store",
		Fields: module.Fields{"path": b.File},
		Label:  "ide token store [" + filepath.Base(b.File) + "]",
	}}
}

type aiIDEStore struct{ module.Base }

func (aiIDEStore) Name() string { return "ai_ide_store" }

func (aiIDEStore) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	if !c.Live() || !c.Intrusive() {
		return []module.Finding{{Key: "token store",
			Value: "AI-IDE plaintext SQLite (Cursor/VS Code state.vscdb) — read its credential keys with --live --intrusive",
			Flag:  cantFlag}}, nil
	}
	findings, _, err := dbrecon.ReconVSCDBFile(ctx, f["path"])
	if err != nil {
		return []module.Finding{{Key: "token store", Value: "not read: " + dbErr(err, f["path"]), Flag: infoFlag}}, nil
	}
	return findings, nil
}

// Harvest extracts the plaintext token values so the pipeline re-triages each
// through its provider module. Gated --live --intrusive by the pipeline.
func (aiIDEStore) Harvest(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	_, kv, err := dbrecon.ReconVSCDBFile(ctx, f["path"])
	if err != nil {
		return nil, nil
	}
	var out []module.Harvested
	for _, s := range kv {
		out = append(out, module.Harvested{Label: "vscdb:" + s.Key, Value: s.Value})
	}
	return out, nil
}

func (aiIDEStore) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "AI-IDE token store (plaintext SQLite)"}
}
