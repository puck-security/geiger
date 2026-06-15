package modules

import (
	"context"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// alibaba flags an Alibaba Cloud RAM credential (LTAI… access key, frequently an
// instance STS credential from the metadata service). geiger doesn't yet sign
// Alibaba's RPC API, so reach enumeration (sts:GetCallerIdentity) is a follow-on —
// the live credential is itself the high-blast-radius signal.
type alibaba struct{ module.Base }

func (alibaba) Name() string { return "alibaba" }

func (alibaba) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{Key: "alibaba ram",
		Value: "live Alibaba Cloud RAM credential — RAM/ECS/OSS reach per the role's policy (Alibaba API signing not yet exercised)",
		Flag:  module.FlagForceMultiplier}}
	if f["security_token"] != "" {
		out = append(out, module.Finding{Key: "type", Value: "STS session credential (instance / assumed role)", Flag: module.FlagInfo})
	}
	return out, nil
}

func (alibaba) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "Alibaba Cloud RAM credential"}
}

func recognizeAlibaba(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	ak := b.Vars["ALIBABA_ACCESS_KEY_ID"]
	if ak == "" || !strings.HasPrefix(ak, "LTAI") {
		return nil
	}
	return []recognize.Match{{
		Module: "alibaba",
		Fields: module.Fields{"access_key": ak, "secret_key": b.Vars["ALIBABA_ACCESS_KEY_SECRET"], "security_token": b.Vars["ALIBABA_SECURITY_TOKEN"]},
		Secret: ak,
		Label:  "alibaba ram credential",
	}}
}

func init() {
	module.Register(alibaba{})
	recognize.RegisterRecognizer(recognizeAlibaba)
}
