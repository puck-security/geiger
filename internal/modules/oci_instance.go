package modules

import (
	"context"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// ociInstancePrincipal flags an OCI instance-principal certificate (harvested from
// the metadata service). The cert+key federate to an OCI security token for the
// instance's dynamic-group policies; geiger reports the instance OCID from the
// cert. Full federation/reach is a follow-on.
type ociInstancePrincipal struct{ module.Base }

func (ociInstancePrincipal) Name() string { return "oci_instance_principal" }

func (ociInstancePrincipal) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	return []module.Finding{{Key: "oci instance principal",
		Value: f["instance"] + " — can federate to an OCI security token for its dynamic-group policies (full reach is a follow-on)",
		Flag:  module.FlagForceMultiplier}}, nil
}

func (ociInstancePrincipal) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "OCI instance principal"}
}

func recognizeOCIInstance(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	p := b.Vars["OCI_INSTANCE_PRINCIPAL"]
	if !strings.HasPrefix(p, "ocid1.") {
		return nil
	}
	return []recognize.Match{{
		Module: "oci_instance_principal",
		Fields: module.Fields{"instance": p},
		Secret: p, // the OCID — used as the dedup key (identifier, not sensitive)
		Label:  "oci instance principal",
	}}
}

func init() {
	module.Register(ociInstancePrincipal{})
	recognize.RegisterRecognizer(recognizeOCIInstance)
}
