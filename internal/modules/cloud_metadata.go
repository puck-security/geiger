package modules

import (
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// These recognizers route credentials harvested from a cloud metadata service
// (via --metadata, which synthesizes a dotenv blob) to the module that already
// knows how to characterize that shape — no new module needed. They also fire on a
// real env var of the same name (e.g. a GCP/Azure access token left in the
// environment), which is the desired behavior.

// recognizeAzureToken routes a bare Azure access token (a JWT — e.g. a managed-
// identity token) to azure_msal, whose Recon characterizes it from the access
// token alone (offline decode + Graph/ARM with the bearer).
func recognizeAzureToken(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	at := b.Vars["AZURE_ACCESS_TOKEN"]
	if at == "" || !strings.HasPrefix(at, "eyJ") {
		return nil
	}
	return []recognize.Match{{
		Module: "azure_msal",
		Fields: module.Fields{"access_token": at},
		Secret: at,
		Label:  "azure managed-identity token",
	}}
}

// recognizeK8sInCluster routes an in-cluster service-account token (apiserver +
// bearer + CA, harvested by --metadata) to the kubeconfig module, reusing its live
// RBAC recon (k8sRecon, gated on --live --intrusive).
func recognizeK8sInCluster(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	server, token := b.Vars["KUBERNETES_SERVER"], b.Vars["KUBERNETES_SA_TOKEN"]
	if server == "" || token == "" {
		return nil
	}
	return []recognize.Match{{
		Module: "kubeconfig",
		Fields: module.Fields{"server": server, "token": token, "ca_data": b.Vars["KUBERNETES_CA_DATA"], "context": "in-cluster"},
		Secret: token,
		Label:  "kubernetes in-cluster SA",
	}}
}

func init() {
	recognize.RegisterRecognizer(recognizeAzureToken)
	recognize.RegisterRecognizer(recognizeK8sInCluster)
}
