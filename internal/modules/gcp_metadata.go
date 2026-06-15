package modules

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// gcpMetadata triages a bare GCP OAuth access token (ya29.…) — e.g. an instance
// service-account token pulled from the metadata server. Unlike gcp_adc (refresh
// token) or gcp_service_account (key), the token is already minted, so there is no
// Authenticate exchange (module.Base's no-op); recon reports identity + reach.
type gcpMetadata struct{ module.Base }

func (gcpMetadata) Name() string { return "gcp_metadata" }

func (gcpMetadata) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding
	if email := f["email"]; email != "" {
		out = append(out, module.Finding{Key: "service account", Value: email, Flag: module.FlagInfo})
	}
	if sc := f["scopes"]; sc != "" {
		flag := module.FlagInfo
		if strings.Contains(sc, "cloud-platform") { // the broad "all APIs" scope
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "scopes", Value: sc, Flag: flag})
	}
	bearer := f["access_token"]
	if bearer == "" || !c.Live() {
		return out, nil
	}
	if email := gcpTokenUserinfo(ctx, c, bearer); email != "" {
		out = append(out, module.Finding{Key: "identity", Value: email, Flag: module.FlagInfo})
	}
	if !c.MinFootprint() {
		if n, ok := gcpTokenProjects(ctx, c, bearer); ok {
			out = append(out, module.Finding{Key: "reachable projects", Value: strconv.Itoa(n), Flag: module.FlagInfo})
		}
	}
	return out, nil
}

func gcpTokenUserinfo(ctx context.Context, c *recon.Client, bearer string) string {
	req, _ := recon.NewRequest(ctx, http.MethodGet, gcpUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	return jsonField(resp.Body, "email")
}

func gcpTokenProjects(ctx context.Context, c *recon.Client, bearer string) (int, bool) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, gcpEndpoints.ResourceManager, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return 0, false
	}
	if projs, ok := jsonDecode(resp.Body)["projects"].([]any); ok {
		return len(projs), true
	}
	return 0, false
}

func (gcpMetadata) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "GCP access token rejected (expired or revoked)"
		return n
	}
	n.Summary = "GCP instance service account — token-scoped reach"
	return n
}

func recognizeGCPMetadata(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	at := b.Vars["GOOGLE_OAUTH_ACCESS_TOKEN"]
	if at == "" || !strings.HasPrefix(at, "ya29.") {
		return nil
	}
	return []recognize.Match{{
		Module: "gcp_metadata",
		Fields: module.Fields{"access_token": at, "email": b.Vars["GCP_SA_EMAIL"], "scopes": b.Vars["GCP_SCOPES"]},
		Secret: at,
		Label:  "gcp metadata token",
	}}
}

func init() {
	module.Register(gcpMetadata{})
	recognize.RegisterRecognizer(recognizeGCPMetadata)
}
