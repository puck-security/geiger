package modules

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/sign"
)

// gcpEndpoints are overridable in tests.
var gcpEndpoints = struct{ Token, ResourceManager, Storage, SecretManager string }{
	Token:           "https://oauth2.googleapis.com/token",
	ResourceManager: "https://cloudresourcemanager.googleapis.com/v1/projects",
	Storage:         "https://storage.googleapis.com/storage/v1/b",
	SecretManager:   "https://secretmanager.googleapis.com/v1",
}

// gcpServiceAccount handles a service-account JSON key. Authenticate mints a
// read-only access token via the jwt-bearer grant; recon lists reachable
// projects and buckets.
type gcpServiceAccount struct{}

func (gcpServiceAccount) Name() string { return "gcp_service_account" }

func (gcpServiceAccount) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	assertion, err := sign.RS256Assertion([]byte(f["private_key"]), f["private_key_id"], map[string]any{
		"iss":   f["client_email"],
		"scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
		"aud":   gcpEndpoints.Token,
	}, 0)
	if err != nil {
		return module.Token{}, err
	}
	return auth.JWTBearer(ctx, c, gcpEndpoints.Token, assertion, url.Values{})
}

func (gcpServiceAccount) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding
	if email := f["client_email"]; email != "" {
		out = append(out, module.Finding{Key: "service account", Value: email, Flag: module.FlagInfo})
	}
	if proj := f["project_id"]; proj != "" {
		flag := module.FlagInfo
		if isProd(proj) {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "project", Value: proj, Flag: flag})
	}

	if c.MinFootprint() {
		return out, nil
	}

	// reachable projects
	req, _ := recon.NewRequest(ctx, http.MethodGet, gcpEndpoints.ResourceManager, nil)
	req.Header.Set("Authorization", "Bearer "+t.Bearer)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil {
		return out, nil
	}
	if !resp.DryRun && resp.Status < 300 {
		d := jsonDecode(resp.Body)
		if projs, ok := d["projects"].([]any); ok {
			out = append(out, module.Finding{Key: "reachable projects", Value: strconv.Itoa(len(projs)), Flag: module.FlagInfo})
		}
	}

	// buckets in the SA's own project
	if proj := f["project_id"]; proj != "" {
		burl := gcpEndpoints.Storage + "?project=" + url.QueryEscape(proj)
		breq, _ := recon.NewRequest(ctx, http.MethodGet, burl, nil)
		breq.Header.Set("Authorization", "Bearer "+t.Bearer)
		bresp, err := c.Do(breq, recon.CallOpts{})
		if err == nil && !bresp.DryRun && bresp.Status < 300 {
			d := jsonDecode(bresp.Body)
			if items, ok := d["items"].([]any); ok {
				names := make([]string, 0, len(items))
				for _, it := range items {
					if m, ok := it.(map[string]any); ok {
						if n, ok := m["name"].(string); ok {
							names = append(names, n)
						}
					}
				}
				flag := module.FlagInfo
				val := strconv.Itoa(len(names)) + " visible"
				if sens := sensitiveNames(names); sens != "" {
					flag, val = module.FlagWarn, val+" — incl. "+sens
				}
				out = append(out, module.Finding{Key: "buckets", Value: val, Flag: flag})
			}
		}
	}
	return out, nil
}

// Harvest drains Secret Manager across the SA's project plus any other
// reachable projects (gated on --live --intrusive).
func (gcpServiceAccount) Harvest(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	projects := []string{f["project_id"]}
	projects = append(projects, gcpProjectIDs(ctx, c, t.Bearer)...)
	return gcpHarvestSecrets(ctx, c, t.Bearer, projects), nil
}

func (gcpServiceAccount) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "token exchange or recon failed"
		return n
	}
	n.Summary = "GCP service account — exchanged a read-only token"
	return n
}

func recognizeGCPSA(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	if t, _ := b.JSON["type"].(string); t != "service_account" {
		return nil
	}
	pk, _ := b.JSON["private_key"].(string)
	email, _ := b.JSON["client_email"].(string)
	if pk == "" || email == "" {
		return nil
	}
	kid, _ := b.JSON["private_key_id"].(string)
	proj, _ := b.JSON["project_id"].(string)
	return []recognize.Match{{
		Module: "gcp_service_account",
		Fields: module.Fields{
			"private_key": pk, "private_key_id": kid,
			"client_email": email, "project_id": proj,
		},
		Secret: strings.TrimSpace(kid),
		Label:  email,
	}}
}

func init() {
	module.Register(gcpServiceAccount{})
	recognize.RegisterRecognizer(recognizeGCPSA)
}
