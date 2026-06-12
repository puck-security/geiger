package modules

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// gcpUserinfo is overridable in tests.
var gcpUserinfo = "https://openidconnect.googleapis.com/v1/userinfo"

// gcpADC triages a gcloud Application Default Credentials file
// (~/.config/gcloud/application_default_credentials.json, type=authorized_user):
// a user's refresh token. Authenticate exchanges it for an access token; recon
// reports the user identity and reachable projects.
type gcpADC struct{}

func (gcpADC) Name() string { return "gcp_adc" }

func (gcpADC) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	// Redeeming the user refresh token is an active sign-in (audit-logged, may
	// rotate the token), so it's gated behind --intrusive; --min-footprint never
	// refreshes. An ADC file carries no cached access token, so plain --live
	// characterizes it from the file alone.
	if c.Intrusive() && !c.MinFootprint() {
		return auth.RefreshToken(ctx, c, gcpEndpoints.Token, f["client_id"], f["client_secret"], f["refresh_token"], url.Values{})
	}
	return module.Token{}, nil
}

func (gcpADC) Recon(ctx context.Context, c *recon.Client, t module.Token, f module.Fields) ([]module.Finding, error) {
	// The refresh token is the exposure: it re-mints a live access token headlessly.
	out := []module.Finding{{Key: "refresh token",
		Value: "gcloud user refresh token — headlessly re-mintable into a live access token; revoke it (gcloud auth application-default revoke)",
		Flag:  module.FlagForceMultiplier}}

	if t.Bearer == "" {
		// Live reach needs the refresh token redeemed (an active token grant) —
		// gated behind --intrusive.
		if c.Live() && !c.Intrusive() && !c.MinFootprint() {
			out = append(out, module.Finding{Key: "deepen",
				Value: "re-run with --intrusive to redeem the refresh token and map identity + reachable projects (this performs a token grant)",
				Flag:  cantFlag})
		}
		return out, nil
	}

	if s := t.Extra["scope"]; s != "" {
		out = append(out, module.Finding{Key: "granted scopes", Value: s, Flag: module.FlagInfo})
	}

	req, _ := recon.NewRequest(ctx, http.MethodGet, gcpUserinfo, nil)
	req.Header.Set("Authorization", "Bearer "+t.Bearer)
	if resp, err := c.Do(req, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
		if email := jsonField(resp.Body, "email"); email != "" {
			out = append(out, module.Finding{Key: "user", Value: email, Flag: module.FlagInfo})
		}
	}

	if !c.MinFootprint() {
		req, _ := recon.NewRequest(ctx, http.MethodGet, gcpEndpoints.ResourceManager, nil)
		req.Header.Set("Authorization", "Bearer "+t.Bearer)
		if resp, err := c.Do(req, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
			if projs, ok := jsonDecode(resp.Body)["projects"].([]any); ok {
				out = append(out, module.Finding{Key: "reachable projects", Value: strconv.Itoa(len(projs)), Flag: module.FlagInfo})
			}
		}
	}
	return out, nil
}

// Harvest drains Secret Manager across every project the user token can reach
// (gated on --live --intrusive).
func (gcpADC) Harvest(ctx context.Context, c *recon.Client, t module.Token, _ module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	return gcpHarvestSecrets(ctx, c, t.Bearer, gcpProjectIDs(ctx, c, t.Bearer)), nil
}

func (gcpADC) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "refresh-token exchange failed (revoked or expired)"
		return n
	}
	n.Summary = "gcloud user credentials — delegated user access"
	return n
}

func recognizeGCPADC(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	if t, _ := b.JSON["type"].(string); t != "authorized_user" {
		return nil
	}
	rt, _ := b.JSON["refresh_token"].(string)
	cid, _ := b.JSON["client_id"].(string)
	csec, _ := b.JSON["client_secret"].(string)
	if rt == "" || cid == "" {
		return nil
	}
	return []recognize.Match{{
		Module: "gcp_adc",
		Fields: module.Fields{"refresh_token": rt, "client_id": cid, "client_secret": csec},
		Secret: rt,
		Label:  "gcloud ADC",
	}}
}

func init() {
	module.Register(gcpADC{})
	recognize.RegisterRecognizer(recognizeGCPADC)
}
