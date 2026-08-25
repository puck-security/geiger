package modules

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// A Google OAuth client secret has no self-validating shape and no vendor
// endpoint that answers "is this key good?", so it used to fall through to
// generic_secret. It IS testable, without minting anything: POST the client id
// and secret to the token endpoint with a refresh token that is junk by
// construction. Google authenticates the client BEFORE it looks at the grant,
// so the error code separates the two failures:
//
//	invalid_grant    the pair authenticated; only the junk token was rejected  → live
//	invalid_client   the client id is unknown, or the secret is wrong          → dead
//
// The probe never yields an access token, and no user is signed in.
type googleOAuthClient struct{ module.Base }

func (googleOAuthClient) Name() string { return "google_oauth_client" }

// googleProbeToken is the sentinel refresh token. It carries Google's "1//"
// refresh-token shape so the request reaches the grant check rather than an
// earlier parse error, and is self-evidently not a real token.
const googleProbeToken = "1//0gGEIGERprobeINVALIDrefreshtoken"

// Findings whose key Summarize reads as a verdict. Counting findings would not
// work here: a rejection and a success are both exactly one finding.
const (
	googleValid      = "client secret"
	googleRejected   = "rejected"
	googleUnverified = "unverified"
	googlePublished  = "published client"
)

func (googleOAuthClient) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	id, secret := f["client_id"], f["client_secret"]
	if id == "" {
		// Still state the reach: naming the missing input without saying what is
		// at stake gives a responder no reason to go and find the client id. The
		// note stays UNKNOWN, so the claim buys no severity it did not earn.
		return append([]module.Finding{{Key: googleUnverified,
			Value: "no client id alongside the secret — a client secret cannot be tested on its own; supply the client id for the same app (it ends .apps.googleusercontent.com) and re-run",
			Flag:  cantFlag}}, googleContext("", f["client_type"], false)...), nil
	}

	// gcloud's own client pair ships in the SDK, so it grants nothing and every
	// ADC file carries it. That is knowable without a call, and making one would
	// spend a request and an OPSEC footprint to confirm something already public.
	// It is still named rather than dropped: staying silent hands the value to
	// generic_secret, which reports it as an unrecognized credential.
	if id == gcloudClientID {
		return googleContext(id, f["client_type"], true), nil
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	form.Set("refresh_token", googleProbeToken)

	req, err := recon.NewRequest(ctx, http.MethodPost, gcpEndpoints.Token, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true,
		Note: "client-secret validation — deliberately invalid refresh token, mints no access token"})

	var verdict module.Finding
	switch {
	case err != nil:
		// A transport failure proves nothing. Reporting it as dead would retire
		// a live secret.
		verdict = module.Finding{Key: googleUnverified,
			Value: "could not reach Google's token endpoint: " + err.Error(), Flag: cantFlag}
	case resp.DryRun:
		verdict = module.Finding{Key: googleUnverified,
			Value: "not probed (dry-run) — re-run with --live to test the pair", Flag: cantFlag}
	default:
		verdict = googleVerdict(resp.Body, resp.Status)
	}
	out := []module.Finding{verdict}
	if verdict.Key == googleRejected {
		return out, nil
	}
	return append(out, googleContext(id, f["client_type"], false)...), nil
}

// googleVerdict reads the token endpoint's answer. It keys on the OAuth error
// CODE, never on error_description: the description is Google's prose and may be
// reworded, and wording drift must not turn a live secret into a dead one. Any
// code it does not recognize is unverified, not rejected.
func googleVerdict(body []byte, status int) module.Finding {
	switch jsonField(body, "error") {
	case "invalid_grant":
		return module.Finding{Key: googleValid,
			Value: "valid — Google accepted this client id and secret (only the probe's junk refresh token was refused)",
			Flag:  module.FlagWarn}
	case "invalid_client":
		if strings.Contains(jsonField(body, "error_description"), "not found") {
			return module.Finding{Key: googleRejected,
				Value: "the OAuth client was not found — it was deleted, or this client id is wrong", Flag: module.FlagInfo}
		}
		return module.Finding{Key: googleRejected,
			Value: "Google refused the client secret — it was rotated, or it does not belong to this client id", Flag: module.FlagInfo}
	case "":
		if status >= 200 && status < 300 {
			// Unreachable by design: the sentinel refresh token cannot be
			// redeemed. If it ever happens, the pair is live beyond doubt.
			return module.Finding{Key: googleValid,
				Value: "valid — the token endpoint returned a grant", Flag: module.FlagWarn}
		}
	}
	return module.Finding{Key: googleUnverified,
		Value: "the token endpoint gave an answer geiger does not recognize (HTTP " + strconv.Itoa(status) + ") — nothing was proved either way",
		Flag:  cantFlag}
}

// googleContext describes what the pair reaches. None of it needs a call.
func googleContext(id, clientType string, public bool) []module.Finding {
	var out []module.Finding
	if public {
		out = append(out, module.Finding{Key: googlePublished,
			Value: "gcloud's own OAuth client, published in the Google Cloud SDK — public by design, and it grants nothing on its own; not probed, because there is nothing to test",
			Flag:  module.FlagInfo})
	} else {
		out = append(out, module.Finding{Key: "reach",
			Value: "redeems any refresh token or authorization code ever issued to this app — including tokens sitting elsewhere in this dump — and drives the app's own consent screen, which shows its real verified name",
			Flag:  module.FlagForceMultiplier})
	}
	if p := googleProjectNumber(id); p != "" {
		// FlagNone: a project number is an identifier, not a count of things
		// reached. Any other flag lets the scorer read it as blast radius and
		// inflate the tier by the width of the number.
		out = append(out, module.Finding{Key: "gcp project", Value: p, Flag: module.FlagNone})
	}
	switch clientType {
	case "web":
		out = append(out, module.Finding{Key: "client type",
			Value: "web application client — Google treats this secret as confidential", Flag: module.FlagWarn})
	case "installed":
		out = append(out, module.Finding{Key: "client type",
			Value: "desktop/installed client — Google does not classify this secret as confidential, because it ships inside the app; it still authorizes the token exchange",
			Flag:  module.FlagInfo})
	}
	return out
}

func (googleOAuthClient) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title}
	summary := "Google OAuth client secret — valid; redeems this app's tokens"
	kept := fs[:0:0]
	for _, f := range fs {
		// The verdict keys are a channel from Recon, not output. The renderer
		// prints Reason itself, so keeping them as findings too would put the
		// same sentence on screen twice.
		switch f.Key {
		case googleRejected:
			n.Invalid, n.Reason = true, f.Value
			continue
		case googleUnverified:
			n.Undetermined, n.Reason = true, f.Value
			summary = "Google OAuth client secret — not verified"
			continue
		case googlePublished:
			summary = "gcloud's published OAuth client — public, not a credential"
		}
		kept = append(kept, f)
	}
	n.Findings = kept
	// A rejected secret reaches nothing, so it gets a reason and no summary.
	if !n.Invalid {
		n.Summary = summary
	}
	return n
}

// --- recognition ---

// Client ids are "<project number>-<hash>.apps.googleusercontent.com"; Google's
// own first-party clients drop the hash.
var googleClientIDRe = regexp.MustCompile(`\b\d{6,}(?:-[a-z0-9_]+)?\.apps\.googleusercontent\.com\b`)

// Secrets minted since ~2021 carry this prefix. Older ones are a bare ~24-char
// string with no shape at all, which is why they need the client id as an anchor.
var googleSecretRe = regexp.MustCompile(`GOCSPX-[A-Za-z0-9_-]{20,40}`)

// googleOwnedNameRe gates the legacy pairing in recognizeGoogleOAuthClient. The
// client id alone is NOT enough to pair with: a .env holding a Google client id
// and a Stripe key would otherwise send the Stripe key to Google's token
// endpoint. Requiring the secret's variable name to say "google" keeps one
// vendor's credential out of another vendor's API.
var googleOwnedNameRe = regexp.MustCompile(`(?i)goog|gcp|gsuite|gworkspace`)

// googleProjectNumber pulls the GCP project number off the front of a client id.
func googleProjectNumber(id string) string {
	for i, r := range id {
		if r >= '0' && r <= '9' {
			continue
		}
		if (r == '-' || r == '.') && i > 0 {
			return id[:i]
		}
		return ""
	}
	return ""
}

func recognizeGoogleOAuthClient(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	// gcp_adc and gcp_service_account own these files and test them with the
	// real credential they carry. Claiming their client_secret as well would
	// probe the same app twice and report it under two modules.
	if b.JSON != nil {
		switch t, _ := b.JSON["type"].(string); t {
		case "authorized_user", "service_account", "external_account", "impersonated_service_account":
			return nil
		}
	}

	// A client_secret_*.json downloaded from the Cloud Console. Highest
	// confidence, and the wrapper key names the client type.
	if m, ok := googleClientSecretFile(b); ok {
		return []recognize.Match{m}
	}

	id := googleClientIDRe.FindString(b.Raw)
	var out []recognize.Match
	seen := map[string]bool{}
	emit := func(secret, label string) {
		if secret == "" || seen[secret] {
			return
		}
		seen[secret] = true
		out = append(out, recognize.Match{
			Module: "google_oauth_client",
			Fields: module.Fields{"client_id": id, "client_secret": secret},
			Secret: secret,
			Label:  label,
			Line:   b.Lines[label],
		})
	}

	// Prefixed secrets stand on their own, with or without a client id.
	for _, s := range googleSecretRe.FindAllString(b.Raw, -1) {
		emit(s, googleVarNamed(b, s))
	}
	// Unprefixed legacy secrets are only recognizable next to a client id, and
	// only when their own variable name claims them for Google.
	if id != "" {
		for name, v := range b.Vars {
			if !googleOwnedNameRe.MatchString(name) || !secretNameRe.MatchString(name) || notSecretNameRe.MatchString(name) {
				continue
			}
			if valueLooksSecret(v) {
				emit(v, name)
			}
		}
	}
	return out
}

// googleClientSecretFile matches the Cloud Console download shape:
// {"web"|"installed": {"client_id": …, "client_secret": …}}.
func googleClientSecretFile(b parse.Blob) (recognize.Match, bool) {
	for _, kind := range []string{"web", "installed"} {
		o, ok := b.JSON[kind].(map[string]any)
		if !ok {
			continue
		}
		id, _ := o["client_id"].(string)
		secret, _ := o["client_secret"].(string)
		if id == "" || secret == "" {
			continue
		}
		return recognize.Match{
			Module: "google_oauth_client",
			Fields: module.Fields{"client_id": id, "client_secret": secret, "client_type": kind},
			Secret: secret,
			Label:  "Google OAuth client (" + kind + ")",
		}, true
	}
	return recognize.Match{}, false
}

// googleVarNamed returns the variable name holding secret, for a friendlier
// label, falling back to a generic one.
func googleVarNamed(b parse.Blob, secret string) string {
	for k, v := range b.Vars {
		if v == secret {
			return k
		}
	}
	return "GOOGLE_CLIENT_SECRET"
}

func init() {
	module.Register(googleOAuthClient{})
	recognize.RegisterRecognizer(recognizeGoogleOAuthClient)
}
