package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/score"
)

const (
	googleTestClientID = "123456789012-abcdefghijklmnop.apps.googleusercontent.com"
	googleTestSecret   = "GOCSPX-MjlfId78mAbCdEfGhIjKlMnOp"
	// A pre-2021 secret carries no prefix, so only its length and character mix
	// matter here. Keep the value visibly fake: gcloud's real published secret
	// would read as a live credential to anyone scanning this repo.
	googleLegacySecret = "NOTAREALlegacyGoogleSec0"
	// Another vendor's key, deliberately malformed. The underscores keep it clear
	// of Stripe's sk_live_[A-Za-z0-9]{24,} shape, which GitHub push protection
	// blocks. It still passes valueLooksSecret, so the test proves the variable
	// NAME gate rejects it, not the value heuristic.
	foreignSecret = "sk_live_NOT_A_REAL_STRIPE_KEY"
)

// --- recognition ---

func TestGoogleOAuthRecognizesPrefixedSecret(t *testing.T) {
	b := parse.Parse("GOOGLE_OAUTH_CLIENT_ID="+googleTestClientID+"\nGOOGLE_OAUTH_CLIENT_SECRET="+googleTestSecret+"\n", ".env")
	ms := recognizeGoogleOAuthClient(b, "", nil)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Module != "google_oauth_client" {
		t.Errorf("module = %q", ms[0].Module)
	}
	if ms[0].Fields["client_secret"] != googleTestSecret {
		t.Errorf("client_secret = %q", ms[0].Fields["client_secret"])
	}
	if ms[0].Fields["client_id"] != googleTestClientID {
		t.Errorf("client_id = %q", ms[0].Fields["client_id"])
	}
	if ms[0].Secret != googleTestSecret {
		t.Errorf("Secret = %q, want the client secret", ms[0].Secret)
	}
}

func TestGoogleOAuthRecognizesWebClientSecretJSON(t *testing.T) {
	raw := `{"web":{"client_id":"` + googleTestClientID + `","project_id":"acme-prod","client_secret":"` + googleTestSecret + `","redirect_uris":["https://acme.test/cb"]}}`
	ms := recognizeGoogleOAuthClient(parse.Parse(raw, "client_secret_123.json"), "", nil)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Fields["client_type"] != "web" {
		t.Errorf("client_type = %q, want web", ms[0].Fields["client_type"])
	}
	if ms[0].Fields["client_secret"] != googleTestSecret {
		t.Errorf("client_secret = %q", ms[0].Fields["client_secret"])
	}
}

func TestGoogleOAuthRecognizesInstalledClientSecretJSON(t *testing.T) {
	raw := `{"installed":{"client_id":"` + googleTestClientID + `","client_secret":"` + googleTestSecret + `"}}`
	ms := recognizeGoogleOAuthClient(parse.Parse(raw, "client_secret.json"), "", nil)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Fields["client_type"] != "installed" {
		t.Errorf("client_type = %q, want installed", ms[0].Fields["client_type"])
	}
}

// Client secrets minted before ~2021 carry no GOCSPX- prefix, so the
// *.apps.googleusercontent.com client id is the only anchor.
func TestGoogleOAuthRecognizesLegacyPairedSecret(t *testing.T) {
	b := parse.Parse("GOOGLE_CLIENT_ID="+googleTestClientID+"\nGOOGLE_CLIENT_SECRET="+googleLegacySecret+"\n", ".env")
	ms := recognizeGoogleOAuthClient(b, "", nil)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Fields["client_secret"] != googleLegacySecret {
		t.Errorf("client_secret = %q", ms[0].Fields["client_secret"])
	}
}

// gcp_adc owns the ADC file and validates it with the real refresh token. A
// second claim on the same client_secret would probe the same credential twice
// and report it under two modules.
func TestGoogleOAuthIgnoresADCFile(t *testing.T) {
	b := parse.Parse(gcpADCFile, "application_default_credentials.json")
	if ms := recognizeGoogleOAuthClient(b, "", nil); len(ms) != 0 {
		t.Fatalf("must not claim an ADC file: %+v", ms)
	}
}

func TestGoogleOAuthIgnoresServiceAccountFile(t *testing.T) {
	raw := `{"type":"service_account","client_id":"123","client_email":"svc@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}`
	if ms := recognizeGoogleOAuthClient(parse.Parse(raw, "sa.json"), "", nil); len(ms) != 0 {
		t.Fatalf("must not claim a service-account key: %+v", ms)
	}
}

// Pairing on the client id alone would send another vendor's credential to
// Google's token endpoint. The secret's variable name must name Google too.
func TestGoogleOAuthDoesNotPairForeignSecret(t *testing.T) {
	b := parse.Parse("GOOGLE_CLIENT_ID="+googleTestClientID+"\nSTRIPE_SECRET_KEY="+foreignSecret+"\n", ".env")
	for _, m := range recognizeGoogleOAuthClient(b, "", nil) {
		if strings.Contains(m.Secret, foreignSecret) || m.Fields["client_secret"] == foreignSecret {
			t.Fatalf("paired a Stripe key with a Google client id: %+v", m)
		}
	}
}

// An unqualified CLIENT_SECRET may belong to any OAuth provider in the blob.
func TestGoogleOAuthDoesNotPairUnqualifiedClientSecret(t *testing.T) {
	b := parse.Parse("GOOGLE_CLIENT_ID="+googleTestClientID+"\nCLIENT_SECRET="+googleLegacySecret+"\n", ".env")
	if ms := recognizeGoogleOAuthClient(b, "", nil); len(ms) != 0 {
		t.Fatalf("must not pair an unqualified CLIENT_SECRET: %+v", ms)
	}
}

func TestGoogleOAuthRecognizesOrphanSecret(t *testing.T) {
	b := parse.Parse("GOOGLE_OAUTH_CLIENT_SECRET="+googleTestSecret+"\n", ".env")
	ms := recognizeGoogleOAuthClient(b, "", nil)
	if len(ms) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(ms), ms)
	}
	if ms[0].Fields["client_id"] != "" {
		t.Errorf("client_id = %q, want empty", ms[0].Fields["client_id"])
	}
}

// --- the probe ---

// driveGoogleOAuth points the token endpoint at h and returns the finished Note.
func driveGoogleOAuth(t *testing.T, f module.Fields, h http.HandlerFunc) module.Note {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	orig := gcpEndpoints
	gcpEndpoints.Token = srv.URL
	defer func() { gcpEndpoints = orig }()
	return driveGoogleOAuthWith(t, f, recon.New(srv.Client(), true))
}

func driveGoogleOAuthWith(t *testing.T, f module.Fields, c *recon.Client) module.Note {
	t.Helper()
	m := googleOAuthClient{}
	ctx := context.Background()
	tok, err := m.Authenticate(ctx, c, f)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if tok.Bearer != "" {
		t.Fatalf("the probe must never mint a token, got bearer %q", tok.Bearer)
	}
	fs, err := m.Recon(ctx, c, tok, f)
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	return m.Summarize("google oauth", fs)
}

func googleFields() module.Fields {
	return module.Fields{"client_id": googleTestClientID, "client_secret": googleTestSecret}
}

func respondJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// invalid_grant proves the client id and secret authenticated: only the
// deliberately-junk refresh token was rejected.
func TestGoogleOAuthInvalidGrantMeansLive(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	if n.Invalid {
		t.Fatalf("invalid_grant means the secret is live, got Invalid: %+v", n)
	}
	if n.Undetermined {
		t.Fatalf("invalid_grant is a verdict, not an unknown: %+v", n)
	}
	got := indexByKey(n.Findings)
	if got["client secret"].Value == "" {
		t.Errorf("want a verdict finding: %+v", got)
	}
	if got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("a live client secret is a force multiplier: %+v", got["reach"])
	}
}

func TestGoogleOAuthWrongSecretIsDead(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 401, `{"error":"invalid_client","error_description":"The provided client secret is invalid."}`)
	})
	if !n.Invalid {
		t.Fatalf("invalid_client means the secret is dead: %+v", n)
	}
	if !strings.Contains(strings.ToLower(n.Reason), "secret") {
		t.Errorf("Reason should say the secret was rejected, got %q", n.Reason)
	}
}

func TestGoogleOAuthMissingClientIsDead(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 401, `{"error":"invalid_client","error_description":"The OAuth client was not found."}`)
	})
	if !n.Invalid {
		t.Fatalf("a deleted client is dead: %+v", n)
	}
	if !strings.Contains(strings.ToLower(n.Reason), "not found") {
		t.Errorf("Reason should say the client was not found, got %q", n.Reason)
	}
}

// API drift must never flip a live secret to dead: only the documented
// invalid_client code is a death certificate.
func TestGoogleOAuthUnknownErrorIsUndetermined(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 503, `{"error":"backend_error"}`)
	})
	if n.Invalid {
		t.Fatalf("an unrecognized error is not proof of death: %+v", n)
	}
	if !n.Undetermined {
		t.Fatalf("an unrecognized error is Undetermined: %+v", n)
	}
}

func TestGoogleOAuthTransportErrorIsUndetermined(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := srv.Client()
	orig := gcpEndpoints
	gcpEndpoints.Token = srv.URL
	srv.Close() // nothing is listening now
	defer func() { gcpEndpoints = orig }()

	n := driveGoogleOAuthWith(t, googleFields(), recon.New(client, true))
	if n.Invalid {
		t.Fatalf("an unreachable endpoint is not proof of death: %+v", n)
	}
	if !n.Undetermined {
		t.Fatalf("an unreachable endpoint is Undetermined: %+v", n)
	}
}

func TestGoogleOAuthProbeSendsRefreshGrantAndMintsNothing(t *testing.T) {
	var method, body string
	driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		body = string(buf[:n])
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if !strings.Contains(body, "grant_type=refresh_token") {
		t.Errorf("body must use the refresh_token grant, got %q", body)
	}
	if !strings.Contains(body, "refresh_token=") {
		t.Errorf("body must carry the sentinel refresh token, got %q", body)
	}
}

func TestGoogleOAuthReportsProjectNumber(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	if got := indexByKey(n.Findings)["gcp project"].Value; got != "123456789012" {
		t.Errorf("gcp project = %q, want the client id's leading digits", got)
	}
}

// A web client's secret is confidential; an installed client's is not, and
// Google documents that difference. Saying it backwards is a bad finding.
func TestGoogleOAuthReportsClientType(t *testing.T) {
	f := googleFields()
	f["client_type"] = "installed"
	n := driveGoogleOAuth(t, f, func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	got := indexByKey(n.Findings)["client type"]
	if !strings.Contains(got.Value, "desktop") {
		t.Errorf("client type = %q, want the installed-app wording", got.Value)
	}
	if got.Flag == module.FlagForceMultiplier {
		t.Errorf("an installed client's secret is not confidential; do not amplify it")
	}
}

// gcloud ships its own client id and secret in the SDK, so they grant nothing
// and every ADC file carries them. That is knowable before any call: probing
// spends a request and an OPSEC footprint to confirm something already public.
// It still has to be NAMED, though — staying silent hands the value to
// generic_secret, which reports it as an unrecognized credential.
func TestGoogleOAuthPublicGcloudClientIsNotAFinding(t *testing.T) {
	called := false
	f := module.Fields{"client_id": gcloudClientID, "client_secret": googleTestSecret}
	n := driveGoogleOAuth(t, f, func(w http.ResponseWriter, r *http.Request) {
		called = true
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	if called {
		t.Error("must not probe a client whose secret is published in the SDK")
	}
	if tier := score.TierFor(n, score.Context{}); tier != score.TierInfo {
		t.Errorf("published SDK client ranked %s (score %d), want INFO",
			tier, score.BlastRadius(n, score.Context{}))
	}
	if indexByKey(n.Findings)["reach"].Flag == module.FlagForceMultiplier {
		t.Errorf("a published SDK client must not be scored as a leak: %+v", n.Findings)
	}
	if !strings.Contains(strings.ToLower(n.Summary), "public") {
		t.Errorf("Summary should name it a published client, got %q", n.Summary)
	}
	if n.Invalid || n.Undetermined {
		t.Errorf("it is neither dead nor unknown — it is simply not a credential: %+v", n)
	}
}

// Without a client id there is nothing to authenticate against, so nothing may
// be claimed either way.
func TestGoogleOAuthOrphanSecretIsUndetermined(t *testing.T) {
	called := false
	n := driveGoogleOAuth(t, module.Fields{"client_secret": googleTestSecret}, func(w http.ResponseWriter, r *http.Request) {
		called = true
		respondJSON(w, 400, `{"error":"invalid_grant"}`)
	})
	if called {
		t.Fatalf("must not probe without a client id")
	}
	if n.Invalid {
		t.Fatalf("a missing input is not proof of death: %+v", n)
	}
	if !n.Undetermined {
		t.Fatalf("want Undetermined: %+v", n)
	}
	if !strings.Contains(strings.ToLower(n.Reason), "client id") {
		t.Errorf("Reason should name the missing input, got %q", n.Reason)
	}
}

// Dry-run records the planned call and makes none.
func TestGoogleOAuthDryRunMakesNoCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	orig := gcpEndpoints
	gcpEndpoints.Token = srv.URL
	defer func() { gcpEndpoints = orig }()

	n := driveGoogleOAuthWith(t, googleFields(), recon.New(srv.Client(), false))
	if called {
		t.Fatalf("dry-run must not call the token endpoint")
	}
	if n.Invalid {
		t.Fatalf("dry-run proves nothing: %+v", n)
	}
}

// The renderer prints Reason itself on an undetermined or dead note, so a
// finding repeating it would put the same sentence on screen twice.
func TestGoogleOAuthDoesNotRepeatTheReasonAsAFinding(t *testing.T) {
	cases := map[string]module.Note{
		"orphan": driveGoogleOAuth(t, module.Fields{"client_secret": googleTestSecret},
			func(w http.ResponseWriter, r *http.Request) {}),
		"rejected": driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
			respondJSON(w, 401, `{"error":"invalid_client","error_description":"The provided client secret is invalid."}`)
		}),
		"unrecognized": driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
			respondJSON(w, 503, `{"error":"backend_error"}`)
		}),
	}
	for name, n := range cases {
		if n.Reason == "" {
			t.Errorf("%s: want a Reason", name)
		}
		for _, f := range n.Findings {
			if f.Value == n.Reason {
				t.Errorf("%s: finding %q repeats Reason verbatim", name, f.Key)
			}
		}
	}
}

// A rejected secret reaches nothing, so the note must not also advertise reach.
func TestGoogleOAuthDeadNoteClaimsNoReach(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 401, `{"error":"invalid_client","error_description":"The provided client secret is invalid."}`)
	})
	if n.Summary != "" {
		t.Errorf("a dead note carries a Reason, not a summary of reach: %q", n.Summary)
	}
	if indexByKey(n.Findings)["reach"].Value != "" {
		t.Errorf("dead note claims reach: %+v", n.Findings)
	}
}

// The GCP project number is an identifier, not a count of things the credential
// reaches. Scored as reach it reads as tens of billions and inflates every
// Google finding by the width of the number.
func TestGoogleOAuthProjectNumberAddsNoBlastRadius(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	withoutProject := module.Note{Title: n.Title, Summary: n.Summary}
	for _, f := range n.Findings {
		if f.Key != "gcp project" {
			withoutProject.Findings = append(withoutProject.Findings, f)
		}
	}
	full, trimmed := score.BlastRadius(n, score.Context{}), score.BlastRadius(withoutProject, score.Context{})
	if full != trimmed {
		t.Errorf("the project number moved the score: %d with, %d without", full, trimmed)
	}
}

// A real, live client secret must still rank high.
func TestGoogleOAuthLiveSecretRanksHigh(t *testing.T) {
	n := driveGoogleOAuth(t, googleFields(), func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, 400, `{"error":"invalid_grant","error_description":"Bad Request"}`)
	})
	if tier := score.TierFor(n, score.Context{}); score.Rank(tier) < score.Rank(score.TierHigh) {
		t.Errorf("a live client secret ranked %s", tier)
	}
}

// The orphan note has to be worth reading. Naming the missing input without
// saying what the secret would reach gives a responder no reason to go find the
// client id. The tier stays UNKNOWN either way — the reach is asserted, not
// observed — so the claim costs nothing.
func TestGoogleOAuthOrphanNoteStatesTheReach(t *testing.T) {
	n := driveGoogleOAuth(t, module.Fields{"client_secret": googleTestSecret},
		func(w http.ResponseWriter, r *http.Request) {})
	if indexByKey(n.Findings)["reach"].Value == "" {
		t.Errorf("orphan note says what is missing but not what is at stake: %+v", n.Findings)
	}
	if tier := score.TierFor(n, score.Context{}); tier != score.TierUnknown {
		t.Errorf("an unprobed secret must not be given a severity, got %s", tier)
	}
}
