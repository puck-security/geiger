package modules

import (
	"context"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Self-hosted / instance-scoped services need an --endpoint (or an instance-URL
// env var) before they can be characterized. The per-service recognizers return
// nil when the token is present but no endpoint resolves — which silently drops
// the credential, so a responder never learns the token is even there. The
// recognizer below is purely ADDITIVE: it fires only in exactly that case (token
// present, no endpoint), so it never collides with the real recognizers (which
// fire only when an endpoint IS present). It surfaces a "recognized, needs
// --endpoint" note naming what to set.
//
// This is a curated set of the highest-impact instance-scoped services (the var
// names mirror their real recognizers). A service merely absent from the table
// just doesn't get the hint — no harm.
var endpointRequiredServices = []struct {
	label        string
	impact       string
	tokenVars    []string
	endpointVars []string
}{
	{"Ansible AWX/Tower", "playbook execution across managed hosts (RCE at scale)",
		[]string{"AWX_OAUTH_TOKEN", "TOWER_OAUTH_TOKEN", "CONTROLLER_OAUTH_TOKEN", "AWX_TOKEN"},
		[]string{"AWX_HOST", "TOWER_HOST", "CONTROLLER_HOST", "AWX_URL"}},
	{"Salesforce", "CRM object access (customer PII)",
		[]string{"SALESFORCE_ACCESS_TOKEN", "SF_ACCESS_TOKEN", "SALESFORCE_TOKEN"},
		[]string{"SALESFORCE_INSTANCE_URL", "SF_INSTANCE_URL", "SALESFORCE_URL"}},
	{"Supabase service_role", "RLS-bypass full DB + auth admin",
		[]string{"SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_KEY", "SUPABASE_KEY"},
		[]string{"SUPABASE_URL", "SUPABASE_PROJECT_URL"}},
	{"Snowflake", "warehouse/database access",
		[]string{"SNOWFLAKE_TOKEN", "SNOWFLAKE_PAT", "SNOWFLAKE_PROGRAMMATIC_ACCESS_TOKEN"},
		[]string{"SNOWFLAKE_ACCOUNT", "SNOWFLAKE_ACCOUNT_IDENTIFIER"}},
	{"Braze", "messaging/campaign + user-profile PII",
		[]string{"BRAZE_API_KEY", "BRAZE_REST_API_KEY"},
		[]string{"BRAZE_REST_ENDPOINT", "BRAZE_ENDPOINT", "BRAZE_INSTANCE_URL"}},
	{"Azure OpenAI", "model deployment access",
		[]string{"AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY"},
		[]string{"AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_BASE_URL"}},
}

func init() {
	module.Register(needsEndpoint{})
	recognize.RegisterRecognizer(recognizeNeedsEndpoint)
}

func recognizeNeedsEndpoint(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	for _, s := range endpointRequiredServices {
		tok := firstVar(b.Vars, s.tokenVars...)
		if tok == "" {
			continue
		}
		if resolveEndpoint(b, endpoint, s.endpointVars...) != "" {
			continue // an endpoint resolved — the real recognizer handles it
		}
		out = append(out, recognize.Match{
			Module: "needs_endpoint",
			Fields: module.Fields{"service": s.label, "impact": s.impact, "endpoint_var": s.endpointVars[0]},
			Secret: tok, Label: s.tokenVars[0],
		})
	}
	return out
}

// needsEndpoint emits a non-validating note for a recognized instance-scoped
// credential whose endpoint is unknown, so the responder knows it exists and how
// to characterize it. It makes no network call.
type needsEndpoint struct{ module.Base }

func (needsEndpoint) Name() string { return "needs_endpoint" }

func (needsEndpoint) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	return []module.Finding{
		{Key: "recognized", Value: f["service"] + " credential present, but no endpoint to characterize it", Flag: cantFlag},
		{Key: "potential reach", Value: f["impact"], Flag: warnFlag},
		{Key: "to characterize", Value: "set --endpoint or " + f["endpoint_var"] + " and re-run with --live", Flag: infoFlag},
	}, nil
}

func (needsEndpoint) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "recognized — provide --endpoint to characterize"}
}
