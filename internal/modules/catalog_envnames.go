package modules

import (
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// envNameRoute maps an exact environment variable name to the module that
// should triage its value. This catches credentials whose value has no
// recognizable prefix for gitleaks but whose variable name is unambiguous.
var envNameRoute = map[string]string{
	"VERCEL_TOKEN":              "vercel",
	"VERCEL_API_TOKEN":          "vercel",
	"LINODE_TOKEN":              "linode",
	"LINODE_API_TOKEN":          "linode",
	"BUILDKITE_API_TOKEN":       "buildkite",
	"TERRAFORM_CLOUD_TOKEN":     "terraform_cloud",
	"TF_TOKEN_app_terraform_io": "terraform_cloud",
	"ASANA_ACCESS_TOKEN":        "asana",
	"ASANA_PAT":                 "asana",
	"COHERE_API_KEY":            "cohere",
	"MISTRAL_API_KEY":           "mistral",
	"REPLICATE_API_TOKEN":       "replicate",
	"CIRCLECI_TOKEN":            "circleci",
	"CIRCLE_TOKEN":              "circleci",
	"HONEYCOMB_API_KEY":         "honeycomb",
	"INTERCOM_ACCESS_TOKEN":     "intercom",
	"ZENDESK_API_TOKEN":         "zendesk",
	"POSTMARK_SERVER_TOKEN":     "postmark",
	"POSTMARK_API_TOKEN":        "postmark",
	"BREVO_API_KEY":             "brevo",
	"SENDINBLUE_API_KEY":        "brevo",
	"BOX_ACCESS_TOKEN":          "box",
	"BOX_DEVELOPER_TOKEN":       "box",
	"DOCUSIGN_ACCESS_TOKEN":     "docusign",
}

// endpointEnvVars maps a module to the variable names that legitimately supply
// ITS OWN instance host, for modules whose base URL is templated as {endpoint}.
//
// The binding is per-service on purpose. An endpoint variable names the host of
// exactly one service, so it must never become the base URL for a different
// service's credential: a single planted line (GRAFANA_URL=https://attacker.tld)
// in a file that already holds a real token would otherwise redirect that token
// to the attacker on the --live path. Add a variable here only under the module
// whose host it actually names.
var endpointEnvVars = map[string][]string{
	"zendesk": {"ZENDESK_URL"},
}

func recognizeEnvNames(b parse.Blob, endpoint string, reg *module.Registry) []recognize.Match {
	var out []recognize.Match
	for name, mod := range envNameRoute {
		v := b.Vars[name]
		if v == "" {
			continue
		}
		if _, ok := reg.ByName(mod); !ok {
			continue
		}
		f := module.Fields{"token": v}
		// The operator's explicit --endpoint is an assertion and outranks anything
		// read out of the scanned data; otherwise fall back to this service's own
		// host variable. Never another service's.
		if ep := resolveEndpoint(b, endpoint, endpointEnvVars[mod]...); ep != "" {
			f["endpoint"] = ep
		}
		out = append(out, recognize.Match{Module: mod, Fields: f, Secret: v, Label: name, Line: b.Lines[name]})
	}
	return out
}

func init() {
	recognize.RegisterRecognizer(recognizeEnvNames)
}
