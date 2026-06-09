package modules

import (
	"strings"

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

// endpointEnvVars are variable names that supply a host/instance for modules
// whose base URL is templated as {endpoint}.
var endpointEnvVars = []string{
	"GRAFANA_URL", "GRAFANA_HOST", "VAULT_ADDR", "GITLAB_URL",
	"ELASTICSEARCH_URL", "ELASTIC_URL", "SPLUNK_URL",
}

func recognizeEnvNames(b parse.Blob, endpoint string, reg *module.Registry) []recognize.Match {
	ep := endpoint
	if ep == "" {
		for _, k := range endpointEnvVars {
			if v := b.Vars[k]; v != "" {
				ep = strings.TrimRight(v, "/")
				break
			}
		}
	}
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
		if ep != "" {
			f["endpoint"] = ep
		}
		out = append(out, recognize.Match{Module: mod, Fields: f, Secret: v, Label: name, Line: b.Lines[name]})
	}
	return out
}

func init() {
	recognize.RegisterRecognizer(recognizeEnvNames)
}
