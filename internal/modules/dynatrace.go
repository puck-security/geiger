package modules

import (
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Dynatrace API/PAT/platform tokens have the shape dt0<x><nn>.<public-id>.<secret>
// (e.g. dt0c01 API token/PAT, dt0s16 platform token). The token authenticates
// against a specific tenant, whose URL almost always sits next to the token in a
// real leak (a config value, a logged request URL, a query param).
var (
	dtTokenRe  = regexp.MustCompile(`dt0[a-z][0-9]{2}\.[A-Za-z0-9-]{8,128}\.[A-Za-z0-9]{64}`)
	dtTenantRe = regexp.MustCompile(`[a-z0-9-]+\.(?:live\.dynatrace|apps\.dynatrace|(?:dev|sprint)\.dynatracelabs|(?:dev|sprint)\.apps\.dynatracelabs)\.com`)
)

func init() { recognize.RegisterRecognizer(recognizeDynatrace) }

func recognizeDynatrace(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	tok := dtTokenRe.FindString(b.Raw)
	if tok == "" {
		tok = firstVar(b.Vars, "DT_API_TOKEN", "DYNATRACE_API_TOKEN", "DYNATRACE_TOKEN", "DT_TOKEN")
	}
	if tok == "" {
		return nil
	}

	// Resolve the tenant, first source wins: the URL discovered next to the token,
	// then an env var, then the --endpoint override. The reported tenant keeps its
	// original host; the endpoint we call is normalized to the classic API host.
	var tenant, apiURL string
	if host := dtTenantRe.FindString(b.Raw); host != "" {
		tenant, apiURL = host, "https://"+dynatraceAPIHost(host)
	} else if env := firstVar(b.Vars, "DT_ENV_URL", "DYNATRACE_ENV_URL", "DYNATRACE_URL", "DT_TENANT"); env != "" {
		tenant, apiURL = env, dynatraceAPIURL(env)
	} else if endpoint != "" {
		apiURL = dynatraceAPIURL(endpoint)
	}

	if apiURL == "" {
		// Token but no tenant: surface a "needs endpoint" hint rather than dropping
		// it, so a responder learns the token exists and how to characterize it.
		return []recognize.Match{{
			Module: "needs_endpoint",
			Fields: module.Fields{
				"service":      "Dynatrace",
				"impact":       "observability data + tenant config API (scope-dependent: metrics/logs read → config write / token minting / extension deploy)",
				"endpoint_var": "DYNATRACE_ENV_URL",
			},
			Secret: tok, Label: "DYNATRACE_API_TOKEN",
		}}
	}

	fields := module.Fields{"token": tok, "endpoint": apiURL}
	if tenant != "" {
		fields["tenant"] = tenant
	}
	return []recognize.Match{{Module: "dynatrace", Fields: fields, Secret: tok, Label: "DYNATRACE_API_TOKEN"}}
}

// dynatraceAPIHost maps a tenant host to the classic API host. The 3rd-gen
// Platform host (*.apps.dynatrace.com, and dev/sprint *.apps.dynatracelabs.com)
// has no usable validation endpoint, but every token — including platform tokens —
// authenticates against the classic API, where /api/v2/apiTokens/lookup lives. The
// live/dev/sprint qualifier is never changed; only the extra "apps" label is
// dropped/rewritten.
func dynatraceAPIHost(host string) string {
	h := strings.Replace(host, ".apps.dynatrace.com", ".live.dynatrace.com", 1) // prod 3rd-gen → classic API
	h = strings.Replace(h, ".apps.", ".", 1)                                    // dev/sprint 3rd-gen → classic API
	return h
}

// dynatraceAPIURL turns a host or full URL (from an env var or --endpoint) into a
// normalized https API base URL.
func dynatraceAPIURL(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i] // drop any path/query
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	return "https://" + dynatraceAPIHost(v)
}
