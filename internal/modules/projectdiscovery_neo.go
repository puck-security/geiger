package modules

import (
	"strings"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// ProjectDiscovery Neo — an autonomous offensive-security agent. A neo_sk_ key
// is two different things at once, and the second is the one that gets missed:
//
//   - it reads the account's finished work: validated findings against the
//     holder's targets, task transcripts, and the files those tasks produced.
//     That is a vulnerability report for someone else's estate.
//   - it starts new work. POST /api/v1/tasks runs an assessment against a
//     target the caller names, from ProjectDiscovery's infrastructure, on the
//     account's credits. geiger never issues it — read-only means read-only —
//     but the note says so, because rotating the key is the only thing that
//     stops it.
//
// The same key authenticates the hosted MCP server at mcp.projectdiscovery.io,
// which is how it usually turns up: a header in an agent config, which is where
// mcp_config finds it and hands it here.
func init() {
	add("", neoSpec(neoBase).Module())
	recognize.RegisterRecognizer(recognizeNeoKey)
}

// neoBase is the documented production API. The spec takes it as an argument so
// a test can point the same calls at a server with canned responses, which is
// what keeps the JSON paths below honest.
const neoBase = "https://neo.api.projectdiscovery.io/api/v1"

func neoSpec(base string) r.HTTP {
	return r.HTTP{
		ModuleName: "projectdiscovery_neo",
		Base:       base,
		Auth:       r.AuthSpec{Kind: r.Header, HeaderName: "X-Api-Key"},
		Endpoint:   saasOnly("projectdiscovery.io"),
		Whoami: r.GET("/user").
			Field("account", "email").
			Field("plan", "tag").
			FlagField("role", "role", warnFlag).
			Field("team", "team.name").
			FlagField("team role", "team.role", warnFlag),
		Calls: []r.Call{
			// Validated findings for the account's own targets: the highest-value
			// read on this API, and unrelated to how much credit is left.
			r.GET("/issues?per_page=1").CountFlag("total", "validated findings", fmFlag),
			// Past assessments, each with its transcript and report.
			r.GET("/tasks?limit=1").CountFlag("total", "assessments", warnFlag),
			// The workspace: scan output, uploads, anything a task wrote.
			r.GET("/files?page_size=1&include_total=true").CountFlag("total", "workspace files", warnFlag),
			r.GET("/projects").CountFlag("count", "projects", infoFlag),
			// What a stolen key can spend before anyone notices.
			r.GET("/billing/credits").
				FlagField("credits available", "available_credits", warnFlag).
				FlagField("card on file", "has_payment_method", warnFlag),
		},
		Static: []module.Finding{{
			Key: "reach",
			Value: "starts assessments against any target the caller names, from ProjectDiscovery's " +
				"infrastructure and on this account's credits (POST /tasks — never issued here)",
			Flag: fmFlag,
		}},
		Summarize: func(fs []module.Finding) string {
			for _, f := range fs {
				if f.Key == "validated findings" {
					return "Neo key — " + f.Value + " validated findings on this account's targets, and can launch new assessments"
				}
			}
			return "Neo key — reads this account's assessments and can launch new ones"
		},
	}
}

// neoPrefix is the documented key prefix. gitleaks has no rule for it, so this
// value scan is the only thing that routes the key away from generic_secret.
const neoPrefix = "neo_sk_"

// recognizeNeoKey matches on the value prefix, whatever the variable is called.
// The key travels in an X-Api-Key header inside an agent config as often as it
// sits in an env var, so a name-based rule alone would miss it.
func recognizeNeoKey(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	seen := map[string]bool{}
	var out []recognize.Match
	for _, k := range sortedVarKeys(b.Vars) {
		v := strings.TrimSpace(b.Vars[k])
		if seen[v] || !strings.HasPrefix(v, neoPrefix) || !valueLooksSecret(v) {
			continue
		}
		seen[v] = true
		out = append(out, recognize.Match{
			Module: "projectdiscovery_neo",
			Fields: module.Fields{"token": v},
			Secret: v,
			Label:  k,
		})
	}
	return out
}
