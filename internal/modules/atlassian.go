package modules

import (
	"context"
	"regexp"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// atlassianInfo types a bare Atlassian API token (ATATT…) that we can see but
// can't validate: Cloud Basic auth needs the account email AND the site URL too.
// It makes no network call — it identifies the token and tells the operator how
// to characterize it. When the email + site ARE present, the jira/confluence
// recognizers claim the token (and this one stays silent), so this only ever
// surfaces for an otherwise-unactionable lone token.
type atlassianInfo struct{ module.Base }

func (atlassianInfo) Name() string { return "atlassian" }

func (atlassianInfo) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{{
		Key:   "atlassian token",
		Value: "Jira/Confluence/Bitbucket API token — set the account email (ATLASSIAN_EMAIL) and site URL (--endpoint https://<tenant>.atlassian.net) to validate its reach",
		Flag:  module.FlagCantCharacterize,
	}}, nil
}

func (atlassianInfo) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "Atlassian API token — set email + site to validate reach"}
}

// atatRe matches Atlassian's prefixed API tokens (ATATT…). Permissive on length
// so the bare-token case is caught even when gitleaks' stricter rule (and its
// entropy gate) doesn't fire.
var atatRe = regexp.MustCompile(`ATATT[A-Za-z0-9_\-=]{10,}`)

func init() {
	module.Register(atlassianInfo{})
	recognize.RegisterRecognizer(recognizeAtlassianBare)
}

func recognizeAtlassianBare(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	tok := firstVar(b.Vars, "ATLASSIAN_API_TOKEN", "JIRA_API_TOKEN", "CONFLUENCE_API_TOKEN", "JIRA_TOKEN", "CONFLUENCE_TOKEN")
	if tok == "" {
		tok = atatRe.FindString(b.Raw)
	}
	if tok == "" {
		return nil
	}
	// With both the account email and the site URL, the jira/confluence
	// recognizers validate the token fully — don't add a redundant info finding.
	email := firstVar(b.Vars, "ATLASSIAN_EMAIL", "JIRA_EMAIL", "CONFLUENCE_EMAIL")
	ep := resolveEndpoint(b, endpoint, "ATLASSIAN_URL", "JIRA_BASE_URL", "JIRA_URL", "CONFLUENCE_BASE_URL", "CONFLUENCE_URL")
	if email != "" && ep != "" {
		return nil
	}
	return []recognize.Match{{Module: "atlassian", Fields: module.Fields{"token": tok}, Secret: tok, Label: "ATLASSIAN_API_TOKEN"}}
}
