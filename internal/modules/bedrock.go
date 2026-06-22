package modules

import (
	"regexp"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Amazon Bedrock API keys are bearer tokens (not SigV4 access keys) that grant an
// IAM principal access to Amazon Bedrock foundation models. Long-lived keys start
// with ABSK (base64 of "BedrockAPIKey-<id>-at-<accountid>…"); short-lived keys
// start with bedrock-api-key-. They authenticate with Authorization: Bearer and
// validate read-only via the ListFoundationModels control-plane call. gitleaks
// recognizes the shapes (length+entropy gated); we also recognize them by the
// AWS_BEARER_TOKEN_BEDROCK variable name and prefix so a token gitleaks' gate
// misses still routes to the module that characterizes it.

func init() {
	add("aws-amazon-bedrock-api-key-long-lived", r.HTTP{
		ModuleName: "bedrock", Base: "https://bedrock.us-east-1.amazonaws.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/foundation-models").CountArray("modelSummaries", "foundation models"),
		Static: []module.Finding{{Key: "reach", Value: "Amazon Bedrock model access — InvokeModel is billable (LLM inference) and sends prompt/response data; abuse runs up cost fast", Flag: warnFlag}},
		Summarize: func([]module.Finding) string {
			return "Amazon Bedrock API key — foundation-model access (billable)"
		},
	}.Module())
	module.MapRule("aws-amazon-bedrock-api-key-short-lived", "bedrock")
	recognize.RegisterRecognizer(recognizeBedrock)
}

// bedrockRe matches both the long-lived (ABSK…) and short-lived
// (bedrock-api-key-…) shapes. Permissive on length — the module re-validates.
var bedrockRe = regexp.MustCompile(`ABSK[A-Za-z0-9+/]{20,}={0,2}|bedrock-api-key-[A-Za-z0-9+/=]{10,}`)

func recognizeBedrock(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	seen := map[string]bool{}
	emit := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module: "bedrock", Fields: module.Fields{"token": tok}, Secret: tok, Label: "AWS_BEARER_TOKEN_BEDROCK",
		})
	}
	emit(firstVar(b.Vars, "AWS_BEARER_TOKEN_BEDROCK", "BEDROCK_API_KEY", "AWS_BEDROCK_API_KEY"))
	for _, tok := range bedrockRe.FindAllString(b.Raw, -1) {
		emit(tok)
	}
	return out
}
