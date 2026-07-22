package modules

import (
	"strings"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// AI/LLM providers (beyond the OpenAI/Anthropic/Cohere/Mistral/Replicate/HF
// already covered) and vector DBs. Reach is mostly billed usage plus access to
// uploaded files / fine-tunes / embedded data — flagged warn, not force
// multiplier (Coinbase is the exception: it moves money). Pinecone embeddings
// can hold proprietary/PII data.

func init() {
	registerGemini()
	registerAzureOpenAI()
	registerOpenAICompatLLM("groq", "https://api.groq.com", "/openai/v1/models", []string{"GROQ_API_KEY"})
	registerOpenAICompatLLM("together", "https://api.together.xyz", "/v1/models", []string{"TOGETHER_API_KEY", "TOGETHERAI_API_KEY"})
	registerOpenAICompatLLM("deepseek", "https://api.deepseek.com", "/models", []string{"DEEPSEEK_API_KEY"})
	registerElevenLabs()
	registerStability()
	registerPinecone()
	registerCoinbase()
	registerPerplexity()
}

// registerOpenAICompatLLM covers the many OpenAI-compatible bearer APIs whose
// only read endpoint is a model list.
func registerOpenAICompatLLM(name, base, modelsPath string, envNames []string) {
	add("", r.HTTP{
		ModuleName: name, Base: base, Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET(modelsPath).CountArrayFlag("data", "models", infoFlag),
		Static:    []module.Finding{{Key: "reach", Value: "call models on this account's billed quota; list/read fine-tunes and uploaded files", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return name + " — LLM API access (billed usage)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, envNames...); k != "" {
			return []recognize.Match{{Module: name, Fields: module.Fields{"token": k}, Secret: k, Label: envNames[0]}}
		}
		return nil
	})
}

// --- Google Gemini (Generative Language API): x-goog-api-key ---

func registerGemini() {
	add("", r.HTTP{
		ModuleName: "gemini", Base: "https://generativelanguage.googleapis.com", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "x-goog-api-key"},
		Whoami:    r.GET("/v1beta/models").CountArrayFlag("models", "models", infoFlag),
		Static:    []module.Finding{{Key: "reach", Value: "call Gemini models on the project's billed quota and read files/tuned models uploaded to the API", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Google Gemini — generative API (billed usage)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		// Env-name only: a bare AIza… key may be Maps/other Google APIs, not Gemini.
		if k := firstVar(b.Vars, "GEMINI_API_KEY", "GOOGLE_GENAI_API_KEY", "GOOGLE_AI_API_KEY", "GOOGLE_API_KEY"); k != "" {
			return []recognize.Match{{Module: "gemini", Fields: module.Fields{"token": k}, Secret: k, Label: "GEMINI_API_KEY"}}
		}
		return nil
	})
}

// --- Azure OpenAI: api-key header against the resource endpoint ---

func registerAzureOpenAI() {
	add("", r.HTTP{
		ModuleName: "azure_openai", Endpoint: saasOnly("openai.azure.com", "cognitiveservices.azure.com", "openai.azure.us"), Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "api-key"},
		Whoami:    r.GET("/openai/deployments?api-version=2023-05-15").CountArrayFlag("data", "deployments", infoFlag),
		Static:    []module.Finding{{Key: "reach", Value: "call models on the Azure OpenAI resource (billed usage) and read its deployments", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Azure OpenAI — resource model access (billed usage)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY")
		ep := resolveEndpoint(b, endpoint, "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_BASE")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "azure_openai", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "AZURE_OPENAI_API_KEY"}}
	})
}

// --- ElevenLabs: xi-api-key ---

func registerElevenLabs() {
	add("", r.HTTP{
		ModuleName: "elevenlabs", Base: "https://api.elevenlabs.io", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "xi-api-key"},
		Whoami:    r.GET("/v1/user").Field("tier", "subscription.tier"),
		Static:    []module.Finding{{Key: "reach", Value: "billed voice synthesis/cloning and access to the account's saved voices and history", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "ElevenLabs — voice API (billed usage + voice library)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "ELEVENLABS_API_KEY", "ELEVEN_API_KEY", "XI_API_KEY"); k != "" {
			return []recognize.Match{{Module: "elevenlabs", Fields: module.Fields{"token": k}, Secret: k, Label: "ELEVENLABS_API_KEY"}}
		}
		return nil
	})
}

// --- Stability AI: bearer ---

func registerStability() {
	add("", r.HTTP{
		ModuleName: "stability", Base: "https://api.stability.ai", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/v1/user/account").Field("email", "email"),
		Static:    []module.Finding{{Key: "reach", Value: "billed image generation and account access (credit balance)", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Stability AI — image API (billed usage)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "STABILITY_API_KEY", "STABILITY_KEY", "SD_API_KEY"); k != "" {
			return []recognize.Match{{Module: "stability", Fields: module.Fields{"token": k}, Secret: k, Label: "STABILITY_API_KEY"}}
		}
		return nil
	})
}

// --- Pinecone (vector DB) control plane: Api-Key header ---

func registerPinecone() {
	add("", r.HTTP{
		ModuleName: "pinecone", Base: "https://api.pinecone.io", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "Api-Key"},
		Whoami:    r.GET("/indexes").CountArrayFlag("indexes", "indexes", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "read/write/delete vector indexes — embeddings can encode proprietary or PII source data, and vectors can be exfiltrated or poisoned", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Pinecone — vector index read/write (embedded data)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "PINECONE_API_KEY", "PINECONE_TOKEN"); k != "" {
			return []recognize.Match{{Module: "pinecone", Fields: module.Fields{"token": k}, Secret: k, Label: "PINECONE_API_KEY"}}
		}
		return nil
	})
}

// --- Coinbase: OAuth access token (moves money) ---

func registerCoinbase() {
	add("coinbase-access-token", r.HTTP{
		ModuleName: "coinbase", Base: "https://api.coinbase.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/v2/user").Field("user", "data.name").Field("email", "data.email"),
		Static:    []module.Finding{{Key: "reach", Value: "read account/transaction history and, with the right scopes, move cryptocurrency funds — financial", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Coinbase — account access (financial; can move funds)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "COINBASE_ACCESS_TOKEN", "COINBASE_TOKEN"); k != "" {
			return []recognize.Match{{Module: "coinbase", Fields: module.Fields{"token": k}, Secret: k, Label: "COINBASE_ACCESS_TOKEN"}}
		}
		return nil
	})
}

// --- Perplexity: recognize + flag (chat-only API, no read-only whoami) ---

func registerPerplexity() {
	add("", staticModule{name: "perplexity", summary: "Perplexity — LLM API (billed usage)", findings: []module.Finding{
		{Key: "reach", Value: "call Perplexity models on this account's billed quota", Flag: warnFlag},
		{Key: "validation", Value: "recognized by name/shape; not exercised (chat-completions only, no read-only endpoint)", Flag: cantFlag},
	}})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "PERPLEXITY_API_KEY", "PPLX_API_KEY")
		if tok == "" {
			for _, v := range b.Vars {
				if strings.HasPrefix(v, "pplx-") {
					tok = v
					break
				}
			}
		}
		if tok == "" {
			return nil
		}
		return []recognize.Match{{Module: "perplexity", Fields: module.Fields{"token": tok}, Secret: tok, Label: "PERPLEXITY_API_KEY"}}
	})
}
