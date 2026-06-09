package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestGeminiRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1beta/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "AIzaXXX" {
			t.Errorf("gemini key header wrong: %q", r.Header.Get("x-goog-api-key"))
		}
		respond(w, `{"models":[{"name":"models/gemini-pro"}]}`)
	})
	got := driveModule(t, "gemini", module.Fields{"token": "AIzaXXX"}, mux)
	if got["models"].Value != "1" || got["reach"].Flag != module.FlagWarn {
		t.Errorf("gemini fields wrong: %+v", got)
	}
}

func TestAzureOpenAIRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/openai/deployments", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != "AZK" {
			t.Errorf("azure api-key header wrong: %q", r.Header.Get("api-key"))
		}
		respond(w, `{"data":[{"id":"gpt-4o"}]}`)
	})
	got := driveModule(t, "azure_openai", module.Fields{"token": "AZK", "endpoint": "https://acme.openai.azure.com"}, mux)
	if got["deployments"].Value != "1" || got["reach"].Flag != module.FlagWarn {
		t.Errorf("azure openai fields wrong: %+v", got)
	}
}

func TestOpenAICompatLLMs(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"groq", "/openai/v1/models"},
		{"together", "/v1/models"},
		{"deepseek", "/models"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(tc.path, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer LLMK" {
					t.Errorf("bearer not set: %q", r.Header.Get("Authorization"))
				}
				respond(w, `{"data":[{"id":"m1"},{"id":"m2"}]}`)
			})
			got := driveModule(t, tc.name, module.Fields{"token": "LLMK"}, mux)
			if got["models"].Value != "2" || got["reach"].Flag != module.FlagWarn {
				t.Errorf("%s fields wrong: %+v", tc.name, got)
			}
		})
	}
}

func TestElevenLabsAndStability(t *testing.T) {
	emux := http.NewServeMux()
	emux.HandleFunc("/v1/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("xi-api-key") != "XIK" {
			t.Errorf("xi-api-key header wrong: %q", r.Header.Get("xi-api-key"))
		}
		respond(w, `{"subscription":{"tier":"creator"}}`)
	})
	if got := driveModule(t, "elevenlabs", module.Fields{"token": "XIK"}, emux); got["tier"].Value != "creator" {
		t.Errorf("elevenlabs tier wrong: %+v", got)
	}
	smux := http.NewServeMux()
	smux.HandleFunc("/v1/user/account", func(w http.ResponseWriter, r *http.Request) { respond(w, `{"email":"ai@acme.com"}`) })
	if got := driveModule(t, "stability", module.Fields{"token": "STK"}, smux); got["email"].Value != "ai@acme.com" {
		t.Errorf("stability email wrong: %+v", got)
	}
}

func TestPineconeAndCoinbase(t *testing.T) {
	pmux := http.NewServeMux()
	pmux.HandleFunc("/indexes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Key") != "PCK" {
			t.Errorf("pinecone Api-Key header wrong: %q", r.Header.Get("Api-Key"))
		}
		respond(w, `{"indexes":[{"name":"prod"}]}`)
	})
	if got := driveModule(t, "pinecone", module.Fields{"token": "PCK"}, pmux); got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("pinecone reach should be fm (embedded data): %+v", got)
	}
	cmux := http.NewServeMux()
	cmux.HandleFunc("/v2/user", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"data":{"name":"Satoshi","email":"s@acme.com"}}`)
	})
	if got := driveModule(t, "coinbase", module.Fields{"token": "CBT"}, cmux); got["user"].Value != "Satoshi" || got["reach"].Flag != module.FlagForceMultiplier {
		t.Errorf("coinbase fields wrong: %+v", got)
	}
}

func TestAIRecognizers(t *testing.T) {
	cases := []struct{ name, env, endpoint, module, secret string }{
		{"gemini", "GEMINI_API_KEY=AIzaK\n", "", "gemini", "AIzaK"},
		{"azure openai", "AZURE_OPENAI_ENDPOINT=https://acme.openai.azure.com\nAZURE_OPENAI_API_KEY=azk\n", "", "azure_openai", "azk"},
		{"groq", "GROQ_API_KEY=gsk_x\n", "", "groq", "gsk_x"},
		{"together", "TOGETHER_API_KEY=tk\n", "", "together", "tk"},
		{"deepseek", "DEEPSEEK_API_KEY=sk-ds\n", "", "deepseek", "sk-ds"},
		{"elevenlabs", "ELEVENLABS_API_KEY=xik\n", "", "elevenlabs", "xik"},
		{"stability", "STABILITY_API_KEY=stk\n", "", "stability", "stk"},
		{"pinecone", "PINECONE_API_KEY=pck\n", "", "pinecone", "pck"},
		{"coinbase", "COINBASE_ACCESS_TOKEN=cbt\n", "", "coinbase", "cbt"},
		{"perplexity (pplx- prefix)", "FOO=pplx-abcdef0123\n", "", "perplexity", "pplx-abcdef0123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.env, ".env")
			by := modulesOf(recognize.Recognize(b, tc.endpoint, module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
		})
	}
}
