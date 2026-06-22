package modules

import (
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestBedrockRecognizer(t *testing.T) {
	const absk = "ABSKQmVkcm9ja0FQSUtleS1qMHo4LWF0LTAyOTI4OTg5OA=="
	cases := []struct{ name, env, secret string }{
		{"by var", "AWS_BEARER_TOKEN_BEDROCK=" + absk + "\n", absk},
		{"bare shape", absk + "\n", absk},
		{"short-lived", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tabc123\n", "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tabc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.env, ".env"), "", module.Default))
			m, ok := by["bedrock"]
			if !ok {
				t.Fatalf("bedrock not recognized: %+v", by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
			if _, generic := by["generic_secret"]; generic {
				t.Errorf("value leaked to generic_secret instead of bedrock")
			}
		})
	}
}

func TestBedrockRecon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foundation-models", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ABSKtok" {
			t.Errorf("bedrock must use Bearer, got %q", r.Header.Get("Authorization"))
		}
		respond(w, `{"modelSummaries":[{"modelId":"anthropic.claude-3"},{"modelId":"amazon.titan"}]}`)
	})
	got := driveModule(t, "bedrock", module.Fields{"token": "ABSKtok"}, mux)
	if got["foundation models"].Value != "2" {
		t.Errorf("model count wrong: %+v", got)
	}
	if got["reach"].Flag != module.FlagWarn {
		t.Errorf("bedrock reach should be warn: %+v", got["reach"])
	}
}
