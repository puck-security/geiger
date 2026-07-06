package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func TestFilestackRecognizer(t *testing.T) {
	const key = "Bpebdas18RqKyahQcCvbAz"
	cases := []struct{ name, raw, apikey string }{
		{"env var", "FILESTACK_API_KEY=" + key, key},
		{"sdk init", `const c = filestack.init("` + key + `");`, key},
		{"sdk client", `new Filestack.Client('` + key + `')`, key},
		{"cdn url", "https://cdn.filestackcontent.com/" + key + "/resize=width:1/https://x/y.jpg", key},
		{"yaml key", "filestack_api_key: " + key, key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.raw, "app.js"), "", module.Default))
			m, ok := by["filestack"]
			if !ok {
				t.Fatalf("filestack not recognized: %+v", by)
			}
			if m.Fields["apikey"] != tc.apikey {
				t.Errorf("apikey = %q, want %q", m.Fields["apikey"], tc.apikey)
			}
		})
	}
	// a bare 22-char base62 with no filestack context must NOT match (too generic).
	if by := modulesOf(recognize.Recognize(parse.Parse(key+"\n", "x"), "", module.Default)); by["filestack"].Module != "" {
		t.Errorf("bare value should not be recognized as filestack")
	}
	// api key + app secret → both captured.
	raw := "FILESTACK_API_KEY=" + key + "\nFILESTACK_APP_SECRET=Zabc1234def5678ghij9012klmn\n"
	m := modulesOf(recognize.Recognize(parse.Parse(raw, ".env"), "", module.Default))["filestack"]
	if m.Fields["secret"] == "" {
		t.Errorf("app secret not captured alongside the api key: %+v", m.Fields)
	}
}

func TestFilestackReconSecurityDisabled(t *testing.T) {
	mux := http.NewServeMux()
	// unsigned metadata read accepted (404 handle) → Security is off.
	mux.HandleFunc("/api/file/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		respond(w, `{"error":"File not found"}`)
	})
	got := driveModule(t, "filestack", module.Fields{"apikey": "APIKEY"}, mux)
	if got["security"].Flag != module.FlagForceMultiplier {
		t.Errorf("security-disabled should be a force multiplier: %+v", got["security"])
	}
	if got["capability"].Flag != module.FlagWarn {
		t.Errorf("expected a capability finding: %+v", got)
	}
}

func TestFilestackReconInvalidKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/file/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		respond(w, `{"error":"Invalid application, apikey not found"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hc := &http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}
	mod, _ := module.Default.ByName("filestack")
	_, err := mod.Recon(context.Background(), recon.New(hc, true), module.Token{}, module.Fields{"apikey": "BADKEY"})
	if err == nil {
		t.Errorf("an invalid api key should return an error (reported dead)")
	}
}
