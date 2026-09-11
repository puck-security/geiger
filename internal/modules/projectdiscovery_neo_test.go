package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// The key travels under whatever name the config gives it, so the prefix is
// what routes it. Without this it lands on generic_secret, which says only that
// the value looks like a credential.
func TestNeoKeyRecognizedByPrefix(t *testing.T) {
	for _, line := range []string{
		"NEO_API_KEY=neo_sk_abcdef0123456789abcdef0123456789",
		"SOME_RANDOM_NAME=neo_sk_abcdef0123456789abcdef0123456789",
	} {
		got := modulesOf(recognize.Recognize(parse.Parse(line+"\n", ".env"), "", module.Default))
		if _, ok := got["projectdiscovery_neo"]; !ok {
			t.Errorf("%q not recognized as projectdiscovery_neo", line)
		}
	}
}

// Where it usually turns up: an X-Api-Key header in an agent config. mcp_config
// re-triages embedded credentials through the recognizers, so the key has to
// survive that path too.
func TestNeoKeyInAnMCPConfigIsRetriaged(t *testing.T) {
	raw := `{"mcpServers":{"neo":{"type":"http","url":"https://mcp.projectdiscovery.io/mcp",
		"headers":{"X-Api-Key":"neo_sk_abcdef0123456789abcdef0123456789"}}}}`
	got := modulesOf(recognize.Recognize(parse.Parse(raw, "/home/u/.claude.json"), "", module.Default))
	m, ok := got["projectdiscovery_neo"]
	if !ok {
		t.Fatal("a neo key in an MCP header must route to its own module")
	}
	if !strings.Contains(m.Label, "neo") {
		t.Errorf("the label should say which server holds it: %q", m.Label)
	}
	if _, generic := got["generic_secret"]; generic {
		t.Error("a typed key must not also be reported as an unrecognized secret")
	}
}

// The blast radius, against the documented response shapes. A wrong JSON path
// is silent — the finding simply never appears — so the paths are pinned here.
func TestNeoReconSizesTheAccount(t *testing.T) {
	mux := http.NewServeMux()
	seen := map[string]string{}
	record := func(pattern, body string) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("%s: method = %s, want GET", pattern, r.Method)
			}
			seen[pattern] = r.Header.Get("X-Api-Key")
			_, _ = w.Write([]byte(body))
		})
	}
	record("/user", `{"email":"a@b.io","role":"admin","tag":"beta","team":{"name":"redteam","role":"owner"}}`)
	record("/issues", `{"issues":[],"total":37,"has_more":true}`)
	record("/tasks", `{"tasks":[],"total":12,"has_more":false}`)
	record("/files", `{"items":[],"total":204}`)
	record("/projects", `{"projects":[],"count":3}`)
	record("/billing/credits", `{"available_credits":815,"issued_credits":1000,"used_credits":185,"has_payment_method":true}`)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := neoSpec(srv.URL).Module()
	fs, err := m.Recon(context.Background(), recon.New(srv.Client(), true), module.Token{},
		module.Fields{"token": "neo_sk_abcdef0123456789abcdef0123456789"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]module.Finding{}
	for _, f := range fs {
		got[f.Key] = f
	}
	for key, want := range map[string]string{
		"account":            "a@b.io",
		"role":               "admin",
		"team":               "redteam",
		"validated findings": "37",
		"assessments":        "12",
		"workspace files":    "204",
		"projects":           "3",
		"credits available":  "815",
	} {
		if got[key].Value != want {
			t.Errorf("%s = %q, want %q", key, got[key].Value, want)
		}
	}
	// Findings against the holder's own targets are the reason to rotate first.
	if got["validated findings"].Flag != module.FlagForceMultiplier {
		t.Errorf("validated findings flag = %v, want force multiplier", got["validated findings"].Flag)
	}
	// The write side is stated and never exercised.
	if r, ok := got["reach"]; !ok || !strings.Contains(r.Value, "never issued") {
		t.Errorf("the note must state the launch reach and that geiger does not use it: %q", r.Value)
	}
	if seen["/user"] != "neo_sk_abcdef0123456789abcdef0123456789" {
		t.Errorf("the key goes in X-Api-Key, got %q", seen["/user"])
	}
	if n := m.Summarize("t", fs).Summary; !strings.Contains(n, "37") {
		t.Errorf("summary should lead with the findings count: %q", n)
	}
}
