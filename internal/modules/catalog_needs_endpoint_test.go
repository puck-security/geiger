package modules

import (
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestNeedsEndpointSurfacedWhenNoHost(t *testing.T) {
	// An AWX token alone (no host) must NOT be silently dropped: a responder
	// needs to know the credential is present and what it can reach.
	b := parse.Parse("AWX_OAUTH_TOKEN=abc123def456ghi789\n", ".env")
	var m recognize.Match
	for _, x := range recognize.Recognize(b, "", module.Default) {
		if x.Module == "needs_endpoint" {
			m = x
		}
	}
	if m.Module == "" {
		t.Fatal("AWX token without endpoint was dropped instead of surfaced")
	}
	if m.Secret != "abc123def456ghi789" {
		t.Errorf("secret not carried: %q", m.Secret)
	}
}

func TestNeedsEndpointSuppressedWhenEndpointPresent(t *testing.T) {
	// With an endpoint available, the real recognizer handles it and the
	// needs_endpoint fallback must NOT also fire (no duplicate).
	b := parse.Parse("AWX_OAUTH_TOKEN=abc123def456ghi789\nAWX_HOST=https://awx.corp\n", ".env")
	for _, x := range recognize.Recognize(b, "", module.Default) {
		if x.Module == "needs_endpoint" {
			t.Errorf("needs_endpoint fired even though an endpoint resolved: %+v", x)
		}
	}
	// And via the --endpoint flag.
	b2 := parse.Parse("AWX_OAUTH_TOKEN=abc123def456ghi789\n", ".env")
	for _, x := range recognize.Recognize(b2, "https://awx.corp", module.Default) {
		if x.Module == "needs_endpoint" {
			t.Errorf("needs_endpoint fired even though --endpoint was given: %+v", x)
		}
	}
}

func TestNeedsEndpointNoteIsNotDead(t *testing.T) {
	mod, _ := module.Default.ByName("needs_endpoint")
	fs, err := mod.Recon(t.Context(), nil, module.Token{}, module.Fields{"service": "Ansible AWX/Tower", "impact": "RCE", "endpoint_var": "AWX_HOST"})
	if err != nil {
		t.Fatal(err)
	}
	note := mod.Summarize("AWX_OAUTH_TOKEN", fs)
	if note.Invalid {
		t.Error("needs_endpoint note must not be marked dead")
	}
	if !strings.Contains(note.Summary, "endpoint") {
		t.Errorf("summary should point to --endpoint: %q", note.Summary)
	}
}
