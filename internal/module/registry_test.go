package module

import (
	"context"
	"testing"

	"github.com/puck-security/geiger/internal/recon"
)

type stub struct {
	Base
	name string
}

func (s stub) Name() string { return s.name }
func (s stub) Recon(context.Context, *recon.Client, Token, Fields) ([]Finding, error) {
	return nil, nil
}
func (s stub) Summarize(title string, fs []Finding) Note { return Note{Title: title} }

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	r.Register(stub{name: "github_pat"})
	r.MapRule("github-pat", "github_pat")

	if _, ok := r.ByName("github_pat"); !ok {
		t.Error("ByName failed")
	}
	if m, ok := r.ByRule("github-pat"); !ok || m.Name() != "github_pat" {
		t.Error("ByRule failed")
	}
	if _, ok := r.ByRule("nonexistent"); ok {
		t.Error("ByRule should miss")
	}
	if len(r.All()) != 1 {
		t.Errorf("All() = %d", len(r.All()))
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	r := NewRegistry()
	r.Register(stub{name: "x"})
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate")
		}
	}()
	r.Register(stub{name: "x"})
}
