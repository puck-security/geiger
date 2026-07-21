package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// a self-contained registry with two tiny modules for deterministic testing.
type fakeBearer struct{ module.Base }

func (fakeBearer) Name() string { return "fake" }
func (fakeBearer) Recon(_ context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	req, _ := recon.NewRequest(context.Background(), "GET", "https://fake.example/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+f["token"])
	_, err := c.Do(req, recon.CallOpts{})
	if err != nil {
		return nil, err
	}
	return []module.Finding{{Key: "user", Value: "bob"}}, nil
}
func (fakeBearer) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid = true
	}
	return n
}

func TestPipelineDryRunRecordsButDoesNotCall(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(fakeBearer{})
	reg.MapRule("__never__", "fake")
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["FAKE_TOKEN"]; v != "" {
			return []recognize.Match{{Module: "fake", Fields: module.Fields{"token": v}, Secret: v, Label: "FAKE_TOKEN"}}
		}
		return nil
	})

	b := parse.Parse("FAKE_TOKEN=supersecretvalue12345\n", ".env")
	results := Run(b, reg, Options{Live: false})

	var fake *Result
	for i := range results {
		if strings.Contains(results[i].Note.Title, "fake") {
			fake = &results[i]
		}
	}
	if fake == nil {
		t.Fatalf("fake module not run; got %d results", len(results))
	}
	if len(fake.Planned) != 1 || fake.Planned[0].Method != "GET" {
		t.Fatalf("expected 1 planned GET, got %+v", fake.Planned)
	}
	// Title must redact the secret.
	if strings.Contains(fake.Note.Title, "supersecretvalue12345") {
		t.Errorf("secret leaked into title: %q", fake.Note.Title)
	}
	// Planned header must not contain the raw secret.
	if h := fake.Planned[0].Headers["Authorization"]; strings.Contains(h, "supersecretvalue12345") {
		t.Errorf("secret leaked into planned headers: %q", h)
	}
}

func TestBatchDedupesSecretAcrossSources(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(fakeBearer{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["DUP_TOKEN"]; v != "" {
			return []recognize.Match{{Module: "fake", Fields: module.Fields{"token": v}, Secret: v, Label: "DUP_TOKEN"}}
		}
		return nil
	})
	const sec = "shared-secret-abc123xyz"
	bt := NewBatch(reg, Options{Live: false})
	var all []Result
	for _, f := range []string{".env", "config/.env.local", "app/settings.py"} {
		all = append(all, bt.Run(parse.Parse("DUP_TOKEN="+sec+"\n", f))...)
	}
	n := 0
	for _, r := range all {
		if r.secret == sec {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("shared secret should be reconned once across 3 files, got %d results", n)
	}
	bt.AnnotateDuplicates(all)
	found := false
	for _, r := range all {
		if r.secret != sec {
			continue
		}
		for _, fnd := range r.Note.Findings {
			// summarized value, full paths in Detail
			if fnd.Key == "also exposed in" && strings.Contains(fnd.Value, "2 other file") && len(fnd.Detail) == 2 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("kept result not annotated with the 2 other locations: %+v", all)
	}
}

// instantMod returns a finding without any network call, so the concurrent path
// runs fast and the race detector can validate shared-state safety.
type instantMod struct{ module.Base }

func (instantMod) Name() string { return "instant" }
func (instantMod) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{{Key: "ok", Value: "x", Flag: module.FlagInfo}}, nil
}
func (instantMod) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs}
}

func TestRunConcurrentCompletesAndDedupes(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(instantMod{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["CC_TOKEN"]; v != "" {
			return []recognize.Match{{Module: "instant", Fields: module.Fields{"token": v}, Secret: v, Label: "CC_TOKEN"}}
		}
		return nil
	})
	// 25 unique secrets, each present in two files → 50 sources.
	var srcs []Source
	for i := range 25 {
		val := fmt.Sprintf("cc-secret-%02d-deadbeef", i)
		srcs = append(srcs,
			Source{Blob: parse.Parse("CC_TOKEN="+val+"\n", fmt.Sprintf("a%02d.env", i))},
			Source{Blob: parse.Parse("CC_TOKEN="+val+"\n", fmt.Sprintf("b%02d.env", i))})
	}
	bt := NewBatch(reg, Options{Live: true, Concurrency: 8})
	var progressTicks int
	results := bt.RunConcurrent(srcs, nil, func(int) { progressTicks++ })
	uniq := map[string]int{}
	for _, r := range results {
		if r.secret != "" {
			uniq[r.secret]++
		}
	}
	if len(uniq) != 25 {
		t.Fatalf("expected 25 unique reconned secrets across concurrent sources, got %d (results=%d)", len(uniq), len(results))
	}
	for s, n := range uniq {
		if n != 1 {
			t.Errorf("secret %s reconned %d times under concurrency, want 1", s, n)
		}
	}
	if progressTicks != len(srcs) {
		t.Errorf("progress called %d times, want %d (one per source)", progressTicks, len(srcs))
	}
}

func TestPipelineIsolatesModuleFailure(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(panicModule{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if b.Vars["PANIC_TOKEN"] != "" {
			return []recognize.Match{{Module: "panic", Fields: module.Fields{}, Secret: "x", Label: "PANIC_TOKEN"}}
		}
		return nil
	})
	b := parse.Parse("PANIC_TOKEN=1\n", ".env")
	results := Run(b, reg, Options{Live: false})
	found := false
	for _, r := range results {
		if strings.Contains(r.Note.Reason, "module error") {
			found = true
		}
	}
	if !found {
		t.Errorf("panic was not isolated into an error note: %+v", results)
	}
}

type panicModule struct{ module.Base }

func (panicModule) Name() string { return "panic" }
func (panicModule) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	panic("boom")
}
func (panicModule) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title}
}

func TestGuardedDialRefusesLinkLocal(t *testing.T) {
	_, err := recon.GuardedDial(context.Background(), "tcp", "169.254.169.254:80")
	if err != recon.ErrBlockedTarget {
		t.Errorf("link-local should be refused, got %v", err)
	}
}

func TestAnnotateContextExposureAndTimeline(t *testing.T) {
	when := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	b := parse.Parse("x", "/Users/x/Library/Application Support/Code/Crashpad/completed/abc.dmp")
	b.ModTime = when

	// live + a call was made → exposure (warn), source modified, validated live.
	res := Result{
		Note:    module.Note{Title: "t", Findings: []module.Finding{{Key: "user", Value: "bob"}}},
		Planned: []recon.PlannedCall{{Method: "GET"}},
	}
	annotateContext(&res, b, Options{Live: true, StartedAt: when})
	idx := map[string]module.Finding{}
	for _, f := range res.Note.Findings {
		idx[f.Key] = f
	}
	if idx["exposure"].Flag != module.FlagWarn || !strings.Contains(idx["exposure"].Value, "crash dump") {
		t.Errorf("crash-dump exposure not surfaced as warn: %+v", idx["exposure"])
	}
	if idx["source modified"].Value != "2026-06-05 (Fri)" {
		t.Errorf("source modified = %q", idx["source modified"].Value)
	}
	if idx["validated live"].Value != "2026-06-05T12:00:00Z" {
		t.Errorf("validated live = %q", idx["validated live"].Value)
	}
	// exposure/modified must lead the note (WHERE/WHEN first)
	if res.Note.Findings[0].Key != "exposure" {
		t.Errorf("exposure should lead the note, got %q", res.Note.Findings[0].Key)
	}

	// dry-run (no calls) → exposure/modified present, but NO validated-live stamp.
	res2 := Result{Note: module.Note{Title: "t", Findings: []module.Finding{{Key: "user", Value: "bob"}}}}
	annotateContext(&res2, b, Options{Live: false})
	for _, f := range res2.Note.Findings {
		if f.Key == "validated live" {
			t.Error("dry-run must not stamp validated-live")
		}
	}

	// dead credential → no context findings at all (not rendered anyway).
	res3 := Result{Note: module.Note{Title: "t", Invalid: true}}
	annotateContext(&res3, b, Options{Live: true, StartedAt: when})
	if len(res3.Note.Findings) != 0 {
		t.Errorf("invalid note must not get context findings: %+v", res3.Note.Findings)
	}
}

// TestHTTPClientAppliesRedirectPolicy: the redirect policy only protects
// credentials if the client geiger actually reconns with installs it. Without
// this, recon.CheckRedirect can sit unused and every module keeps leaking custom
// auth headers across a redirect.
func TestHTTPClientAppliesRedirectPolicy(t *testing.T) {
	c, err := httpClient(5*time.Second, "")
	if err != nil {
		t.Fatalf("httpClient: %v", err)
	}
	if c.CheckRedirect == nil {
		t.Fatal("recon HTTP client has no CheckRedirect: credential headers would follow a cross-host redirect")
	}
	req := httptest.NewRequest(http.MethodGet, "https://collector.attacker.tld/x", nil)
	req.Header.Set("X-Vault-Token", "hvs.TKN")
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://vault.acme.internal/v1/auth", nil)}
	if err := c.CheckRedirect(req, via); err != nil {
		t.Fatalf("CheckRedirect: %v", err)
	}
	if got := req.Header.Get("X-Vault-Token"); got != "" {
		t.Errorf("X-Vault-Token = %q after cross-host redirect, want stripped", got)
	}
}
