package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

type prefetchMod struct{ module.Base }

func (prefetchMod) Name() string { return "prefetch" }
func (prefetchMod) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{{Key: "ok", Value: "x", Flag: module.FlagInfo}}, nil
}
func (prefetchMod) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs}
}

// The offline path recognizes sources through a worker pool but must still
// triage them serially in input order. A secret present in several files is
// reported against the FIRST one, with the rest rolled up under "also exposed
// in" — if recognition order leaked into triage, the primary would vary between
// runs of the same scan.
func TestOfflineBatchKeepsFirstSourceAsPrimary(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(prefetchMod{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["PF_TOKEN"]; v != "" {
			return []recognize.Match{{Module: "prefetch", Fields: module.Fields{"token": v}, Secret: v, Label: "PF_TOKEN"}}
		}
		return nil
	})

	const sec = "prefetch-secret-abc123xyz"
	files := []string{"a-first.env", "b.env", "c.env", "d.env", "e-last.env"}
	srcs := make([]Source, len(files))
	for i, f := range files {
		srcs[i] = Source{Label: f, Blob: parse.Parse("PF_TOKEN="+sec+"\n", f)}
	}

	for run := range 10 {
		bt := NewBatch(reg, Options{Live: false})
		got := bt.RunConcurrent(srcs, nil, nil)
		bt.AnnotateDuplicates(got)

		var hits []Result
		for _, r := range got {
			if r.secret == sec {
				hits = append(hits, r)
			}
		}
		if len(hits) != 1 {
			t.Fatalf("run %d: shared secret reconned %d times across %d files, want 1", run, len(hits), len(files))
		}
		if !strings.Contains(hits[0].Note.Title, files[0]) {
			t.Fatalf("run %d: primary is %q, want the first source (%s)", run, hits[0].Note.Title, files[0])
		}
		var dup *module.Finding
		for i, f := range hits[0].Note.Findings {
			if f.Key == "also exposed in" {
				dup = &hits[0].Note.Findings[i]
			}
		}
		if dup == nil {
			t.Fatalf("run %d: primary not annotated with the other locations: %+v", run, hits[0].Note.Findings)
		}
		if len(dup.Detail) != len(files)-1 {
			t.Fatalf("run %d: %d other locations, want %d", run, len(dup.Detail), len(files)-1)
		}
		for i, p := range dup.Detail {
			if want := files[i+1]; p != want {
				t.Fatalf("run %d: other location %d is %s, want %s", run, i, p, want)
			}
		}
	}
}

// Recognition running ahead of triage must not change which sources produce
// results, nor their order.
func TestOfflineBatchResultOrderFollowsInputOrder(t *testing.T) {
	reg := module.NewRegistry()
	reg.Register(prefetchMod{})
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if v := b.Vars["PF_ORDER"]; v != "" {
			return []recognize.Match{{Module: "prefetch", Fields: module.Fields{"token": v}, Secret: v, Label: "PF_ORDER"}}
		}
		return nil
	})

	var srcs []Source
	var want []string
	for i := range 40 {
		f := string(rune('a'+i%26)) + "-" + itoa(i) + ".env"
		// Every other source holds nothing recognizable, so gaps in the result
		// sequence are exercised too.
		body := "NOTHING=here\n"
		if i%2 == 0 {
			body = "PF_ORDER=order-secret-" + itoa(i) + "\n"
			want = append(want, f)
		}
		srcs = append(srcs, Source{Label: f, Blob: parse.Parse(body, f)})
	}

	for run := range 10 {
		bt := NewBatch(reg, Options{Live: false})
		got := bt.RunConcurrent(srcs, nil, nil)
		if len(got) != len(want) {
			t.Fatalf("run %d: %d results, want %d", run, len(got), len(want))
		}
		for i, r := range got {
			if !strings.Contains(r.Note.Title, want[i]) {
				t.Fatalf("run %d: result %d is %q, want one from %s", run, i, r.Note.Title, want[i])
			}
		}
	}
}
