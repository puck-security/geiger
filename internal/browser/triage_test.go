package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func findingByKey(fs []module.Finding, key string) (module.Finding, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return module.Finding{}, false
}

func TestTriageFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"name":"x","manifest_version":3,"host_permissions":["<all_urls>"]}`), 0o600)
	// One file with: a real C2 websocket (public IP) + benign allowlisted ws host +
	// loopback + private IP + a plain domain HTTP URL. Only the C2 must survive.
	os.WriteFile(filepath.Join(dir, "bg.js"), []byte(`
		const c2   = "wss://45.32.11.22:8080/ws";
		const ok   = "wss://stream.googleapis.com/v1";
		const dev  = "ws://127.0.0.1:9222/devtools";
		const priv = "http://10.0.0.5/api";
		fetch("https://cdn.example.com/lib.js");
	`), 0o600)

	mani := map[string]any{"name": "x", "manifest_version": float64(3)}
	out := triageFindings(triageInput{
		profileDir: dir, id: "aaaabbbbccccddddeeeeffffgggghhhh",
		srcDir: dir, external: true, manifest: mani, intrusive: false,
	})

	// Context findings present and NON-severity (FlagNone) so they don't inflate the tier.
	for _, k := range []string{"id", "installed", "ui", "project"} {
		f, ok := findingByKey(out, k)
		if !ok {
			t.Errorf("missing context finding %q: %+v", k, out)
			continue
		}
		if f.Flag != module.FlagNone {
			t.Errorf("context finding %q must be FlagNone, got %v", k, f.Flag)
		}
	}
	if f, _ := findingByKey(out, "ui"); !strings.Contains(f.Value, "headless") {
		t.Errorf("no-UI manifest should read headless: %q", f.Value)
	}
	if f, _ := findingByKey(out, "id"); len(f.Detail) != 1 || f.Detail[0] != "aaaabbbbccccddddeeeeffffgggghhhh" {
		t.Errorf("id must be a machine-readable IOC in Detail: %+v", f)
	}

	// The IOC grep: warn, C2 flagged, everything benign filtered (the FP guards).
	ind, ok := findingByKey(out, "indicators")
	if !ok || ind.Flag != module.FlagWarn {
		t.Fatalf("expected an indicators warn finding: %+v", out)
	}
	joined := strings.Join(ind.Detail, ",")
	if !strings.Contains(joined, "45.32.11.22") {
		t.Errorf("public-IP C2 websocket must be flagged: %v", ind.Detail)
	}
	for _, benign := range []string{"googleapis", "127.0.0.1", "10.0.0.5", "example.com"} {
		if strings.Contains(joined, benign) {
			t.Errorf("false positive: %q should be filtered out, got %v", benign, ind.Detail)
		}
	}
}

func TestTriageProjectMarkersAndGating(t *testing.T) {
	// A dev checkout (has .git) with the C2 only in persisted STORAGE, not source.
	home := t.TempDir()
	prof := filepath.Join(home, "profile")
	src := filepath.Join(home, "my-ext")
	os.MkdirAll(filepath.Join(src, ".git"), 0o755)
	os.WriteFile(filepath.Join(src, "manifest.json"), []byte(`{"name":"x","manifest_version":3}`), 0o600)
	os.WriteFile(filepath.Join(src, "bg.js"), []byte(`console.log("hi")`), 0o600)
	// storage LevelDB with a plaintext C2 host
	les := filepath.Join(prof, "Local Extension Settings", "aaaabbbbccccddddeeeeffffgggghhhh")
	os.MkdirAll(les, 0o755)
	os.WriteFile(filepath.Join(les, "000003.log"), []byte("\x01\x00cfg\x00wss://198.51.100.7:443/c2\x00"), 0o600)

	in := triageInput{profileDir: prof, id: "aaaabbbbccccddddeeeeffffgggghhhh", srcDir: src, external: true,
		manifest: map[string]any{"name": "x"}}

	// project markers → dev project (.git)
	base := triageFindings(in)
	if f, _ := findingByKey(base, "project"); !strings.Contains(f.Value, ".git") {
		t.Errorf("expected dev-project markers: %q", f.Value)
	}
	// Without --intrusive, storage is NOT scanned → no indicators.
	if _, ok := findingByKey(base, "indicators"); ok {
		t.Errorf("storage must not be scanned without --intrusive: %+v", base)
	}
	// With --intrusive, the storage C2 host surfaces.
	in.intrusive = true
	got := triageFindings(in)
	ind, ok := findingByKey(got, "indicators")
	if !ok || !strings.Contains(strings.Join(ind.Detail, ","), "198.51.100.7") {
		t.Errorf("intrusive storage scan should surface the C2 host: %+v", got)
	}
}
