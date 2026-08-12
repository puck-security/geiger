package module_test

import (
	"encoding/json"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	_ "github.com/puck-security/geiger/internal/modules" // register the catalog
)

// The file-store table is keyed by module name, so a rename in internal/modules
// silently unmarks a module — and the consumer's coverage guard goes quiet
// instead of failing, which is the exact failure mode the listing exists to
// prevent.
func TestFileStoreTableNamesAreRegistered(t *testing.T) {
	for _, name := range module.FileStoreNames() {
		if _, ok := module.Default.ByName(name); !ok {
			t.Errorf("file-store table names %q, which is not a registered module (renamed or removed?)", name)
		}
	}
}

func TestListingsCoverEveryModuleAndAreSorted(t *testing.T) {
	all := module.Default.All()
	ls := module.Default.Listings()
	if len(ls) != len(all) {
		t.Fatalf("Listings() returned %d entries for %d registered modules", len(ls), len(all))
	}
	for i := 1; i < len(ls); i++ {
		if ls[i-1].Name >= ls[i].Name {
			t.Fatalf("Listings() not sorted by name: %q before %q", ls[i-1].Name, ls[i].Name)
		}
	}
	byName := map[string]module.Listing{}
	for _, l := range ls {
		byName[l.Name] = l
	}
	for _, m := range all {
		if _, ok := byName[m.Name()]; !ok {
			t.Errorf("registered module %q missing from Listings()", m.Name())
		}
	}
}

func TestFileStoreMarksTheStoresAConsumerMustFind(t *testing.T) {
	byName := map[string]module.Listing{}
	for _, l := range module.Default.Listings() {
		byName[l.Name] = l
	}
	// Anchors: a credential that only exists inside a specific file. If one of
	// these ever reads false the listing has gone vacuous.
	for _, name := range []string{
		"aws", "aws_sso", "ssh_private_key", "kubeconfig", "mcp_config", "ai_ide_store",
	} {
		l, ok := byName[name]
		if !ok {
			t.Fatalf("expected module %q to be registered", name)
		}
		if !l.FileStore {
			t.Errorf("%q should be file-store-backed", name)
		}
	}
	// Counter-anchors: recognised from a token pattern in arbitrary text, so
	// they ride along in whatever file the walker already opened. Marking these
	// would make the consumer's guard demand paths that buy no coverage.
	for _, name := range []string{"github_pat", "slack", "stripe", "openai", "jwt"} {
		if l, ok := byName[name]; ok && l.FileStore {
			t.Errorf("%q is pattern-recognised, not file-store-backed", name)
		}
	}
}

func TestListingsMarshalToTheDocumentedShape(t *testing.T) {
	b, err := json.Marshal(module.Default.Listings()[:1])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back []map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := back[0]["name"]; !ok {
		t.Errorf("listing JSON has no \"name\" key: %s", b)
	}
	if _, ok := back[0]["file_store"]; !ok {
		t.Errorf("listing JSON has no \"file_store\" key: %s", b)
	}
}
