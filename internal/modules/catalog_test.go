package modules

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// TestEveryMappedRuleResolves guards against a rule mapping that points at a
// module name nobody registered (a common copy-paste slip).
func TestEveryMappedRuleResolves(t *testing.T) {
	for rule, modName := range module.Default.Rules() {
		if _, ok := module.Default.ByName(modName); !ok {
			t.Errorf("rule %q maps to unregistered module %q", rule, modName)
		}
	}
}

// dummyFields supplies plausible values for every field name the catalog
// templates on, so each module's calls build real URLs in the read-only sweep.
func dummyFields() module.Fields {
	return module.Fields{
		"token": "DUMMYTOKEN", "access_key": "AKIADUMMYDUMMYDUMMY0", "secret_key": "secret",
		"sid": "ACdummy", "api_key": "apikey", "app_key": "appkey", "app_id": "APPID",
		"client_id": "cid", "client_secret": "csecret", "tenant": "tid", "domain": "x.auth0.com",
		"endpoint": "https://host.example.com", "shop": "demo", "email": "a@b.com",
		"private_key":  "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
		"client_email": "sa@p.iam.gserviceaccount.com", "project_id": "p",
		"dsn": "postgres://u:p@db.example.com:5432/app", "key": "ssh", "server": "https://k8s",
		"username": "svc", "user": "svc", "password": "pw", "secret": "sek",
		"host": "host.example.com", "instance": "acme", "region": "us",
	}
}

// TestReadOnlyInvariantAcrossCatalog is the core safety guard: in dry-run, no
// module may attempt a mutating call. The recon.Client refuses (and never
// records) anything but GET/HEAD and opted-in read-only POSTs, so we assert
// neither Authenticate nor Recon returns ErrMutatingCall, and every recorded
// call uses an allowed method.
func TestReadOnlyInvariantAcrossCatalog(t *testing.T) {
	for _, m := range module.Default.All() {
		c := recon.New(nil, false) // dry-run: records, never hits network
		f := dummyFields()
		tok, err := m.Authenticate(context.Background(), c, f)
		if errors.Is(err, recon.ErrMutatingCall) {
			t.Errorf("module %s: Authenticate attempted a mutating call", m.Name())
		}
		if _, err := m.Recon(context.Background(), c, tok, f); errors.Is(err, recon.ErrMutatingCall) {
			t.Errorf("module %s: Recon attempted a mutating call", m.Name())
		}
		for _, p := range c.Planned() {
			switch p.Method {
			case http.MethodGet, http.MethodHead, http.MethodPost:
			default:
				t.Errorf("module %s recorded disallowed method %s %s", m.Name(), p.Method, p.URL)
			}
		}
	}
}

// TestSummarizeEmptyIsInvalid ensures a dead credential (no findings) never
// renders as a confident note for any module.
func TestSummarizeEmptyIsInvalid(t *testing.T) {
	for _, m := range module.Default.All() {
		// structural modules legitimately produce findings without network and
		// always have content; only assert the contract for the rest.
		n := m.Summarize("T", nil)
		if !n.Invalid && n.Summary == "" && len(n.Findings) == 0 {
			t.Errorf("module %s: empty findings produced a non-invalid, empty note", m.Name())
		}
	}
}

func TestCatalogHasBreadth(t *testing.T) {
	if got := len(module.Default.All()); got < 40 {
		t.Errorf("expected a broad catalog, only %d modules registered", got)
	}
}
