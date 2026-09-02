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

// A device list shaped like the real fields=all response: one plain laptop, one
// subnet router that also advertises a default route (an exit node), and one
// tagged CI node whose key never expires.
const tsDevices = `{"devices":[
 {"nodeId":"n1","name":"laptop.tail1a2b3.ts.net","hostname":"laptop","os":"macOS",
  "user":"dev@acme.com","addresses":["100.64.0.1"],"keyExpiryDisabled":false,
  "enabledRoutes":[],"advertisedRoutes":[],"tags":null},
 {"nodeId":"n2","name":"gw.tail1a2b3.ts.net","hostname":"gw","os":"linux",
  "user":"ops@acme.com","addresses":["100.64.0.2"],"keyExpiryDisabled":false,
  "enabledRoutes":["10.0.0.0/8","192.168.1.0/24","0.0.0.0/0","::/0"],
  "advertisedRoutes":["10.0.0.0/8","192.168.1.0/24","0.0.0.0/0","::/0"],"tags":["tag:subnetrouter"]},
 {"nodeId":"n3","name":"ci.tail1a2b3.ts.net","hostname":"ci","os":"linux",
  "user":"ci@acme.com","addresses":["100.64.0.3"],"keyExpiryDisabled":true,
  "enabledRoutes":[],"advertisedRoutes":[],"tags":["tag:ci"]}]}`

const tsACL = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
 "ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["autogroup:nonroot","root"]}],
 "tagOwners":{"tag:ci":["group:eng"]}}`

const tsKeys = `{"keys":[
 {"id":"kAAA1CNTRL","keyType":"api","scopes":["all"],"description":"prod key"},
 {"id":"kBBB2CNTRL","keyType":"client","scopes":["all"],"description":"ci client"},
 {"id":"kCCC3CNTRL","keyType":"auth","capabilities":{"devices":{"create":{"reusable":true,"ephemeral":false,"preauthorized":true}}}}]}`

// tsMux serves the three read-only endpoints the shared recon walks. wantAuth is
// the Authorization header every call must carry.
func tsMux(t *testing.T, wantAuth string, hits map[string]int) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	check := func(w http.ResponseWriter, r *http.Request, body string) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("%s: Authorization = %q, want %q", r.URL.Path, got, wantAuth)
		}
		hits[r.URL.Path]++
		respond(w, body)
	}
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fields") != "all" {
			t.Errorf("devices call must ask for fields=all, got %q", r.URL.RawQuery)
		}
		check(w, r, tsDevices)
	})
	mux.HandleFunc("/api/v2/tailnet/-/acl", func(w http.ResponseWriter, r *http.Request) { check(w, r, tsACL) })
	mux.HandleFunc("/api/v2/tailnet/-/keys", func(w http.ResponseWriter, r *http.Request) { check(w, r, tsKeys) })
	return mux
}

func TestTailscaleAPIKeyRecon(t *testing.T) {
	hits := map[string]int{}
	got := driveModule(t, "tailscale", module.Fields{"token": "tskey-api-kAAA1CNTRL-secret"},
		tsMux(t, "Bearer tskey-api-kAAA1CNTRL-secret", hits))

	if got["tailnet"].Value != "tail1a2b3.ts.net" {
		t.Errorf("tailnet not derived from device names: %+v", got["tailnet"])
	}
	if got["devices"].Value != "3" {
		t.Errorf("devices = %q, want 3", got["devices"].Value)
	}
	// The finding that decides blast radius: the tailnet bridges into RFC1918.
	routes := got["subnet routes"]
	if routes.Flag != module.FlagForceMultiplier {
		t.Errorf("subnet routes must be a force multiplier, got %+v", routes)
	}
	if !strings.Contains(routes.Value, "10.0.0.0/8") || !strings.Contains(routes.Value, "192.168.1.0/24") {
		t.Errorf("subnet routes should name the internal CIDRs: %q", routes.Value)
	}
	// A default route is an exit node, not a subnet route, and must not be
	// reported as internal address space.
	if strings.Contains(routes.Value, "0.0.0.0/0") || strings.Contains(routes.Value, "::/0") {
		t.Errorf("default routes must not be listed as subnet routes: %q", routes.Value)
	}
	if got["exit nodes"].Flag != module.FlagForceMultiplier {
		t.Errorf("exit nodes must be a force multiplier: %+v", got["exit nodes"])
	}
	if got["tailscale ssh"].Flag != module.FlagForceMultiplier {
		t.Errorf("tailscale ssh must be a force multiplier: %+v", got["tailscale ssh"])
	}
	if got["key expiry disabled"].Value != "1" {
		t.Errorf("key expiry disabled = %q, want 1", got["key expiry disabled"].Value)
	}
	if got["access rules"].Value != "1" {
		t.Errorf("access rules = %q, want 1", got["access rules"].Value)
	}
	if got["other keys"].Value == "" {
		t.Error("expected an inventory of the tailnet's other keys")
	}
	for _, p := range []string{"/api/v2/tailnet/-/devices", "/api/v2/tailnet/-/acl", "/api/v2/tailnet/-/keys"} {
		if hits[p] != 1 {
			t.Errorf("%s hit %d times, want 1", p, hits[p])
		}
	}
}

// The ACL and keys calls are optional: a scoped token that may read devices but
// not the policy file still has to produce a full note.
func TestTailscaleAPIKeyPartialScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) { respond(w, tsDevices) })
	mux.HandleFunc("/api/v2/tailnet/-/acl", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc("/api/v2/tailnet/-/keys", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	got := driveModule(t, "tailscale", module.Fields{"token": "tskey-api-x-y"}, mux)
	if got["devices"].Value != "3" {
		t.Errorf("a 403 on an optional call must not lose the device inventory: %+v", got)
	}
	if _, ok := got["tailscale ssh"]; ok {
		t.Error("ssh finding invented from a forbidden ACL read")
	}
}

// A tailnet on the newer "grants" syntax leaves acls empty. Counting only acls
// there reported a fully-configured tailnet as having no rules at all.
func TestTailscaleACLCountsGrantsNotJustACLs(t *testing.T) {
	fs := tsACLFindings([]byte(`{"acls":[],"grants":[{"src":["*"],"dst":["*:*"],"ip":["*"]}],
	 "ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"]}]}`))
	got := indexByKey(fs)
	if got["access rules"].Value != "1" {
		t.Errorf("a grants-only policy must still count its rules, got %+v", got["access rules"])
	}
	if got["acl wide open"].Flag != module.FlagForceMultiplier {
		t.Errorf("a wide-open grant must be flagged like a wide-open acl: %+v", got)
	}
}

// An empty policy file must stay silent rather than printing a zero that reads
// as "this tailnet has no rules".
func TestTailscaleACLEmptyEmitsNoCount(t *testing.T) {
	got := indexByKey(tsACLFindings([]byte(`{"acls":[],"grants":[]}`)))
	if _, ok := got["access rules"]; ok {
		t.Errorf("a zero rule count must not be emitted: %+v", got)
	}
}

func TestTailscaleOAuthClientExchangeAndRecon(t *testing.T) {
	hits := map[string]int{}
	mux := tsMux(t, "Bearer tskey-api-minted", hits)
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("token exchange must be POST, got %s", r.Method)
		}
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "tskey-client-kBBB2CNTRL-secret" {
			t.Errorf("client_secret not sent: %v", r.Form)
		}
		respond(w, `{"access_token":"tskey-api-minted","token_type":"Bearer","expires_in":3600,"scope":"all"}`)
	})
	got := driveModule(t, "tailscale_oauth_client",
		module.Fields{"client_secret": "tskey-client-kBBB2CNTRL-secret"}, mux)

	if got["scopes"].Value != "all" {
		t.Errorf("granted scopes not reported: %+v", got["scopes"])
	}
	if got["scopes"].Flag != module.FlagForceMultiplier {
		t.Errorf("the all scope must be a force multiplier: %+v", got["scopes"])
	}
	// The reason an OAuth client beats a stolen API key: it never expires.
	if !strings.Contains(strings.ToLower(got["no expiry"].Value), "not expire") {
		t.Errorf("must state that trust credentials do not expire: %+v", got["no expiry"])
	}
	// The minted token must actually drive the recon.
	if got["devices"].Value != "3" || got["subnet routes"].Flag != module.FlagForceMultiplier {
		t.Errorf("recon did not run with the minted token: %+v", got)
	}
	if hits["/api/v2/tailnet/-/devices"] != 1 {
		t.Errorf("devices hit %d times", hits["/api/v2/tailnet/-/devices"])
	}
}

// A client whose scope can mint auth keys can enroll attacker nodes without
// ever touching the API again.
func TestTailscaleOAuthClientAuthKeysScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		respond(w, `{"access_token":"tskey-api-minted","token_type":"Bearer","expires_in":3600,"scope":"auth_keys devices:core:read"}`)
	})
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) { respond(w, tsDevices) })
	mux.HandleFunc("/api/v2/tailnet/-/acl", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc("/api/v2/tailnet/-/keys", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	got := driveModule(t, "tailscale_oauth_client", module.Fields{"client_secret": "tskey-client-k-s"}, mux)
	if got["node enrollment"].Flag != module.FlagForceMultiplier {
		t.Errorf("auth_keys scope must flag node enrollment: %+v", got["node enrollment"])
	}
}

// A revoked secret must come back dead, and must not reach recon.
func TestTailscaleOAuthClientRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		respond(w, `{"message":"API token invalid"}`)
	})
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) {
		t.Error("recon must not run after the exchange was refused")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := recon.New(&http.Client{Transport: rewriteTransport{base: srv.Listener.Addr().String(), rt: http.DefaultTransport}}, true)
	mod, _ := module.Default.ByName("tailscale_oauth_client")
	if _, err := mod.Authenticate(context.Background(), c, module.Fields{"client_secret": "tskey-client-k-dead"}); err == nil {
		t.Fatal("a 401 from the token endpoint must be an auth error, so the note reads dead")
	}
}

// A transport failure proves nothing. It must not retire a live secret.
func TestTailscaleOAuthClientUnreachableIsNotDead(t *testing.T) {
	srv := httptest.NewServer(http.NewServeMux())
	addr := srv.Listener.Addr().String()
	srv.Close() // nothing is listening now
	c := recon.New(&http.Client{Transport: rewriteTransport{base: addr, rt: http.DefaultTransport}}, true)
	mod, _ := module.Default.ByName("tailscale_oauth_client")
	tok, err := mod.Authenticate(context.Background(), c, module.Fields{"client_secret": "tskey-client-k-s"})
	if err != nil {
		t.Fatalf("an unreachable endpoint must not be reported as a rejection: %v", err)
	}
	fs, err := mod.Recon(context.Background(), c, tok, module.Fields{"client_secret": "tskey-client-k-s"})
	if err != nil {
		t.Fatalf("recon: %v", err)
	}
	n := mod.Summarize("t", fs)
	if !n.Undetermined || n.Invalid {
		t.Errorf("unreachable must be undetermined, not dead: %+v", n)
	}
}

// An auth key cannot be validated read-only: redeeming one registers a device,
// which is a write. The module must state the reach and make no call.
func TestTailscaleAuthKeyIsUnverifiedAndMakesNoCall(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("auth-key module must make no call, got %s %s", r.Method, r.URL.Path)
	})
	got := driveModule(t, "tailscale_auth_key", module.Fields{"token": "tskey-auth-kCCC3CNTRL-secret"}, mux)
	if got["reach"].Value == "" {
		t.Error("the reach of a leaked auth key must be stated")
	}
	mod, _ := module.Default.ByName("tailscale_auth_key")
	fs, _ := mod.Recon(context.Background(), recon.New(http.DefaultClient, false), module.Token{},
		module.Fields{"token": "tskey-auth-k-s"})
	n := mod.Summarize("t", fs)
	if !n.Undetermined || n.Invalid {
		t.Errorf("an untestable auth key is undetermined, never dead: %+v", n)
	}
	// The reason has to say WHY geiger stopped, not just that it did: redeeming
	// registers a device, which is a write this tool does not make.
	for _, want := range []string{"redeem", "registers a new device", "scope"} {
		if !strings.Contains(n.Reason, want) {
			t.Errorf("reason must explain the write it declined to make (missing %q): %q", want, n.Reason)
		}
	}
}

func TestTailscaleRecognizers(t *testing.T) {
	cases := []struct{ name, raw, module, secret string }{
		{"api key by env name", "TAILSCALE_API_KEY=tskey-api-kAAA-s\n", "tailscale", "tskey-api-kAAA-s"},
		{"api key bare on stdin", "tskey-api-kAAA1CNTRL-abcdefghij\n", "tailscale", "tskey-api-kAAA1CNTRL-abcdefghij"},
		{"auth key by env name", "TS_AUTHKEY=tskey-auth-kCCC-s\n", "tailscale_auth_key", "tskey-auth-kCCC-s"},
		{"auth key bare on stdin", "tskey-auth-kCCC3CNTRL-abcdefghij\n", "tailscale_auth_key", "tskey-auth-kCCC3CNTRL-abcdefghij"},
		{"auth key in compose yaml", "services:\n  ts:\n    environment:\n      - TS_AUTHKEY=tskey-auth-kCCC3CNTRL-abcdefghij\n", "tailscale_auth_key", "tskey-auth-kCCC3CNTRL-abcdefghij"},
		{"oauth client by env name", "TS_OAUTH_CLIENT_SECRET=tskey-client-kBBB-s\n", "tailscale_oauth_client", "tskey-client-kBBB-s"},
		{"oauth client bare on stdin", "tskey-client-kBBB2CNTRL-abcdefghij\n", "tailscale_oauth_client", "tskey-client-kBBB2CNTRL-abcdefghij"},
		{"legacy bare auth key", "TAILSCALE_AUTHKEY=tskey-abcdef1432341818\n", "tailscale_auth_key", "tskey-abcdef1432341818"},
		{"k8s operator secret", "client_id: kBBB2CNTRL\nclient_secret: tskey-client-kBBB2CNTRL-abcdefghij\n", "tailscale_oauth_client", "tskey-client-kBBB2CNTRL-abcdefghij"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			by := modulesOf(recognize.Recognize(parse.Parse(tc.raw, ".env"), "", module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
			if _, generic := by["generic_secret"]; generic {
				t.Error("a recognized Tailscale key must not also surface as generic_secret")
			}
		})
	}
}

// The OAuth client id sits inside the secret, so a leaked secret is self-contained.
func TestTailscaleOAuthClientIDRecoveredFromSecret(t *testing.T) {
	by := modulesOf(recognize.Recognize(parse.Parse("TS_OAUTH_CLIENT_SECRET=tskey-client-kBBB2CNTRL-abcdefghij\n", ".env"), "", module.Default))
	m, ok := by["tailscale_oauth_client"]
	if !ok {
		t.Fatal("oauth client not recognized")
	}
	if m.Fields["client_id"] != "kBBB2CNTRL" {
		t.Errorf("client_id = %q, want kBBB2CNTRL (embedded in the secret)", m.Fields["client_id"])
	}
}

// Values that merely start with the prefix but carry no key body must not be
// promoted to a Tailscale credential.
func TestTailscaleRecognizerIgnoresNonKeys(t *testing.T) {
	for _, raw := range []string{"FOO=tskey-\n", "FOO=tskey-api\n", "NOTE=see tskey- docs\n"} {
		by := modulesOf(recognize.Recognize(parse.Parse(raw, ".env"), "", module.Default))
		for _, name := range []string{"tailscale", "tailscale_auth_key", "tailscale_oauth_client"} {
			if _, ok := by[name]; ok {
				t.Errorf("%q must not be recognized as %s", raw, name)
			}
		}
	}
}
