package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func parse(t *testing.T, file, raw string) Surface {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return ParseSurface(file, root)
}

func serverNamed(t *testing.T, s Surface, name string) Server {
	t.Helper()
	for _, srv := range s.Servers {
		if srv.Name == name {
			return srv
		}
	}
	t.Fatalf("no server %q in %v", name, s.Servers)
	return Server{}
}

func hasChain(cs []Chain, name string) bool {
	for _, c := range cs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func findingFor(fs []module.Finding, key string) (module.Finding, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return module.Finding{}, false
}

// The premise of the whole package: a config whose credentials are all stored
// correctly still has a blast radius, and it comes from the tool chain.
const noSecretsFixture = `{
  "mcpServers": {
    "fs":         {"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]},
    "confluence": {"command":"uvx","args":["mcp-atlassian"],"env":{"CONFLUENCE_URL":"https://acme.atlassian.net"}},
    "slack":      {"command":"npx","args":["-y","@modelcontextprotocol/server-slack"]},
    "clock":      {"command":"npx","args":["-y","@modelcontextprotocol/server-time"]}
  }
}`

func TestReachIsIndependentOfInlineSecrets(t *testing.T) {
	s := parse(t, "/home/u/.claude/settings.json", noSecretsFixture)
	set := s.Caps().Set()

	// Not one credential in the file, yet the agent reaches all of this.
	for _, want := range []Cap{CapCorpusSearch, CapFSRead, CapFSWrite, CapNetEgress, CapUntrustedIn} {
		if !set.Has(want) {
			t.Errorf("surface with no inline secrets must still report %s: %v", want.Name(), set.Names())
		}
	}
	if s.Runtime != "Claude Code" {
		t.Errorf("runtime = %q, want Claude Code", s.Runtime)
	}
}

// Bulk corpus read is the top-yield red-team primitive and must outrank a
// scoped read, not be folded into it.
func TestCorpusSearchIsAForceMultiplier(t *testing.T) {
	if got := CapCorpusSearch.Flag(false); got != module.FlagForceMultiplier {
		t.Errorf("corpus-search flag = %v, want force multiplier", got)
	}
	if got := CapDataRead.Flag(false); got != module.FlagWarn {
		t.Errorf("data-read flag = %v, want warn — it must NOT rank with corpus-search", got)
	}
	s := parse(t, "mcp.json", noSecretsFixture)
	f, ok := findingFor(s.Findings(), "corpus-search")
	if !ok {
		t.Fatal("no corpus-search finding")
	}
	if f.Flag != module.FlagForceMultiplier {
		t.Errorf("corpus-search finding flag = %v, want force multiplier", f.Flag)
	}
	// And it must not be doubled up with a redundant data-read line.
	if _, dup := findingFor(s.Findings(), "data-read"); dup {
		t.Error("data-read should be demoted when corpus-search is already present")
	}
}

// Filesystem scope is the entire difference between a project helper and a
// credential-harvesting primitive, and it lives in argv, not in the package name.
func TestFilesystemScopeDecidesSeverity(t *testing.T) {
	broad := parse(t, "mcp.json", `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}`)
	narrow := parse(t, "mcp.json", `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","./project"]}}}`)

	if !broad.Caps().BroadFS() {
		t.Error("a filesystem server rooted at / must be broad")
	}
	if narrow.Caps().BroadFS() {
		t.Error("a filesystem server rooted at ./project must NOT be broad")
	}
	bf, _ := findingFor(broad.Findings(), "fs-read")
	nf, _ := findingFor(narrow.Findings(), "fs-read")
	if bf.Flag != module.FlagForceMultiplier {
		t.Errorf("fs-read at / = %v, want force multiplier", bf.Flag)
	}
	if nf.Flag == module.FlagForceMultiplier {
		t.Error("fs-read at ./project must not be a force multiplier")
	}
}

func TestBroadPath(t *testing.T) {
	for _, p := range []string{"/", "~", "$HOME", "/home", "/Users", "/home/alice", "/Users/alice/", "~/", "/etc"} {
		if !broadPath(p) {
			t.Errorf("%q should be broad", p)
		}
	}
	for _, p := range []string{"./project", "/srv/app", "/home/alice/work/repo", "/Users/alice/code/x"} {
		if broadPath(p) {
			t.Errorf("%q should NOT be broad", p)
		}
	}
}

// The chains are the reason a surface-level view exists: none is visible from a
// single server.
func TestChains(t *testing.T) {
	s := parse(t, "mcp.json", noSecretsFixture)
	cs := Chains(s)
	for _, want := range []string{"corpus exfiltration", "lethal trifecta", "cross-server shadowing", "unpinned supply chain"} {
		if !hasChain(cs, want) {
			t.Errorf("missing chain %q; got %v", want, cs)
		}
	}

	// exec closure only when something actually runs code.
	if hasChain(cs, "exec closure") {
		t.Error("no exec tool on this surface, so no exec closure")
	}
	sh := parse(t, "mcp.json", `{"mcpServers":{"sh":{"command":"uvx","args":["mcp-server-shell"]}}}`)
	if !hasChain(Chains(sh), "exec closure") {
		t.Error("a shell server must produce exec closure")
	}

	// A lone corpus server has nowhere to send anything: no exfil chain.
	solo := parse(t, "mcp.json", `{"mcpServers":{"c":{"command":"uvx","args":["mcp-atlassian"]}}}`)
	if hasChain(Chains(solo), "corpus exfiltration") {
		t.Error("corpus search with no egress channel is not an exfiltration chain")
	}
}

// Shadowing is about content crossing a trust boundary, so a single server
// holding both legs is not it.
func TestShadowingNeedsTwoServers(t *testing.T) {
	one := parse(t, "mcp.json", `{"mcpServers":{"gh":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}}`)
	if lo, hi := shadowPair(one); lo != "" || hi != "" {
		t.Errorf("one server cannot shadow itself, got %q -> %q", lo, hi)
	}
	two := parse(t, "mcp.json", `{"mcpServers":{
		"web": {"command":"npx","args":["-y","@modelcontextprotocol/server-fetch"]},
		"sh":  {"command":"uvx","args":["mcp-server-shell"]},
		"wiki":{"command":"uvx","args":["mcp-atlassian"]}}}`)
	lo, hi := shadowPair(two)
	if lo == "" || hi == "" {
		t.Fatal("expected a shadowing pair")
	}
	// The counterpart named should be the strongest one available (exec beats
	// corpus-search), not whichever sorted first.
	if hi != "sh" {
		t.Errorf("shadow counterpart = %q, want the exec server %q", hi, "sh")
	}
}

func TestUnpinnedLaunch(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		want bool
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-filesystem"}, true},
		{"uvx", []string{"mcp-atlassian"}, true},
		{"npx", []string{"-y", "some-server@1.2.3"}, false},
		{"npx", []string{"./local/server.js"}, false},
		{"node", []string{"server.js"}, false},
		{"/usr/local/bin/uvx", []string{"pkg"}, true},
		{"docker", []string{"run", "img"}, false},
	}
	for _, c := range cases {
		if got := unpinnedLaunch(c.cmd, c.args); got != c.want {
			t.Errorf("unpinnedLaunch(%q, %v) = %v, want %v", c.cmd, c.args, got, c.want)
		}
	}
}

// A docker bind mount is reach the catalog cannot see: it is in argv, and it
// overrides whatever the image claims to be.
func TestDockerBindMountIsTyped(t *testing.T) {
	s := parse(t, "mcp.json", `{"mcpServers":{"d":{"command":"docker","args":["run","-i","-v","/:/host","some/image"]}}}`)
	srv := serverNamed(t, s, "d")
	set := srv.Caps.Set()
	if !set.Has(CapExec) {
		t.Error("a container launch is code execution")
	}
	if !srv.Caps.BroadFS() {
		t.Errorf("-v /:/host is the whole filesystem: %v", srv.Caps.Summary())
	}
}

// Auto-approval removes the last mitigation from every chain at once, so it is a
// property of the surface rather than of one server.
func TestApprovalPosture(t *testing.T) {
	none := parse(t, "mcp.json", noSecretsFixture)
	if none.AutoApproved() {
		t.Error("no allow rules and no per-server approval means a human is still in the loop")
	}
	if _, ok := findingFor(none.Findings(), "approval"); ok {
		t.Error("no approval finding should be emitted when nothing is pre-approved")
	}

	for _, raw := range []string{
		`{"mcpServers":{"sh":{"command":"uvx","args":["mcp-server-shell"]}},"permissions":{"allow":["mcp__sh__*"]}}`,
		`{"mcpServers":{"sh":{"command":"uvx","args":["mcp-server-shell"],"alwaysAllow":["run_command"]}}}`,
		`{"mcpServers":{"sh":{"command":"uvx","args":["mcp-server-shell"]}},"settings":{"yoloMode":true}}`,
	} {
		s := parse(t, "mcp.json", raw)
		if !s.AutoApproved() {
			t.Errorf("auto-approval not detected in %s", raw)
		}
		f, ok := findingFor(s.Findings(), "approval")
		if !ok {
			t.Fatalf("no approval finding for %s", raw)
		}
		// Real reach behind the approval makes it a force multiplier.
		if f.Flag != module.FlagForceMultiplier {
			t.Errorf("auto-approved exec should be a force multiplier, got %v", f.Flag)
		}
	}
}

// Hooks run shell on lifecycle events with no model and no approval anywhere in
// the path — more reach than any MCP tool, and nothing else inventories them.
func TestHooksAreReported(t *testing.T) {
	s := parse(t, "/home/u/.claude/settings.json", `{
		"hooks": {"PreToolUse": [{"hooks": [{"command": "/opt/ci/audit.sh"}]}]}}`)
	if len(s.Hooks) != 1 || s.Hooks[0].Command != "/opt/ci/audit.sh" {
		t.Fatalf("hook not parsed: %+v", s.Hooks)
	}
	f, ok := findingFor(s.Findings(), "hooks")
	if !ok {
		t.Fatal("no hooks finding")
	}
	if f.Flag != module.FlagForceMultiplier {
		t.Errorf("hooks flag = %v, want force multiplier", f.Flag)
	}
}

// Every client puts the server map somewhere different.
func TestServerMapLayouts(t *testing.T) {
	cases := map[string]string{
		"mcpServers":      `{"mcpServers":{"a":{"command":"x"}}}`,
		"servers":         `{"servers":{"a":{"command":"x"}}}`,
		"mcp.servers":     `{"mcp":{"servers":{"a":{"command":"x"}}}}`,
		"context_servers": `{"context_servers":{"a":{"command":"x"}}}`,
	}
	for name, raw := range cases {
		s := parse(t, "mcp.json", raw)
		if len(s.Servers) != 1 {
			t.Errorf("%s layout: got %d servers, want 1", name, len(s.Servers))
		}
	}
}

func TestRemoteTransportDetection(t *testing.T) {
	s := parse(t, "mcp.json", `{"mcpServers":{
		"a":{"url":"https://mcp.example.com/mcp"},
		"b":{"type":"sse","url":"http://internal.example.com/sse"},
		"c":{"command":"npx","args":["-y","pkg"]}}}`)
	if got := serverNamed(t, s, "a").Transport; got != TransportHTTP {
		t.Errorf("url implies remote, got %v", got)
	}
	if b := serverNamed(t, s, "b"); !b.PlaintextHTTP {
		t.Error("http:// remote server must be flagged as plaintext")
	}
	if got := serverNamed(t, s, "c").Transport; got != TransportStdio {
		t.Errorf("command implies stdio, got %v", got)
	}
}

// A config that types cleanly is scored on what it says. The config file is the
// observation; withholding a tier until enumeration would leave the default mode,
// which is the one most people run, reporting nothing.
func TestConfigTypedSurfaceIsScored(t *testing.T) {
	s := parse(t, "mcp.json", noSecretsFixture)
	if s.Enumerated() {
		t.Fatal("nothing has been enumerated yet")
	}
	n := s.Summarize("t")
	if n.Undetermined {
		t.Error("a surface typed from its config must be scored, not left Undetermined")
	}
	if _, ok := findingFor(n.Findings, "corpus-search"); !ok {
		t.Error("the typed reach must be reported")
	}
	// The reader still has to be told the reach came from the config, since the
	// tier no longer encodes that.
	e, ok := findingFor(n.Findings, "evidence")
	if !ok {
		t.Fatal("a config-typed surface must state how its reach was established")
	}
	if !strings.Contains(e.Value, "typed from the config") || !strings.Contains(e.Value, "--live") {
		t.Errorf("evidence should name the source and the way to confirm it: %q", e.Value)
	}
	if !strings.Contains(e.Value, "--spawn-stdio") {
		t.Errorf("stdio servers need the second flag named too: %q", e.Value)
	}
}

// Undetermined is kept for what it was meant for: servers are configured, but
// nothing about their reach could be established.
func TestUntypeableSurfaceIsUndetermined(t *testing.T) {
	s := parse(t, "mcp.json", `{"mcpServers":{"mystery":{"command":"./some-unknown-binary"}}}`)
	if len(s.Servers) != 1 {
		t.Fatalf("expected one server, got %d", len(s.Servers))
	}
	if !s.Caps().Set().Empty() {
		t.Fatalf("fixture should type to nothing, got %v", s.Caps().Summary())
	}
	n := s.Summarize("t")
	if !n.Undetermined {
		t.Error("a surface with no identifiable reach must be Undetermined")
	}
	if n.Reason == "" {
		t.Error("an Undetermined note must say why")
	}
}

// Once every server has reported its own tool list, the note says so.
func TestEnumeratedSurfaceReportsObservedEvidence(t *testing.T) {
	s := parse(t, "mcp.json", `{"mcpServers":{"sh":{"command":"uvx","args":["mcp-server-shell"]}}}`)
	s.Servers[0].Enumerated = true
	e, ok := findingFor(s.Summarize("t").Findings, "evidence")
	if !ok {
		t.Fatal("no evidence finding")
	}
	if !strings.Contains(e.Value, "observed") {
		t.Errorf("a fully enumerated surface should report observed reach: %q", e.Value)
	}
}

// A stdio server is never run without both gates, because running it executes an
// argv that came out of the scanned file.
func TestStdioSpawnIsGated(t *testing.T) {
	// A command that would be obvious if it ever ran.
	srv := Server{Name: "x", Transport: TransportStdio, Command: "/bin/echo", Args: []string{"hello"}}
	for _, o := range []SpawnOptions{
		{Live: false, Permitted: false},
		{Live: true, Permitted: false},
		{Live: false, Permitted: true},
	} {
		s := srv
		ran := false
		o.Record = func(string) { ran = true }
		EnumerateStdio(context.Background(), &s, o)
		if ran {
			t.Errorf("spawned with Live=%v Permitted=%v — both gates are required", o.Live, o.Permitted)
		}
		if s.Enumerated {
			t.Error("an un-spawned server must not be marked enumerated")
		}
		if !strings.Contains(s.EnumErr, "--spawn-stdio") {
			t.Errorf("the reason should name the missing flag, got %q", s.EnumErr)
		}
	}
}

// With both gates open, a real (trivial) server is enumerated and the argv is
// recorded before it starts.
func TestStdioSpawnEnumerates(t *testing.T) {
	// A one-line shell server: read requests, answer the tools/list (id 2).
	const reply = `{"jsonrpc":"2.0","id":2,"result":{"tools":[` +
		`{"name":"run_command","description":"run a shell command"},` +
		`{"name":"search_pages","description":"search all pages in the wiki"}]}}`
	srv := Server{
		Name: "x", Transport: TransportStdio,
		Command: "/bin/sh",
		Args:    []string{"-c", "cat >/dev/null & sleep 0.1; echo '" + reply + "'; sleep 0.2"},
	}
	var recorded string
	EnumerateStdio(context.Background(), &srv, SpawnOptions{
		Live: true, Permitted: true, Timeout: 5 * time.Second,
		Record: func(a string) { recorded = a },
	})
	if recorded == "" {
		t.Error("the argv must be recorded before the process starts")
	}
	if !srv.Enumerated {
		t.Fatalf("server not enumerated: %s", srv.EnumErr)
	}
	if len(srv.Tools) != 2 {
		t.Fatalf("tools = %v", srv.Tools)
	}
	set := srv.Caps.Set()
	if !set.Has(CapExec) {
		t.Error("run_command should classify as exec")
	}
	if !set.Has(CapCorpusSearch) {
		t.Error("search_pages should classify as corpus-search")
	}
}

func TestClassifyTools(t *testing.T) {
	caps, unclassified := ClassifyTools([]Tool{
		{Name: "execute_bash"},
		{Name: "search_confluence", Description: "search all pages"},
		{Name: "read_file"},
		{Name: "write_file"},
		{Name: "get_secret"},
		{Name: "create_pull_request"},
		{Name: "delete_bucket"},
		{Name: "send_slack_message"},
		{Name: "fetch", Description: "fetch a page from the web"},
		{Name: "zzz_undocumented_thing"},
	})
	set := caps.Set()
	for _, want := range []Cap{CapExec, CapCorpusSearch, CapFSRead, CapFSWrite, CapSecretsRead, CapCodeWrite, CapDestructive, CapNetEgress, CapUntrustedIn} {
		if !set.Has(want) {
			t.Errorf("missing %s from %v", want.Name(), set.Names())
		}
	}
	if unclassified != 1 {
		t.Errorf("unclassified = %d, want 1 — coverage must be reported honestly", unclassified)
	}
}

// A server prefix must not leak into the rules: "execute-api__get_status" is a
// read, not an exec tool.
func TestToolNameNamespaceIsStripped(t *testing.T) {
	caps, _ := ClassifyTools([]Tool{{Name: "execute_api__get_status"}})
	if caps.Set().Has(CapExec) {
		t.Errorf("the server prefix must not be matched as a verb: %v", caps.Summary())
	}
}

// tools/list is the protocol's own inventory method and must go out as a
// read-only POST; tools/call must never be issued.
func TestRemoteEnumerationIsReadOnly(t *testing.T) {
	var methods []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		methods = append(methods, req.Method)
		if r.Header.Get("Mcp-Method") == "" {
			t.Error("the 2026 spec requires an Mcp-Method header on streamable-HTTP POSTs")
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search_all_docs","description":"search all documents"}]}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer ts.Close()

	srv := Server{Name: "r", Transport: TransportHTTP, URL: ts.URL}
	EnumerateRemote(context.Background(), recon.New(ts.Client(), true), &srv)

	if !srv.Enumerated {
		t.Fatalf("not enumerated: %s", srv.EnumErr)
	}
	if !srv.Caps.Set().Has(CapCorpusSearch) {
		t.Errorf("search_all_docs should be corpus-search: %v", srv.Caps.Summary())
	}
	for _, m := range methods {
		if strings.HasPrefix(m, "tools/call") {
			t.Fatal("tools/call must never be issued — that is exercising reach, not enumerating it")
		}
	}
	// No auth header was configured and the server answered anyway.
	if !srv.Unauthenticated {
		t.Error("a server that lists tools with no credential is open to anyone who can route to it")
	}
}

// A 401 names the authorization server that actually gates the reach.
func TestRemoteEnumerationRecordsAuthServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://idp.example.com/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	srv := Server{Name: "r", Transport: TransportHTTP, URL: ts.URL}
	EnumerateRemote(context.Background(), recon.New(ts.Client(), true), &srv)
	if srv.Enumerated {
		t.Error("a 401 is not an enumeration")
	}
	if !strings.Contains(srv.AuthServer, "idp.example.com") {
		t.Errorf("authorization server not recorded: %q (err %q)", srv.AuthServer, srv.EnumErr)
	}
}

// Dry-run makes no call at all, and says what --live would do.
func TestRemoteEnumerationDryRun(t *testing.T) {
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer ts.Close()

	srv := Server{Name: "r", Transport: TransportHTTP, URL: ts.URL}
	c := recon.New(ts.Client(), false)
	EnumerateRemote(context.Background(), c, &srv)
	if hit {
		t.Fatal("dry-run must not send a request")
	}
	if srv.Enumerated {
		t.Error("dry-run enumerates nothing")
	}
	if len(c.Planned()) == 0 {
		t.Error("dry-run should still record the planned call")
	}
}

// An SSE-framed reply to a POST is still one JSON-RPC response.
func TestDecodeSSEFramedResponse(t *testing.T) {
	body := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n")
	raw, err := decodeRPC(body)
	if err != nil {
		t.Fatalf("SSE-framed response should decode: %v", err)
	}
	if !strings.Contains(string(raw), "tools") {
		t.Errorf("result = %s", raw)
	}
}

func TestCapsMergeKeepsBroaderScope(t *testing.T) {
	var cs Caps
	cs = cs.Add(Capability{Cap: CapFSRead, Scope: "./a"})
	cs = cs.Add(Capability{Cap: CapFSRead, Scope: "/", Broad: true})
	if len(cs) != 1 {
		t.Fatalf("the same primitive must merge, got %d entries", len(cs))
	}
	if !cs[0].Broad || cs[0].Scope != "/" {
		t.Errorf("the broader scope must win: %+v", cs[0])
	}
}
