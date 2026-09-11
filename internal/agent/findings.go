package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Rendering a Surface into geiger's finding vocabulary.
//
// Density. A note is read by someone deciding what to look at, and the facts
// they need are the server, the endpoint, the tools and the reach. Prose around
// those facts pushes them off the line and repeats, run after run, what the
// reader learned the first time. So a line here names things instead of
// counting them, glosses a primitive in three words, and stops.
//
// Scoring discipline. Reading a config file tells you what an agent is wired
// to. It does not tell you whether that is appropriate: a filesystem server
// scoped to a project directory is the normal setup, and geiger has no way to
// know from the file whether the machine it is on is a laptop or a build
// runner. So the inventory carries no weight.
//
// Weight is attached only where the config itself establishes something:
//
//   - a filesystem root that is broad (/ or $HOME) rather than scoped,
//   - a chain, where several capabilities meet in one context (chains.go),
//   - approval turned off, which removes the human from every chain at once,
//   - a server observed serving content with no credential, or reached over
//     plaintext.
//
// This keeps an ordinary developer setup at INFO and reserves the top of the
// scale for surfaces where the file says something specific went wrong.

// Findings renders the surface as note findings, worst first.
func (s Surface) Findings() []module.Finding {
	var out []module.Finding
	out = append(out, s.capabilityFindings()...)
	out = append(out, s.chainFindings()...)
	if f, ok := s.postureFinding(); ok {
		out = append(out, f)
	}
	out = append(out, s.serverFindings()...)
	out = append(out, s.hookFindings()...)
	out = append(out, s.evidenceFindings()...)
	return out
}

// Untypeable reports that servers are configured but nothing is known about
// what any of them exposes.
func (s Surface) Untypeable() bool {
	return len(s.Servers) > 0 && s.Caps().Set().Empty()
}

// capabilityFindings list the surface's total reach, one line per primitive:
// a three-word gloss, then the servers and the tools that typed it.
func (s Surface) capabilityFindings() []module.Finding {
	caps := s.Caps().Sorted()
	broad := s.Caps().BroadFS()
	// Read and write at the same broad path are one fact. Mark the first line
	// only, so a server that does both does not count twice.
	marked := false
	out := make([]module.Finding, 0, len(caps))
	for _, c := range caps {
		v := gloss(c.Cap, remoteFS(s, c.Cap))
		if c.Scope != "" {
			v += " (" + c.Scope + ")"
		}
		flag := module.FlagNone
		if broad && (c.Cap == CapFSRead || c.Cap == CapFSWrite) && !marked {
			v += " — whole disk or home, not one project"
			flag, marked = c.Cap.Flag(true), true
		}
		src := capSources(s, c.Cap)
		if len(src) > 0 {
			v += " · " + capped(src, 3, "; ")
		}
		out = append(out, module.Finding{
			Key:    c.Cap.Name(),
			Value:  v,
			Flag:   flag,
			Detail: overflow(src, 3),
		})
	}
	return out
}

// gloss is the primitive in a few words. Cap.Why is a sentence written for
// someone meeting the word once; a note is read by someone who has met it
// before, and the sentence costs the same space as the server and tool names
// that are the actual news.
func gloss(c Cap, remote bool) string {
	if remote && (c == CapFSRead || c == CapFSWrite) {
		// "local files" is false for a hosted server: get_file there reads the
		// workspace at the other end of the wire, not this disk.
		if c == CapFSRead {
			return "reads server-side files"
		}
		return "writes server-side files"
	}
	switch c {
	case CapExec:
		return "runs commands here"
	case CapCorpusSearch:
		return "bulk store read"
	case CapSecretsRead:
		return "reads a secret store"
	case CapCodeWrite:
		return "pushes code"
	case CapCloudControl:
		return "cloud control plane"
	case CapDestructive:
		return "deletes/terminates"
	case CapIdentityAdmin:
		return "writes to an IdP"
	case CapFSRead:
		return "reads local files"
	case CapFSWrite:
		return "writes local files"
	case CapDataRead:
		return "reads private data"
	case CapNetEgress:
		return "data out, caller picks the URL"
	case CapUntrustedIn:
		return "reads attacker-influenced content"
	}
	return c.Name()
}

// remoteFS reports a filesystem primitive that comes only from remote servers,
// whose files are on their own host rather than on this one.
func remoteFS(s Surface, c Cap) bool {
	if c != CapFSRead && c != CapFSWrite {
		return false
	}
	seen := false
	for _, srv := range s.Servers {
		if !srv.Caps.Set().Has(c) {
			continue
		}
		if srv.Transport != TransportHTTP {
			return false
		}
		seen = true
	}
	return seen
}

// capSources names each server that supplies a primitive and, where the server
// reported its own tool list, the tools that typed it.
func capSources(s Surface, c Cap) []string {
	var out []string
	for _, srv := range s.Servers {
		if !srv.Caps.Set().Has(c) {
			continue
		}
		entry := srv.Name
		if tools := toolsFor(srv, c); len(tools) > 0 {
			entry += ": " + capped(tools, 3, ", ")
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out
}

// toolsFor returns the enumerated tool names that typed a primitive on one
// server. Capabilities read off a package name carry no tools, and the server
// name alone is then the whole of what is known.
func toolsFor(srv Server, c Cap) []string {
	var out []string
	for _, cp := range srv.Caps {
		if cp.Cap != c {
			continue
		}
		for _, e := range strings.Split(cp.Evidence, ", ") {
			if t, ok := strings.CutPrefix(e, "tool:"); ok {
				out = append(out, t)
			}
		}
	}
	return out
}

// chainFindings report the compositions. The value is the path — which server
// supplies which leg — because that is what an operator acts on.
func (s Surface) chainFindings() []module.Finding {
	chains := Chains(s)
	out := make([]module.Finding, 0, len(chains))
	for _, c := range chains {
		out = append(out, module.Finding{
			Key:   c.Name,
			Value: c.Why,
			Flag:  c.Flag,
		})
	}
	return out
}

// postureFinding reports whether a human approves tool calls. This is not a
// fact about one server: it removes the prompt from every chain on the surface
// at once, so it is reported as a property of the surface. It carries weight
// only in proportion to what is behind it — turning off prompts for a clock
// server is housekeeping.
func (s Surface) postureFinding() (module.Finding, bool) {
	if !s.AutoApproved() {
		return module.Finding{}, false
	}
	var how []string
	if s.SkipPermissions {
		how = append(how, "runtime bypass")
	}
	if n := len(s.AllowRules); n > 0 {
		how = append(how, plural(n, "allow rule"))
	}
	for _, srv := range s.Servers {
		if len(srv.AutoApproved) == 0 {
			continue
		}
		if approvedAll(srv) {
			how = append(how, srv.Name+" (all tools)")
			continue
		}
		how = append(how, fmt.Sprintf("%s (%s)", srv.Name, plural(len(autoApprovedTools(srv)), "tool")))
	}

	// A chain with no prompt in front of it is the case worth the top weight:
	// the last thing standing between a poisoned page and the action is gone.
	flag := module.FlagInfo
	switch {
	case hasForceMultiplier(Chains(s)):
		flag = module.FlagForceMultiplier
	case s.Caps().Set()&highReach != 0:
		flag = module.FlagWarn
	}
	return module.Finding{
		Key:    "no approval",
		Value:  strings.Join(how, " · "),
		Flag:   flag,
		Detail: s.AllowRules,
	}, true
}

// hasForceMultiplier reports whether any chain is top-weight.
func hasForceMultiplier(cs []Chain) bool {
	for _, c := range cs {
		if c.Flag == module.FlagForceMultiplier {
			return true
		}
	}
	return false
}

// serverFindings give a line per server: where it is, what came back, what it
// reaches, and anything wrong with the server itself.
//
// Servers with nothing to report collapse into one line that names them, the
// way --browser collapses narrow extensions: a long list of harmless servers
// buries the two that matter. Narrow is the only state that collapses. A server
// nothing could type is unknown reach rather than none, and a server that was
// asked and never answered is neither — both keep their own line.
func (s Surface) serverFindings() []module.Finding {
	var out []module.Finding
	var narrow []string
	for _, srv := range s.Servers {
		if isNarrow(srv) {
			narrow = append(narrow, srv.Name+labelSuffix(srv))
			continue
		}
		out = append(out, serverFinding(srv))
	}
	if len(narrow) > 0 {
		sort.Strings(narrow)
		out = append(out, module.Finding{
			Key:   "no reach",
			Value: strings.Join(narrow, " · "),
			Flag:  module.FlagNone,
		})
	}
	return out
}

// isNarrow reports a server that answered, or that the catalog knows, and
// exposes no reach primitive.
func isNarrow(srv Server) bool {
	if !srv.Caps.Set().Empty() || srv.OpenSurface() || srv.PlaintextHTTP {
		return false
	}
	if srv.Asked && !srv.Enumerated {
		return false // it did not answer; that is not a clean bill of health
	}
	return srv.Enumerated || srv.Label != ""
}

// serverFinding renders one server: endpoint · state · reach · what is wrong.
func serverFinding(srv Server) module.Finding {
	parts := []string{srvEndpoint(srv), srvState(srv)}
	if names := srv.Caps.Set().Names(); len(names) > 0 {
		parts = append(parts, strings.Join(names, ", "))
	} else {
		parts = append(parts, "reach unknown")
	}
	flag := module.FlagNone
	if srv.OpenSurface() {
		parts = append(parts, openSurfaceWhy(srv))
		flag = openSurfaceFlag(srv)
	}
	if srv.PlaintextHTTP {
		parts = append(parts, "cleartext http — the token crosses the wire in clear")
		if flag < module.FlagWarn {
			flag = module.FlagWarn
		}
	}

	detail := append([]string(nil), srv.Tools...)
	if envs := srv.CredentialEnvNames(); len(envs) > 0 {
		detail = append(detail, "inherits credentials from: "+strings.Join(envs, ", "))
	}
	if srv.AuthServer != "" {
		detail = append(detail, "authorization server: "+srv.AuthServer)
	}
	if srv.EnumErr != "" {
		detail = append(detail, "enumeration: "+srv.EnumErr)
	}
	return module.Finding{Key: srv.Name, Value: strings.Join(parts, " · "), Flag: flag, Detail: detail}
}

// srvState says what came back, or why nothing did.
//
// "Not asked" is a third answer and the one that used to go missing. --live
// asks every remote server over HTTP; a local one is only asked under
// --spawn-stdio, because asking it means running the command in the config. A
// reader who does not know that reads "not typed" as a failure. The remedy is
// named once, on the evidence line.
func srvState(srv Server) string {
	switch {
	case srv.Enumerated:
		s := plural(len(srv.Tools), "tool")
		if srv.ResourceCount > 0 {
			s += ", " + plural(srv.ResourceCount, "resource")
		}
		if srv.PromptCount > 0 {
			s += ", " + plural(srv.PromptCount, "prompt")
		}
		return s
	case srv.Asked:
		return enumOutcome(srv)
	}
	return "not asked"
}

// enumOutcome turns a transport error into something an operator can act on.
// The exact error is already in the audit trail; what belongs in the note is
// which of a handful of things went wrong.
func enumOutcome(srv Server) string {
	e := strings.ToLower(srv.EnumErr)
	where := srv.URL
	if where == "" {
		where = strings.TrimSpace(srv.Command + " " + strings.Join(srv.Args, " "))
	}
	switch {
	case strings.Contains(e, "connection refused"):
		return "nothing listening"
	case strings.Contains(e, "no such host"), strings.Contains(e, "name resolution"):
		return "host does not resolve"
	case strings.Contains(e, "executable file not found"), strings.Contains(e, "no such file"):
		return "`" + where + "` not installed"
	case strings.Contains(e, "timeout"), strings.Contains(e, "deadline exceeded"), strings.Contains(e, "timed out"):
		return "timed out"
	case strings.Contains(e, "authentication required"):
		return "credential refused"
	case strings.Contains(e, "certificate"), strings.Contains(e, "tls"):
		return "TLS handshake failed"
	case srv.EnumErr == "":
		return "no tool list"
	}
	return "no tool list"
}

// labelSuffix adds the catalog's name for a server, unless that is what the
// server is already called in the config.
func labelSuffix(srv Server) string {
	if srv.Label == "" || squash(srv.Label) == squash(srv.Name) {
		return ""
	}
	return " (" + srv.Label + ")"
}

// squash reduces a name to its letters and digits, so "sequential-thinking" and
// "sequential thinking" compare equal.
func squash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// srvEndpoint renders where a server is, in the form the reader would use to go
// and look at it: the URL for a remote server, the launch command for a local
// one.
func srvEndpoint(srv Server) string {
	if srv.Transport == TransportHTTP {
		if srv.URL != "" {
			return srv.URL
		}
		return "http, no url"
	}
	cmd := strings.TrimSpace(srv.Command + " " + strings.Join(srv.Args, " "))
	if cmd == "" {
		return "stdio, no command"
	}
	// The word says the transport, which says which flag reaches this server.
	// A remote one shows a URL, and its scheme says the same thing.
	return "stdio " + truncate(cmd, 52)
}

// truncate bounds a command line so one long argv does not push the reach off
// the end of the line. The full string stays in the detail. It counts runes:
// cutting a multi-byte character in half would produce a rune the renderer
// drops, and the line would lose a character with nothing to show for it.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// openSurfaceKey and openSurfaceFlag separate the two cases. See Server.OpenData
// for why a public tool list and readable content are not the same finding.
func openSurfaceFlag(srv Server) module.FlagLevel {
	if srv.OpenData() {
		return module.FlagForceMultiplier
	}
	return module.FlagWarn
}

// openSurfaceWhy states what an unauthenticated answer means. geiger never
// sends the credential in the config, so whatever came back was served to an
// anonymous caller — the token in the file is not what gates it.
//
// What that is worth depends on what came back. Tool names say what the server
// offers; geiger never calls a tool, so it cannot say whether a call needs the
// key, and the line does not claim otherwise. Resources are the data itself.
func openSurfaceWhy(srv Server) string {
	if srv.OpenData() {
		return fmt.Sprintf("OPEN: %s served to a request with no credential",
			plural(srv.ResourceCount, "resource"))
	}
	why := "tool list public"
	if len(srv.HeaderNames) > 0 {
		why += " (" + strings.Join(srv.HeaderNames, ", ") + " not needed; calls untested)"
		return why
	}
	return why + " (no credential sent; calls untested)"
}

// hookFindings list lifecycle shell commands and the instruction surface. A
// hook is not a tool the model chooses to call — the runtime runs it on an
// event, so no model and no approval sit in that path. That is worth a look,
// and nothing else inventories it; whether the command is dangerous depends on
// what it is, which is why the commands are in the detail.
func (s Surface) hookFindings() []module.Finding {
	var out []module.Finding
	if len(s.Hooks) > 0 {
		detail := make([]string, 0, len(s.Hooks))
		events := make([]string, 0, len(s.Hooks))
		for _, h := range s.Hooks {
			detail = append(detail, h.Event+": "+h.Command)
			events = append(events, h.Event)
		}
		out = append(out, module.Finding{
			Key:    "hooks",
			Value:  capped(events, 4, ", ") + " — shell on a lifecycle event, no model and no approval in that path",
			Flag:   module.FlagInfo,
			Detail: detail,
		})
	}
	if n := len(s.Skills) + len(s.Subagents); n > 0 {
		detail := append(append([]string(nil), s.Skills...), s.Subagents...)
		out = append(out, module.Finding{
			Key:     "instructions",
			Value:   fmt.Sprintf("%d skill(s)/subagent(s) the agent loads and follows", n),
			Flag:    module.FlagNone,
			Detail:  detail,
			Verbose: true,
		})
	}
	return out
}

// evidenceFindings say how the reach above was established: enumerated from the
// servers themselves, or read off the config. It names the servers rather than
// counting them, and names the flag that would settle the rest — but only a
// flag the reader has not already passed.
func (s Surface) evidenceFindings() []module.Finding {
	if len(s.Servers) == 0 {
		return nil
	}
	var enumerated, fromConfig []string
	stdio := 0
	for _, srv := range s.Servers {
		switch {
		case srv.Enumerated:
			enumerated = append(enumerated, srv.Name)
		case !srv.Caps.Set().Empty():
			// Its reach is geiger's reading of a package name. A server with no
			// reach at all is already marked "not typed" on its own line.
			fromConfig = append(fromConfig, srv.Name)
		}
		if !srv.Enumerated && srv.Transport == TransportStdio {
			stdio++
		}
	}
	var v []string
	if len(enumerated) > 0 {
		v = append(v, capped(enumerated, 4, ", ")+" enumerated")
	}
	if len(fromConfig) > 0 {
		v = append(v, capped(fromConfig, 4, ", ")+" typed from the package name, not observed")
	}
	switch {
	case len(s.Servers) == len(enumerated):
	case !s.Live:
		v = append(v, "--live asks the remote ones over http")
		if stdio > 0 {
			v = append(v, "--spawn-stdio runs "+plural(stdio, "local server")+" to ask")
		}
	case stdio > 0 && !s.SpawnStdio:
		v = append(v, "--spawn-stdio runs "+plural(stdio, "local server")+" to ask (--live only asks remote ones)")
	}
	if len(v) == 0 {
		return nil
	}
	return []module.Finding{{Key: "evidence", Value: strings.Join(v, " · "), Flag: module.FlagNone}}
}

// plural renders "1 server" / "3 servers".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// capped joins a list, keeping the first n and counting the rest. What it drops
// is in the finding's Detail, so nothing is lost — this only bounds the line an
// operator reads first.
func capped(items []string, n int, sep string) string {
	if len(items) <= n {
		return strings.Join(items, sep)
	}
	return fmt.Sprintf("%s%s+%d more", strings.Join(items[:n], sep), sep, len(items)-n)
}

// overflow returns the detail list for a capped line, and nothing when the line
// already showed everything. A -v expansion that repeats the line above it is
// noise dressed as evidence.
func overflow(items []string, n int) []string {
	if len(items) <= n {
		return nil
	}
	return items
}

// Summarize builds the note and applies the Undetermined rule.
//
// A config is not a credential. For a credential, Undetermined means geiger
// could not establish the thing is even live, so putting a tier on it would
// invent a severity. Here the config file is the observation: "server-filesystem
// /" in the arguments is read off disk, and what it grants is not in doubt.
// Only the exact tool list is, and that changes precision, not the class of
// reach.
//
// Withholding a tier until enumeration would also make the common case useless.
// Most servers are local, and enumerating those needs --spawn-stdio, which runs
// third-party code and often cannot be run at all — so the default mode, the one
// people actually use, would never report anything.
//
// Undetermined is kept for the case it was meant for: servers are configured
// but nothing about their reach could be established.
func (s Surface) Summarize(title string) module.Note {
	fs := s.Findings()
	n := module.Note{Title: title, Findings: fs, Summary: s.Summary()}
	if s.Untypeable() {
		n.Undetermined = true
		n.Reason = "no catalog entry, no recognizable arguments, no tool list"
	}
	return n
}

// Summary is the one-line takeaway: runtime, size, worst reach.
func (s Surface) Summary() string {
	if len(s.Servers) == 0 {
		return string(s.Runtime) + " — no MCP servers configured"
	}
	stdio, remote := 0, 0
	for _, srv := range s.Servers {
		if srv.Transport == TransportHTTP {
			remote++
		} else {
			stdio++
		}
	}
	sum := fmt.Sprintf("%s · %s", s.Runtime, plural(len(s.Servers), "server"))
	if stdio > 0 && remote > 0 {
		sum += fmt.Sprintf(" (%d local, %d remote)", stdio, remote)
	}
	if names := s.Caps().Set().Names(); len(names) > 0 {
		sum += " · " + capped(names, 4, ", ")
	} else {
		sum += " · reach unknown"
	}
	if s.AutoApproved() {
		sum += " · no approval prompt"
	}
	return sum
}
