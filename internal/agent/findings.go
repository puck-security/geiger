package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Rendering a Surface into geiger's finding vocabulary.
//
// Scoring discipline. Reading a config file tells you what an agent is wired
// to. It does not tell you whether that is appropriate: a filesystem server
// scoped to a project directory is the normal setup, and geiger has no way to
// know from the file whether the machine it is on is a laptop or a build
// runner. So the inventory carries no weight. The census line is the one
// informational finding; capability lines, server lines and the evidence
// caveat are context.
//
// Weight is attached only where the config itself establishes something:
//
//   - a filesystem root that is broad (/ or $HOME) rather than scoped,
//   - a chain, where several capabilities meet in one context (chains.go),
//   - approval turned off, which removes the human from every chain at once,
//   - a server observed answering with no credential, or reached over plaintext.
//
// This keeps an ordinary developer setup at INFO and reserves the top of the
// scale for surfaces where the file says something specific went wrong.

// Findings renders the surface as note findings, worst first.
func (s Surface) Findings() []module.Finding {
	var out []module.Finding
	out = append(out, s.inventoryFinding())

	// Nothing about the servers' reach could be established. The capability,
	// chain and per-server lines are all empty in that case, and four lines
	// saying so in different words are worse than one, so stop here — the
	// census line names the servers and the note's undetermined reason says
	// what would change it. Two things still get reported: the approval posture,
	// because prompts being off is a fact about the file rather than about what
	// the servers reach, and what came back when a server was asked, because
	// "nothing answered" is the answer to the reader's next question.
	if f, ok := s.postureFinding(); ok {
		out = append(out, f)
	}
	if s.Untypeable() {
		if f, ok := s.enumerationFinding(); ok {
			out = append(out, f)
		}
		out = append(out, s.exposureFindings()...)
		return append(out, s.hookFindings()...)
	}
	out = append(out, s.capabilityFindings()...)
	out = append(out, s.chainFindings()...)
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

// enumerationFinding reports what came back when the servers were asked.
//
// A note that says only "the reach is unknown" leaves the obvious question
// unanswered: were they even running? geiger knows — it has the connection
// error — and not saying so reads as if the flags did nothing. Servers that
// were never asked (no --live, or a local server without --spawn-stdio) are not
// reported here; the undetermined reason names the missing flag instead.
func (s Surface) enumerationFinding() (module.Finding, bool) {
	asked, answered := 0, 0
	var detail []string
	for _, srv := range s.Servers {
		if !srv.Asked {
			continue
		}
		asked++
		if srv.Enumerated {
			answered++
			continue
		}
		detail = append(detail, srv.Name+": "+enumOutcome(srv))
	}
	if asked == 0 {
		return module.Finding{}, false
	}
	sort.Strings(detail)
	v := fmt.Sprintf("%d of %s answered", answered, plural(asked, "server"))
	if answered == 0 {
		v += " — nothing is serving them right now. The agent still starts them when it needs them, " +
			"so this bounds what geiger could confirm, not what the agent reaches"
	}
	return module.Finding{Key: "asked", Value: v, Flag: module.FlagNone, Detail: detail}, true
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
		return "nothing is listening on " + where
	case strings.Contains(e, "no such host"), strings.Contains(e, "name resolution"):
		return "the host in " + where + " does not resolve"
	case strings.Contains(e, "executable file not found"), strings.Contains(e, "no such file"):
		return "`" + where + "` is not installed on this machine"
	case strings.Contains(e, "timeout"), strings.Contains(e, "deadline exceeded"), strings.Contains(e, "timed out"):
		return "timed out"
	case strings.Contains(e, "authentication required"):
		return "the credential in this config was not accepted"
	case strings.Contains(e, "certificate"), strings.Contains(e, "tls"):
		return "TLS handshake failed"
	case srv.EnumErr == "":
		return "no tool list came back"
	}
	return srv.EnumErr
}

// exposureFindings report the two conditions that are about a server itself
// rather than about its reach, so they survive a surface nothing could be typed
// on. Both need --live: no config says either.
func (s Surface) exposureFindings() []module.Finding {
	var out []module.Finding
	for _, srv := range s.Servers {
		if srv.Unauthenticated {
			out = append(out, module.Finding{
				Key:    "open tool surface",
				Value:  srv.Name + " answered tools/list with no credential, so anyone who can route to it has its tools",
				Flag:   module.FlagForceMultiplier,
				Detail: []string{srv.URL},
			})
		}
		if srv.PlaintextHTTP {
			out = append(out, module.Finding{
				Key:    "plaintext",
				Value:  srv.Name + " is reached over http, so its credential crosses the wire in clear",
				Flag:   module.FlagWarn,
				Detail: []string{srv.URL},
			})
		}
	}
	return out
}

// evidenceFindings say how the reach above was established: read from the
// config, or reported by the servers themselves. Only a flag that is not
// already in use is named — telling someone to pass --live when they just did
// reads like the tool did not notice.
func (s Surface) evidenceFindings() []module.Finding {
	if len(s.Servers) == 0 {
		return nil
	}
	enumerated, stdio := 0, 0
	total := len(s.Servers)
	for _, srv := range s.Servers {
		if srv.Enumerated {
			enumerated++
		} else if srv.Transport == TransportStdio {
			stdio++
		}
	}
	if enumerated == total {
		return []module.Finding{{
			Key:   "evidence",
			Value: fmt.Sprintf("observed: all %s reported their own tool list", plural(total, "server")),
			Flag:  module.FlagNone,
		}}
	}
	v := fmt.Sprintf("read from the config for %d of %d servers — what these packages are known to do, "+
		"not what this install was seen doing", total-enumerated, total)
	switch {
	case !s.Live:
		v += ". --live asks each server directly"
	case stdio > 0 && !s.SpawnStdio:
		v += fmt.Sprintf(". %d are local; --spawn-stdio runs each configured command to ask it", stdio)
	}
	return []module.Finding{{Key: "evidence", Value: v, Flag: module.FlagNone}}
}

// plural renders "1 server" / "3 servers".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// inventoryFinding is the always-present census line. When nothing about the
// servers could be typed it also names them, because the name and the command
// are then the only facts there are and they are what the reader goes and looks
// up.
func (s Surface) inventoryFinding() module.Finding {
	stdio, remote := 0, 0
	for _, srv := range s.Servers {
		if srv.Transport == TransportHTTP {
			remote++
		} else {
			stdio++
		}
	}
	v := fmt.Sprintf("%s wired to %s: %d local, %d remote",
		plural(len(s.Servers), "MCP server"), s.Runtime, stdio, remote)
	f := module.Finding{Key: "tool chain", Value: v, Flag: module.FlagInfo}
	if s.Untypeable() {
		names, detail := serverNamesAndLaunch(s)
		f.Value = fmt.Sprintf("%s wired to %s (%s): %d local, %d remote",
			plural(len(s.Servers), "MCP server"), s.Runtime, names, stdio, remote)
		f.Detail = detail
	}
	return f
}

// serverNamesAndLaunch renders the server names for a one-line summary, capped
// so a laptop with a dozen servers does not produce an unreadable line, plus the
// full name-and-launch list for the detail.
func serverNamesAndLaunch(s Surface) (string, []string) {
	names := make([]string, 0, len(s.Servers))
	detail := make([]string, 0, len(s.Servers))
	for _, srv := range s.Servers {
		names = append(names, srv.Name)
		switch {
		case srv.URL != "":
			detail = append(detail, srv.Name+": "+srv.URL)
		case srv.Command != "":
			detail = append(detail, srv.Name+": "+strings.TrimSpace(srv.Command+" "+strings.Join(srv.Args, " ")))
		default:
			detail = append(detail, srv.Name+": no command or url in the config")
		}
	}
	sort.Strings(names)
	sort.Strings(detail)
	const cap = 4
	if len(names) > cap {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:cap], ", "), len(names)-cap), detail
	}
	return strings.Join(names, ", "), detail
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
		how = append(how, "prompts disabled for the whole runtime")
	}
	if n := len(s.AllowRules); n > 0 {
		how = append(how, fmt.Sprintf("%d blanket allow rule(s)", n))
	}
	var perServer []string
	for _, srv := range s.Servers {
		if len(srv.AutoApproved) == 0 {
			continue
		}
		if approvedAll(srv) {
			perServer = append(perServer, srv.Name+" (all tools)")
			continue
		}
		perServer = append(perServer, fmt.Sprintf("%s (%d tool(s))", srv.Name, len(autoApprovedTools(srv))))
	}
	if len(perServer) > 0 {
		how = append(how, "pre-approved servers: "+strings.Join(perServer, ", "))
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
		Key:    "approval",
		Value:  "no prompt before a tool runs — " + strings.Join(how, "; "),
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

// capabilityFindings list the surface's total reach, one line per primitive,
// each naming the servers that supply it. Inventory: see the note at the top of
// this file for why these carry no weight.
func (s Surface) capabilityFindings() []module.Finding {
	caps := s.Caps().Sorted()
	broad := s.Caps().BroadFS()
	// Read and write at the same broad path are one fact. Mark the first line
	// only, so a server that does both does not count twice.
	marked := false
	out := make([]module.Finding, 0, len(caps))
	for _, c := range caps {
		v := c.Cap.Why()
		if c.Scope != "" {
			v = "scope " + c.Scope + " — " + v
		}
		flag := module.FlagNone
		if broad && (c.Cap == CapFSRead || c.Cap == CapFSWrite) && !marked {
			v += " — anywhere on the disk or in the home directory, not one project"
			flag, marked = c.Cap.Flag(true), true
		}
		out = append(out, module.Finding{
			Key:    c.Cap.Name(),
			Value:  v,
			Flag:   flag,
			Detail: serversWith(s, c.Cap),
		})
	}
	return out
}

// chainFindings report the compositions.
func (s Surface) chainFindings() []module.Finding {
	chains := Chains(s)
	out := make([]module.Finding, 0, len(chains))
	for _, c := range chains {
		out = append(out, module.Finding{
			Key:    "chain: " + c.Name,
			Value:  c.Why,
			Flag:   c.Flag,
			Detail: c.Via,
		})
	}
	return out
}

// serverFindings list the servers. Servers with no identified reach are
// collapsed into a count, the way --browser collapses narrow extensions: a long
// list of harmless servers buries the two that matter.
func (s Surface) serverFindings() []module.Finding {
	var out []module.Finding
	var benign []string
	for _, srv := range s.Servers {
		// No identified reach and nothing observed to contradict that. The
		// enumeration note is not evidence either way — every local server that
		// was not spawned carries one — so it does not keep a server off this
		// list.
		if srv.Caps.Set().Empty() && !srv.Unauthenticated && !srv.PlaintextHTTP {
			benign = append(benign, srv.Name)
			continue
		}
		out = append(out, serverFinding(srv))
	}
	if len(benign) > 0 {
		sort.Strings(benign)
		out = append(out, module.Finding{
			Key:    "narrow servers",
			Value:  plural(len(benign), "server") + " with no identified reach",
			Flag:   module.FlagNone,
			Detail: benign,
		})
	}
	return out
}

// serverFinding renders one server. The line is inventory unless the server was
// observed doing something a config cannot show: answering with no credential,
// or being reached over plaintext http.
func serverFinding(srv Server) module.Finding {
	var parts []string
	if srv.Label != "" {
		parts = append(parts, srv.Label)
	}
	parts = append(parts, string(srv.Transport))
	if srv.Enumerated {
		parts = append(parts, fmt.Sprintf("%d tools observed", len(srv.Tools)))
	} else {
		parts = append(parts, "not enumerated")
	}
	head := strings.Join(parts, ", ")

	v := head + " — " + srv.Caps.Summary()
	flag := module.FlagNone

	detail := append([]string(nil), srv.Tools...)
	if srv.Transport == TransportHTTP && srv.URL != "" {
		detail = append(detail, "url: "+srv.URL)
	}
	if srv.Command != "" {
		detail = append(detail, "command: "+strings.TrimSpace(srv.Command+" "+strings.Join(srv.Args, " ")))
	}
	if envs := srv.CredentialEnvNames(); len(envs) > 0 {
		detail = append(detail, "inherits credentials from: "+strings.Join(envs, ", "))
	}
	if srv.EnumErr != "" {
		detail = append(detail, "enumeration: "+srv.EnumErr)
	}
	if srv.ResourceCount > 0 || srv.PromptCount > 0 {
		detail = append(detail, fmt.Sprintf("%d resources, %d prompts", srv.ResourceCount, srv.PromptCount))
	}

	if srv.Unauthenticated {
		v += " — answers tools/list with no credential, so this tool surface is open to anyone who can route to it"
		flag = module.FlagForceMultiplier
	}
	if srv.PlaintextHTTP {
		v += " — reached over plaintext http, so its token crosses the wire in clear"
		if flag < module.FlagWarn {
			flag = module.FlagWarn
		}
	}
	if srv.AuthServer != "" {
		detail = append(detail, "authorization server: "+srv.AuthServer)
	}

	return module.Finding{Key: "server " + srv.Name, Value: v, Flag: flag, Detail: detail}
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
		for _, h := range s.Hooks {
			detail = append(detail, h.Event+": "+h.Command)
		}
		out = append(out, module.Finding{
			Key: "hooks",
			Value: fmt.Sprintf("%d hook(s) run shell commands when the agent hits a lifecycle event — "+
				"no model and no approval in that path", len(s.Hooks)),
			Flag:   module.FlagInfo,
			Detail: detail,
		})
	}
	if n := len(s.Skills) + len(s.Subagents); n > 0 {
		detail := append(append([]string(nil), s.Skills...), s.Subagents...)
		out = append(out, module.Finding{
			Key:    "instruction surface",
			Value:  fmt.Sprintf("%d skill(s)/subagent(s) load instructions the agent follows", n),
			Flag:   module.FlagNone,
			Detail: detail,
		})
	}
	return out
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
	if len(s.Servers) > 0 && s.Caps().Set().Empty() {
		n.Undetermined = true
		n.Reason = "servers are configured but none could be typed: no catalog entry, no recognizable " +
			"arguments, and no tool list observed. Re-run with --live (and --spawn-stdio for local servers) " +
			"to ask each server what it exposes"
	}
	return n
}

// Summary is the one-line takeaway.
func (s Surface) Summary() string {
	if len(s.Servers) == 0 {
		return string(s.Runtime) + " config — no MCP servers configured"
	}
	caps := s.Caps().Set()
	worst := ""
	for _, c := range allCaps {
		if caps.Has(c) {
			worst = c.Name()
			break
		}
	}
	sum := fmt.Sprintf("%s agent surface — %s", s.Runtime, plural(len(s.Servers), "server"))
	switch {
	case worst != "":
		sum += ", reaches " + worst
	case s.Untypeable():
		sum += ", reach unknown"
	}
	if s.AutoApproved() {
		sum += ", auto-approved"
	}
	return sum
}
