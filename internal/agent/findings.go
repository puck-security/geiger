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
	if f, ok := s.postureFinding(); ok {
		out = append(out, f)
	}
	out = append(out, s.capabilityFindings()...)
	out = append(out, s.chainFindings()...)
	out = append(out, s.serverFindings()...)
	out = append(out, s.hookFindings()...)
	out = append(out, s.evidenceFindings()...)
	return out
}

// evidenceFindings say how the reach above was established: typed from the
// config, or reported by the servers themselves.
func (s Surface) evidenceFindings() []module.Finding {
	if len(s.Servers) == 0 {
		return nil
	}
	enumerated, total := 0, len(s.Servers)
	stdio := 0
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
			Value: fmt.Sprintf("observed: all %d server(s) reported their own tool list", total),
			Flag:  module.FlagNone,
		}}
	}
	v := fmt.Sprintf("read from the config for %d of %d server(s) — what these packages are known to do, "+
		"not what this install was seen doing. Use --live to ask each server", total-enumerated, total)
	if stdio > 0 {
		v += fmt.Sprintf("; %d are local and also need --spawn-stdio, which runs the configured command", stdio)
	}
	return []module.Finding{{Key: "evidence", Value: v, Flag: module.FlagNone}}
}

// inventoryFinding is the always-present census line.
func (s Surface) inventoryFinding() module.Finding {
	stdio, remote := 0, 0
	for _, srv := range s.Servers {
		if srv.Transport == TransportHTTP {
			remote++
		} else {
			stdio++
		}
	}
	v := fmt.Sprintf("%d MCP server(s) wired to %s: %d local, %d remote",
		len(s.Servers), s.Runtime, stdio, remote)
	return module.Finding{Key: "tool chain", Value: v, Flag: module.FlagInfo}
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
			Value:  fmt.Sprintf("%d server(s) with no identified reach", len(benign)),
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
	sum := fmt.Sprintf("%s agent surface — %d server(s)", s.Runtime, len(s.Servers))
	if worst != "" {
		sum += ", reaches " + worst
	}
	if s.AutoApproved() {
		sum += ", auto-approved"
	}
	return sum
}
