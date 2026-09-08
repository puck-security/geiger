package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Rendering a Surface into geiger's finding vocabulary.
//
// A surface that types cleanly is scored, whether or not its servers were
// enumerated: the config file is itself an observation of what the agent is
// wired to. Undetermined is kept for the case where servers are configured but
// nothing about their reach could be established. See Surface.Summarize for the
// reasoning, and evidenceFindings for how the note tells the reader which of the
// two it is looking at.

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

// evidenceFindings say how the reach above was established. The tier no longer
// encodes that, so the note states it plainly: a config-typed surface is scored
// on what its servers are known to do, and --live replaces that with what they
// report doing.
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
			Value: fmt.Sprintf("reach observed: all %d server(s) reported their own tool list", total),
			Flag:  module.FlagInfo,
		}}
	}
	v := fmt.Sprintf("reach typed from the config for %d of %d server(s) — what these servers are known to do, "+
		"not what this deployment was seen doing. Re-run with --live to ask each one", total-enumerated, total)
	if stdio > 0 {
		v += fmt.Sprintf("; %d are stdio and also need --spawn-stdio, which runs the configured command", stdio)
	}
	return []module.Finding{{Key: "evidence", Value: v, Flag: module.FlagInfo}}
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
	v := fmt.Sprintf("%d MCP server(s) wired to %s: %d stdio, %d remote",
		len(s.Servers), s.Runtime, stdio, remote)
	return module.Finding{Key: "tool chain", Value: v, Flag: module.FlagInfo}
}

// postureFinding reports the approval posture. Auto-approval is not a finding
// about one server — it removes the human from every chain on the surface at
// once, which is why it is reported as a property of the surface and why it
// carries force-multiplier weight when real reach sits behind it.
func (s Surface) postureFinding() (module.Finding, bool) {
	if !s.AutoApproved() {
		return module.Finding{}, false
	}
	var how []string
	if s.SkipPermissions {
		how = append(how, "permission prompts disabled runtime-wide")
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

	// Weight follows what is actually reachable without a human. Auto-approving
	// a time server is housekeeping; auto-approving exec or a secret store means
	// the last mitigation on every chain below is gone.
	flag := module.FlagWarn
	if s.Caps().Set()&forceMultipliers != 0 {
		flag = module.FlagForceMultiplier
	}
	return module.Finding{
		Key: "approval",
		Value: "no human in the loop — " + strings.Join(how, "; ") +
			". Every capability below is reachable without a prompt.",
		Flag:   flag,
		Detail: s.AllowRules,
	}, true
}

// capabilityFindings report the surface's total reach, one line per primitive,
// each carrying the servers that supply it.
func (s Surface) capabilityFindings() []module.Finding {
	caps := s.Caps().Sorted()
	broad := s.Caps().BroadFS()
	out := make([]module.Finding, 0, len(caps))
	for _, c := range caps {
		v := c.Cap.Why()
		if c.Scope != "" {
			v = "scope " + c.Scope + " — " + v
		}
		out = append(out, module.Finding{
			Key:    c.Cap.Name(),
			Value:  v,
			Flag:   c.Cap.Flag(broad && (c.Cap == CapFSRead || c.Cap == CapFSWrite)),
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

// serverFindings report per-server detail. Servers with no identified reach are
// collapsed into a count, the way --browser collapses narrow extensions: a long
// inventory of benign servers buries the two that matter.
func (s Surface) serverFindings() []module.Finding {
	var out []module.Finding
	var benign []string
	for _, srv := range s.Servers {
		// No identified reach and nothing observed to contradict that. The
		// enumeration note is not evidence either way — every un-spawned stdio
		// server carries one — so it does not keep a benign server in the list.
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
			Flag:   module.FlagInfo,
			Detail: benign,
		})
	}
	return out
}

// serverFinding renders one server.
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
	flag := module.FlagInfo
	switch {
	case srv.Caps.Set()&forceMultipliers != 0, srv.Caps.BroadFS():
		flag = module.FlagForceMultiplier
	case srv.Caps.Set()&warnCaps != 0:
		flag = module.FlagWarn
	}

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

	// Two conditions that are about the server itself rather than its reach, and
	// that an operator acts on directly.
	if srv.Unauthenticated {
		v += " — ANSWERS tools/list WITH NO CREDENTIAL: this tool surface is open to anyone who can route to it"
		flag = module.FlagForceMultiplier
	}
	if srv.PlaintextHTTP {
		v += " — reached over plaintext http://, so its token crosses the wire in clear"
		if flag < module.FlagWarn {
			flag = module.FlagWarn
		}
	}
	if srv.AuthServer != "" {
		detail = append(detail, "authorization server: "+srv.AuthServer)
	}

	return module.Finding{Key: "server " + srv.Name, Value: v, Flag: flag, Detail: detail}
}

// hookFindings report lifecycle shell commands. A hook is not a tool the model
// chooses to call — the runtime runs it on an event — so it executes with no
// model and no approval anywhere in the path. That is strictly more reach than
// any MCP tool on the same surface, and nothing else inventories it.
func (s Surface) hookFindings() []module.Finding {
	var out []module.Finding
	if len(s.Hooks) > 0 {
		detail := make([]string, 0, len(s.Hooks))
		for _, h := range s.Hooks {
			detail = append(detail, h.Event+": "+h.Command)
		}
		out = append(out, module.Finding{
			Key: "hooks",
			Value: fmt.Sprintf("%d lifecycle hook(s) run shell on agent events — no model and no approval in the path, "+
				"so this is host code execution triggered by the agent's own activity", len(s.Hooks)),
			Flag:   module.FlagForceMultiplier,
			Detail: detail,
		})
	}
	if n := len(s.Skills) + len(s.Subagents); n > 0 {
		detail := append(append([]string(nil), s.Skills...), s.Subagents...)
		out = append(out, module.Finding{
			Key:    "instruction surface",
			Value:  fmt.Sprintf("%d skill(s)/subagent(s) load instructions the agent follows", n),
			Flag:   module.FlagInfo,
			Detail: detail,
		})
	}
	return out
}

// Summarize builds the note, and is the single place the Undetermined rule is
// applied.
//
// A config is not a credential. For a credential, Undetermined means geiger
// could not establish the thing is even live, so scoring it would invent a
// severity. Here the config file IS the observation: "server-filesystem /" in
// the arguments is read off disk, and what it grants is not in doubt. Only the
// exact tool list is, and that changes precision, not the reach class. geiger's
// standing rule is likely impact, not perfect impact.
//
// Withholding a tier until enumeration would also make the common case useless.
// Most servers are stdio, and enumerating those needs --spawn-stdio, which runs
// third-party code and often cannot be run at all — so the default mode, the one
// people actually use, would never report anything.
//
// Undetermined is therefore kept for the case it was meant for: servers are
// configured but nothing about their reach could be established.
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
