// Package agent triages the reach of an agentic system's tool chain.
//
// geiger's other modules answer "what does this credential unlock". That is the
// wrong unit for an agent: a config whose every secret is stored correctly — OS
// env, a keychain, an OAuth flow — can still wire the agent to a filesystem
// server rooted at /, a shell server, and the corporate wiki. The credential
// hygiene is irrelevant to the blast radius; the TOOL CHAIN is the unit.
//
// The package types each configured server into a set of reach primitives
// (offline, from the catalog and from argv/env heuristics), optionally confirms
// them by enumerating the server's real tool list read-only, and reports the
// compositions that are worth more than the sum of their parts — bulk corpus
// read plus an egress channel, the lethal trifecta, exec closure over the host.
//
// See docs/design/agentic-reach.md.
package agent

import (
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Cap is one reach primitive. A tool, a server, and a whole agent surface are
// each described by a set of these.
type Cap uint32

const (
	// CapExec runs code on the host: shell, python eval, docker, k8s exec, a CI
	// trigger. The strongest primitive there is — it closes over every other
	// credential on the box.
	CapExec Cap = 1 << iota
	// CapCorpusSearch searches or bulk-reads a whole document corpus: wiki,
	// ticketing, chat, drive, mail, code search, a vector index. Separated from
	// CapDataRead because it needs no chaining to be an incident: "give me every
	// credential in Confluence" is one tool call, and it is the highest-yield
	// move in a real engagement.
	CapCorpusSearch
	// CapSecretsRead reads a secret store, environment, or keychain — the edge
	// from the tool chain into every credential geiger already triages.
	CapSecretsRead
	// CapCodeWrite pushes code, opens PRs, or publishes packages (supply chain).
	CapCodeWrite
	// CapCloudControl reaches a cloud control plane.
	CapCloudControl
	// CapDestructive deletes, wipes, or terminates.
	CapDestructive
	// CapIdentityAdmin writes to an IdP or directory.
	CapIdentityAdmin
	// CapFSRead / CapFSWrite touch the local filesystem. Their weight depends
	// entirely on the root scope, which is why Capability carries one.
	CapFSRead
	CapFSWrite
	// CapDataRead reads scoped private data: a record, a bounded table. The
	// non-bulk sibling of CapCorpusSearch.
	CapDataRead
	// CapNetEgress sends data outward: fetch with a caller-controlled URL, a
	// webhook, mail, a chat post. The exfiltration half of every data chain.
	CapNetEgress
	// CapUntrustedIn ingests attacker-influenceable content: the web, GitHub
	// issues, mail, tickets. The prompt-injection entry point.
	CapUntrustedIn
)

// allCaps is every primitive in report order (worst first).
var allCaps = []Cap{
	CapExec, CapCorpusSearch, CapSecretsRead, CapCodeWrite, CapCloudControl,
	CapDestructive, CapIdentityAdmin, CapFSWrite, CapFSRead, CapDataRead,
	CapNetEgress, CapUntrustedIn,
}

// Set is a union of primitives.
type Set uint32

// Add returns the set with c included.
func (s Set) Add(c Cap) Set { return s | Set(c) }

// Has reports whether c is present.
func (s Set) Has(c Cap) bool { return s&Set(c) != 0 }

// HasAny reports whether any of cs is present.
func (s Set) HasAny(cs ...Cap) bool {
	for _, c := range cs {
		if s.Has(c) {
			return true
		}
	}
	return false
}

// Union merges two sets.
func (s Set) Union(o Set) Set { return s | o }

// Empty reports whether no primitive is set.
func (s Set) Empty() bool { return s == 0 }

// List returns the present primitives in report order.
func (s Set) List() []Cap {
	var out []Cap
	for _, c := range allCaps {
		if s.Has(c) {
			out = append(out, c)
		}
	}
	return out
}

// Names returns the present primitives' short names, worst first.
func (s Set) Names() []string {
	caps := s.List()
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, c.Name())
	}
	return out
}

// SetOf builds a set from primitives.
func SetOf(cs ...Cap) Set {
	var s Set
	for _, c := range cs {
		s = s.Add(c)
	}
	return s
}

// Name is the short stable identifier used in output and JSON.
func (c Cap) Name() string {
	switch c {
	case CapExec:
		return "exec"
	case CapCorpusSearch:
		return "corpus-search"
	case CapSecretsRead:
		return "secrets-read"
	case CapCodeWrite:
		return "code-write"
	case CapCloudControl:
		return "cloud-control"
	case CapDestructive:
		return "destructive"
	case CapIdentityAdmin:
		return "identity-admin"
	case CapFSRead:
		return "fs-read"
	case CapFSWrite:
		return "fs-write"
	case CapDataRead:
		return "data-read"
	case CapNetEgress:
		return "net-egress"
	case CapUntrustedIn:
		return "untrusted-in"
	}
	return "unknown"
}

// Why is the one-line reason this primitive matters, written for a responder
// deciding what to do first.
func (c Cap) Why() string {
	switch c {
	case CapExec:
		return "runs commands on the host — the agent's reach is the host's reach, including every other credential on it"
	case CapCorpusSearch:
		return "searches an entire document corpus in one call — the highest-yield agentic recon primitive (one query returns every secret a human ever pasted into the wiki)"
	case CapSecretsRead:
		return "reads a secret store — yields downstream credentials, each with its own blast radius"
	case CapCodeWrite:
		return "pushes code or publishes packages — supply-chain reach beyond this host"
	case CapCloudControl:
		return "reaches a cloud control plane — infrastructure-level actions"
	case CapDestructive:
		return "deletes or terminates resources — irreversible without a restore"
	case CapIdentityAdmin:
		return "writes to an identity provider or directory — can grant itself standing access"
	case CapFSRead:
		return "reads local files"
	case CapFSWrite:
		return "writes local files — can plant code that later executes"
	case CapDataRead:
		return "reads scoped private data"
	case CapNetEgress:
		return "sends data outward on a caller-controlled destination — the exfiltration channel"
	case CapUntrustedIn:
		return "ingests attacker-influenceable content — the prompt-injection entry point"
	}
	return ""
}

// forceMultipliers are the primitives that turn "an agent is configured" into
// "an incident" on their own, without needing to be chained.
const forceMultipliers = Set(CapExec | CapCorpusSearch | CapSecretsRead |
	CapCodeWrite | CapCloudControl | CapDestructive | CapIdentityAdmin)

// warnCaps are notable but not, alone, an incident.
const warnCaps = Set(CapDataRead | CapNetEgress | CapUntrustedIn)

// Flag maps a primitive to its finding significance, given the scope it was
// found at. Filesystem reach is the one primitive whose weight is decided by
// scope rather than by kind: a server rooted at / and one rooted at ./project
// are the same package two orders of magnitude apart, so scope is an input here
// rather than a cosmetic detail on the finding.
func (c Cap) Flag(broadScope bool) module.FlagLevel {
	switch {
	case forceMultipliers.Has(c):
		return module.FlagForceMultiplier
	case c == CapFSWrite, c == CapFSRead:
		if broadScope {
			return module.FlagForceMultiplier
		}
		return module.FlagWarn
	case warnCaps.Has(c):
		return module.FlagWarn
	}
	return module.FlagInfo
}

// Capability is one primitive as found on a specific server, with the scope it
// applies at and the evidence for it.
type Capability struct {
	Cap Cap
	// Scope bounds the primitive where one is knowable — a filesystem root, a
	// database name, a corpus host. Empty means unbounded or unknown.
	Scope string
	// Broad marks a scope that is effectively unbounded (a filesystem server
	// rooted at / or at $HOME, a wildcard host).
	Broad bool
	// Evidence is what typed it: a catalog package name, an argv pattern, or an
	// enumerated tool name.
	Evidence string
}

// String renders the capability for a finding line.
func (c Capability) String() string {
	s := c.Cap.Name()
	if c.Scope != "" {
		s += " (" + c.Scope + ")"
	}
	return s
}

// Caps is an ordered, deduplicated list of capabilities.
type Caps []Capability

// Set collapses the list to a plain primitive union.
func (cs Caps) Set() Set {
	var s Set
	for _, c := range cs {
		s = s.Add(c.Cap)
	}
	return s
}

// BroadFS reports whether any filesystem capability is at a broad scope.
func (cs Caps) BroadFS() bool {
	for _, c := range cs {
		if (c.Cap == CapFSRead || c.Cap == CapFSWrite) && c.Broad {
			return true
		}
	}
	return false
}

// Add appends a capability, merging into an existing entry for the same
// primitive rather than repeating it. The broader scope wins, since that is the
// reach an operator has to assume.
func (cs Caps) Add(c Capability) Caps {
	for i := range cs {
		if cs[i].Cap != c.Cap {
			continue
		}
		if c.Broad && !cs[i].Broad {
			cs[i].Broad, cs[i].Scope = true, c.Scope
		} else if cs[i].Scope == "" && c.Scope != "" && !cs[i].Broad {
			cs[i].Scope = c.Scope
		}
		if c.Evidence != "" && !strings.Contains(cs[i].Evidence, c.Evidence) {
			cs[i].Evidence += ", " + c.Evidence
		}
		return cs
	}
	return append(cs, c)
}

// Merge folds another list in.
func (cs Caps) Merge(o Caps) Caps {
	for _, c := range o {
		cs = cs.Add(c)
	}
	return cs
}

// Sorted returns the capabilities in report order (worst first).
func (cs Caps) Sorted() Caps {
	rank := map[Cap]int{}
	for i, c := range allCaps {
		rank[c] = i
	}
	out := append(Caps(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Cap] < rank[out[j].Cap] })
	return out
}

// Summary renders the capability set as a compact, worst-first phrase for a note
// title or one-line summary.
func (cs Caps) Summary() string {
	names := cs.Sorted()
	out := make([]string, 0, len(names))
	for _, c := range names {
		out = append(out, c.String())
	}
	if len(out) == 0 {
		return "no reach primitives identified"
	}
	return strings.Join(out, ", ")
}
