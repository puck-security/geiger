package agent

import (
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Compositions: reach that exists only because several tools share one context.
//
// Each chain below is a property of the UNION of an agent's tools, which is why
// a per-component scanner cannot see any of them. A wiki search tool is a
// warning; a wiki search tool in the same context window as a webhook tool is an
// exfiltration path that needs no exploit and no privilege boundary crossed —
// the agent is doing exactly what it was configured to do.
//
// These are reported as findings, not as a graph. geiger stays triage: the
// output says how bad this surface is and why, in the same vocabulary as every
// other note. Path visualisation is a different tool.

// Chain is one composition found on a surface.
type Chain struct {
	Name string
	// Why states the composition in the operator's terms.
	Why string
	// Via names the servers that supply each leg, so the reader can act on it.
	Via []string
	// Flag is the finding's significance.
	Flag module.FlagLevel
}

// Chains returns every composition present on the surface, worst first.
func Chains(s Surface) []Chain {
	var out []Chain
	set := s.Caps().Set()

	// 1. Corpus exfiltration. The highest-yield agentic attack there is, and it
	// needs no injection and no chained privilege: search the wiki, post the
	// results out. "Give me every credential in Confluence" is one tool call;
	// sending them somewhere is the second.
	if set.Has(CapCorpusSearch) && set.HasAny(CapNetEgress, CapCodeWrite) {
		out = append(out, Chain{
			Name: "corpus exfiltration",
			Why: "bulk corpus search shares a context with an outbound channel — one query returns every secret a human pasted into the wiki, " +
				"and the next call sends it out. No exploit and no privilege boundary crossed.",
			Via:  serversWith(s, CapCorpusSearch, CapNetEgress, CapCodeWrite),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 2. The lethal trifecta (Willison, 2025): untrusted input, private data,
	// and a way out. Any one is fine; all three in one agent means a poisoned
	// document is sufficient to exfiltrate.
	if set.Has(CapUntrustedIn) &&
		set.HasAny(CapCorpusSearch, CapSecretsRead, CapDataRead, CapFSRead) &&
		set.HasAny(CapNetEgress, CapCodeWrite) {
		out = append(out, Chain{
			Name: "lethal trifecta",
			Why: "untrusted content, private data, and an outbound channel are all reachable in one context — " +
				"a single poisoned page, issue, or ticket can make the agent exfiltrate whatever it can read",
			Via:  serversWith(s, CapUntrustedIn, CapCorpusSearch, CapSecretsRead, CapDataRead, CapFSRead, CapNetEgress, CapCodeWrite),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 3. Exec closure. An exec tool makes the agent's reach the host's reach:
	// every credential on the box, including all the ones geiger found in the
	// same run, and every network path the host has.
	if set.Has(CapExec) {
		out = append(out, Chain{
			Name: "exec closure",
			Why: "a tool runs commands on this host, so the agent's reach is the host's reach — " +
				"every credential on this box (including the other findings in this run) and every network path it has",
			Via:  serversWith(s, CapExec),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 4. Credential laundering. A secrets tool converts tool-chain access into
	// real credentials, each with its own blast radius — the same fan-out
	// geiger's --intrusive secret-store harvesting already performs.
	if set.Has(CapSecretsRead) {
		out = append(out, Chain{
			Name: "credential laundering",
			Why:  "a tool reads a secret store, so tool-chain access converts into standing credentials that outlive the agent session",
			Via:  serversWith(s, CapSecretsRead),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 5. Cross-server shadowing. A server that ingests untrusted content shares
	// a context window with a high-reach one; the model reads both tool lists
	// and both results, so content from the low-trust server can steer calls to
	// the high-trust one. The content half of this analysis (is a description
	// actually poisoned) is agent-scan's job; the composition is ours.
	if lo, hi := shadowPair(s); lo != "" && hi != "" {
		out = append(out, Chain{
			Name: "cross-server shadowing",
			Why: "an untrusted-content server (" + lo + ") shares one context with a high-reach server (" + hi + ") — " +
				"content returned by the first is read by the model that calls the second",
			Via:  []string{lo, hi},
			Flag: module.FlagWarn,
		})
	}

	// 6. Unpinned supply chain. The capability set has no shelf life: a launcher
	// that resolves "latest" at every start runs different code tomorrow with no
	// change to the config anyone reviewed.
	if un := unpinnedServers(s); len(un) > 0 {
		flag := module.FlagWarn
		// Unpinned code that is ALSO pre-approved is a rug-pull with no human in
		// the path at any point.
		if s.AutoApproved() {
			flag = module.FlagForceMultiplier
		}
		out = append(out, Chain{
			Name: "unpinned supply chain",
			Why: strings.Join(un, ", ") + " refetch their package at every launch — " +
				"the code that runs tomorrow is not the code typed here, and a rug-pull needs no config change",
			Via:  un,
			Flag: flag,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Flag > out[j].Flag })
	return out
}

// serversWith names the servers supplying any of the given primitives, so a
// chain finding points at what to actually go and look at.
func serversWith(s Surface, cs ...Cap) []string {
	var out []string
	for _, srv := range s.Servers {
		if !srv.Caps.Set().HasAny(cs...) {
			continue
		}
		out = append(out, srv.Name+" ("+strings.Join(intersect(srv.Caps.Set(), cs), "+")+")")
	}
	sort.Strings(out)
	return out
}

// intersect returns the names of the primitives in both the set and the list.
func intersect(set Set, cs []Cap) []string {
	var out []string
	for _, c := range cs {
		if set.Has(c) {
			out = append(out, c.Name())
		}
	}
	return out
}

// shadowRank orders the high-reach primitives a shadowing attack would aim at,
// strongest first, so the reported pair names the worst counterpart rather than
// whichever server sorted first.
var shadowRank = []Cap{CapExec, CapSecretsRead, CapCloudControl, CapCodeWrite, CapCorpusSearch}

// shadowPair finds the untrusted-input / high-reach server pair worth naming.
// It returns empty strings when a single server supplies both legs — that is not
// shadowing, it is one dangerous server, already reported on its own line.
//
// A counterpart that does not itself ingest untrusted content is preferred: the
// point of the finding is that content crosses a trust boundary, and two
// untrusted-content servers sitting together is a weaker version of the same
// story.
func shadowPair(s Surface) (lo, hi string) {
	best := -1
	for _, a := range s.Servers {
		if !a.Caps.Set().Has(CapUntrustedIn) {
			continue
		}
		for _, b := range s.Servers {
			if a.Name == b.Name {
				continue
			}
			for rank, c := range shadowRank {
				if !b.Caps.Set().Has(c) {
					continue
				}
				// Lower rank is stronger; a clean counterpart wins a tie.
				score := rank * 2
				if b.Caps.Set().Has(CapUntrustedIn) {
					score++
				}
				if best < 0 || score < best {
					best, lo, hi = score, a.Name, b.Name
				}
				break
			}
		}
	}
	return lo, hi
}

// unpinnedServers names the servers whose launcher resolves its package fresh at
// every start.
func unpinnedServers(s Surface) []string {
	var out []string
	for _, srv := range s.Servers {
		if srv.Unpinned {
			out = append(out, srv.Name)
		}
	}
	sort.Strings(out)
	return out
}
