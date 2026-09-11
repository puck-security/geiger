package agent

import (
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Compositions: reach that exists only because several tools share one context.
//
// Each chain below is a property of the whole tool set, which is why a scanner
// that looks at one server at a time cannot see any of them. A wiki search tool
// on its own is inventory. A wiki search tool in the same context window as a
// webhook tool is a way to leak the wiki, with no exploit and no privilege
// boundary crossed — the agent is doing exactly what it was configured to do.
//
// This is also where severity comes from. A capability list says what the agent
// is wired to; a scan of a config file cannot say whether that is appropriate.
// A chain says several of those capabilities meet in one place, which is a fact
// about the configuration rather than a guess about the operator.
//
// Chains are reported as findings, not as a graph. geiger stays triage: the
// output says how bad this surface is and why, in the same vocabulary as every
// other note. Drawing paths is a different tool.

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

	// 1. The lethal trifecta (Willison, 2025): untrusted input, private data,
	// and a way out. Any one alone is fine. All three in one agent means a
	// poisoned document is enough to leak whatever the agent can read.
	trifecta := set.Has(CapUntrustedIn) &&
		set.HasAny(CapCorpusSearch, CapSecretsRead, CapDataRead, CapFSRead) &&
		set.HasAny(CapNetEgress, CapCodeWrite)
	if trifecta {
		out = append(out, Chain{
			Name: "lethal trifecta",
			Why: chainPath(s, CapUntrustedIn, firstOf(set, CapCorpusSearch, CapSecretsRead, CapDataRead, CapFSRead),
				firstOf(set, CapNetEgress, CapCodeWrite)) + " — one poisoned page leaks what the agent can read",
			Via:  serversWith(s, CapUntrustedIn, CapCorpusSearch, CapSecretsRead, CapDataRead, CapFSRead, CapNetEgress, CapCodeWrite),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 2. Bulk read plus a way out. One search returns everything anyone ever
	// pasted into the wiki, and the next call sends it somewhere. Reported only
	// when the trifecta did not already fire: with untrusted input in the mix
	// this is the same finding with a weaker story, and counting it twice
	// inflates the tier.
	if !trifecta && set.Has(CapCorpusSearch) && set.HasAny(CapNetEgress, CapCodeWrite) {
		out = append(out, Chain{
			Name: "bulk read plus a way out",
			Why:  chainPath(s, CapCorpusSearch, firstOf(set, CapNetEgress, CapCodeWrite)) + " — one search, one send",
			Via:  serversWith(s, CapCorpusSearch, CapNetEgress, CapCodeWrite),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 3. Exec closure. An exec tool makes the agent's reach the host's reach:
	// every credential on the box, including the ones geiger found in the same
	// run, and every network path the host has.
	if set.Has(CapExec) {
		out = append(out, Chain{
			Name: "exec on this host",
			Why:  chainPath(s, CapExec) + " — agent reach is host reach, this run's other findings included",
			Via:  serversWith(s, CapExec),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 4. A secrets tool turns tool-chain access into real credentials, each with
	// its own blast radius.
	if set.Has(CapSecretsRead) {
		out = append(out, Chain{
			Name: "reads a secret store",
			Why:  chainPath(s, CapSecretsRead) + " — agent access outlives the session as whatever those credentials open",
			Via:  serversWith(s, CapSecretsRead),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 5. Cross-server shadowing. A server that ingests untrusted content shares
	// a context window with a high-reach one. The model reads both tool lists
	// and both sets of results, so text from the first can steer calls to the
	// second. Whether a description is actually poisoned is a content question
	// and a different tool's job; the pairing is ours.
	if lo, hi := shadowPair(s); lo != "" && hi != "" {
		out = append(out, Chain{
			Name: "shared context",
			Why: lo + " (untrusted-in) shares a context with " + hi + " — " +
				"text the first returns is read by the model that calls the second",
			Via:  []string{lo, hi},
			Flag: module.FlagInfo,
		})
	}

	// 6. Unpinned launchers. The capability list has no shelf life if the
	// package is resolved fresh at every start.
	if un := unpinnedServers(s); len(un) > 0 {
		flag := module.FlagInfo
		// Unpinned code that is also pre-approved has no human anywhere in the
		// path, so a package takeover lands straight on the host.
		if s.AutoApproved() {
			flag = module.FlagWarn
		}
		out = append(out, Chain{
			Name: "unpinned package",
			Why:  strings.Join(un, ", ") + " — " + refetch(len(un)) + " at launch, so tomorrow's code need not be this config's",
			Via:  un,
			Flag: flag,
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Flag > out[j].Flag })
	return out
}

// refetch agrees the verb with the number of unpinned servers.
func refetch(n int) string {
	if n == 1 {
		return "refetches its package"
	}
	return "refetch their packages"
}

// chainPath renders a chain as the legs that make it: which server supplies which
// primitive, in the order the data moves. That is the fact an operator acts on;
// the sentence explaining what a trifecta is belongs in the docs, not in every
// run of every scan.
func chainPath(s Surface, caps ...Cap) string {
	legs := make([]string, 0, len(caps))
	for _, c := range caps {
		if c == 0 {
			continue
		}
		names := serverNamesWith(s, c)
		if len(names) == 0 {
			continue
		}
		legs = append(legs, c.Name()+" "+strings.Join(names, ", "))
	}
	return strings.Join(legs, " → ")
}

// firstOf returns the first primitive the set actually has, so a chain names the
// leg that is present rather than every one it would accept.
func firstOf(set Set, cs ...Cap) Cap {
	for _, c := range cs {
		if set.Has(c) {
			return c
		}
	}
	return 0
}

// serverNamesWith names the servers supplying one primitive.
func serverNamesWith(s Surface, c Cap) []string {
	var out []string
	for _, srv := range s.Servers {
		if srv.Caps.Set().Has(c) {
			out = append(out, srv.Name)
		}
	}
	sort.Strings(out)
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
