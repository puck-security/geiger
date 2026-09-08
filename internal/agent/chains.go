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
			Why: "the agent can read untrusted content, read private data, and send data out. " +
				"One poisoned page, issue, or ticket is enough to make it leak what it can read.",
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
			Why: "the agent can search a whole document store and can also send data out. " +
				"One search and one send is the whole path.",
			Via:  serversWith(s, CapCorpusSearch, CapNetEgress, CapCodeWrite),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 3. Exec closure. An exec tool makes the agent's reach the host's reach:
	// every credential on the box, including the ones geiger found in the same
	// run, and every network path the host has.
	if set.Has(CapExec) {
		out = append(out, Chain{
			Name: "runs commands on this host",
			Why: "a tool runs commands here, so the agent reaches whatever this host reaches — " +
				"the other findings in this run included",
			Via:  serversWith(s, CapExec),
			Flag: module.FlagForceMultiplier,
		})
	}

	// 4. A secrets tool turns tool-chain access into real credentials, each with
	// its own blast radius.
	if set.Has(CapSecretsRead) {
		out = append(out, Chain{
			Name: "reads a secret store",
			Why:  "a tool reads stored credentials, so access to the agent becomes access to whatever those credentials open, after the session ends",
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
			Name: "untrusted content next to wide reach",
			Why: lo + " reads untrusted content and " + hi + " has wide reach. " +
				"They share one context, so text returned by the first is read by the model that calls the second.",
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
			Name: "package fetched fresh at every start",
			Why: strings.Join(un, ", ") + " refetch their package each time they launch, " +
				"so the code that runs tomorrow need not be the code in this config",
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
