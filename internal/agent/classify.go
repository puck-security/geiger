package agent

import (
	"regexp"
	"strings"
)

// Classification of an ENUMERATED tool list — the observed half of typing.
//
// Unlike the catalog, which guesses from a package name, this reads the tool
// names and descriptions the server actually advertises. That is why an
// enumerated server's note is no longer Undetermined: the reach was reported by
// the server itself rather than asserted by geiger.
//
// The rules are deliberately keyword-shaped and conservative. A tool that cannot
// be classified contributes nothing rather than a guess, and the note reports
// how many such tools there were so the reader knows the coverage.

// Tool is one enumerated tool.
type Tool struct {
	Name        string
	Description string
}

// toolRule maps a keyword set to a primitive. Name matches are strong; a
// description match alone is only accepted for the ingress/egress primitives,
// where the description is the only place the direction of data flow appears.
type toolRule struct {
	cap Cap
	// name matches against the tool name (word-ish boundaries).
	name *regexp.Regexp
	// desc, when set, also matches against the description.
	desc *regexp.Regexp
}

var toolRules = []toolRule{
	{cap: CapExec, name: regexp.MustCompile(`(?i)(execute|exec_|_exec|run_command|run_shell|shell|bash|terminal|spawn|eval|run_code|run_script|system|subprocess|kubectl|docker_run)`)},

	// Bulk read is the highest-yield primitive, so its rule is the most
	// carefully drawn: a SEARCH or LIST verb over a corpus noun, not any read.
	{cap: CapCorpusSearch, name: regexp.MustCompile(`(?i)(search|query|find|list_all|grep|fetch_all|dump|export)`),
		desc: regexp.MustCompile(`(?i)(search|query across|all (pages|documents|issues|messages|files|records|tickets|spaces|repositories))`)},

	{cap: CapSecretsRead, name: regexp.MustCompile(`(?i)(secret|credential|vault|keychain|keyring|password|token|env_var|get_env)`)},
	{cap: CapCodeWrite, name: regexp.MustCompile(`(?i)(push|commit|create_pull|merge|publish|create_branch|create_release|upload_package|deploy)`)},
	{cap: CapCloudControl, name: regexp.MustCompile(`(?i)(instance|bucket|iam_|assume_role|lambda|function_|cluster|provision|terraform|cloudformation)`)},
	{cap: CapDestructive, name: regexp.MustCompile(`(?i)(delete|destroy|remove|drop_|truncate|terminate|purge|wipe|revoke)`)},
	{cap: CapIdentityAdmin, name: regexp.MustCompile(`(?i)(create_user|update_user|assign_role|grant|add_member|group_add|reset_password|sso_)`)},

	{cap: CapFSWrite, name: regexp.MustCompile(`(?i)(write_file|create_file|edit_file|move_file|copy_file|mkdir|put_file|patch_file)`)},
	{cap: CapFSRead, name: regexp.MustCompile(`(?i)(read_file|list_directory|read_text|get_file|directory_tree|list_files|stat_file)`)},
	{cap: CapDataRead, name: regexp.MustCompile(`(?i)(get_|read_|fetch_|describe_|show_|select|retrieve)`)},

	{cap: CapNetEgress, name: regexp.MustCompile(`(?i)(send|post_|publish_message|webhook|notify|email|sms|upload|request|http_)`),
		desc: regexp.MustCompile(`(?i)(send (a )?(message|email|request)|post to|upload to|arbitrary url)`)},
	{cap: CapUntrustedIn, name: regexp.MustCompile(`(?i)(fetch|browse|crawl|scrape|read_url|get_page|web_search|read_issue|read_comment|read_email|read_message)`),
		desc: regexp.MustCompile(`(?i)(from (the )?(web|internet|a url)|user-generated|third-party content|external (web)?site)`)},
}

// ClassifyTools types an enumerated tool list. It returns the capability set and
// the number of tools no rule matched, so the note can state its own coverage
// rather than implying the list was fully understood.
func ClassifyTools(tools []Tool) (Caps, int) {
	var out Caps
	unclassified := 0
	for _, t := range tools {
		// Match on the bare verb: clients commonly namespace a tool as
		// "github__search_code", and the server prefix would otherwise leak into
		// every rule (a server called "execute-api" is not an exec tool).
		name := normalizeToolName(t.Name)
		desc := t.Description
		matched := false
		for _, r := range toolRules {
			hit := r.name.MatchString(name)
			if !hit && r.desc != nil && desc != "" {
				hit = r.desc.MatchString(desc)
			}
			if !hit {
				continue
			}
			matched = true
			out = out.Add(Capability{Cap: r.cap, Evidence: "tool:" + name})
		}
		if !matched {
			unclassified++
		}
	}
	return demoteRedundantDataRead(out), unclassified
}

// demoteRedundantDataRead drops the generic data-read primitive when the
// stronger corpus-search primitive is already present from the same server.
// Every corpus search is also a read; reporting both adds a warn line that says
// nothing the force multiplier above it did not already say.
func demoteRedundantDataRead(cs Caps) Caps {
	if !cs.Set().Has(CapCorpusSearch) {
		return cs
	}
	out := make(Caps, 0, len(cs))
	for _, c := range cs {
		if c.Cap == CapDataRead {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ToolNames returns just the names, for the note's detail expansion.
func ToolNames(tools []Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

// autoApprovedTools reports the tools of a server that the runtime pre-approves,
// resolved against the enumerated list so "*" expands to what it actually
// covers. An auto-approved tool is reachable with no human in the loop, which is
// what removes the last mitigation from every chain in chains.go.
func autoApprovedTools(s Server) []string {
	for _, a := range s.AutoApproved {
		if a == "*" {
			if len(s.Tools) > 0 {
				return s.Tools
			}
			return []string{"all tools"}
		}
	}
	return s.AutoApproved
}

// approvedAll reports whether every tool on the server is pre-approved.
func approvedAll(s Server) bool {
	for _, a := range s.AutoApproved {
		if a == "*" {
			return true
		}
	}
	return len(s.Tools) > 0 && len(s.AutoApproved) >= len(s.Tools)
}

// normalizeToolName trims a server-prefixed tool name ("github__search_code")
// down to the bare verb so the rules match consistently across servers.
func normalizeToolName(n string) string {
	if i := strings.LastIndex(n, "__"); i >= 0 {
		return n[i+2:]
	}
	return n
}
