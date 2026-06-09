package modules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// sshCandidateHosts reads a bounded set of well-known local hints under home and
// returns hosts the key *might* authenticate to. This is opt-in (--correlate)
// and only ever reads these specific files — Geiger still doesn't crawl the
// filesystem. Acceptance is never confirmed (that needs a login).
func sshCandidateHosts(home string) []string {
	set := map[string]bool{}
	add := func(h string) {
		h = strings.TrimSpace(h)
		if strings.HasPrefix(h, "[") { // [host]:port form
			if i := strings.Index(h, "]"); i > 1 {
				h = h[1:i]
			}
		}
		h = strings.Trim(h, "[]")
		if h == "" || h == "*" || strings.ContainsAny(h, "*?") {
			return
		}
		if h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" {
			return
		}
		set[h] = true
	}

	// ~/.ssh/config — HostName and concrete Host entries.
	if data, err := os.ReadFile(filepath.Join(home, ".ssh", "config")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "hostname":
				add(fields[1])
			case "host":
				for _, h := range fields[1:] {
					add(h)
				}
			}
		}
	}

	// ~/.ssh/known_hosts — first field is comma-separated hostnames (skip hashed).
	if data, err := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "|") { // |1| = hashed
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, h := range strings.Split(fields[0], ",") {
				add(h)
			}
		}
	}

	// shell history — ssh invocations.
	for _, hist := range []string{".bash_history", ".zsh_history", ".history"} {
		if data, err := os.ReadFile(filepath.Join(home, hist)); err == nil {
			for _, m := range sshHistRe.FindAllStringSubmatch(string(data), -1) {
				add(m[1])
			}
		}
	}

	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}

// sshHistRe matches `ssh [opts] [user@]host` in shell history.
var sshHistRe = regexp.MustCompile(`\bssh\s+(?:-\S+\s+|-\S+ \S+\s+)*(?:[\w.-]+@)?([\w][\w.-]+)`)
