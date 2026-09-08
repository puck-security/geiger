package agent

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// Static typing: what a configured server reaches, derived without running it.
//
// Two sources, in order. The catalog identifies known servers by their
// invocation. The heuristics here cover everything the catalog does not, and
// refine what it does — most importantly the SCOPE, which the catalog cannot
// know because it lives in the arguments (a filesystem server rooted at / and
// one rooted at ./project are the same package two orders of magnitude apart).
//
// Everything here is an assertion about a package name and an argv, not an
// observation of the server's real tool list. Callers must keep the resulting
// note Undetermined until enumeration confirms it; see docs/design/agentic-reach.md.

// Transport is how the client reaches a server.
type Transport string

const (
	// TransportStdio launches a local process. Enumerating it means EXECUTING
	// the configured command, which is why it is gated behind --spawn-stdio.
	TransportStdio Transport = "stdio"
	// TransportHTTP is a remote server over streamable HTTP (or the deprecated
	// HTTP+SSE). Enumerating it is an ordinary read-only HTTP call.
	TransportHTTP Transport = "http"
)

// Server is one configured MCP server, before or after enumeration.
type Server struct {
	Name      string
	Transport Transport
	Command   string
	Args      []string
	URL       string
	// EnvNames are the env var names the server config sets, values omitted —
	// the names alone say which credentials the server is handed.
	EnvNames []string
	// HeaderNames are the auth header names on a remote server.
	HeaderNames []string

	// Caps is the union of statically-typed and enumerated reach.
	Caps Caps
	// Label is the catalog's human name for the server, when it matched.
	Label string
	// Unpinned marks a launcher that refetches the package at every start
	// (npx -y, uvx, pipx run without a version). The capability set has no shelf
	// life: the code that runs tomorrow is not the code typed today.
	Unpinned bool
	// PlaintextHTTP marks a remote server reached over http:// — the token in
	// its headers crosses the wire in clear.
	PlaintextHTTP bool
	// AutoApproved lists the tools (or "*") this server is pre-approved for by
	// the runtime's configuration, so no human sees the call.
	AutoApproved []string

	// Enumerated is set once a real tool list was observed. Until then every
	// capability above is geiger's claim about a package name, not a fact.
	Enumerated bool
	// Tools are the enumerated tool names.
	Tools []string
	// ResourceCount / PromptCount are the enumerated resource and prompt counts.
	ResourceCount int
	PromptCount   int
	// Asked records that geiger actually sent the server a request. It separates
	// "we tried and it did not answer" from "we never tried", which are
	// different answers to the reader's question and need different advice.
	Asked bool
	// EnumErr explains why enumeration did not happen or did not succeed.
	EnumErr string
	// Unauthenticated records that the remote server answered tools/list with no
	// credential at all — its whole tool surface is available to anyone who can
	// route to it.
	Unauthenticated bool
	// AuthServer is the authorization server named by a 401's protected-resource
	// metadata (RFC 9728), when the server gates access.
	AuthServer string
}

// Invocation is the lowercased string the catalog matches against: the command
// and arguments for a stdio server, the host and path for a remote one.
func (s Server) Invocation() string {
	if s.Transport == TransportHTTP {
		if u, err := url.Parse(s.URL); err == nil {
			return strings.ToLower(u.Host + u.Path)
		}
		return strings.ToLower(s.URL)
	}
	return strings.ToLower(s.Command + " " + strings.Join(s.Args, " "))
}

// credEnvRe matches an environment variable name that hands a credential to the
// server. The server inherits that credential's whole blast radius, which the
// rest of geiger already knows how to compute.
var credEnvRe = regexp.MustCompile(`(?i)(token|secret|key|password|passwd|credential|apikey|api_key|auth|dsn|connection_string|kubeconfig)`)

// cloudEnvRe matches env names that hand over a cloud identity specifically.
var cloudEnvRe = regexp.MustCompile(`(?i)^(aws_|google_|gcp_|azure_|arm_|kubeconfig|kube_)`)

// unpinnedRe matches a launcher that resolves the package fresh at every run.
var unpinnedRe = regexp.MustCompile(`^(npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx)$`)

// Type fills in a server's static capabilities from the catalog and the argv/env
// heuristics. It never runs anything.
func Type(s *Server) {
	inv := s.Invocation()
	if e, ok := lookup(inv); ok {
		s.Label = e.label
		for _, c := range e.caps {
			s.Caps = s.Caps.Add(Capability{Cap: c, Scope: e.scope, Evidence: "catalog:" + e.match})
		}
	}
	s.Unpinned = unpinnedLaunch(s.Command, s.Args)
	if s.Transport == TransportHTTP {
		s.PlaintextHTTP = plaintextOffHost(s.URL)
	}
	s.Caps = s.Caps.Merge(inferFromArgv(s))
	s.Caps = s.Caps.Merge(inferFromEnv(s))
	s.Caps = refineFSScope(s.Caps, s)
	// Every corpus search is also a read. Reporting both adds a warn line that
	// says nothing the force multiplier above it did not already say.
	s.Caps = demoteRedundantDataRead(s.Caps)
}

// loopbackHosts never leave the machine, so a token sent to one over http does
// not cross a wire anyone can read. A local MCP server on http://localhost is
// the normal way to run one, and warning about it is noise.
var loopbackHosts = map[string]bool{
	"localhost": true, "127.0.0.1": true, "::1": true, "[::1]": true, "0.0.0.0": true,
}

// plaintextOffHost reports a cleartext URL whose token actually crosses a
// network.
func plaintextOffHost(raw string) bool {
	if !strings.HasPrefix(strings.ToLower(raw), "http://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return true // unparseable but cleartext: assume the worse case
	}
	return !loopbackHosts[strings.ToLower(u.Hostname())]
}

// unpinnedLaunch reports whether the launcher refetches its package on every
// start. `npx -y pkg` and `uvx pkg` resolve "latest" at launch, so the code that
// runs is whatever the registry serves that day — a rug-pull needs no change to
// the config an operator reviewed. A version-pinned spec (pkg@1.2.3) is not
// flagged, and neither is a local path.
func unpinnedLaunch(cmd string, args []string) bool {
	base := strings.ToLower(path.Base(strings.TrimSpace(cmd)))
	if !unpinnedRe.MatchString(base) {
		return false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") { // -y, --quiet, …
			continue
		}
		// A local path is not fetched from a registry.
		if strings.HasPrefix(a, ".") || strings.HasPrefix(a, "/") {
			return false
		}
		// pkg@1.2.3 is pinned; @scope/pkg (leading @, no second @) is not.
		if i := strings.LastIndex(a, "@"); i > 0 {
			return false
		}
		return true // first non-flag token is an unpinned package spec
	}
	return false
}

// inferFromArgv reads reach out of the arguments the catalog cannot see: docker
// bind mounts, filesystem roots, and connection strings.
func inferFromArgv(s *Server) Caps {
	var out Caps
	if s.Transport != TransportStdio {
		return out
	}
	joined := strings.ToLower(strings.Join(s.Args, " "))
	base := strings.ToLower(path.Base(s.Command))

	// A docker bind mount grants the container whatever it maps. `-v /:/host`
	// is the whole filesystem regardless of what the image claims to do.
	if base == "docker" || base == "podman" {
		out = out.Add(Capability{Cap: CapExec, Evidence: "container launch"})
		for i, a := range s.Args {
			if a != "-v" && a != "--volume" && !strings.HasPrefix(a, "--volume=") {
				continue
			}
			spec := strings.TrimPrefix(a, "--volume=")
			if spec == a && i+1 < len(s.Args) {
				spec = s.Args[i+1]
			}
			host, _, _ := strings.Cut(spec, ":")
			if host == "" {
				continue
			}
			broad := broadPath(host)
			out = out.Add(Capability{Cap: CapFSRead, Scope: host, Broad: broad, Evidence: "bind mount"})
			out = out.Add(Capability{Cap: CapFSWrite, Scope: host, Broad: broad, Evidence: "bind mount"})
		}
		if strings.Contains(joined, "--privileged") {
			out = out.Add(Capability{Cap: CapDestructive, Evidence: "--privileged"})
		}
	}

	// A DSN in the arguments is a live data plane; geiger's db_connection_string
	// module triages the credential itself, this records the reach.
	for _, a := range s.Args {
		if dsnRe.MatchString(a) {
			scheme, _, _ := strings.Cut(a, "://")
			out = out.Add(Capability{Cap: CapDataRead, Scope: scheme, Evidence: "DSN in args"})
			out = out.Add(Capability{Cap: CapCorpusSearch, Scope: scheme, Evidence: "DSN in args"})
		}
	}
	return out
}

// dsnRe matches a database connection string in an argument.
var dsnRe = regexp.MustCompile(`^(postgres|postgresql|mysql|mongodb(\+srv)?|redis|rediss|mssql|sqlserver|clickhouse|cassandra)://`)

// inferFromEnv types a server by the credentials its config hands it. A server
// given AWS_SECRET_ACCESS_KEY reaches AWS whether or not the catalog knows the
// package, and one given a generic *_TOKEN is at minimum reading data with it.
func inferFromEnv(s *Server) Caps {
	var out Caps
	for _, n := range s.EnvNames {
		switch {
		case cloudEnvRe.MatchString(n):
			out = out.Add(Capability{Cap: CapCloudControl, Evidence: "env:" + n})
		case credEnvRe.MatchString(n):
			out = out.Add(Capability{Cap: CapDataRead, Evidence: "env:" + n})
		}
	}
	return out
}

// refineFSScope attaches the real filesystem root to a filesystem server's
// capabilities. The catalog knows @modelcontextprotocol/server-filesystem grants
// fs-read and fs-write; only the arguments say whether that is the whole disk or
// one project directory, and that is the entire difference in severity.
func refineFSScope(cs Caps, s *Server) Caps {
	if !cs.Set().HasAny(CapFSRead, CapFSWrite) || s.Transport != TransportStdio {
		return cs
	}
	roots := fsRoots(s.Args)
	if len(roots) == 0 {
		// A filesystem server with no root argument serves its working
		// directory, which we cannot see from the config. Unknown, not broad.
		return cs
	}
	scope := strings.Join(roots, ", ")
	broad := false
	for _, r := range roots {
		if broadPath(r) {
			broad = true
			break
		}
	}
	for i := range cs {
		if cs[i].Cap != CapFSRead && cs[i].Cap != CapFSWrite {
			continue
		}
		// Only fill in an UNKNOWN scope. A capability that already carries one
		// was typed by something that knew better than the raw argv — a docker
		// bind mount reads "/" out of "/:/host", and re-deriving it from the
		// arguments would put the container-side path back.
		if cs[i].Scope != "" {
			continue
		}
		cs[i].Scope, cs[i].Broad = scope, broad
	}
	return cs
}

// fsRoots pulls the directory arguments out of a filesystem server's argv,
// skipping flags and the package spec itself.
func fsRoots(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if !strings.HasPrefix(a, "/") && !strings.HasPrefix(a, "~") &&
			!strings.HasPrefix(a, ".") && !strings.HasPrefix(a, "$") {
			continue // a package name, not a path
		}
		out = append(out, a)
	}
	return out
}

// broadPath reports whether a filesystem root is effectively unbounded: the
// root, a home directory, or one of the top-level trees that contains every
// user's credentials.
func broadPath(p string) bool {
	c := strings.TrimSuffix(path.Clean(strings.TrimSpace(p)), "/")
	switch c {
	case "", "/", "~", "$HOME", "${HOME}", "/home", "/Users", "/root", "/etc", "/var", "/mnt", "/host", "C:", "C:\\":
		return true
	}
	// /home/alice and /Users/alice are a whole user profile: every dotfile
	// credential store geiger otherwise scans for.
	for _, pre := range []string{"/home/", "/Users/", "~/"} {
		if !strings.HasPrefix(c, pre) {
			continue
		}
		rest := strings.Trim(strings.TrimPrefix(c, pre), "/")
		if rest == "" || !strings.Contains(rest, "/") {
			return true // exactly one level down: the home directory itself
		}
	}
	return false
}

// CredentialEnvNames returns the env var names that hand this server a
// credential. Used to say, in the note, which of geiger's other findings the
// server inherits.
func (s Server) CredentialEnvNames() []string {
	var out []string
	for _, n := range s.EnvNames {
		if credEnvRe.MatchString(n) || cloudEnvRe.MatchString(n) {
			out = append(out, n)
		}
	}
	return out
}
