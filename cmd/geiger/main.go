// Command geiger triages leaked credentials: it recognizes the credentials in
// piped text, a file, the environment, a directory, or a scanner report, runs
// read-only recon with each, and prints a short note on what the credential is
// and what it can reach.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/color"
	"github.com/puck-security/geiger/internal/note"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/pipeline"
	"github.com/puck-security/geiger/internal/recon"

	gmodule "github.com/puck-security/geiger/internal/module"
	_ "github.com/puck-security/geiger/internal/modules" // register the catalog
	"github.com/puck-security/geiger/internal/score"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// config holds the parsed CLI flags, so the core can run against injectable
// writers (and a test can prove stdout is independent of the stderr status).
type config struct {
	live, intrusive, minFootprint, useEnv, correlate, trace, asJSON, verbose, stream, quiet bool
	endpoint, proxy, fromGitleaks, fromTrufflehog, contextTerms, colorMode, only, skip      string
	userAgent                                                                               string
	timeout                                                                                 time.Duration
	concurrency                                                                             int
	args                                                                                    []string
}

func main() {
	var c config
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(&c.live, "live", false, "actually make recon calls (default: dry-run, prints planned calls)")
	flag.BoolVar(&c.intrusive, "intrusive", false, "permit read-only-but-invasive actions: connect to databases, hit cluster APIs, harvest downstream secrets (requires --live)")
	flag.BoolVar(&c.minFootprint, "min-footprint", false, "OPSEC: run only the identity (whoami) call per credential, skip inventory fan-out")
	flag.BoolVar(&c.useEnv, "env", false, "read credentials from the current environment variables")
	flag.StringVar(&c.endpoint, "endpoint", "", "tenant/instance/host for set-shaped credentials")
	flag.StringVar(&c.proxy, "proxy", "", "route HTTP recon through a proxy (http/https/socks5 URL)")
	flag.StringVar(&c.fromGitleaks, "from-gitleaks", "", "ingest a gitleaks JSON report and triage each finding")
	flag.StringVar(&c.fromTrufflehog, "from-trufflehog", "", "ingest a TruffleHog v3 JSON report and triage each finding")
	flag.StringVar(&c.contextTerms, "context", "", "comma-separated crown-jewel terms (account ids, prod hosts, critical repos) that raise a credential's tier when matched")
	flag.BoolVar(&c.correlate, "ssh-correlate", false, "for SSH keys, read local hints (~/.ssh/config, known_hosts, shell history) to list candidate target hosts")
	flag.BoolVar(&c.trace, "trace", false, "print the raw request and response of each call (secrets masked); implies showing all calls")
	flag.StringVar(&c.colorMode, "color", "auto", "colorize output: auto|always|never")
	flag.BoolVar(&c.asJSON, "json", false, "machine-readable JSON output")
	flag.BoolVar(&c.verbose, "v", false, "show the planned/executed recon calls")
	flag.BoolVar(&c.stream, "stream", false, "stream results as they're found (discovery order) instead of buffering and sorting by impact")
	flag.BoolVar(&c.quiet, "q", false, "quiet: suppress the stderr status header and progress line")
	flag.StringVar(&c.only, "only", "", "scope recon to these credential types — module names or categories (databases,cloud,secrets,ai,vcs,kubernetes,identity,backup,endpoint), comma-separated")
	flag.StringVar(&c.skip, "skip", "", "exclude these credential types from recon — module names or categories, comma-separated")
	flag.StringVar(&c.userAgent, "user-agent", "", "User-Agent for recon calls (default geiger/<version>)")
	flag.DurationVar(&c.timeout, "timeout", 15*time.Second, "per-credential recon timeout (e.g. 5s, 30s)")
	flag.IntVar(&c.concurrency, "concurrency", 8, "max credentials reconned at once on the --live path")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("geiger", version)
		return
	}
	c.args = flag.Args()
	// Progress is only shown on an interactive stderr (and never under -q), so
	// pipes, redirects, and CI logs stay clean.
	os.Exit(run(os.Stdout, os.Stderr, !c.quiet && isTTY(os.Stderr), c))
}

// run is the testable core: all human-facing status goes to stderr, all results
// to stdout, so the two never interleave on a pipe. It returns the exit code.
func run(stdout, stderr io.Writer, statusOn bool, c config) int {
	color.Enabled = wantColor(c.colorMode, c.asJSON)
	ctx := score.Context{Terms: splitCSV(c.contextTerms)}
	st := &status{w: stderr, on: statusOn}

	// Identify recon traffic as geiger/<version> by default (overridable). Honest
	// attribution over Go's anonymous default UA.
	if recon.UserAgent = c.userAgent; recon.UserAgent == "" {
		recon.UserAgent = "geiger/" + version
	}

	// Header first — printed before the (possibly slow) directory walk so a huge
	// scan shows the tool, version, target, and mode immediately.
	if !c.quiet {
		fmt.Fprintln(stderr, header(c))
	}

	sources, err := readSources(c, st)
	if err != nil {
		fmt.Fprintln(stderr, "geiger:", err)
		return 2
	}
	st.clear()

	if !c.quiet {
		if !c.live {
			fmt.Fprintln(stderr, "geiger: dry-run (no calls made). Re-run with --live to exercise credentials.")
		} else if c.intrusive {
			fmt.Fprintln(stderr, "geiger: --intrusive enabled — will connect to databases and cluster APIs (read-only).")
		}
	}

	opts := pipeline.Options{
		Live: c.live, Intrusive: c.intrusive, MinFootprint: c.minFootprint,
		Endpoint: c.endpoint, Proxy: c.proxy, Correlate: c.correlate, Trace: c.trace,
		Timeout: c.timeout, Concurrency: c.concurrency,
		Select: c.selector(),
	}

	if c.stream {
		return runStream(stdout, stderr, sources, opts, ctx, c)
	}
	return runSorted(stdout, stderr, st, sources, opts, ctx, c)
}

// runSorted is the default: triage every source, then sort by blast radius so
// the highest-impact credential prints first.
func runSorted(stdout, stderr io.Writer, st *status, sources []pipeline.Source, opts pipeline.Options, ctx score.Context, c config) int {
	bt := pipeline.NewBatch(gmodule.Default, opts)
	results := bt.RunConcurrent(sources, nil, func(done int) {
		st.update("triaging %d/%d", done, len(sources))
	})
	bt.AnnotateDuplicates(results) // note any secret also found in other files
	st.clear()
	if len(results) == 0 {
		if !c.quiet {
			fmt.Fprintln(stderr, "geiger: no credentials recognized.")
		}
		return 0
	}
	pipeline.SortBySeverity(results, ctx)
	for i, r := range results {
		printResult(stdout, r, ctx, c, i > 0)
	}
	if !c.asJSON && len(results) > 1 {
		printSummary(stdout, results, ctx)
	}
	printIntrusiveHint(stderr, results, c)
	return 0
}

// runStream prints each result the moment it's found (discovery order, not
// sorted) for immediate feedback on huge or --live scans. The closing summary —
// including the rotate-first queue — is still computed across everything, so the
// "what to fix first" takeaway survives the loss of ordering. No recon progress
// line here: the streamed results are the feedback.
func runStream(stdout, stderr io.Writer, sources []pipeline.Source, opts pipeline.Options, ctx score.Context, c config) int {
	bt := pipeline.NewBatch(gmodule.Default, opts)
	printed := 0
	all := bt.RunConcurrent(sources, func(r pipeline.Result) {
		printResult(stdout, r, ctx, c, printed > 0)
		printed++
	}, nil)
	if len(all) == 0 {
		if !c.quiet {
			fmt.Fprintln(stderr, "geiger: no credentials recognized.")
		}
		return 0
	}
	if !c.asJSON && len(all) > 1 {
		printSummary(stdout, all, ctx)
	}
	printIntrusiveHint(stderr, all, c)
	return 0
}

// printResult renders one credential's note (or its JSON line) to w.
func printResult(w io.Writer, r pipeline.Result, ctx score.Context, c config, leadingBlank bool) {
	if c.asJSON {
		fmt.Fprintln(w, note.JSON(r.Note))
		return
	}
	if leadingBlank {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "[%s] ", color.Tier(string(score.TierFor(r.Note, ctx))))
	fmt.Fprint(w, note.Text(r.Note))
	// Always show destinations: a preview in dry-run, an audit trail in --live
	// (so a credential sent to an input-controlled host is visible).
	if c.verbose || c.trace || !c.live || len(r.Planned) > 0 {
		printCalls(w, r.Planned, c.verbose || c.trace)
	}
}

// header is the one-line stderr banner: tool, version, target, and mode.
func header(c config) string {
	target := "stdin"
	switch {
	case c.useEnv:
		target = "environment"
	case c.fromGitleaks != "":
		target = "gitleaks report " + c.fromGitleaks
	case c.fromTrufflehog != "":
		target = "trufflehog report " + c.fromTrufflehog
	case len(c.args) > 0:
		target = "scanning " + c.args[0]
	}
	mode := "dry-run"
	if c.live {
		if mode = "live"; c.intrusive {
			mode = "live --intrusive"
		}
	}
	return fmt.Sprintf("geiger %s · %s · %s", version, target, mode)
}

// isTTY reports whether f is an interactive terminal.
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// status writes a transient, carriage-return-rewritten progress line to its
// writer (stderr). It is a no-op unless enabled (an interactive, non-quiet
// stderr), so stdout — and any piped/redirected stderr — is never touched.
type status struct {
	w      io.Writer
	on     bool
	active bool
}

func (s *status) update(format string, a ...any) {
	if !s.on {
		return
	}
	fmt.Fprintf(s.w, "\r\x1b[K"+format, a...)
	s.active = true
}

// clear erases the current progress line so it doesn't linger above the results.
func (s *status) clear() {
	if !s.on || !s.active {
		return
	}
	fmt.Fprint(s.w, "\r\x1b[K")
	s.active = false
}

// wantColor resolves the --color mode against NO_COLOR and TTY detection.
func wantColor(mode string, asJSON bool) bool {
	if asJSON {
		return false
	}
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default: // auto
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			return false
		}
		return isTTY(os.Stdout)
	}
}

// categoryModules maps a category alias to the module names it covers, so
// --only/--skip (and the deepen hint) can speak in categories, not 100+ names.
var categoryModules = map[string][]string{
	"databases":  {"db_connection_string", "snowflake", "planetscale", "neon", "aiven", "upstash", "redis_cloud", "clickhouse_cloud", "clickhouse_selfhosted", "supabase", "mongodb_atlas", "databricks"},
	"cloud":      {"aws", "aws_sso", "aws_sso_registration", "gcp_service_account", "gcp_adc", "azure_msal", "entra_sp", "digitalocean", "digitalocean_oauth", "linode", "cloudflare", "cloudflare_global", "heroku", "render", "railway", "flyio", "vercel", "netlify", "fastly"},
	"secrets":    {"vault", "onepassword_connect", "onepassword_sa", "onepassword_secret_key", "doppler", "conjur", "cyberark_pvwa", "keepass_db", "bitwarden", "bitwarden_vault", "vault_export_plaintext"},
	"ai":         {"openai", "anthropic", "cohere", "mistral", "replicate", "huggingface", "gemini", "azure_openai", "groq", "together", "deepseek", "elevenlabs", "stability", "pinecone", "perplexity"},
	"vcs":        {"github_pat", "gitlab", "gitlab_ci_token"},
	"kubernetes": {"kubeconfig"},
	"identity":   {"okta", "auth0", "pingone", "pingfederate", "sailpoint", "jumpcloud", "workday", "duo", "servicenow"},
	"backup":     {"veeam", "acronis", "cohesity", "netbackup", "commvault"},
	"endpoint":   {"ninjaone", "kandji", "jamf", "mosyle", "automox", "tanium", "ansible_awx", "puppet_enterprise", "saltstack", "fleet", "atera"},
}

var categoryAlias = map[string]string{"db": "databases", "database": "databases", "k8s": "kubernetes", "kube": "kubernetes", "llm": "ai"}

// expandSelector turns a comma list of category/module tokens into a set of
// module names. Unknown tokens are kept as literal module names.
func expandSelector(csv string) map[string]bool {
	set := map[string]bool{}
	for _, tok := range splitCSV(csv) {
		tok = strings.ToLower(tok)
		if a, ok := categoryAlias[tok]; ok {
			tok = a
		}
		if mods, ok := categoryModules[tok]; ok {
			for _, m := range mods {
				set[m] = true
			}
			continue
		}
		set[tok] = true
	}
	return set
}

// selector builds the pipeline Select predicate from --only/--skip, or nil when
// neither is set (recon everything).
func (c config) selector() func(string) bool {
	if c.only == "" && c.skip == "" {
		return nil
	}
	only, skip := expandSelector(c.only), expandSelector(c.skip)
	return func(mod string) bool {
		if len(only) > 0 && !only[mod] {
			return false
		}
		return !skip[mod]
	}
}

// moduleCategory returns a module's category (for the hint), or the module name
// itself if it belongs to none.
func moduleCategory(mod string) string {
	for cat, mods := range categoryModules {
		for _, m := range mods {
			if m == mod {
				return cat
			}
		}
	}
	return mod
}

// noteWantsIntrusive reports whether a credential's note says deeper recon needs
// --intrusive (modules self-declare this in a finding value).
func noteWantsIntrusive(n gmodule.Note) bool {
	for _, f := range n.Findings {
		if strings.Contains(f.Value, "--intrusive") {
			return true
		}
	}
	return false
}

// moduleOf extracts the module name (first token) from a note title.
func moduleOf(title string) string {
	if i := strings.IndexByte(title, ' '); i > 0 {
		return title[:i]
	}
	return title
}

// printIntrusiveHint, after a --live (non-intrusive) run, prints a copy-paste
// command to deepen just the credentials that declared they need --intrusive —
// so the user scopes the second pass instead of re-scanning everything.
func printIntrusiveHint(stderr io.Writer, results []pipeline.Result, c config) {
	if c.quiet || !c.live || c.intrusive {
		return
	}
	sel := map[string]bool{}
	n := 0
	for _, r := range results {
		if noteWantsIntrusive(r.Note) {
			n++
			sel[moduleCategory(moduleOf(r.Note.Title))] = true
		}
	}
	if n == 0 {
		return
	}
	toks := make([]string, 0, len(sel))
	for k := range sel {
		toks = append(toks, k)
	}
	sort.Strings(toks)
	cmd := "geiger --live --intrusive --only " + strings.Join(toks, ",")
	if t := strings.Join(c.args, " "); t != "" {
		cmd += " " + t
	}
	fmt.Fprintf(stderr, "\n↳ %d credential(s) can go deeper with --intrusive — re-run scoped:\n    %s\n", n, cmd)
}

// printSummary prints a triage takeaway: the tier breakdown, the rotate-first
// queue, and follow-up actions.
func printSummary(w io.Writer, results []pipeline.Result, ctx score.Context) {
	var tiers []string
	counts := map[score.Tier]int{}
	var rotateFirst []string
	var secretsStore, cantChar, dead int
	for _, r := range results {
		tier := score.TierFor(r.Note, ctx)
		counts[tier]++
		if tier == score.TierCritical || tier == score.TierHigh {
			rotateFirst = append(rotateFirst, note.Sanitize(firstField(r.Note.Title)))
		}
		if r.Note.Invalid {
			dead++
		}
		for _, f := range r.Note.Findings {
			if f.Flag == gmodule.FlagCantCharacterize {
				cantChar++
				break
			}
		}
		for _, f := range r.Note.Findings {
			if f.Flag == gmodule.FlagForceMultiplier && readsSecretsStore(f.Value) {
				secretsStore++
				break
			}
		}
	}
	for _, t := range []score.Tier{score.TierCritical, score.TierHigh, score.TierMedium, score.TierLow, score.TierInfo, score.TierDead} {
		if counts[t] > 0 {
			tiers = append(tiers, fmt.Sprintf("%s %d", color.Tier(string(t)), counts[t]))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "── summary ── %d credentials: %s\n", len(results), strings.Join(tiers, "  "))
	if len(rotateFirst) > 0 {
		fmt.Fprintf(w, "  rotate first: %s\n", strings.Join(rotateFirst, ", "))
	}
	if secretsStore > 0 {
		fmt.Fprintf(w, "  %d reach a secrets store — rotate downstream creds too (or re-run --live --intrusive to harvest)\n", secretsStore)
	}
	if cantChar > 0 {
		fmt.Fprintf(w, "  %d not fully characterizable read-only — need --live, the right scope, or a passphrase\n", cantChar)
	}
	if dead > 0 {
		fmt.Fprintf(w, "  %d dead/expired — no action needed\n", dead)
	}
}

// firstField returns the module + redacted key from a note title (drops the
// "(from …)" provenance) for a compact rotate-first list.
func firstField(title string) string {
	if i := strings.Index(title, " (from "); i > 0 {
		return title[:i]
	}
	return title
}

func readsSecretsStore(v string) bool {
	v = strings.ToLower(v)
	for _, kw := range []string{"secret", "config-var", "config var", "datasource", "state", "vault", "key vault", "harvest"} {
		if strings.Contains(v, kw) {
			return true
		}
	}
	return false
}

// indentBody keeps a traced response body readable under the curl line.
func indentBody(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n      ")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printCalls renders planned calls as curl to w. By default it shows up to two
// example commands; -v shows them all.
func printCalls(w io.Writer, calls []recon.PlannedCall, verbose bool) {
	limit := 2
	if verbose || limit > len(calls) {
		limit = len(calls)
	}
	for _, c := range calls[:limit] {
		if c.Note != "" {
			fmt.Fprintf(w, "    # %s\n", c.Note)
		}
		fmt.Fprintf(w, "    %s\n", c.Curl())
		if c.RespBody != "" {
			fmt.Fprintf(w, "    ← %d %s\n", c.RespStatus, indentBody(c.RespBody))
		}
	}
	if n := len(calls) - limit; n > 0 {
		fmt.Fprintf(w, "    (+%d more read-only call(s); -v to show)\n", n)
	}
}

const banner = `
                .-.
              .'   '.
             :  (☢)  :   ·))
              '.   .'   ·)))
                '-'      ·))

 ██████╗ ███████╗██╗ ██████╗ ███████╗██████╗
██╔════╝ ██╔════╝██║██╔════╝ ██╔════╝██╔══██╗
██║  ███╗█████╗  ██║██║  ███╗█████╗  ██████╔╝
██║   ██║██╔══╝  ██║██║   ██║██╔══╝  ██╔══██╗
╚██████╔╝███████╗██║╚██████╔╝███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
       credential blast-radius triage

`

// usage prints the banner and a short command summary to stderr. It runs on
// --help, on a flag error, and when geiger is invoked with no input.
func usage() {
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprint(os.Stderr, `usage:
  cat ~/.aws/credentials | geiger
  geiger .env
  geiger --env
  geiger ./leaked-repo            # walk a directory
  geiger a.env b.env services/    # multiple files/dirs at once
  geiger --live --intrusive --only databases ./repo   # deepen just DB creds
  geiger --from-gitleaks report.json
  aws configure export-credentials | geiger

flags:
  --live              make read-only recon calls (default: dry-run)
  --intrusive         connect to DBs / cluster APIs, harvest downstream secrets
                      (read-only; requires --live)
  --min-footprint     OPSEC: identity call only, skip inventory fan-out
  --env               read current environment variables
  --endpoint URL      tenant/instance/host for set-shaped credentials
  --proxy URL         route HTTP recon through a proxy (http/https/socks5)
  --timeout DUR       per-credential recon timeout (default 15s)
  --concurrency N     credentials reconned at once on --live (default 8)
  --context TERMS     comma-separated crown-jewel terms that raise tier on match
  --ssh-correlate     SSH: read local hints for candidate target hosts
  --trace             print raw request/response of each call (secrets masked)
  --color MODE        auto|always|never (default auto; off when piped)
  --from-gitleaks F   triage each finding in a gitleaks JSON report
  --from-trufflehog F triage each finding in a TruffleHog v3 JSON report
  --json              machine-readable output
  --stream            stream results as found (discovery order), not sorted by impact
  --only TYPES        scope recon to module names or categories
                      (databases,cloud,secrets,ai,vcs,kubernetes,identity,backup,endpoint)
  --skip TYPES        exclude module names or categories from recon
  --user-agent UA     User-Agent for recon calls (default geiger/<version>)
  -v                  show planned/executed calls
  -q                  quiet: suppress the stderr status header and progress
`)
}

func readSources(c config, st *status) ([]pipeline.Source, error) {
	if c.useEnv {
		return []pipeline.Source{{Label: "environment", Blob: parse.FromEnv(os.Environ())}}, nil
	}
	if c.fromGitleaks != "" {
		return pipeline.FromGitleaks(c.fromGitleaks)
	}
	if c.fromTrufflehog != "" {
		return pipeline.FromTrufflehog(c.fromTrufflehog)
	}
	if len(c.args) > 0 {
		// Multiple paths (files, dirs, or scanner reports) are merged, so a deeper
		// second pass can target just the few files that mattered.
		var all []pipeline.Source
		scanned := 0
		for _, path := range c.args {
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			switch {
			case info.IsDir():
				base := scanned
				srcs, err := pipeline.WalkDir(path, func(n int) {
					if (base+n)%64 == 0 {
						st.update("scanning %s — %d files", path, base+n)
					}
				})
				if err != nil {
					return nil, err
				}
				scanned += len(srcs)
				all = append(all, srcs...)
			case pipeline.LooksLikeGitleaks(path):
				srcs, err := pipeline.FromGitleaks(path)
				if err != nil {
					return nil, err
				}
				all = append(all, srcs...)
			default:
				data, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				all = append(all, pipeline.Source{Label: path, Blob: parse.Parse(string(data), path)})
			}
		}
		return all, nil
	}
	// stdin
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeCharDevice != 0 {
		usage()
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20)) // cap at 32 MiB
	if err != nil {
		return nil, err
	}
	return []pipeline.Source{{Label: "stdin", Blob: parse.Parse(string(data), "stdin")}}, nil
}
