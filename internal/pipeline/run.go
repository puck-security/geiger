// Package pipeline wires the stages together: parsed blob → recognize → for
// each match (authenticate → recon → summarize) → notes. Each credential is
// isolated so one module's failure never aborts the others.
package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/redact"
)

// Options controls a run.
type Options struct {
	Live         bool
	Intrusive    bool // permit read-only-but-invasive actions (DB connect, k8s live, harvest)
	MinFootprint bool // OPSEC: run only the identity call, skip inventory fan-out
	Correlate    bool // read local hints to correlate SSH keys to candidate hosts
	Trace        bool // capture masked request/response bodies
	Endpoint     string
	Proxy        string // SOCKS5/HTTP proxy URL for HTTP recon egress
	Timeout      time.Duration
	Concurrency  int       // max credentials reconned at once on the live path (0 = default)
	StartedAt    time.Time // run start, stamped on live-validated findings (zero = now)
	// Select, when set, scopes the run: only recognized credentials whose module
	// name passes are reconned (the rest are skipped entirely, not just hidden).
	// Backs --only/--skip so a second, deeper pass needn't re-exercise everything.
	Select func(moduleName string) bool
}

// Result pairs a note with the calls that were planned/made for it.
type Result struct {
	Note      module.Note
	Planned   []recon.PlannedCall
	harvested []module.Harvested
	secret    string // for cross-source dedup/annotation
}

const (
	maxHarvestDepth  = 3
	maxHarvestBudget = 100
)

// shellIdent matches a label that is a usable shell variable name.
var shellIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// nonSecretField names fields that locate a service but are not secret, so they
// are not scrubbed from the audit trail (the visible destination is what lets an
// operator spot exfil to an unexpected host).
var nonSecretField = map[string]bool{
	"endpoint": true, "host": true, "region": true, "project_id": true,
	"account": true, "app_id": true, "sid": true, "domain": true,
	"server": true, "context": true, "email": true, "client_id": true,
	"tenant": true, "_rule": true, "identity": true,
}

// harvestState bounds transitive harvesting and dedupes secrets across the whole
// batch: a global set of seen secret values (cycle + cross-file dupe guard), the
// other source files each deduped secret also appeared in (so the footprint
// isn't lost), and a total budget (explosion guard). All fields are guarded by
// mu so sources can be reconned concurrently.
type harvestState struct {
	mu      sync.Mutex
	seen    map[string]bool
	dupLocs map[string][]string
	budget  int
}

func newHarvestState() *harvestState {
	return &harvestState{seen: map[string]bool{}, dupLocs: map[string][]string{}, budget: maxHarvestBudget}
}

// claim records the first sighting of a secret and returns true; on a repeat it
// returns false and (for a top-level source) remembers the extra location.
func (st *harvestState) claim(secret, file string, depth int) bool {
	if secret == "" {
		return true // unnamed values aren't deduped
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.seen[secret] {
		if depth == 0 && file != "" {
			st.dupLocs[secret] = append(st.dupLocs[secret], file)
		}
		return false
	}
	st.seen[secret] = true
	return true
}

// takeHarvest reserves budget for one harvested secret if it's new and budget
// remains. It mirrors the original ordering: known/empty values are skipped
// without spending budget.
func (st *harvestState) takeHarvest(value string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.budget <= 0 || value == "" || st.seen[value] {
		return false
	}
	st.budget--
	return true
}

// Batch triages many sources sharing one harvestState, so a credential appearing
// in several files is reconned ONCE (saving network/OPSEC cost and de-noising
// output); the extra locations are recorded for AnnotateDuplicates.
type Batch struct {
	reg  *module.Registry
	opts Options
	st   *harvestState
}

// NewBatch creates a batch runner with fresh shared dedupe state.
func NewBatch(reg *module.Registry, opts Options) *Batch {
	return &Batch{reg: reg, opts: opts, st: newHarvestState()}
}

// Run triages one source within the batch (deduping against earlier sources).
func (bt *Batch) Run(b parse.Blob) []Result { return runBlob(b, bt.reg, bt.opts, bt.st, 0) }

const defaultConcurrency = 8

// effConcurrency is the worker count: 1 on the dry-run path (instant; keep it
// deterministic) and for a single source, otherwise Options.Concurrency or the
// default. Recon is network-bound, so a few-way pool is a large wall-clock win.
func (bt *Batch) effConcurrency(nsrc int) int {
	if !bt.opts.Live || nsrc <= 1 {
		return 1
	}
	c := bt.opts.Concurrency
	if c <= 0 {
		c = defaultConcurrency
	}
	if c > nsrc {
		c = nsrc
	}
	return c
}

// RunConcurrent triages every source through a bounded worker pool and returns
// all results. emit (may be nil) is invoked for each result as it is produced;
// progress (may be nil) is invoked with the running count of completed sources.
// Both callbacks are serialized, so they may touch shared state and write output
// safely. Result order is not meaningful on the concurrent path — the caller
// sorts. Duplicate locations are still recorded for AnnotateDuplicates.
func (bt *Batch) RunConcurrent(srcs []Source, emit func(Result), progress func(done int)) []Result {
	conc := bt.effConcurrency(len(srcs))
	var (
		mu   sync.Mutex
		all  []Result
		done int
	)
	finish := func(rs []Result) {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range rs {
			if emit != nil {
				emit(r)
			}
			all = append(all, r)
		}
		done++
		if progress != nil {
			progress(done)
		}
	}
	if conc <= 1 {
		for _, s := range srcs {
			finish(bt.Run(s.Blob))
		}
		return all
	}
	jobs := make(chan Source)
	var wg sync.WaitGroup
	for range conc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				finish(runBlob(s.Blob, bt.reg, bt.opts, bt.st, 0))
			}
		}()
	}
	for _, s := range srcs {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	return all
}

// AnnotateDuplicates appends an "also exposed in" finding to each result whose
// secret was also found in other source files (deduped away). The value groups
// those locations by exposure class — so N auto-saved history snapshots of one
// file read as one source, not N leaks — and the full path list rides in Detail
// (shown with -v / in JSON). Call it after all sources run, before sorting.
// (Not usable with streaming, where earlier results are already printed.)
func (bt *Batch) AnnotateDuplicates(results []Result) {
	for i := range results {
		locs := bt.st.dupLocs[results[i].secret]
		if results[i].secret == "" || len(locs) == 0 {
			continue
		}
		results[i].Note.Findings = append(results[i].Note.Findings, dupFinding(locs))
	}
}

// dupFinding summarizes the other locations a secret was found in, grouped and
// counted by exposure class, with the de-duplicated full path list in Detail.
func dupFinding(locs []string) module.Finding {
	seen := map[string]bool{}
	var paths, order []string
	counts := map[string]int{}
	for _, p := range locs {
		if seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
		class, _, _ := classifyExposure(p)
		if class == "" {
			class = "other file"
		}
		if counts[class] == 0 {
			order = append(order, class)
		}
		counts[class]++
	}
	sort.Strings(paths)
	sort.Strings(order)
	var parts []string
	for _, c := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[c], plural(c, counts[c])))
	}
	return module.Finding{Key: "also exposed in", Value: strings.Join(parts, "; "), Flag: module.FlagInfo, Detail: paths}
}

func plural(noun string, n int) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

// annotateContext prepends exposure-surface + timeline context to a live note so
// the responder leads with WHERE the credential was exposed (and what that
// means) and WHEN. No-op for dead notes (their findings aren't rendered anyway).
func annotateContext(res *Result, b parse.Blob, opts Options) {
	if res.Note.Invalid {
		return
	}
	var lead []module.Finding
	if class, note, flag := classifyExposure(b.File); class != "" {
		lead = append(lead, module.Finding{Key: "exposure", Value: note, Flag: flag})
	}
	if !b.ModTime.IsZero() {
		lead = append(lead, module.Finding{Key: "source modified", Value: b.ModTime.Format("2006-01-02 (Mon)"), Flag: module.FlagInfo})
	}
	if len(lead) > 0 {
		res.Note.Findings = append(lead, res.Note.Findings...)
	}
	// Live-validated: a credential that actually made recon calls (and wasn't
	// rejected) gets a timestamp anchor for the incident timeline.
	if opts.Live && len(res.Planned) > 0 {
		ts := opts.StartedAt
		if ts.IsZero() {
			ts = time.Now()
		}
		res.Note.Findings = append(res.Note.Findings, module.Finding{Key: "validated live", Value: ts.UTC().Format(time.RFC3339), Flag: module.FlagInfo})
	}
}

// Run executes the pipeline over a blob and returns one result per credential,
// recursively triaging any secrets harvested from a secrets store (under
// --live --intrusive only).
func Run(b parse.Blob, reg *module.Registry, opts Options) []Result {
	return runBlob(b, reg, opts, newHarvestState(), 0)
}

func runBlob(b parse.Blob, reg *module.Registry, opts Options, st *harvestState, depth int) []Result {
	matches := recognize.Recognize(b, opts.Endpoint, reg)
	var results []Result
	for _, m := range matches {
		if opts.Select != nil && !opts.Select(m.Module) {
			continue // scoped run (--only/--skip): don't recon non-matching creds
		}
		if !st.claim(m.Secret, b.File, depth) {
			continue // already triaged this exact secret (cycle/cross-file dupe guard)
		}
		res := runOne(b, reg, opts, m)
		res.secret = m.Secret
		annotateContext(&res, b, opts)
		results = append(results, res)

		// Transitive harvest: feed downstream secrets back through the pipeline.
		if opts.Live && opts.Intrusive && depth < maxHarvestDepth {
			for _, h := range res.harvested {
				if !st.takeHarvest(h.Value) {
					continue
				}
				child := parse.Parse(h.Value, "harvested via "+m.Module+": "+h.Label)
				results = append(results, runBlob(child, reg, opts, st, depth+1)...)
			}
		}
	}
	return results
}

func runOne(b parse.Blob, reg *module.Registry, opts Options, m recognize.Match) (res Result) {
	title := titleFor(b, m)
	// Per-credential isolation: a module panic becomes an error note.
	defer func() {
		if r := recover(); r != nil {
			res.Note = module.Note{Title: title, Invalid: true, Reason: fmt.Sprintf("module error: %v", r)}
		}
	}()

	if strings.HasPrefix(m.Module, "__unknown__:") {
		rule := strings.TrimPrefix(m.Module, "__unknown__:")
		return Result{Note: module.Note{
			Title:   title,
			Summary: "unknown type, not characterized",
			Reason:  "no Geiger module for rule " + rule,
			Findings: []module.Finding{
				{Key: "detected", Value: rule, Flag: module.FlagInfo},
				{Key: "status", Value: "recognized but not characterizable — no module", Flag: module.FlagCantCharacterize},
			},
		}}
	}

	mod, ok := reg.ByName(m.Module)
	if !ok {
		return Result{Note: module.Note{Title: title, Invalid: true, Reason: "no module named " + m.Module}}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	hc, err := httpClient(timeout, opts.Proxy)
	if err != nil {
		return Result{Note: module.Note{Title: title, Invalid: true, Reason: "proxy config: " + err.Error()}}
	}
	client := recon.New(hc, opts.Live)
	client.SetIntrusive(opts.Intrusive)
	client.SetMinFootprint(opts.MinFootprint)
	client.SetCorrelate(opts.Correlate)
	client.SetTrace(opts.Trace)
	// Seed the scrubber with secret values so none can leak into a recorded URL
	// or header (e.g. a token carried in the URL path). Skip clearly non-secret
	// fields (endpoint/host/region/…) so the destination stays visible in the
	// audit trail — that visibility is the SSRF/exfil mitigation.
	// When the credential came from a named env/dotenv var, display it as a shell
	// variable reference so the rendered curl is runnable (without the value).
	secrets := []string{m.Secret}
	if shellIdent.MatchString(m.Label) {
		client.RegisterSecretRef(m.Secret, "$"+m.Label)
	} else {
		client.RegisterSecret(m.Secret)
	}
	for k, v := range m.Fields {
		if nonSecretField[k] {
			continue
		}
		client.RegisterSecret(v)
		secrets = append(secrets, v)
	}
	// scrubErr removes any known secret echoed verbatim in an error string
	// (e.g. a token-endpoint error body) before it reaches the note.
	scrubErr := func(err error) string {
		s := redact.Line(err.Error())
		for _, sec := range secrets {
			if len(sec) >= 4 {
				s = strings.ReplaceAll(s, sec, redact.Secret(sec))
			}
		}
		return s
	}

	tok, err := mod.Authenticate(ctx, client, m.Fields)
	client.RegisterSecret(tok.Bearer)
	if err != nil {
		return Result{
			Note:    module.Note{Title: title, Invalid: true, Reason: "auth failed: " + scrubErr(err)},
			Planned: client.Planned(),
		}
	}
	findings, err := mod.Recon(ctx, client, tok, m.Fields)
	planned := client.Planned()
	// In dry-run, network modules return no findings (responses are synthetic),
	// so don't render them as "invalid" — present the planned read-only calls.
	if !opts.Live && len(planned) > 0 {
		return Result{Note: dryRunNote(title, len(planned)), Planned: planned}
	}
	if err != nil {
		return Result{
			Note:    module.Note{Title: title, Invalid: true, Reason: scrubErr(err)},
			Planned: planned,
		}
	}
	note := mod.Summarize(title, findings)
	res = Result{Note: note, Planned: client.Planned()}

	// Transitive harvest (extracts downstream secret values) — gated.
	if opts.Live && opts.Intrusive {
		if h, ok := mod.(module.Harvester); ok {
			if got, herr := h.Harvest(ctx, client, tok, m.Fields); herr == nil {
				res.harvested = got
				if n := len(got); n > 0 {
					res.Note.Findings = append(res.Note.Findings, module.Finding{
						Key:   "harvested",
						Value: itoa(n) + ` downstream secret(s) extracted — re-triaged as separate "harvested via ` + m.Module + `" findings`,
						Flag:  module.FlagForceMultiplier,
					})
				}
			}
		}
		res.Planned = client.Planned()
	}
	return res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// httpClient builds the recon HTTP client. Egress can be routed through a proxy
// (http/https/socks5). The dialer refuses metadata/loopback targets (see
// recon.GuardedDial) so an input-controlled endpoint — or a harvested value
// re-triaged internally — can't be used to reach the cloud metadata service.
// RFC1918 private ranges stay reachable (internal Vault/GitLab triage is
// legitimate).
func httpClient(timeout time.Duration, proxy string) (*http.Client, error) {
	tr := &http.Transport{DialContext: recon.GuardedDial}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

func dryRunNote(title string, n int) module.Note {
	plural := "call"
	if n != 1 {
		plural = "calls"
	}
	return module.Note{
		Title:   title,
		Summary: fmt.Sprintf("dry-run — would make %d read-only %s; re-run with --live to characterize", n, plural),
	}
}

// titleFor builds "<module> <redacted-secret> (from <label>)".
func titleFor(b parse.Blob, m recognize.Match) string {
	red := redact.Secret(m.Secret)
	src := m.Label
	if src == "" {
		src = string(b.Kind)
	}
	loc := b.File
	if loc == "" {
		loc = string(b.Kind)
	}
	if m.Line > 0 {
		loc += fmt.Sprintf(":%d", m.Line)
	}
	if red == "" {
		return fmt.Sprintf("%s (from %s: %s)", m.Module, loc, src)
	}
	return fmt.Sprintf("%s %s (from %s: %s)", m.Module, red, loc, src)
}
