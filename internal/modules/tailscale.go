package modules

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Tailscale mints three credentials that all start "tskey-", and they are not
// interchangeable:
//
//	tskey-api-…     an API access token. Carries the owning user's permissions
//	                and expires in 1-90 days.
//	tskey-client-…  an OAuth client secret ("trust credential"). It does NOT
//	                expire, and it mints one-hour API tokens on demand — so a
//	                leaked one is durable access, where a leaked API key is a
//	                90-day clock. It also works directly as an auth key.
//	tskey-auth-…    an auth key. It enrolls a device into the tailnet. Redeeming
//	                one is a write, so geiger cannot prove it live.
//
// Key prefixes and the expiry rules are from Tailscale's own OpenAPI description
// at https://api.tailscale.com/api/v2?outputOpenapiSchema=true.
//
// gitleaks ships no Tailscale rule, so this recognizer is the only thing that
// sees these keys — which is why it scans the raw blob rather than only parsed
// variables: auth keys leak in compose files and CI logs, not just .env.
const tailscaleAPI = "https://api.tailscale.com/api/v2"

// "-" is Tailscale's alias for "the tailnet this credential belongs to", so
// recon never has to know the tailnet name up front.
const tailscaleTailnet = "-"

func init() {
	module.Register(tailscaleAPIKey{})
	module.Register(tailscaleOAuthClient{})
	module.Register(tailscaleAuthKey{})
	recognize.RegisterRecognizer(recognizeTailscale)
}

// tsUnverified keys a finding that Summarize reads as a verdict and removes,
// rather than printing it as one more line of reach.
const tsUnverified = "unverified"

// --- shared recon -----------------------------------------------------------

// tsGet performs one read-only GET against the Tailscale API. Callers decide
// what a refusal means: the device list is the one call every token kind can
// make, while the policy file and the key inventory need their own scopes and
// are routinely refused from a perfectly live token.
func tsGet(ctx context.Context, c *recon.Client, bearer, path string) (*recon.Response, error) {
	req, err := recon.NewRequest(ctx, http.MethodGet, tailscaleAPI+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return c.Do(req, recon.CallOpts{})
}

// tailscaleRecon walks the read-only surface an API token reaches. Both the API
// key and the OAuth client end up here — an OAuth client secret is just a token
// factory, so once it has minted one the reach is identical.
func tailscaleRecon(ctx context.Context, c *recon.Client, bearer string) ([]module.Finding, error) {
	resp, err := tsGet(ctx, c, bearer, "/tailnet/"+tailscaleTailnet+"/devices?fields=all")
	if err != nil {
		return nil, err
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return nil, errStatus(resp.Status)
	}
	out := tsDeviceFindings(resp.Body)

	// Optional from here: a scoped token that cannot read these is still a live
	// token with everything above already proved.
	if r, err := tsGet(ctx, c, bearer, "/tailnet/"+tailscaleTailnet+"/acl"); err == nil && tsOK(r) {
		out = append(out, tsACLFindings(r.Body)...)
	}
	if r, err := tsGet(ctx, c, bearer, "/tailnet/"+tailscaleTailnet+"/keys"); err == nil && tsOK(r) {
		out = append(out, tsKeyFindings(r.Body)...)
	}

	// Dry-run bodies are synthetic. Returning findings built from them would
	// invent an inventory; the pipeline prints the planned calls instead.
	if resp.DryRun {
		return nil, nil
	}
	out = append(out, module.Finding{Key: "reach",
		Value: "read every device in the tailnet, rewrite the ACL policy file, and mint auth keys that enroll attacker-controlled nodes into the private network",
		Flag:  fmFlag})
	return out, nil
}

func tsOK(r *recon.Response) bool { return !r.DryRun && r.Status >= 200 && r.Status < 300 }

// tsDeviceFindings turns the device list into the answer a responder actually
// needs: how wide is this tailnet, and does it bridge into internal address
// space.
func tsDeviceFindings(body []byte) []module.Finding {
	var devices []any
	if raw, ok := jsonDecode(body)["devices"].([]any); ok {
		devices = raw
	}
	var out []module.Finding
	out = append(out, module.Finding{Key: "devices", Value: strconv.Itoa(len(devices)), Flag: warnFlag})

	var subnets, exits, tags []string
	var expiryDisabled int
	var tailnet string
	seenSubnet, seenExit, seenTag := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, d := range devices {
		dev, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if tailnet == "" {
			tailnet = tsTailnetFromName(tsStr(dev["name"]))
		}
		if b, ok := dev["keyExpiryDisabled"].(bool); ok && b {
			expiryDisabled++
		}
		// enabledRoutes, not advertisedRoutes: a route only carries traffic once
		// an admin approves it. Reporting what a node merely asked for would
		// overstate the reach.
		for _, r := range tsStrings(dev["enabledRoutes"]) {
			switch {
			case tsIsDefaultRoute(r):
				if !seenExit[r] {
					seenExit[r] = true
					exits = append(exits, r)
				}
			case !seenSubnet[r]:
				seenSubnet[r] = true
				subnets = append(subnets, r)
			}
		}
		for _, t := range tsStrings(dev["tags"]) {
			if !seenTag[t] {
				seenTag[t] = true
				tags = append(tags, t)
			}
		}
	}
	sort.Strings(subnets)
	sort.Strings(exits)
	sort.Strings(tags)

	if tailnet != "" {
		out = append(out, module.Finding{Key: "tailnet", Value: tailnet, Flag: module.FlagNone})
	}
	if len(subnets) > 0 {
		out = append(out, module.Finding{Key: "subnet routes",
			Value: strings.Join(subnets, ", ") + " — the tailnet bridges into these internal networks, so a node enrolled with this credential reaches them",
			Flag:  fmFlag, Detail: subnets})
	}
	if len(exits) > 0 {
		out = append(out, module.Finding{Key: "exit nodes",
			Value: "a device advertises a default route (" + strings.Join(exits, ", ") + ") — enrolled nodes can route all their traffic through the tailnet",
			Flag:  fmFlag, Detail: exits})
	}
	if expiryDisabled > 0 {
		out = append(out, module.Finding{Key: "key expiry disabled", Value: strconv.Itoa(expiryDisabled), Flag: warnFlag})
	}
	if len(tags) > 0 {
		out = append(out, module.Finding{Key: "device tags", Value: strings.Join(tags, ", "), Flag: infoFlag, Detail: tags})
	}
	return out
}

// tsACLFindings reads the policy file. Tailscale SSH is the finding that matters:
// where it is enabled, reaching the tailnet is reaching a shell.
func tsACLFindings(body []byte) []module.Finding {
	decoded := jsonDecode(body)
	var out []module.Finding
	if ssh, ok := decoded["ssh"].([]any); ok && len(ssh) > 0 {
		out = append(out, module.Finding{Key: "tailscale ssh",
			Value: strconv.Itoa(len(ssh)) + " SSH rule(s) in the policy file — tailnet access grants shell on the matching nodes",
			Flag:  fmFlag})
	}
	// "grants" is Tailscale's newer access-rule syntax and the one it now
	// recommends; a tailnet that has migrated leaves "acls" present but empty.
	// Counting only "acls" there reports a fully-configured tailnet as having no
	// rules at all, so both are counted together.
	var rules []any
	for _, key := range []string{"acls", "grants"} {
		if r, ok := decoded[key].([]any); ok {
			rules = append(rules, r...)
		}
	}
	// A zero count says nothing and reads as though the tailnet were unconfigured.
	if len(rules) > 0 {
		out = append(out, module.Finding{Key: "access rules", Value: strconv.Itoa(len(rules)), Flag: infoFlag})
		for _, a := range rules {
			rule, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if tsHasWildcard(rule["src"]) && tsHasWildcard(rule["dst"]) {
				out = append(out, module.Finding{Key: "acl wide open",
					Value: "the policy file accepts * to *:* — every node may reach every other node and port",
					Flag:  fmFlag})
				break
			}
		}
	}
	return out
}

// tsKeyFindings inventories the tailnet's other live credentials. A token that
// can read this can also tell an attacker which other keys to go looking for.
func tsKeyFindings(body []byte) []module.Finding {
	decoded := jsonDecode(body)
	keys, _ := decoded["keys"].([]any)
	if len(keys) == 0 {
		return nil
	}
	byType := map[string]int{}
	broad := 0
	for _, k := range keys {
		key, ok := k.(map[string]any)
		if !ok {
			continue
		}
		byType[tsStr(key["keyType"])]++
		if slices.Contains(tsStrings(key["scopes"]), "all") {
			broad++
		}
	}
	kinds := make([]string, 0, len(byType))
	for t, n := range byType {
		if t == "" {
			t = "other"
		}
		kinds = append(kinds, strconv.Itoa(n)+" "+t)
	}
	sort.Strings(kinds)
	out := []module.Finding{{Key: "other keys",
		Value: strings.Join(kinds, ", ") + " — this credential can enumerate the tailnet's other live keys",
		Flag:  warnFlag, Detail: kinds}}
	if broad > 0 {
		out = append(out, module.Finding{Key: "all-scope keys",
			Value: strconv.Itoa(broad) + " other credential(s) hold the 'all' scope", Flag: warnFlag})
	}
	return out
}

// --- tailscale: API access token (tskey-api-…) -------------------------------

type tailscaleAPIKey struct{ module.Base }

func (tailscaleAPIKey) Name() string { return "tailscale" }

func (tailscaleAPIKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	return tailscaleRecon(ctx, c, f["token"])
}

func (tailscaleAPIKey) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: tsSummary("Tailscale API token", fs)}
}

// --- tailscale_oauth_client: OAuth client secret (tskey-client-…) ------------

type tailscaleOAuthClient struct{}

func (tailscaleOAuthClient) Name() string { return "tailscale_oauth_client" }

// Authenticate runs the client-credentials exchange. Minting a one-hour access
// token is the documented way to use this credential and reads nothing on its
// own, so it sits alongside the other token exchanges geiger permits.
//
// The error return is reserved for a definitive rejection. A transport failure
// or an unrecognized status proves nothing, and reporting either as dead would
// retire a live secret — those come back as a token carrying an "unverified"
// note that Recon turns into an UNKNOWN verdict.
func (tailscaleOAuthClient) Authenticate(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
	form := url.Values{}
	form.Set("client_secret", f["client_secret"])
	// The client id is embedded in the secret, and Tailscale accepts the secret
	// on its own; send the id too when the blob carried it separately.
	if id := f["client_id"]; id != "" {
		form.Set("client_id", id)
	}
	req, err := recon.NewRequest(ctx, http.MethodPost, tailscaleAPI+"/oauth/token", []byte(form.Encode()))
	if err != nil {
		return module.Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true,
		Note: "OAuth client-credentials exchange — mints a short-lived read token, changes nothing"})
	switch {
	case err != nil:
		return module.Token{Extra: map[string]string{
			tsUnverified: "could not reach Tailscale's token endpoint: " + err.Error()}}, nil
	case resp.DryRun:
		return module.Token{Bearer: "<dry-run-token>"}, nil
	case resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden:
		return module.Token{}, errors.New("the token endpoint refused this OAuth client secret — it was revoked, or the client was deleted")
	case resp.Status < 200 || resp.Status >= 300:
		return module.Token{Extra: map[string]string{
			tsUnverified: "the token endpoint answered HTTP " + strconv.Itoa(resp.Status) + ", which geiger does not recognize — nothing was proved either way"}}, nil
	}
	tok := module.Token{Bearer: jsonField(resp.Body, "access_token")}
	if s := jsonField(resp.Body, "scope"); s != "" {
		tok.Extra = map[string]string{"scope": s}
	}
	return tok, nil
}

func (tailscaleOAuthClient) Recon(ctx context.Context, c *recon.Client, t module.Token, _ module.Fields) ([]module.Finding, error) {
	if reason := t.Extra[tsUnverified]; reason != "" {
		return []module.Finding{{Key: tsUnverified, Value: reason, Flag: cantFlag}}, nil
	}
	// Stated without a call: Tailscale documents that trust credentials never
	// expire, which is what separates this from a stolen API key.
	out := []module.Finding{{Key: "no expiry",
		Value: "OAuth client secrets do not expire — unlike API tokens, which are capped at 90 days, this keeps working until someone revokes it",
		Flag:  warnFlag}}
	out = append(out, tsScopeFindings(t.Extra["scope"])...)

	rest, err := tailscaleRecon(ctx, c, t.Bearer)
	if err != nil {
		return nil, err
	}
	return append(out, rest...), nil
}

// tsScopeFindings reads the granted scopes off the token response. Scopes are
// the honest measure of an OAuth client's reach — far better than assuming the
// worst — so an unscoped read-only client scores as what it is.
func tsScopeFindings(scope string) []module.Finding {
	if scope == "" {
		return nil
	}
	scopes := strings.Fields(strings.ReplaceAll(scope, ",", " "))
	// Tailscale spells read-only scopes with a ":read" suffix (dns:read,
	// devices:core:read, all:read). Anything else grants writes, and "all" is
	// total tailnet control. A broad read stays FlagWarn — it is not nothing,
	// but it cannot enroll a node or rewrite the policy file.
	flag := warnFlag
	for _, s := range scopes {
		if !strings.HasSuffix(s, ":read") {
			flag = fmFlag
			break
		}
	}
	out := []module.Finding{{Key: "scopes", Value: strings.Join(scopes, " "), Flag: flag, Detail: scopes}}
	for _, s := range scopes {
		if s == "auth_keys" || s == "all" {
			out = append(out, module.Finding{Key: "node enrollment",
				Value: "this scope mints auth keys, and the secret itself works as one (tailscale up --auth-key=…) — an attacker can join their own node to the tailnet",
				Flag:  fmFlag})
			break
		}
	}
	return out
}

func (tailscaleOAuthClient) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title}
	kept := fs[:0:0]
	for _, f := range fs {
		if f.Key == tsUnverified {
			n.Undetermined, n.Reason = true, f.Value
			continue
		}
		kept = append(kept, f)
	}
	n.Findings = kept
	if !n.Undetermined {
		n.Summary = tsSummary("Tailscale OAuth client (non-expiring)", kept)
	}
	return n
}

// --- tailscale_auth_key: auth key (tskey-auth-… and the legacy bare form) ----

type tailscaleAuthKey struct{ module.Base }

func (tailscaleAuthKey) Name() string { return "tailscale_auth_key" }

// tsAuthKeyUnverifiable is the standing reason this module reports. It is a
// constant because it is not conditional: no code path here proves an auth key
// live, so every note it produces is UNKNOWN.
const tsAuthKeyUnverifiable = "an auth key can only be tested by redeeming it, and redeeming registers a new device on the tailnet — a write, and outside the scope of a read-only tool; confirm the key yourself in the admin console under Settings → Keys"

// Recon makes no call. The only way to test an auth key is to redeem it, and
// redeeming registers a device on the tailnet — a write, and a noisy one that
// would show up in the victim's own device list. That is outside what this tool
// does, so it states the reach and leaves the verdict UNKNOWN rather than buying
// a liveness answer with a side effect.
func (tailscaleAuthKey) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return []module.Finding{
		{Key: tsUnverified, Value: tsAuthKeyUnverifiable, Flag: cantFlag},
		{Key: "reach",
			Value: "enrolls a device into the tailnet, which then reaches whatever the policy file allows the key's tags or owner to reach — including any subnet routes and Tailscale SSH targets",
			Flag:  fmFlag},
		{Key: "expiry",
			Value: "auth keys last at most 90 days from creation; reusable keys enroll any number of devices until then",
			Flag:  infoFlag},
	}, nil
}

// Summarize is unconditionally undetermined: an auth key that geiger never
// tested is not a dead one, and marking it dead would retire a key that still
// enrolls devices.
func (tailscaleAuthKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Undetermined: true, Reason: tsAuthKeyUnverifiable,
		Summary: "Tailscale auth key — enrolls a device into the tailnet; not verifiable read-only"}
	kept := fs[:0:0]
	for _, f := range fs {
		if f.Key == tsUnverified {
			n.Reason = f.Value
			continue
		}
		kept = append(kept, f)
	}
	n.Findings = kept
	return n
}

// --- shared helpers ---------------------------------------------------------

// tsSummary leads with whatever the recon actually proved, so the one-liner
// changes when the reach does.
func tsSummary(kind string, fs []module.Finding) string {
	has := map[string]bool{}
	for _, f := range fs {
		has[f.Key] = true
	}
	switch {
	case has["subnet routes"]:
		return kind + " — tailnet admin, and the tailnet routes into internal networks"
	case has["tailscale ssh"]:
		return kind + " — tailnet admin, with Tailscale SSH enabled"
	}
	return kind + " — tailnet device/ACL admin + auth-key minting"
}

// tsTailnetFromName pulls the tailnet out of a device's MagicDNS name
// ("laptop.tail1a2b3.ts.net" → "tail1a2b3.ts.net").
func tsTailnetFromName(name string) string {
	if _, rest, ok := strings.Cut(name, "."); ok && strings.Contains(rest, ".") {
		return rest
	}
	return ""
}

func tsIsDefaultRoute(r string) bool { return r == "0.0.0.0/0" || r == "::/0" }

func tsHasWildcard(v any) bool {
	for _, s := range tsStrings(v) {
		if s == "*" || s == "*:*" {
			return true
		}
	}
	return false
}

// tsStrings reads a decoded JSON array of strings, tolerating null and absent.
func tsStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func tsStr(v any) string {
	s, _ := v.(string)
	return s
}

// --- recognition ------------------------------------------------------------

// tsKeyRe matches the "tskey-" family loosely and lets classifyTailscaleKey
// decide. Matching the shape loosely is cheap — a value that is not really a key
// fails its first API call — while a strict pattern would miss the next format
// Tailscale ships.
var tsKeyRe = regexp.MustCompile(`\btskey-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*`)

// tsAuthKeyVars are names that hold an auth key whose value has been templated
// away (a CI expression, a placeholder). They carry no tskey- shape to match, so
// the name is the only signal.
var tsAuthKeyVars = []string{"TS_AUTHKEY", "TAILSCALE_AUTHKEY", "TS_AUTH_KEY", "TAILSCALE_AUTH_KEY"}

// classifyTailscaleKey routes a "tskey-" value to its module. The infix names
// the kind; a value with no infix is the pre-2022 auth-key format.
func classifyTailscaleKey(tok string) (mod, clientID string, ok bool) {
	rest, found := strings.CutPrefix(tok, "tskey-")
	if !found || rest == "" {
		return "", "", false
	}
	parts := strings.Split(rest, "-")
	// Modern keys are <kind>-<key id>-<secret>. Anything shorter is a prefix
	// someone wrote in prose, not a key.
	switch parts[0] {
	case "api":
		return "tailscale", "", len(parts) >= 3
	case "client":
		if len(parts) < 3 {
			return "", "", false
		}
		return "tailscale_oauth_client", parts[1], true
	case "auth":
		return "tailscale_auth_key", "", len(parts) >= 3
	}
	// Legacy bare key. Require a body long enough not to be a stray word.
	if len(parts) == 1 && len(parts[0]) >= 10 {
		return "tailscale_auth_key", "", true
	}
	return "", "", false
}

func recognizeTailscale(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	seen := map[string]bool{}
	for _, tok := range tsKeyRe.FindAllString(b.Raw, -1) {
		mod, clientID, ok := classifyTailscaleKey(tok)
		if !ok || seen[tok] {
			continue
		}
		seen[tok] = true
		fields := module.Fields{"token": tok}
		if mod == "tailscale_oauth_client" {
			// The module authenticates with the secret; keep the recovered id so
			// the exchange can send both halves.
			fields = module.Fields{"client_secret": tok, "client_id": clientID}
		}
		out = append(out, recognize.Match{
			Module: mod, Fields: fields, Secret: tok,
			Label: tsLabel(b, tok, mod),
		})
	}
	// An auth key named but not shaped like one (a CI expression, a placeholder
	// the operator will substitute) is still worth naming: it tells a responder
	// which credential to go and rotate.
	for _, name := range tsAuthKeyVars {
		v := b.Vars[name]
		if v == "" || seen[v] || strings.HasPrefix(v, "tskey-") {
			continue
		}
		seen[v] = true
		out = append(out, recognize.Match{
			Module: "tailscale_auth_key",
			Fields: module.Fields{"token": v}, Secret: v, Label: name,
		})
	}
	return out
}

// tsLabel prefers the variable the key was found in. A key matched out of raw
// text — a compose file, a CI log — has no variable to name, so it falls back to
// a kind label in the hyphenated style the other raw-scan recognizers use.
// Naming a plausible variable there instead would tell a responder to go and
// rotate a variable the file does not contain.
func tsLabel(b parse.Blob, tok, mod string) string {
	for k, v := range b.Vars {
		if v == tok {
			return k
		}
	}
	switch mod {
	case "tailscale":
		return "tailscale-api-key"
	case "tailscale_oauth_client":
		return "tailscale-oauth-client-secret"
	}
	return "tailscale-auth-key"
}
