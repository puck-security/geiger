package modules

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Freshworks: Freshservice (ITSM), Freshdesk (help desk), Freshchat, Freshsales.
//
// Freshservice and Freshdesk are hand-written, not recipes: "is this an admin
// key" needs the agent's role ids joined against the account's role table, and a
// recipe emits findings per call without correlating them.

func init() {
	module.Register(freshservice{})
	module.Register(freshdesk{})
	recognize.RegisterRecognizer(recognizeFreshservice)
	recognize.RegisterRecognizer(recognizeFreshdesk)
	registerFreshchat()
	registerFreshsales()
}

// The key is the Basic username; the password is ignored but must be non-empty,
// so recipe's BasicKeyUser (which sends "") won't work.
const freshDummyPassword = "X"

// freshGET builds a Basic-auth GET against a Freshworks tenant.
func freshGET(ctx context.Context, base, key, path string) (*http.Request, error) {
	req, err := recon.NewRequest(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(key, freshDummyPassword)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// freshAdminRoleRe matches ONE role name. Freshworks exposes no is_admin flag,
// so this is a heuristic, anchored so "Non-Admin Reviewer" doesn't match. Apply
// per role: anchored against a joined "IT Agent, Admin" it matches nothing.
var freshAdminRoleRe = regexp.MustCompile(`(?i)^(account admin|admin|administrator|super ?admin|workspace admin)`)

// freshHasAdminRole reports whether any single held role is an admin one.
func freshHasAdminRole(held []string) bool {
	for _, name := range held {
		if freshAdminRoleRe.MatchString(strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// Avoids the words "secret", "vault" and "harvest": readsSecretsStore() matches
// those and would advise --intrusive harvesting, but these credentials can't be
// read back through the API.
const freshPivotValue = "admin can reconfigure Discovery Probe and Orchestration connectors, " +
	"which hold Windows domain-admin, SSH, SNMP and SCCM credentials for the estate — " +
	"not readable through the API, but reachable by repointing the integrations that use them"

// freshRoleNames resolves role ids to names via GET /api/v2/roles. Shared by
// both products: the roles endpoint has the same shape on each.
func freshRoleNames(ctx context.Context, c *recon.Client, base, key string) map[string]string {
	req, err := freshGET(ctx, base, key, "/api/v2/roles")
	if err != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "list roles (resolve the agent's role ids to names)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	out := map[string]string{}
	for _, v := range freshList(resp.Body, "roles") {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if id, name := freshNum(m["id"]), freshStr(m["name"]); id != "" && name != "" {
			out[id] = name
		}
	}
	return out
}

// freshList pulls a named array out of a Freshworks response, tolerating both
// the wrapped ({"agents":[…]}) and bare ([…]) shapes the products use.
func freshList(body []byte, key string) []any {
	if arr, ok := jsonDecodeArray(body); ok {
		return arr
	}
	arr, _ := jsonDecode(body)[key].([]any)
	return arr
}

func freshStr(v any) string {
	s, _ := v.(string)
	return s
}

// freshNum renders a JSON number as an integer string; ids arrive as float64.
func freshNum(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatInt(int64(n), 10)
	case string:
		return n
	}
	return ""
}

// At per_page=1 the rel="last" page number is the total row count:
//
//	Link: <https://acme.freshservice.com/api/v2/tickets?per_page=1&page=8412>; rel="last"
var freshLastPageRe = regexp.MustCompile(`[?&]page=(\d+)[^>]*>\s*;\s*rel="last"`)

// freshTotal returns the row count a paginated response implies, or 0 when the
// tenant sends no rel="last" link (not every Freshworks endpoint does).
func freshTotal(h http.Header) int {
	m := freshLastPageRe.FindStringSubmatch(h.Get("Link"))
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

// freshCount sizes a resource. A non-200 is not fatal: a scoped key legitimately
// 403s, and that absence is itself signal. Returns a row count when the tenant
// sends rel="last" (score.reachBonus reads the number), else bare reachability.
func freshCount(ctx context.Context, c *recon.Client, base, key, path, listKey, label string, flag module.FlagLevel) *module.Finding {
	req, err := freshGET(ctx, base, key, path)
	if err != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil
	}
	if len(freshList(resp.Body, listKey)) == 0 {
		return nil
	}
	value := "reachable"
	if n := freshTotal(resp.Header); n > 0 {
		value = strconv.Itoa(n) + " reachable"
	}
	return &module.Finding{Key: label, Value: value, Flag: flag}
}

// freshUnreachable marks a note the pipeline should read as UNKNOWN rather than
// DEAD: the tenant never answered, so nothing was proved either way.
const freshUnreachable = "tenant unreachable"

// freshNeedsEndpoint is returned when there is no base URL to call. That happens
// when enforceEndpointPolicy clears a host outside the vendor's domains, so it is
// reachable in normal use — and an empty findings list would otherwise be
// summarized as "credential rejected", reporting a live key as DEAD.
func freshNeedsEndpoint(product, domainVar string) []module.Finding {
	return []module.Finding{{Key: "needs_endpoint",
		Value: "no " + product + " tenant URL — set --endpoint or " + domainVar + " and re-run with --live",
		Flag:  cantFlag}}
}

func freshSummarize(title, summary string, fs []module.Finding) module.Note {
	// No findings means the tenant answered 401: the key is rejected. Matching
	// the recipe engine's contract, and the catalog-wide guard that an empty note
	// must never render as a live credential.
	if len(fs) == 0 {
		return module.Note{Title: title, Invalid: true, Reason: "credential rejected by the tenant"}
	}
	n := module.Note{Title: title, Findings: fs, Summary: summary}
	for _, f := range fs {
		if f.Key == freshUnreachable {
			n.Undetermined = true
			n.Reason = "tenant unreachable — could not confirm whether this key works"
		}
	}
	return n
}

// ---- Freshservice (ITSM) ----

type freshservice struct{ module.Base }

func (freshservice) Name() string { return "freshservice" }

func (freshservice) EndpointPolicy() module.EndpointPolicy { return saasOnly("freshservice.com") }

func (m freshservice) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	base, key := f["endpoint"], f["token"]
	if base == "" {
		return freshNeedsEndpoint("Freshservice", "FRESHSERVICE_DOMAIN"), nil
	}
	var out []module.Finding

	// Validation probe. NOT /api/v2/agents/me — that path is documented for
	// Freshdesk only; the Freshservice reference publishes just /agents (list)
	// and /agents/[id]. This one is documented, cheap, and read-only.
	req, err := freshGET(ctx, base, key, "/api/v2/agents?per_page=1")
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "list agents (documented key-validation probe)"})
	if err != nil {
		return []module.Finding{{Key: freshUnreachable, Value: "no response from " + base, Flag: cantFlag}}, nil
	}
	// Dry-run still walks the whole sequence: the point of the preview is to show
	// every call --live would make, so an operator consents to the real footprint
	// rather than to the first request. The findings are discarded by the
	// pipeline, which substitutes its own dry-run note.
	switch {
	case resp.DryRun:
	case resp.Status == http.StatusUnauthorized:
		return nil, nil // dead — Summarize marks it invalid
	case resp.Status == http.StatusForbidden:
		// Authenticated but not permitted to list agents. That is itself a
		// privilege signal: this key is not account-admin.
		out = append(out, module.Finding{Key: "scope",
			Value: "cannot list agents — a scoped (non-admin) agent key", Flag: infoFlag})
	case resp.Status >= 300:
		return []module.Finding{{Key: freshUnreachable, Value: "unexpected status " + strconv.Itoa(resp.Status), Flag: cantFlag}}, nil
	default:
		out = append(out, module.Finding{Key: "agents readable",
			Value: "can enumerate the agent directory", Flag: warnFlag})
	}

	out = append(out, m.identity(ctx, c, base, key)...)
	if c.MinFootprint() {
		return out, nil
	}
	out = append(out, m.reach(ctx, c, base, key)...)
	return out, nil
}

// identity resolves who the key acts as. /api/v2/agents/me is undocumented on
// Freshservice, so it runs only after the documented probe has decided
// live-vs-dead; a 404 here costs nothing but the agent's name.
func (m freshservice) identity(ctx context.Context, c *recon.Client, base, key string) []module.Finding {
	req, err := freshGET(ctx, base, key, "/api/v2/agents/me")
	if err != nil {
		return nil
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "undocumented whoami (best-effort identity)"})
	if err == nil && resp.DryRun {
		return nil // call planned; nothing to parse yet
	}
	if err != nil || resp.Status >= 300 {
		return []module.Finding{{Key: "identity",
			Value: "not resolvable — Freshservice publishes no whoami endpoint, so the acting agent is unknown", Flag: cantFlag}}
	}
	agent, _ := jsonDecode(resp.Body)["agent"].(map[string]any)
	if agent == nil {
		return nil
	}
	var out []module.Finding
	if email := freshStr(agent["email"]); email != "" {
		out = append(out, module.Finding{Key: "identity", Value: email, Flag: infoFlag})
	}
	// Freshservice deprecated ticket_scope/role_ids in favour of a roles array
	// of {role_id, assignment_scope}. Parsing the old attributes here would
	// silently report nothing.
	roles, _ := agent["roles"].([]any)
	return append(out, m.roles(ctx, c, base, key, roles)...)
}

// roles correlates the agent's role ids against the account's role table and
// decides whether this key is an admin one.
func (m freshservice) roles(ctx context.Context, c *recon.Client, base, key string, roles []any) []module.Finding {
	if len(roles) == 0 {
		return nil
	}
	names := freshRoleNames(ctx, c, base, key)
	var held, scopes []string
	for _, v := range roles {
		rm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if n := names[freshNum(rm["role_id"])]; n != "" {
			held = append(held, n)
		}
		if s := freshStr(rm["assignment_scope"]); s != "" {
			scopes = append(scopes, s)
		}
	}
	var out []module.Finding
	if len(held) > 0 {
		out = append(out, module.Finding{Key: "roles", Value: strings.Join(held, ", "), Flag: warnFlag})
	}
	if len(scopes) > 0 {
		out = append(out, module.Finding{Key: "scope", Value: strings.Join(scopes, ", "), Flag: infoFlag})
	}
	if !freshHasAdminRole(held) {
		return out
	}
	return append(out,
		module.Finding{Key: "agent creation",
			Value: "admin role — can create agents and assign admin roles, so the key re-mints its own access after rotation", Flag: fmFlag},
		module.Finding{Key: "pivot", Value: freshPivotValue, Flag: fmFlag})
}

// reach sizes what the key actually touches. Each probe is count-only and a 403
// simply yields nothing, so a low-privilege key costs no extra findings.
func (m freshservice) reach(ctx context.Context, c *recon.Client, base, key string) []module.Finding {
	probes := []struct {
		path, listKey, label string
		flag                 module.FlagLevel
	}{
		{"/api/v2/tickets?per_page=1", "tickets", "tickets", warnFlag},
		{"/api/v2/requesters?per_page=1", "requesters", "requester PII", fmFlag},
		{"/api/v2/assets?per_page=1", "assets", "CMDB assets", warnFlag},
	}
	var out []module.Finding
	for _, p := range probes {
		if fnd := freshCount(ctx, c, base, key, p.path, p.listKey, p.label, p.flag); fnd != nil {
			out = append(out, *fnd)
		}
	}
	return out
}

func (freshservice) Summarize(title string, fs []module.Finding) module.Note {
	return freshSummarize(title, "Freshservice ITSM key — tickets, requester PII and CMDB", fs)
}

// ---- Freshdesk (help desk) ----

type freshdesk struct{ module.Base }

func (freshdesk) Name() string { return "freshdesk" }

func (freshdesk) EndpointPolicy() module.EndpointPolicy { return saasOnly("freshdesk.com") }

func (m freshdesk) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	base, key := f["endpoint"], f["token"]
	if base == "" {
		return freshNeedsEndpoint("Freshdesk", "FRESHDESK_DOMAIN"), nil
	}

	// Freshdesk DOES document a whoami, so identity and validation are one call.
	req, err := freshGET(ctx, base, key, "/api/v2/agents/me")
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "currently authenticated agent (documented whoami)"})
	if err != nil {
		return []module.Finding{{Key: freshUnreachable, Value: "no response from " + base, Flag: cantFlag}}, nil
	}
	if !resp.DryRun && resp.Status == http.StatusUnauthorized {
		return nil, nil
	}
	if !resp.DryRun && resp.Status >= 300 {
		return []module.Finding{{Key: freshUnreachable, Value: "unexpected status " + strconv.Itoa(resp.Status), Flag: cantFlag}}, nil
	}

	agent := jsonDecode(resp.Body)
	// A 2xx is proof the key authenticated. Record that before parsing anything,
	// or an unexpected body shape leaves the findings empty and Summarize reports
	// a live credential as rejected.
	out := []module.Finding{{Key: "authenticated",
		Value: "tenant accepted the key", Flag: infoFlag}}
	// Freshdesk agents are flat with a nested contact — the opposite of
	// Freshservice, which deprecated these attributes entirely.
	if contact, ok := agent["contact"].(map[string]any); ok {
		if email := freshStr(contact["email"]); email != "" {
			out = append(out, module.Finding{Key: "identity", Value: email, Flag: infoFlag})
		}
	}
	if s := freshTicketScope(agent["ticket_scope"]); s != "" {
		out = append(out, module.Finding{Key: "scope", Value: s, Flag: infoFlag})
	}
	out = append(out, m.roles(ctx, c, base, key, agent)...)
	if c.MinFootprint() {
		return out, nil
	}
	for _, p := range []struct {
		path, listKey, label string
		flag                 module.FlagLevel
	}{
		{"/api/v2/tickets?per_page=1", "tickets", "tickets", warnFlag},
		{"/api/v2/contacts?per_page=1", "contacts", "contact PII", fmFlag},
	} {
		if fnd := freshCount(ctx, c, base, key, p.path, p.listKey, p.label, p.flag); fnd != nil {
			out = append(out, *fnd)
		}
	}
	return out, nil
}

func (m freshdesk) roles(ctx context.Context, c *recon.Client, base, key string, agent map[string]any) []module.Finding {
	ids, _ := agent["role_ids"].([]any)
	if len(ids) == 0 {
		return nil
	}
	names := freshRoleNames(ctx, c, base, key)
	var held []string
	for _, v := range ids {
		if n := names[freshNum(v)]; n != "" {
			held = append(held, n)
		}
	}
	if len(held) == 0 {
		return nil
	}
	out := []module.Finding{{Key: "roles", Value: strings.Join(held, ", "), Flag: warnFlag}}
	if !freshHasAdminRole(held) {
		return out
	}
	return append(out, module.Finding{Key: "agent creation",
		Value: "admin role — can create agents and grant admin, so the key re-mints its own access after rotation", Flag: fmFlag})
}

// freshTicketScope renders Freshdesk's numeric ticket_scope. Freshservice has no
// equivalent — it deprecated the attribute.
func freshTicketScope(v any) string {
	switch freshNum(v) {
	case "1":
		return "global — every ticket in the account"
	case "2":
		return "group — tickets in the agent's groups"
	case "3":
		return "restricted — only tickets assigned to the agent"
	}
	return ""
}

func (freshdesk) Summarize(title string, fs []module.Finding) module.Note {
	return freshSummarize(title, "Freshdesk help desk key — tickets and contact PII", fs)
}

// ---- Freshchat: Bearer, region-specific host ----

func registerFreshchat() {
	add("", r.HTTP{
		ModuleName: "freshchat", Endpoint: saasOnly("freshchat.com"), Base: "{endpoint}",
		Auth:   r.AuthSpec{Kind: r.Bearer},
		Accept: "application/json",
		Whoami: r.GET("/v2/agents").CountArrayFlag("agents", "agents", warnFlag),
		// A Freshchat token is account-wide by construction — there is no finer
		// role model to enumerate, so no correlation call is warranted.
		Static: []module.Finding{{Key: "reach",
			Value: "account-wide by design — every user record and conversation, including whatever customers pasted into chat", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Freshchat — all conversations and contact PII" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "FRESHCHAT_API_TOKEN", "FRESHCHAT_TOKEN", "FRESHCHAT_API_KEY")
		if tok == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "FRESHCHAT_URL", "FRESHCHAT_API_URL")
		if ep == "" {
			// Region-specific hosts; US is the unsuffixed default.
			if region := firstVar(b.Vars, "FRESHCHAT_REGION"); region != "" && region != "us" {
				ep = "https://api." + region + ".freshchat.com"
			} else {
				ep = "https://api.freshchat.com"
			}
		}
		return []recognize.Match{{Module: "freshchat",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok,
			Label: "FRESHCHAT_API_TOKEN", Line: b.Lines["FRESHCHAT_API_TOKEN"]}}
	})
}

// ---- Freshsales / Freshworks CRM: Authorization: Token token=<key> ----

func registerFreshsales() {
	add("", r.HTTP{
		ModuleName: "freshsales", Endpoint: saasOnly("myfreshworks.com", "freshworks.com"),
		Base:   "{endpoint}/crm/sales/api",
		Auth:   r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Token token="},
		Accept: "application/json",
		// selector/owners is the conventional light probe but is not confirmed in
		// Freshworks' published reference; the live/dead verdict rests on its
		// status code, not on any field parsed out of the body.
		Whoami: r.GET("/selector/owners").CountArrayFlag("users", "CRM users", warnFlag),
		Static: []module.Finding{{Key: "reach",
			Value: "CRM contacts, accounts and deals — customer PII plus pipeline and revenue data", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Freshsales CRM — contact PII and pipeline data" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "FRESHSALES_API_KEY", "FRESHWORKS_CRM_API_KEY", "FRESHSALES_TOKEN")
		if tok == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "FRESHSALES_URL", "FRESHSALES_DOMAIN", "FRESHWORKS_CRM_URL")
		if ep == "" {
			if alias := firstVar(b.Vars, "FRESHSALES_BUNDLE_ALIAS", "BUNDLE_ALIAS"); alias != "" {
				ep = "https://" + alias + ".myfreshworks.com"
			}
		}
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "freshsales",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok,
			Label: "FRESHSALES_API_KEY", Line: b.Lines["FRESHSALES_API_KEY"]}}
	})
}

// ---- recognizers for the hand-written pair ----

// freshBase turns a bare subdomain into a tenant URL, leaving an already
// qualified host alone. saasOnly then pins it, so a planted
// FRESHSERVICE_DOMAIN=attacker.tld loses the endpoint rather than receiving the key.
func freshBase(v, suffix string) string {
	v = strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://"), "/")
	if v == "" {
		return ""
	}
	if strings.Contains(v, ".") {
		return "https://" + v
	}
	return "https://" + v + "." + suffix
}

func recognizeFreshservice(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	tok := firstVar(b.Vars, "FRESHSERVICE_API_KEY", "FRESH_SERVICE_API_KEY", "FRESHSERVICE_TOKEN")
	if tok == "" {
		return nil
	}
	ep := endpoint
	if ep == "" {
		ep = freshBase(firstVar(b.Vars, "FRESHSERVICE_DOMAIN", "FRESHSERVICE_URL", "FRESHSERVICE_SUBDOMAIN"), "freshservice.com")
	}
	if ep == "" {
		return nil // catalog_needs_endpoint reports it instead
	}
	return []recognize.Match{{Module: "freshservice",
		Fields: module.Fields{"token": tok, "password": freshDummyPassword, "endpoint": ep},
		Secret: tok, Label: "FRESHSERVICE_API_KEY", Line: b.Lines["FRESHSERVICE_API_KEY"]}}
}

func recognizeFreshdesk(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	tok := firstVar(b.Vars, "FRESHDESK_API_KEY", "FRESHDESK_TOKEN")
	if tok == "" {
		return nil
	}
	ep := endpoint
	if ep == "" {
		ep = freshBase(firstVar(b.Vars, "FRESHDESK_DOMAIN", "FRESHDESK_URL", "FRESHDESK_SUBDOMAIN"), "freshdesk.com")
	}
	if ep == "" {
		return nil
	}
	return []recognize.Match{{Module: "freshdesk",
		Fields: module.Fields{"token": tok, "password": freshDummyPassword, "endpoint": ep},
		Secret: tok, Label: "FRESHDESK_API_KEY", Line: b.Lines["FRESHDESK_API_KEY"]}}
}
