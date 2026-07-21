package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// RMM / MDM / patch / config-management platforms. The unifying risk (per
// entit.md) is that one API credential can run code or wipe devices across a
// fleet. geiger is read-only: it validates the credential and sizes reach, and
// NAMES the remote-exec/wipe capability as a force-multiplier finding — it never
// calls those endpoints. Self-hosted services need a host (env var or --endpoint).

func init() {
	registerNinjaOne()
	registerAtera()
	registerKandji()
	registerJamf()
	registerMosyle()
	registerAutomox()
	registerTanium()
	registerAnsibleAWX()
	registerPuppet()
	registerSaltStack()
	registerFleet()
}

// --- shared helpers ---

// normalizeURL trims and ensures an https:// scheme on a host/URL.
func normalizeURL(h string) string {
	h = strings.TrimRight(strings.TrimSpace(h), "/")
	if h != "" && !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		h = "https://" + h
	}
	return h
}

// resolveEndpoint picks the host to triage against: the operator's --endpoint
// flag if given, else the first non-empty of the named env vars.
//
// The flag wins deliberately. It is an explicit operator assertion, while a
// value read out of the scanned blob is untrusted input that an attacker may
// have planted; letting the file outrank the flag would mean the operator can
// name a host and still have geiger send the credential somewhere else.
func resolveEndpoint(b parse.Blob, endpoint string, envNames ...string) string {
	if endpoint != "" {
		return normalizeURL(endpoint)
	}
	return normalizeURL(firstVar(b.Vars, envNames...))
}

// staticOr returns a static token as a PreAuthed bearer when present, otherwise
// runs the login exchange. Lets one recipe accept either a long-lived token or
// a username/password that's traded for a session token.
func staticOr(token string, login func() (module.Token, error)) (module.Token, error) {
	if token != "" {
		return module.Token{Bearer: token}, nil
	}
	return login()
}

func jsonBody(pairs ...string) []byte {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonQuote(pairs[i]))
		b.WriteByte(':')
		b.WriteString(jsonQuote(pairs[i+1]))
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// --- NinjaOne (NinjaRMM): OAuth client_credentials ---

func ninjaRegionHost(region string) string {
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "eu":
		return "https://eu.ninjarmm.com"
	case "oc":
		return "https://oc.ninjarmm.com"
	case "ca":
		return "https://ca.ninjarmm.com"
	case "us2":
		return "https://us2.ninjarmm.com"
	default:
		return "https://app.ninjarmm.com"
	}
}

func registerNinjaOne() {
	add("", r.HTTP{
		ModuleName: "ninjaone", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.ClientCredentials(ctx, c, f["endpoint"]+"/ws/oauth/token",
				f["client_id"], f["client_secret"], url.Values{"scope": {"monitoring management control"}})
		},
		Whoami: r.GET("/v2/organizations").Field("first org", "0.name").CountArrayFlag("", "organizations", warnFlag),
		Static: []module.Finding{{Key: "reach", Value: "management scope runs scripts and control scope opens remote sessions across managed endpoints — remote code execution at scale", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "NinjaOne RMM — script execution + remote control across endpoints"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "NINJA_CLIENT_ID", "NINJAONE_CLIENT_ID")
		secret := firstVar(b.Vars, "NINJA_CLIENT_SECRET", "NINJAONE_CLIENT_SECRET")
		if id == "" || secret == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "NINJA_URL", "NINJAONE_URL")
		if ep == "" {
			ep = ninjaRegionHost(firstVar(b.Vars, "NINJA_REGION", "NINJAONE_REGION"))
		}
		return []recognize.Match{{Module: "ninjaone",
			Fields: module.Fields{"client_id": id, "client_secret": secret, "endpoint": ep},
			Secret: secret, Label: "NINJA_CLIENT_SECRET"}}
	})
}

// --- Atera: X-API-KEY header ---

func registerAtera() {
	add("", r.HTTP{
		ModuleName: "atera", Base: "https://app.atera.com/api/v3", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "X-API-KEY"},
		Whoami:    r.GET("/agents?itemsInPage=1").CountFlag("totalItemCount", "agents (managed endpoints)", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "read all agents/customers/tickets — agent inventory maps the managed-endpoint estate (script actions run via the agent/console, not this REST API)", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Atera RMM/PSA — full agent & customer inventory" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "ATERA_API_KEY", "ATERA_TOKEN"); k != "" {
			return []recognize.Match{{Module: "atera", Fields: module.Fields{"token": k}, Secret: k, Label: "ATERA_API_KEY"}}
		}
		return nil
	})
}

// --- Kandji (Apple MDM): Bearer, region-specific host ---

func registerKandji() {
	add("", r.HTTP{
		ModuleName: "kandji", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/api/v1/devices?limit=1").Field("device", "0.device_name"),
		Static:    []module.Finding{{Key: "reach", Value: "POST /api/v1/devices/{id}/action/erase wipes a device and lock returns the macOS unlock PIN — high-impact MDM control", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Kandji MDM — device inventory + remote lock/erase" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "KANDJI_API_TOKEN", "KANDJI_TOKEN")
		if tok == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "KANDJI_API_URL", "KANDJI_URL")
		if ep == "" {
			if sub := firstVar(b.Vars, "KANDJI_SUBDOMAIN"); sub != "" {
				host := sub + ".api.kandji.io"
				if strings.EqualFold(firstVar(b.Vars, "KANDJI_REGION"), "eu") {
					host = sub + ".api.eu.kandji.io"
				}
				ep = "https://" + host
			}
		}
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "kandji",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "KANDJI_API_TOKEN"}}
	})
}

// --- Jamf Pro: OAuth client credentials OR basic-auth → bearer ---

func registerJamf() {
	add("", r.HTTP{
		ModuleName: "jamf", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			if f["client_id"] != "" {
				return auth.ClientCredentials(ctx, c, f["endpoint"]+"/api/oauth/token", f["client_id"], f["client_secret"], nil)
			}
			req, err := recon.NewRequest(ctx, http.MethodPost, f["endpoint"]+"/api/v1/auth/token", nil)
			if err != nil {
				return module.Token{}, err
			}
			req.SetBasicAuth(f["username"], f["password"])
			resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "Jamf token (read-only)"})
			if err != nil {
				return module.Token{}, err
			}
			if resp.DryRun {
				return module.Token{Bearer: "<dry-run-token>"}, nil
			}
			if resp.Status < 200 || resp.Status >= 300 {
				return module.Token{}, errStatus(resp.Status)
			}
			return module.Token{Bearer: jsonPath(resp.Body, "token")}, nil
		},
		Whoami: r.GET("/api/v1/auth").Field("account", "account.username").
			Signal(r.Signal{Path: "account.privilegeSet", Regex: "(?i)administrator", Key: "privilege", Value: "full-administrator API role", Flag: fmFlag}),
		Calls:     []r.Call{r.GET("/api/v1/computers-inventory?page-size=1").CountFlag("totalCount", "computers", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "run scripts and issue MDM commands incl. device lock and erase/wipe across managed Macs", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Jamf Pro — script execution + MDM lock/wipe" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "JAMF_URL", "JAMF_PRO_URL", "JAMF_BASE_URL")
		if ep == "" {
			return nil
		}
		if id := firstVar(b.Vars, "JAMF_CLIENT_ID"); id != "" {
			secret := firstVar(b.Vars, "JAMF_CLIENT_SECRET")
			if secret == "" {
				return nil
			}
			return []recognize.Match{{Module: "jamf",
				Fields: module.Fields{"client_id": id, "client_secret": secret, "endpoint": ep},
				Secret: secret, Label: "JAMF_CLIENT_SECRET"}}
		}
		user := firstVar(b.Vars, "JAMF_USERNAME", "JAMF_USER")
		pass := firstVar(b.Vars, "JAMF_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "jamf",
			Fields: module.Fields{"username": user, "password": pass, "endpoint": ep},
			Secret: pass, Label: "JAMF_PASSWORD"}}
	})
}

// --- Mosyle (Apple MDM): access token in the JSON request body ---

func registerMosyle() {
	add("", r.HTTP{
		ModuleName: "mosyle", Base: "https://managerapi.mosyle.com/v2", Auth: r.AuthSpec{Kind: r.None},
		Whoami: r.Call{Method: http.MethodPost, Path: "/listdevices", ReadOnlyPOST: true,
			Body:  `{"accessToken":"{token}","options":{"os":"mac"}}`,
			Count: &r.CountSpec{Key: "devices", Path: "devices", ArrayLen: true, Flag: warnFlag}},
		Static:    []module.Finding{{Key: "reach", Value: "MDM token — wipe, remote lock, restart, and Lost Mode across enrolled Apple devices", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Mosyle MDM — device control incl. remote wipe/lock" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "MOSYLE_ACCESS_TOKEN", "MOSYLE_API_TOKEN")
		if tok == "" {
			return nil
		}
		return []recognize.Match{{Module: "mosyle", Fields: module.Fields{"token": tok}, Secret: tok, Label: "MOSYLE_ACCESS_TOKEN"}}
	})
}

// --- Automox: Bearer ---

func registerAutomox() {
	add("", r.HTTP{
		ModuleName: "automox", Base: "https://console.automox.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/api/users/self").Field("user", "email"),
		Calls: []r.Call{
			r.GET("/api/servers?limit=1").FlagField("servers", "0.id", warnFlag),
			r.GET("/api/orgs").CountArrayFlag("", "orgs", warnFlag),
		},
		Static: []module.Finding{{Key: "reach", Value: "create and run patch policies and worklets (arbitrary scripts) and reboot endpoints — remote code execution at scale", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "Automox — patch policies + worklet script execution across endpoints"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "AUTOMOX_API_KEY", "AUTOMOX_TOKEN", "AMX_API_KEY"); k != "" {
			return []recognize.Match{{Module: "automox", Fields: module.Fields{"token": k}, Secret: k, Label: "AUTOMOX_API_KEY"}}
		}
		return nil
	})
}

// --- Tanium: token in the `session` header (not Authorization) ---

func registerTanium() {
	add("", r.HTTP{
		ModuleName: "tanium", Base: "{endpoint}/api/v2", Auth: r.AuthSpec{Kind: r.Header, HeaderName: "session"},
		Whoami:    r.GET("/session/current").Field("user", "data.name"),
		Calls:     []r.Call{r.GET("/computer_groups").CountArrayFlag("data", "computer groups (targetable scope)", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "deploy packages and run actions across endpoints (questions + actions) — remote execution at scale", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Tanium — package deploy + action execution across endpoints" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "TANIUM_API_TOKEN", "TANIUM_SESSION", "TANIUM_TOKEN")
		ep := resolveEndpoint(b, endpoint, "TANIUM_URL", "TANIUM_HOST")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "tanium",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "TANIUM_API_TOKEN"}}
	})
}

// --- Ansible Automation Platform / AWX / Tower: Bearer ---

func registerAnsibleAWX() {
	add("", r.HTTP{
		ModuleName: "ansible_awx", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/api/v2/me/").Field("user", "results.0.username"),
		Calls: []r.Call{
			r.GET("/api/v2/inventories/?page_size=1").CountFlag("count", "inventories", warnFlag),
			r.GET("/api/v2/job_templates/?page_size=1").CountFlag("count", "job templates", warnFlag),
		},
		Static:    []module.Finding{{Key: "reach", Value: "launch job templates that run playbooks against managed hosts — full remote execution (Execute role + write scope)", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Ansible AWX/Tower — playbook execution across managed hosts" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "AWX_OAUTH_TOKEN", "TOWER_OAUTH_TOKEN", "CONTROLLER_OAUTH_TOKEN", "AWX_TOKEN")
		ep := resolveEndpoint(b, endpoint, "AWX_HOST", "TOWER_HOST", "CONTROLLER_HOST", "AWX_URL")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "ansible_awx",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "AWX_OAUTH_TOKEN"}}
	})
}

// --- Puppet Enterprise: RBAC token in X-Authentication (token or login) ---

func registerPuppet() {
	add("", r.HTTP{
		ModuleName: "puppet_enterprise", Base: "{endpoint}",
		Auth: r.AuthSpec{Kind: r.PreAuthed, HeaderName: "X-Authentication"},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return staticOr(f["token"], func() (module.Token, error) {
				return sessionLogin(ctx, c, f["endpoint"]+"/rbac-api/v1/auth/token",
					jsonBody("login", f["username"], "password", f["password"]), "application/json", "token", "")
			})
		},
		Whoami: r.GET("/rbac-api/v1/users/current").Field("user", "login").
			Signal(r.Signal{Path: "role_ids.0", Regex: ".+", Key: "roles", Value: "RBAC roles assigned", Flag: warnFlag}),
		Calls:  []r.Call{r.GET("/classifier-api/v1/groups").CountArrayFlag("", "node groups", warnFlag)},
		Static: []module.Finding{{Key: "reach", Value: "POST /orchestrator/v1/command/task runs ad-hoc tasks/plans on nodes — remote execution gated by RBAC", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "Puppet Enterprise — orchestrator task/plan execution on nodes"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "PUPPET_URL", "PE_CONSOLE", "PUPPET_HOST")
		if ep == "" {
			return nil
		}
		if tok := firstVar(b.Vars, "PUPPET_TOKEN", "PE_TOKEN"); tok != "" {
			return []recognize.Match{{Module: "puppet_enterprise",
				Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "PUPPET_TOKEN"}}
		}
		user := firstVar(b.Vars, "PUPPET_USERNAME", "PE_USERNAME")
		pass := firstVar(b.Vars, "PUPPET_PASSWORD", "PE_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "puppet_enterprise",
			Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "PUPPET_PASSWORD"}}
	})
}

// --- SaltStack salt-api: eauth login → token in X-Auth-Token ---

func registerSaltStack() {
	add("", r.HTTP{
		ModuleName: "saltstack", Base: "{endpoint}",
		Auth: r.AuthSpec{Kind: r.PreAuthed, HeaderName: "X-Auth-Token"},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			eauth := f["eauth"]
			if eauth == "" {
				eauth = "pam"
			}
			form := url.Values{"username": {f["username"]}, "password": {f["password"]}, "eauth": {eauth}}
			return sessionLogin(ctx, c, f["endpoint"]+"/login", []byte(form.Encode()),
				"application/x-www-form-urlencoded", "return.0.token", "")
		},
		Whoami: r.GET("/").Field("salt-api", "clients.0"),
		Static: []module.Finding{{Key: "reach", Value: "run arbitrary execution modules on minions (cmd.run, state.apply) — full remote execution at scale, gated by eauth ACLs", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "SaltStack salt-api — arbitrary module execution across minions"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "SALT_API_URL", "SALTAPI_URL", "SALT_URL")
		user := firstVar(b.Vars, "SALT_API_USER", "SALTAPI_USER", "SALT_USER")
		pass := firstVar(b.Vars, "SALT_API_PASSWORD", "SALTAPI_PASS", "SALT_PASSWORD")
		if ep == "" || user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "saltstack",
			Fields: module.Fields{"username": user, "password": pass, "eauth": firstVar(b.Vars, "SALT_API_EAUTH", "SALTAPI_EAUTH"), "endpoint": ep},
			Secret: pass, Label: "SALT_API_PASSWORD"}}
	})
}

// --- Fleet (FleetDM / osquery): Bearer (token or login) ---

func registerFleet() {
	add("", r.HTTP{
		ModuleName: "fleet", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return staticOr(f["token"], func() (module.Token, error) {
				return sessionLogin(ctx, c, f["endpoint"]+"/api/v1/fleet/login",
					jsonBody("email", f["username"], "password", f["password"]), "application/json", "token", "")
			})
		},
		Whoami: r.GET("/api/v1/fleet/me").Field("user", "user.email").
			Signal(r.Signal{Path: "user.global_role", Regex: "(?i)admin", Key: "privilege", Value: "global admin", Flag: fmFlag}),
		Calls:     []r.Call{r.GET("/api/v1/fleet/hosts/count").CountFlag("count", "hosts", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "run live queries across hosts, POST /api/v1/fleet/scripts/run executes scripts, and MDM commands incl. device wipe — remote execution + wipe, gated by role/team", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Fleet (osquery) — live queries + script execution + MDM wipe" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "FLEET_URL", "FLEET_SERVER_URL", "FLEET_HOST")
		if ep == "" {
			return nil
		}
		if tok := firstVar(b.Vars, "FLEET_API_TOKEN", "FLEET_TOKEN"); tok != "" {
			return []recognize.Match{{Module: "fleet",
				Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "FLEET_API_TOKEN"}}
		}
		user := firstVar(b.Vars, "FLEET_EMAIL", "FLEET_USERNAME")
		pass := firstVar(b.Vars, "FLEET_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "fleet",
			Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "FLEET_PASSWORD"}}
	})
}
