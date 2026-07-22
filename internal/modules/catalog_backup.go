package modules

import (
	"context"
	"encoding/base64"
	"net/url"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Backup / DR platforms. The Tier-0 capability here is restore/recovery — the
// ability to overwrite production data or exfiltrate it via a restore. geiger
// validates the credential, sizes the protected estate, and names the restore
// capability as a force multiplier. All are self-hosted → need a host.

func init() {
	registerVeeam()
	registerAcronis()
	registerCohesity()
	registerNetBackup()
	registerCommvault()
}

// --- Veeam Backup & Replication: OAuth password grant ---

func registerVeeam() {
	add("", r.HTTP{
		ModuleName: "veeam", Endpoint: selfHosted, Base: "{endpoint}", Accept: "application/json",
		Headers: map[string]string{"x-api-version": "1.1-rev2"},
		Auth:    r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.Exchange(ctx, c, f["endpoint"]+"/api/oauth2/token",
				url.Values{"grant_type": {"password"}, "username": {f["username"]}, "password": {f["password"]}},
				map[string]string{"x-api-version": "1.1-rev2"})
		},
		Whoami:    r.GET("/api/v1/serverInfo").Field("server", "name").Field("version", "buildVersion"),
		Calls:     []r.Call{r.GET("/api/v1/jobs").CountFlag("pagination.total", "backup jobs", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "start jobs and perform restores (file/VM/application recovery) — high-impact production data overwrite/recovery", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Veeam Backup & Replication — job control + restores" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "VEEAM_URL", "VBR_URL", "VEEAM_HOST")
		user := firstVar(b.Vars, "VEEAM_USERNAME", "VBR_USERNAME", "VEEAM_USER")
		pass := firstVar(b.Vars, "VEEAM_PASSWORD", "VBR_PASSWORD")
		if ep == "" || user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "veeam", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "VEEAM_PASSWORD"}}
	})
}

// --- Acronis Cyber Protect Cloud: OAuth client credentials ---

func registerAcronis() {
	add("", r.HTTP{
		ModuleName: "acronis", Endpoint: selfHosted, Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return auth.ClientCredentials(ctx, c, f["endpoint"]+"/api/2/idp/token", f["client_id"], f["client_secret"], nil)
		},
		Whoami:    r.GET("/api/2/users/me").Field("user", "login").Field("email", "contact.email"),
		Calls:     []r.Call{r.GET("/api/2/agents").CountArrayFlag("items", "agents", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "apply backup plans and trigger backup/restore across the tenant hierarchy — high-impact data-protection control", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Acronis Cyber Protect — backup/restore + agent control" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "ACRONIS_CLIENT_ID")
		secret := firstVar(b.Vars, "ACRONIS_CLIENT_SECRET")
		if id == "" || secret == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "ACRONIS_DATACENTER_URL", "ACRONIS_URL", "ACRONIS_BASE_URL")
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "acronis", Fields: module.Fields{"client_id": id, "client_secret": secret, "endpoint": ep}, Secret: secret, Label: "ACRONIS_CLIENT_SECRET"}}
	})
}

// --- Cohesity: POST /public/accessTokens (username+password) → bearer ---

func registerCohesity() {
	add("", r.HTTP{
		ModuleName: "cohesity", Endpoint: selfHosted, Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			dom := f["domain"]
			if dom == "" {
				dom = "LOCAL"
			}
			return sessionLogin(ctx, c, f["endpoint"]+"/irisservices/api/v1/public/accessTokens",
				jsonBody("username", f["username"], "password", f["password"], "domain", dom), "application/json", "accessToken", "")
		},
		Whoami:    r.GET("/irisservices/api/v1/public/sessionUser").Field("user", "username").Field("domain", "domain"),
		Calls:     []r.Call{r.GET("/irisservices/api/v1/public/protectionJobs").CountArrayFlag("", "protection jobs", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "perform restores/clones incl. REMOTE_RESTORE and modify/upgrade the cluster — high-impact recovery & cluster control", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Cohesity — protection-job & restore control" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "COHESITY_CLUSTER", "COHESITY_URL", "COHESITY_HOST")
		user := firstVar(b.Vars, "COHESITY_USERNAME", "COHESITY_USER")
		pass := firstVar(b.Vars, "COHESITY_PASSWORD")
		if ep == "" || user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "cohesity",
			Fields: module.Fields{"username": user, "password": pass, "domain": firstVar(b.Vars, "COHESITY_DOMAIN"), "endpoint": ep},
			Secret: pass, Label: "COHESITY_PASSWORD"}}
	})
}

// --- Veritas NetBackup: API key (Bearer) or username/password login ---

func registerNetBackup() {
	add("", r.HTTP{
		ModuleName: "netbackup", Endpoint: selfHosted, Base: "{endpoint}", Accept: "application/vnd.netbackup+json;version=8.0",
		Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return staticOr(f["token"], func() (module.Token, error) {
				return sessionLogin(ctx, c, f["endpoint"]+"/netbackup/login",
					jsonBody("userName", f["username"], "password", f["password"]), "application/json", "token", "")
			})
		},
		Whoami:    r.GET("/netbackup/admin/jobs?page[limit]=1").FlagField("jobs", "data.0.id", warnFlag),
		Calls:     []r.Call{r.GET("/netbackup/config/policies").CountArrayFlag("data", "policies", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "run/modify backup policies and restore operations — high-impact data recovery, gated by RBAC", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Veritas NetBackup — policy & restore control" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "NETBACKUP_URL", "NBU_HOST", "NETBACKUP_HOST")
		if ep == "" {
			return nil
		}
		if tok := firstVar(b.Vars, "NETBACKUP_API_KEY", "NBU_API_KEY"); tok != "" {
			return []recognize.Match{{Module: "netbackup", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "NETBACKUP_API_KEY"}}
		}
		user := firstVar(b.Vars, "NETBACKUP_USERNAME", "NBU_USERNAME")
		pass := firstVar(b.Vars, "NETBACKUP_PASSWORD", "NBU_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "netbackup", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "NETBACKUP_PASSWORD"}}
	})
}

// --- Commvault: POST /Login → token on the "Authtoken: QSDK" header ---

func registerCommvault() {
	add("", r.HTTP{
		ModuleName: "commvault", Endpoint: selfHosted, Base: "{endpoint}", Accept: "application/json",
		Auth: r.AuthSpec{Kind: r.PreAuthed, HeaderName: "Authtoken", ValuePrefix: "QSDK "},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			pw := base64.StdEncoding.EncodeToString([]byte(f["password"]))
			return sessionLogin(ctx, c, f["endpoint"]+"/Login",
				jsonBody("username", f["username"], "password", pw), "application/json", "token", "")
		},
		Whoami:    r.GET("/CommServ").Field("commcell", "commcell.commCellName"),
		Calls:     []r.Call{r.GET("/Client").CountArrayFlag("clientProperties", "clients", warnFlag)},
		Static:    []module.Finding{{Key: "reach", Value: "run backups and restores/recoveries and manage clients/policies — high-impact data overwrite, gated by role", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Commvault — backup/restore + client management" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "COMMVAULT_URL", "CV_WEBCONSOLE", "COMMVAULT_HOST")
		user := firstVar(b.Vars, "COMMVAULT_USERNAME", "CV_USERNAME")
		pass := firstVar(b.Vars, "COMMVAULT_PASSWORD", "CV_PASSWORD")
		if ep == "" || user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "commvault", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "COMMVAULT_PASSWORD"}}
	})
}
