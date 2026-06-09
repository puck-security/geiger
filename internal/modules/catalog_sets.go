package modules

import (
	"context"
	"net/url"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// envStagePrefixes / envStageSuffixes are the common environment/stage
// decorations real .env files put around a canonical credential var
// (STAGING_COHERE_API_KEY, COHERE_API_KEY_PROD). Matching is restricted to this
// known set and applied as an exact lookup of "<prefix><name>" / "<name><suffix>"
// so it catches the same credential under a stage label WITHOUT risking
// confusion between distinct variants (e.g. ANON vs SERVICE keys).
var envStagePrefixes = []string{
	"STAGING_", "STAGE_", "PROD_", "PRODUCTION_", "DEV_", "DEVELOPMENT_",
	"TEST_", "TESTING_", "LOCAL_", "QA_", "UAT_", "SANDBOX_", "DEMO_", "CI_",
}

var envStageSuffixes = []string{
	"_STAGING", "_PROD", "_PRODUCTION", "_DEV", "_TEST", "_LOCAL", "_QA", "_UAT", "_SANDBOX",
}

// firstVar returns the first non-empty value among the given variable names,
// trying each name exactly first, then the same name under a known
// environment/stage prefix or suffix.
func firstVar(vars map[string]string, names ...string) string {
	for _, n := range names {
		if v := vars[n]; v != "" {
			return v
		}
	}
	for _, n := range names {
		for _, p := range envStagePrefixes {
			if v := vars[p+n]; v != "" {
				return v
			}
		}
		for _, s := range envStageSuffixes {
			if v := vars[n+s]; v != "" {
				return v
			}
		}
	}
	return ""
}

func init() {
	registerTwilio()
	registerDatadog()
	registerAlgolia()
	registerEntra()
	registerAuth0()
}

// ---- Twilio: Account SID + auth token, HTTP Basic ----
func registerTwilio() {
	add("", r.HTTP{
		ModuleName: "twilio", Base: "https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
		Auth:   r.AuthSpec{Kind: r.Basic, UserField: "sid", PassField: "token"},
		Whoami: r.GET("").Field("friendly_name", "friendly_name").Field("status", "status").Field("type", "type"),
		Summarize: func(fs []module.Finding) string {
			for _, f := range fs {
				if f.Key == "type" && f.Value == "Full" {
					return "full Twilio account — real telephony spend"
				}
			}
			return "Twilio account"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		sid := firstVar(b.Vars, "TWILIO_ACCOUNT_SID")
		tok := firstVar(b.Vars, "TWILIO_AUTH_TOKEN")
		if sid == "" || tok == "" {
			return nil
		}
		return []recognize.Match{{Module: "twilio", Fields: module.Fields{"sid": sid, "token": tok},
			Secret: tok, Label: "TWILIO_AUTH_TOKEN"}}
	})
}

// ---- Datadog: API key + app key, custom headers ----
func registerDatadog() {
	add("", r.HTTP{
		ModuleName: "datadog", Base: "https://api.datadoghq.com", Auth: r.AuthSpec{Kind: r.None},
		Headers: map[string]string{"DD-API-KEY": "{api_key}", "DD-APPLICATION-KEY": "{app_key}"},
		Whoami:  r.GET("/api/v1/validate").Field("valid", "valid"),
		Calls:   []r.Call{r.GET("/api/v2/users?page[size]=1").FlagField("users-readable", "data.0.id", warnFlag)},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		api := firstVar(b.Vars, "DD_API_KEY", "DATADOG_API_KEY")
		app := firstVar(b.Vars, "DD_APP_KEY", "DD_APPLICATION_KEY", "DATADOG_APP_KEY")
		if api == "" {
			return nil
		}
		return []recognize.Match{{Module: "datadog", Fields: module.Fields{"api_key": api, "app_key": app},
			Secret: api, Label: "DD_API_KEY"}}
	})
}

// ---- Algolia: app id + admin/search key ----
func registerAlgolia() {
	add("algolia-api-key", r.HTTP{
		ModuleName: "algolia", Base: "https://{app_id}.algolia.net", Auth: r.AuthSpec{Kind: r.None},
		Headers: map[string]string{"X-Algolia-API-Key": "{token}", "X-Algolia-Application-Id": "{app_id}"},
		Whoami:  r.GET("/1/indexes").CountArray("items", "indices"),
		Static:  []module.Finding{{Key: "note", Value: "admin key can read /1/keys (all keys + ACLs)", Flag: warnFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, reg *module.Registry) []recognize.Match {
		app := firstVar(b.Vars, "ALGOLIA_APPLICATION_ID", "ALGOLIA_APP_ID")
		key := firstVar(b.Vars, "ALGOLIA_API_KEY", "ALGOLIA_ADMIN_KEY")
		if app == "" || key == "" {
			return nil
		}
		return []recognize.Match{{Module: "algolia", Fields: module.Fields{"app_id": app, "token": key},
			Secret: key, Label: "ALGOLIA_API_KEY"}}
	})
}

// ---- Entra/Azure service principal: client_credentials ----
func registerEntra() {
	add("azure-ad-client-secret", r.HTTP{
		ModuleName: "entra_sp", Base: "https://graph.microsoft.com/v1.0", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			tokenURL := "https://login.microsoftonline.com/" + f["tenant"] + "/oauth2/v2.0/token"
			return auth.ClientCredentials(ctx, c, tokenURL, f["client_id"], f["client_secret"],
				url.Values{"scope": {"https://graph.microsoft.com/.default"}})
		},
		Whoami: r.GET("/organization").Field("tenant", "value.0.displayName").Field("tenant-id", "value.0.id"),
		Static: []module.Finding{{Key: "note", Value: "decode token roles claim; Directory.ReadWrite.All = force multiplier", Flag: infoFlag}},
		Harvest: func(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
			if !c.Live() || !c.Intrusive() {
				return nil, nil
			}
			return azureVaultHarvestSP(ctx, c, f["tenant"], f["client_id"], f["client_secret"]), nil
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "AZURE_CLIENT_ID", "ARM_CLIENT_ID")
		secret := firstVar(b.Vars, "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET")
		tenant := firstVar(b.Vars, "AZURE_TENANT_ID", "ARM_TENANT_ID")
		if id == "" || secret == "" || tenant == "" {
			return nil
		}
		return []recognize.Match{{Module: "entra_sp",
			Fields: module.Fields{"client_id": id, "client_secret": secret, "tenant": tenant},
			Secret: secret, Label: "AZURE_CLIENT_SECRET"}}
	})
}

// ---- Auth0: client_credentials against the Management API ----
func registerAuth0() {
	add("", r.HTTP{
		ModuleName: "auth0", Base: "https://{domain}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			tokenURL := "https://" + f["domain"] + "/oauth/token"
			return auth.ClientCredentials(ctx, c, tokenURL, f["client_id"], f["client_secret"],
				url.Values{"audience": {"https://" + f["domain"] + "/api/v2/"}})
		},
		Whoami: r.GET("/api/v2/clients?per_page=1").FlagField("mgmt-api", "0.client_id", fmFlag),
		Static: []module.Finding{{Key: "note", Value: "Management API token — create:users/update:* = full IdP control", Flag: fmFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		dom := firstVar(b.Vars, "AUTH0_DOMAIN")
		id := firstVar(b.Vars, "AUTH0_CLIENT_ID")
		secret := firstVar(b.Vars, "AUTH0_CLIENT_SECRET")
		if dom == "" || id == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "auth0",
			Fields: module.Fields{"domain": dom, "client_id": id, "client_secret": secret},
			Secret: secret, Label: "AUTH0_CLIENT_SECRET"}}
	})
}
