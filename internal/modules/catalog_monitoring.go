package modules

import (
	"context"
	"net/http"
	"net/url"

	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Monitoring / observability platforms. Two of them (Zabbix global scripts,
// Splunk scripted inputs) reach remote command execution; the rest are read.
// All are self-hosted → need a host (env var or --endpoint).

func init() {
	registerZabbix()
	registerSplunk()
	registerAuvik()
	registerManageEngineOpManager()
}

// --- Zabbix: JSON-RPC; token (6.4+) or user.login → token, sent as Bearer ---

func zabbixRPC(method, params string) []byte {
	return []byte(`{"jsonrpc":"2.0","method":"` + method + `","params":` + params + `,"id":1}`)
}

func registerZabbix() {
	add("", r.HTTP{
		ModuleName: "zabbix", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			return staticOr(f["token"], func() (module.Token, error) {
				body := zabbixRPC("user.login", string(jsonBody("username", f["username"], "password", f["password"])))
				return sessionLogin(ctx, c, f["endpoint"]+"/api_jsonrpc.php", body, "application/json-rpc", "result", "")
			})
		},
		Whoami: r.Call{Method: http.MethodPost, Path: "/api_jsonrpc.php", ReadOnlyPOST: true,
			Body:  string(zabbixRPC("host.get", `{"countOutput":true}`)),
			Count: &r.CountSpec{Key: "hosts (in reach)", Path: "result", Flag: warnFlag}},
		Static:    []module.Finding{{Key: "reach", Value: "script.execute runs global scripts on monitored hosts — remote command execution gated by role", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Zabbix — global script execution on monitored hosts" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "ZABBIX_URL", "ZABBIX_HOST")
		if ep == "" {
			return nil
		}
		if tok := firstVar(b.Vars, "ZABBIX_API_TOKEN", "ZABBIX_TOKEN"); tok != "" {
			return []recognize.Match{{Module: "zabbix", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "ZABBIX_API_TOKEN"}}
		}
		user := firstVar(b.Vars, "ZABBIX_USER", "ZABBIX_USERNAME")
		pass := firstVar(b.Vars, "ZABBIX_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "zabbix", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "ZABBIX_PASSWORD"}}
	})
}

// --- Splunk: JWT token (Bearer) or session-key login (Splunk scheme) ---

func registerSplunk() {
	add("", r.HTTP{
		ModuleName: "splunk", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed, RawAuth: true},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			if f["token"] != "" { // a Splunk auth token (JWT) authenticates as Bearer
				return module.Token{Bearer: "Bearer " + f["token"]}, nil
			}
			form := url.Values{"username": {f["username"]}, "password": {f["password"]}, "output_mode": {"json"}}
			tok, err := sessionLogin(ctx, c, f["endpoint"]+"/services/auth/login",
				[]byte(form.Encode()), "application/x-www-form-urlencoded", "sessionKey", "")
			if err != nil || tok.Bearer == "<dry-run-token>" {
				return tok, err
			}
			return module.Token{Bearer: "Splunk " + tok.Bearer}, nil // session keys use the Splunk scheme
		},
		Whoami: r.GET("/services/authentication/current-context?output_mode=json").
			Field("user", "entry.0.content.username"),
		Calls:  []r.Call{r.GET("/services/data/indexes?output_mode=json&count=1").CountFlag("paging.total", "indexes", warnFlag)},
		Static: []module.Finding{{Key: "reach", Value: "run searches over indexed data; scripted inputs effectively execute commands on the Splunk host", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "Splunk — search over all data + scripted-input command execution"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		ep := resolveEndpoint(b, endpoint, "SPLUNK_URL", "SPLUNK_HOST")
		if ep == "" {
			return nil
		}
		if tok := firstVar(b.Vars, "SPLUNK_TOKEN", "SPLUNK_BEARER_TOKEN"); tok != "" {
			return []recognize.Match{{Module: "splunk", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "SPLUNK_TOKEN"}}
		}
		user := firstVar(b.Vars, "SPLUNK_USERNAME", "SPLUNK_USER")
		pass := firstVar(b.Vars, "SPLUNK_PASSWORD")
		if user == "" || pass == "" {
			return nil
		}
		return []recognize.Match{{Module: "splunk", Fields: module.Fields{"username": user, "password": pass, "endpoint": ep}, Secret: pass, Label: "SPLUNK_PASSWORD"}}
	})
}

// --- Auvik: HTTP Basic (email + per-user API key) ---

func registerAuvik() {
	add("", r.HTTP{
		ModuleName: "auvik", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Basic, UserField: "username", PassField: "token"},
		Whoami:    r.GET("/v1/inventory/device/info?page[first]=1").FlagField("devices", "data.0.id", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "read full network topology, device/interface inventory and configs (read-oriented API)", Flag: warnFlag}},
		Summarize: func([]module.Finding) string { return "Auvik — network topology & device inventory" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		user := firstVar(b.Vars, "AUVIK_USERNAME", "AUVIK_USER", "AUVIK_EMAIL")
		tok := firstVar(b.Vars, "AUVIK_API_KEY", "AUVIK_TOKEN")
		if user == "" || tok == "" {
			return nil
		}
		ep := resolveEndpoint(b, endpoint, "AUVIK_URL", "AUVIK_BASE_URL")
		if ep == "" {
			if region := firstVar(b.Vars, "AUVIK_REGION"); region != "" {
				ep = "https://auvikapi." + region + ".my.auvik.com"
			}
		}
		if ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "auvik",
			Fields: module.Fields{"username": user, "token": tok, "endpoint": ep}, Secret: tok, Label: "AUVIK_API_KEY"}}
	})
}

// --- ManageEngine OpManager: apiKey as a URL query parameter ---

func registerManageEngineOpManager() {
	add("", r.HTTP{
		ModuleName: "manageengine_opmanager", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.None},
		Whoami: r.GET("/api/json/device/listDevices?apiKey={token}").CountArrayFlag("", "devices", warnFlag),
		Static: []module.Finding{{Key: "reach", Value: "manage monitored devices and trigger IT-automation workflows that run scripts on managed devices — remote-action surface gated by role", Flag: fmFlag}},
		Summarize: func([]module.Finding) string {
			return "ManageEngine OpManager — device management + workflow script execution"
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "OPMANAGER_API_KEY", "OPM_API_KEY", "OPMANAGER_APIKEY")
		ep := resolveEndpoint(b, endpoint, "OPMANAGER_URL", "OPMANAGER_HOST")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "manageengine_opmanager",
			Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "OPMANAGER_API_KEY"}}
	})
}
