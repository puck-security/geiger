package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func init() {
	registerZoom()
	registerVonage()
	registerMailchimp()
	registerBoxDocuSign()
}

// ---- Zoom: server-to-server OAuth (account_credentials grant) ----
func registerZoom() {
	add("", r.HTTP{
		ModuleName: "zoom", Base: "https://api.zoom.us/v2", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			form := url.Values{"grant_type": {"account_credentials"}, "account_id": {f["account_id"]}}
			hdrs := auth.BasicAuthExtra(f["client_id"], f["client_secret"])
			return auth.Exchange(ctx, c, "https://zoom.us/oauth/token", form, hdrs)
		},
		Whoami: r.Call{Method: "GET", Path: "/users/me",
			Fields:  []r.Extract{{Key: "email", Path: "email"}, {Key: "type", Path: "type"}, {Key: "role", Path: "role_name"}},
			Signals: []r.Signal{{Path: "role_name", Regex: "(?i)admin|owner", Key: "privilege", Value: "account admin/owner", Flag: fmFlag}}},
		Calls: []r.Call{
			r.GET("/users?page_size=1").CountFlag("total_records", "users (PII)", warnFlag),
			{Path: "/users?page_size=1", Signals: []r.Signal{{Path: "users.0.id", Regex: ".+", Key: "data",
				Value: "can read users, meetings, cloud recordings & chat", Flag: warnFlag}}},
		},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		id := firstVar(b.Vars, "ZOOM_CLIENT_ID")
		secret := firstVar(b.Vars, "ZOOM_CLIENT_SECRET")
		acct := firstVar(b.Vars, "ZOOM_ACCOUNT_ID")
		if id == "" || secret == "" || acct == "" {
			return nil
		}
		return []recognize.Match{{Module: "zoom",
			Fields: module.Fields{"client_id": id, "client_secret": secret, "account_id": acct},
			Secret: secret, Label: "ZOOM_CLIENT_SECRET"}}
	})
}

// ---- Vonage / Nexmo: api_key + api_secret in the query ----
func registerVonage() {
	add("", r.HTTP{
		ModuleName: "vonage", Base: "https://rest.nexmo.com", Auth: r.AuthSpec{Kind: r.None},
		Whoami: r.GET("/account/get-balance?api_key={api_key}&api_secret={api_secret}").
			Field("balance", "value").Field("auto-reload", "autoReload"),
		Static: []module.Finding{{Key: "reach", Value: "can send SMS/voice (real telephony spend) & read account", Flag: warnFlag}},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "VONAGE_API_KEY", "NEXMO_API_KEY")
		secret := firstVar(b.Vars, "VONAGE_API_SECRET", "NEXMO_API_SECRET")
		if key == "" || secret == "" {
			return nil
		}
		return []recognize.Match{{Module: "vonage",
			Fields: module.Fields{"api_key": key, "api_secret": secret},
			Secret: secret, Label: "VONAGE_API_SECRET"}}
	})
}

// ---- Mailchimp: key carries its datacenter suffix (…-us21) ----
func registerMailchimp() {
	add("", r.HTTP{
		ModuleName: "mailchimp", Base: "https://{dc}.api.mailchimp.com/3.0", Auth: r.AuthSpec{Kind: r.Basic, UserField: "user", PassField: "token"},
		Whoami: r.GET("/").Field("account", "account_name").Field("email", "email").Field("role", "role"),
		Calls:  []r.Call{r.GET("/lists?count=1").CountFlag("total_items", "audiences (subscriber PII)", fmFlag)},
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		key := firstVar(b.Vars, "MAILCHIMP_API_KEY", "MC_API_KEY")
		if key == "" || !strings.Contains(key, "-us") {
			return nil
		}
		dc := key[strings.LastIndex(key, "-")+1:]
		return []recognize.Match{{Module: "mailchimp",
			Fields: module.Fields{"token": key, "user": "geiger", "dc": dc},
			Secret: key, Label: "MAILCHIMP_API_KEY"}}
	})
}

// ---- Box & DocuSign: OAuth access tokens (env-routed) ----
func registerBoxDocuSign() {
	add("", r.HTTP{
		ModuleName: "box", Base: "https://api.box.com/2.0", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.Call{Method: "GET", Path: "/users/me",
			Fields:  []r.Extract{{Key: "name", Path: "name"}, {Key: "login", Path: "login"}, {Key: "role", Path: "role"}},
			Signals: []r.Signal{{Path: "role", Regex: "(?i)admin|coadmin", Key: "privilege", Value: "enterprise (co)admin", Flag: fmFlag}}},
		Static: []module.Finding{{Key: "data", Value: "can read/download files in scope", Flag: warnFlag}},
	}.Module())

	add("", r.HTTP{
		ModuleName: "docusign", Base: "https://account.docusign.com", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami: r.GET("/oauth/userinfo").Field("name", "name").Field("email", "email").
			Field("account", "accounts.0.account_name"),
		Static: []module.Finding{{Key: "data", Value: "can read envelopes & signed agreements (legal docs / PII)", Flag: fmFlag}},
	}.Module())
}
