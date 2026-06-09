package modules

import (
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Analytics / marketing-automation credentials. The blast radius is customer
// PII — exporting profiles/events and, for the messaging platforms, blasting
// every user. Klaviyo and Braze are exercised read-only; Segment, Mixpanel,
// Amplitude, and Customer.io are recognized and flagged but not exercised (their
// read APIs need date-ranged exports or write-only keys, with no safe whoami).

func init() {
	registerKlaviyo()
	registerBraze()
	registerAnalyticsFlagged()
}

// --- Klaviyo: "Authorization: Klaviyo-API-Key <pk_…>" + revision header ---

func registerKlaviyo() {
	add("", r.HTTP{
		ModuleName: "klaviyo", Base: "https://a.klaviyo.com",
		Auth:      r.AuthSpec{Kind: r.Header, HeaderName: "Authorization", ValuePrefix: "Klaviyo-API-Key "},
		Headers:   map[string]string{"revision": "2024-10-15", "Accept": "application/json"},
		Whoami:    r.GET("/api/accounts/").Field("account", "data.0.id"),
		Static:    []module.Finding{{Key: "reach", Value: "read/export customer profiles (email, phone, location — marketing PII) and send campaigns/flows to the whole list", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Klaviyo — customer-profile export (PII) + campaign send" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		if k := firstVar(b.Vars, "KLAVIYO_API_KEY", "KLAVIYO_PRIVATE_KEY", "KLAVIYO_PRIVATE_API_KEY"); k != "" {
			return []recognize.Match{{Module: "klaviyo", Fields: module.Fields{"token": k}, Secret: k, Label: "KLAVIYO_API_KEY"}}
		}
		return nil
	})
}

// --- Braze: bearer REST API key, region-specific endpoint ---

func registerBraze() {
	add("", r.HTTP{
		ModuleName: "braze", Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.Bearer},
		Whoami:    r.GET("/campaigns/list").CountArrayFlag("campaigns", "campaigns", warnFlag),
		Static:    []module.Finding{{Key: "reach", Value: "send push/email/SMS to all users and export user profiles (PII) via the export endpoints", Flag: fmFlag}},
		Summarize: func([]module.Finding) string { return "Braze — message-send to all users + profile export (PII)" },
	}.Module())
	recognize.RegisterRecognizer(func(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
		tok := firstVar(b.Vars, "BRAZE_API_KEY", "BRAZE_REST_API_KEY")
		ep := resolveEndpoint(b, endpoint, "BRAZE_REST_ENDPOINT", "BRAZE_URL", "BRAZE_ENDPOINT")
		if tok == "" || ep == "" {
			return nil
		}
		return []recognize.Match{{Module: "braze", Fields: module.Fields{"token": tok, "endpoint": ep}, Secret: tok, Label: "BRAZE_API_KEY"}}
	})
}

// --- Segment / Mixpanel / Amplitude / Customer.io: recognize + flag ---

func registerAnalyticsFlagged() {
	flagged := func(name, summary, capability string) {
		add("", staticModule{name: name, summary: summary, findings: []module.Finding{
			{Key: "reach", Value: capability, Flag: warnFlag},
			{Key: "validation", Value: "recognized by variable name/shape; not exercised read-only (export APIs need date ranges, or the key is write-only)", Flag: cantFlag},
		}})
	}
	flagged("segment", "Segment — customer event-pipeline access (behavioral PII)",
		"a write key injects events into every connected destination; a Public API token reads/modifies sources, destinations, and warehouse syncs — customer behavioral PII")
	flagged("mixpanel", "Mixpanel — product-analytics data (behavioral PII)",
		"export user profiles and event streams, and read project data — product-analytics PII")
	flagged("amplitude", "Amplitude — product-analytics data (behavioral PII)",
		"export event and user data across the project via the Dashboard/Export APIs — product-analytics PII")
	flagged("customerio", "Customer.io — messaging + customer data (PII)",
		"trigger messages to customers and read/modify people & segments — customer PII")

	recognize.RegisterRecognizer(func(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
		var out []recognize.Match
		if k := firstVar(b.Vars, "SEGMENT_WRITE_KEY", "SEGMENT_PUBLIC_API_TOKEN", "SEGMENT_TOKEN"); k != "" {
			out = append(out, recognize.Match{Module: "segment", Fields: module.Fields{"token": k}, Secret: k, Label: "SEGMENT_WRITE_KEY"})
		}
		if k := firstVar(b.Vars, "MIXPANEL_API_SECRET", "MIXPANEL_SECRET", "MIXPANEL_PROJECT_SECRET"); k != "" {
			out = append(out, recognize.Match{Module: "mixpanel", Fields: module.Fields{"token": k}, Secret: k, Label: "MIXPANEL_API_SECRET"})
		}
		if k := firstVar(b.Vars, "AMPLITUDE_SECRET_KEY", "AMPLITUDE_API_SECRET"); k != "" {
			out = append(out, recognize.Match{Module: "amplitude", Fields: module.Fields{"token": k}, Secret: k, Label: "AMPLITUDE_SECRET_KEY"})
		}
		if k := firstVar(b.Vars, "CUSTOMERIO_APP_API_KEY", "CUSTOMERIO_API_KEY", "CUSTOMER_IO_API_KEY"); k != "" {
			out = append(out, recognize.Match{Module: "customerio", Fields: module.Fields{"token": k}, Secret: k, Label: "CUSTOMERIO_API_KEY"})
		}
		return out
	})
}
