package modules

import (
	"net/http"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// liveness records what a module's probes said about the credential itself, so
// an empty recon can be classified instead of defaulting to DEAD.
//
// Summarize implementations treat "no findings" as "the credential was
// rejected". That inference is only safe when the endpoint actually rejected
// it. A 2xx whose body we failed to parse means the tenant ACCEPTED the key —
// reporting it dead sends a responder past a live credential. The recipe engine
// already classifies this (recipe.go:456); hand-written modules have to
// re-derive it, and have repeatedly lost it. This is that logic, shared.
//
// Usage: observe every probe, then fall back to classify() when the probes
// produced no findings of their own.
//
//	lv := liveness{}
//	n := len(out) // findings so far are echoes of our own input, not evidence
//	resp, err := c.Do(req, recon.CallOpts{})
//	lv.observe(resp, err, true)
//	... parse resp into out ...
//	if len(out) == n {
//	        out = append(out, lv.classify()...)
//	}
type liveness struct{ authed, sawHTTP, whoami401, transportErr bool }

// withLiveness appends the liveness classification when the probes produced no
// evidence of their own. Pass the length out had before the first probe ran, so
// findings echoing the module's own input don't count as evidence the tenant
// answered.
func withLiveness(out []module.Finding, evidence int, lv *liveness) []module.Finding {
	if len(out) > evidence {
		return out
	}
	return append(out, lv.classify()...)
}

// observe records one probe's outcome. Set identity for the call that
// establishes who the credential is: only that call's 401 is a dead signal,
// since a scoped key can be denied elsewhere while remaining perfectly valid.
//
// A dry-run response carries no verdict and is ignored, which keeps
// classify() silent when no packet ever left the host.
func (l *liveness) observe(resp *recon.Response, err error, identity bool) {
	if err != nil {
		// DNS failure, refused, timeout — says nothing about the credential.
		l.transportErr = true
		return
	}
	if resp == nil || resp.DryRun {
		return
	}
	l.sawHTTP = true
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		l.authed = true
	case resp.Status == http.StatusForbidden:
		// Authenticated, then refused by policy — scoped, not dead.
		l.authed = true
	case resp.Status == http.StatusUnauthorized && identity:
		l.whoami401 = true
	}
}

// classify returns the findings that explain a recon which produced none of its
// own. An empty return means the credential is genuinely dead (its identity
// call rejected it and nothing else accepted it), leaving Summarize free to
// mark the note Invalid.
//
// Acceptance anywhere outranks a 401 on the identity call: a key can lack
// permission to name itself yet still work.
func (l *liveness) classify() []module.Finding {
	switch {
	case l.authed:
		return []module.Finding{{Key: "authenticated",
			Value: "credential accepted (HTTP 2xx/403) but identity not parsed — scoped key or the API shape changed",
			Flag:  module.FlagWarn}}
	case l.whoami401:
		// Rejected, and nothing else accepted it. Genuinely dead.
		return nil
	case l.transportErr && !l.sawHTTP:
		return []module.Finding{{Key: "unreachable",
			Value: "endpoint unreachable from here — credential may be valid in its own network",
			Flag:  module.FlagInfo}}
	case l.sawHTTP:
		return []module.Finding{{Key: "unconfirmed",
			Value: "endpoint returned an unexpected response — could not confirm credential validity",
			Flag:  module.FlagInfo}}
	}
	return nil
}
