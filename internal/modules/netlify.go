package modules

import (
	"regexp"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Netlify tokens carry the owner's FULL account privileges — Netlify has no
// read-only, per-site, or scoped PATs — so a leak is effectively team/account
// takeover (create/delete sites, read/write env vars & secrets, change access
// controls). The netlify recon module lives in catalog_bearer.go; this adds
// recognition for the prefixed token format (nfp_ PAT, nfc_ CLI, nfo_ OAuth,
// nfu_ app, nfb_ build), which gitleaks misses: its rule only fires next to the
// literal "netlify" keyword and captures a lowercase-only body, so mixed-case
// prefixed tokens and bare tokens slip through. The nf?_ prefix is distinctive
// enough to key on directly (geiger re-validates, so over-match is free).
var netlifyTokenRe = regexp.MustCompile(`nf[a-z]_[A-Za-z0-9]{30,}`)

func init() { recognize.RegisterRecognizer(recognizeNetlify) }

func recognizeNetlify(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var out []recognize.Match
	seen := map[string]bool{}
	emit := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, recognize.Match{
			Module: "netlify", Fields: module.Fields{"token": tok}, Secret: tok, Label: "NETLIFY_AUTH_TOKEN",
		})
	}
	// Legacy un-prefixed tokens have no distinctive shape → key on the var name.
	emit(firstVar(b.Vars, "NETLIFY_AUTH_TOKEN", "NETLIFY_TOKEN", "NETLIFY_PERSONAL_ACCESS_TOKEN", "NETLIFY_API_TOKEN"))
	// Prefixed tokens anywhere in the blob (bare on stdin, or as any value).
	for _, tok := range netlifyTokenRe.FindAllString(b.Raw, -1) {
		emit(tok)
	}
	return out
}
