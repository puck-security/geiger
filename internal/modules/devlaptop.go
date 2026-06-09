package modules

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Dev-laptop credential stores that supply-chain malware (e.g. Shai-Hulud)
// harvests: ~/.docker/config.json, ~/.npmrc, ~/.netrc, and Terraform state.

func init() {
	module.Register(dockerRegistry{})
	recognize.RegisterRecognizer(recognizeDockerConfig)
	recognize.RegisterRecognizer(recognizeNpmrc)
	recognize.RegisterRecognizer(recognizeNetrc)
	recognize.RegisterRecognizer(recognizeTFState)
}

// ---- ~/.docker/config.json (registry push creds = supply-chain) ----

type dockerRegistry struct{ module.Base }

func (dockerRegistry) Name() string { return "docker_registry" }

func (dockerRegistry) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{
		{Key: "registry", Value: f["registry"], Flag: module.FlagInfo},
	}
	if u := f["user"]; u != "" {
		out = append(out, module.Finding{Key: "user", Value: u, Flag: module.FlagInfo})
	}
	out = append(out, module.Finding{
		Key:   "supply chain",
		Value: "registry push rights — can publish a backdoored image (rotate immediately)",
		Flag:  module.FlagForceMultiplier,
	})
	return out, nil
}

func (dockerRegistry) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "container registry credential"}
}

func recognizeDockerConfig(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	auths, _ := b.JSON["auths"].(map[string]any)
	if auths == nil {
		return nil
	}
	var out []recognize.Match
	for registry, v := range auths {
		e, _ := v.(map[string]any)
		enc, _ := e["auth"].(string)
		if enc == "" {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		user, pass, _ := strings.Cut(string(dec), ":")
		if pass == "" {
			continue
		}
		out = append(out, recognize.Match{
			Module: "docker_registry",
			// Carry the base64 "auth" blob too so the generic-secret recognizer
			// that also trips on it is suppressed (it's the same credential).
			Fields: module.Fields{"registry": registry, "user": user, "token": pass, "auth_b64": enc},
			Secret: pass,
			Label:  "docker config [" + registry + "]",
		})
	}
	return out
}

// ---- ~/.npmrc (registry auth tokens) ----

var npmrcTokenRe = regexp.MustCompile(`(?m)^//([^/:]+)/?[^:]*:_authToken=(.+)$`)

func recognizeNpmrc(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(b.Raw, "_authToken=") {
		return nil
	}
	var out []recognize.Match
	for _, m := range npmrcTokenRe.FindAllStringSubmatch(b.Raw, -1) {
		registry, tok := m[1], strings.TrimSpace(m[2])
		tok = strings.Trim(tok, `"'`)
		if tok == "" || strings.HasPrefix(tok, "${") || strings.HasPrefix(tok, "$") {
			continue
		}
		// Route by registry: the public npm registry exercises the npm module;
		// GitHub Packages tokens are GitHub PATs; any other (Artifactory, Nexus,
		// GitLab, Verdaccio) we can't assume speaks npm's /-/whoami, so we keep
		// it generic rather than mis-hitting registry.npmjs.org.
		mod := "generic_secret"
		switch {
		case strings.Contains(registry, "npmjs.org"):
			mod = "npm"
		case registry == "npm.pkg.github.com":
			mod = "github_pat"
		}
		out = append(out, recognize.Match{
			Module: mod,
			Fields: module.Fields{"token": tok},
			Secret: tok,
			Label:  ".npmrc [" + registry + "]",
		})
	}
	return out
}

// ---- ~/.netrc (per-machine login/password) ----

func recognizeNetrc(b parse.Blob, _ string, reg *module.Registry) []recognize.Match {
	if !strings.Contains(b.Raw, "machine ") || !strings.Contains(b.Raw, "password ") {
		return nil
	}
	// netrc host → module (where a dedicated one exists).
	hostModule := map[string]string{
		"api.heroku.com": "heroku", "registry.npmjs.org": "npm",
	}
	fields := strings.Fields(b.Raw)
	var out []recognize.Match
	var machine, login, password string
	flush := func() {
		if machine == "" || password == "" {
			return
		}
		mod, f := "generic_secret", module.Fields{"token": password}
		if m, ok := hostModule[machine]; ok {
			if _, reg2 := reg.ByName(m); reg2 {
				mod = m
			}
		}
		out = append(out, recognize.Match{Module: mod, Fields: f, Secret: password,
			Label: ".netrc [" + machine + " / " + login + "]"})
	}
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "machine":
			flush()
			machine, login, password = "", "", ""
			if i+1 < len(fields) {
				machine = fields[i+1]
				i++
			}
		case "login":
			if i+1 < len(fields) {
				login = fields[i+1]
				i++
			}
		case "password":
			if i+1 < len(fields) {
				password = fields[i+1]
				i++
			}
		}
	}
	flush()
	return out
}

// ---- Terraform state (.tfstate) — plaintext secrets in resource attributes ----

func recognizeTFState(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	if _, ok := b.JSON["terraform_version"]; !ok {
		return nil
	}
	resources, _ := b.JSON["resources"].([]any)
	if resources == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []recognize.Match
	for _, r := range resources {
		rm, _ := r.(map[string]any)
		addr := tfAddr(rm)
		insts, _ := rm["instances"].([]any)
		for _, inst := range insts {
			im, _ := inst.(map[string]any)
			attrs, _ := im["attributes"].(map[string]any)
			for k, v := range attrs {
				s, ok := v.(string)
				if !ok || seen[s] {
					continue
				}
				if !secretNameRe.MatchString(k) || notSecretNameRe.MatchString(k) {
					continue
				}
				if !valueLooksSecret(s) {
					continue
				}
				seen[s] = true
				out = append(out, recognize.Match{
					Module: "generic_secret",
					Fields: module.Fields{"token": s},
					Secret: s,
					Label:  "tfstate [" + addr + "." + k + "]",
				})
			}
		}
	}
	return out
}

func tfAddr(rm map[string]any) string {
	t, _ := rm["type"].(string)
	n, _ := rm["name"].(string)
	if t == "" {
		return n
	}
	return t + "." + n
}
