package modules

import (
	"encoding/base64"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// modulesOf indexes recognizer matches by module name (last match per module).
func modulesOf(ms []recognize.Match) map[string]recognize.Match {
	out := map[string]recognize.Match{}
	for _, m := range ms {
		out[m.Module] = m
	}
	return out
}

func TestDockerConfigRecognized(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("deployer:s3cr3tPushT0ken"))
	raw := `{"auths":{"registry.example.com":{"auth":"` + auth + `"}}}`
	b := parse.Parse(raw, "config.json")

	matches := recognize.Recognize(b, "", module.Default)
	by := modulesOf(matches)
	m, ok := by["docker_registry"]
	if !ok {
		t.Fatalf("docker config not recognized: %+v", matches)
	}
	if m.Fields["user"] != "deployer" || m.Secret != "s3cr3tPushT0ken" {
		t.Errorf("decoded auth wrong: %+v", m.Fields)
	}
	// The base64 auth blob must not also surface as a standalone generic secret.
	if _, dup := by["generic_secret"]; dup {
		t.Errorf("base64 auth blob leaked as generic_secret: %+v", matches)
	}
}

func TestNpmrcRoutesByRegistry(t *testing.T) {
	raw := "//registry.npmjs.org/:_authToken=npm_AbCdEf0123456789AbCdEf0123456789AbCd\n" +
		"//npm.pkg.github.com/:_authToken=ghp_realtokenhere0123456789ABCDEFGHIJKL\n" +
		"//acme.jfrog.io/artifactory/api/npm/:_authToken=cmVmdGtuOjAxOmFydA\n" +
		"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"
	b := parse.Parse(raw, ".npmrc")

	matches := recognize.Recognize(b, "", module.Default)
	var npm, gh, generic int
	for _, m := range matches {
		switch m.Module {
		case "npm":
			npm++
			if m.Secret == "" || m.Secret[:4] != "npm_" {
				t.Errorf("npm token wrong: %q", m.Secret)
			}
		case "github_pat":
			gh++
		case "generic_secret":
			generic++
		}
	}
	if npm != 1 {
		t.Errorf("want 1 npmjs token routed to npm, got %d (%+v)", npm, matches)
	}
	if gh != 1 {
		t.Errorf("want GitHub Packages token routed to github_pat, got %d", gh)
	}
	if generic != 1 {
		t.Errorf("want Artifactory token kept generic, got %d", generic)
	}
	// The ${NPM_TOKEN} placeholder must be skipped, not triaged.
	for _, m := range matches {
		if m.Secret == "${NPM_TOKEN}" {
			t.Errorf("env placeholder should be skipped: %+v", m)
		}
	}
}

func TestNetrcRecognized(t *testing.T) {
	raw := "machine api.heroku.com\n  login me@example.com\n  password hsk_0123456789abcdef0123456789abcdef\n" +
		"machine git.internal\n  login deploy\n  password supersecretpasswordvalue123\n"
	b := parse.Parse(raw, ".netrc")

	matches := recognize.Recognize(b, "", module.Default)
	by := modulesOf(matches)
	if _, ok := by["heroku"]; !ok {
		t.Errorf("heroku netrc machine not routed to heroku module: %+v", matches)
	}
	g, ok := by["generic_secret"]
	if !ok {
		t.Errorf("unknown netrc machine not kept as generic_secret: %+v", matches)
	}
	if g.Secret != "supersecretpasswordvalue123" {
		t.Errorf("netrc password wrong: %q", g.Secret)
	}
}

func TestTFStateSecretsExtracted(t *testing.T) {
	raw := `{
	  "terraform_version": "1.7.0",
	  "resources": [
	    {"type":"aws_db_instance","name":"main","instances":[
	      {"attributes":{"id":"db-1","password":"Sup3rSecretDBpass!23","username":"admin"}}]},
	    {"type":"random_pet","name":"x","instances":[
	      {"attributes":{"id":"calm-cat","length":2}}]}
	  ]
	}`
	b := parse.Parse(raw, "terraform.tfstate")

	matches := recognize.Recognize(b, "", module.Default)
	var found bool
	for _, m := range matches {
		if m.Secret == "Sup3rSecretDBpass!23" {
			found = true
		}
		if m.Secret == "admin" {
			t.Errorf("username should not be flagged as a secret: %+v", m)
		}
	}
	if !found {
		t.Errorf("tfstate db password not extracted: %+v", matches)
	}
}
