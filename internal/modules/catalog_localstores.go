package modules

import (
	"regexp"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// Device-local credential stores beyond the ones devlaptop.go already covers
// (docker/npmrc/netrc/tfstate) and the cloud caches (aws/gcloud/azure). These
// parse a local file format, pair host↔token where the format provides it, and
// route to the live module for that service. gitleaks independently scans the
// raw bytes for prefixed tokens, so the value here is non-prefixed secrets,
// host pairing, and structured/odd formats.

func init() {
	module.Register(staticModule{
		name:    "oci_config",
		summary: "Oracle Cloud — API signing config (key_file referenced, not inline)",
		findings: []module.Finding{
			{Key: "type", Value: "OCI API signing config — user/tenancy OCIDs + key fingerprint", Flag: infoFlag},
			{Key: "validation", Value: "the API signing private key is referenced by key_file (a path), not stored inline — supply the .pem to exercise", Flag: cantFlag},
			{Key: "impact", Value: "with that private key: full OCI tenancy API access per the user's IAM policy (compute, object storage, IAM)", Flag: fmFlag},
		},
	})
	recognize.RegisterRecognizer(recognizeGitCredentials)
	recognize.RegisterRecognizer(recognizeGhHosts)
	recognize.RegisterRecognizer(recognizeFlyConfig)
	recognize.RegisterRecognizer(recognizeDatabricksCfg)
	recognize.RegisterRecognizer(recognizeTerraformCredFile)
	recognize.RegisterRecognizer(recognizeSnowflakeConnToml)
	recognize.RegisterRecognizer(recognizeVaultTokenFile)
	recognize.RegisterRecognizer(recognizeOCIConfig)
}

// ---- ~/.git-credentials: proto://user:token@host lines ----

var gitCredRe = regexp.MustCompile(`(?m)^\s*(https?)://([^:/@\s]+):([^@\s]+)@([^/\s]+)`)

func recognizeGitCredentials(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !gitCredRe.MatchString(b.Raw) {
		return nil
	}
	var out []recognize.Match
	for _, m := range gitCredRe.FindAllStringSubmatch(b.Raw, -1) {
		user, tok, host := m[2], m[3], m[4]
		if len(tok) < 8 || strings.HasPrefix(tok, "$") {
			continue
		}
		mod := "generic_secret"
		switch {
		case strings.Contains(host, "github"):
			mod = "github_pat"
		case strings.Contains(host, "gitlab"):
			mod = "gitlab"
		}
		out = append(out, recognize.Match{Module: mod, Fields: module.Fields{"token": tok},
			Secret: tok, Label: "git-credentials [" + host + " / " + user + "]"})
	}
	return out
}

// ---- gh CLI ~/.config/gh/hosts.yml: oauth_token: gho_… ----

var ghOAuthRe = regexp.MustCompile(`(?m)oauth_token:\s*(\S+)`)

func recognizeGhHosts(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(b.Raw, "oauth_token:") {
		return nil
	}
	var out []recognize.Match
	for _, m := range ghOAuthRe.FindAllStringSubmatch(b.Raw, -1) {
		tok := strings.Trim(m[1], `"'`)
		if len(tok) < 8 || strings.HasPrefix(tok, "$") {
			continue
		}
		out = append(out, recognize.Match{Module: "github_pat", Fields: module.Fields{"token": tok},
			Secret: tok, Label: "gh hosts.yml"})
	}
	return out
}

// ---- Fly.io ~/.fly/config.yml: access_token: FlyV1 … ----

var flyTokenRe = regexp.MustCompile(`(?m)access_token:\s*(\S.*?)\s*$`)

func recognizeFlyConfig(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(strings.ToLower(b.File), "fly") || !strings.Contains(b.Raw, "access_token:") {
		return nil
	}
	m := flyTokenRe.FindStringSubmatch(b.Raw)
	if m == nil {
		return nil
	}
	tok := strings.Trim(m[1], `"'`)
	if len(tok) < 8 {
		return nil
	}
	return []recognize.Match{{Module: "flyio", Fields: module.Fields{"token": tok}, Secret: tok, Label: "fly config.yml"}}
}

// ---- Databricks ~/.databrickscfg (INI: host + token=dapi…) ----

func recognizeDatabricksCfg(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	tok := strings.Trim(b.Vars["token"], `"'`)
	if tok == "" || (!strings.HasPrefix(tok, "dapi") && !strings.Contains(b.File, "databricks")) {
		return nil
	}
	f := module.Fields{"token": tok}
	if host := strings.Trim(b.Vars["host"], `"'`); host != "" {
		f["endpoint"] = strings.TrimRight(host, "/")
	}
	return []recognize.Match{{Module: "databricks", Fields: f, Secret: tok, Label: ".databrickscfg"}}
}

// ---- Terraform CLI ~/.terraform.d/credentials.tfrc.json ----

func recognizeTerraformCredFile(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	creds, _ := b.JSON["credentials"].(map[string]any)
	if creds == nil {
		return nil
	}
	var out []recognize.Match
	for host, v := range creds {
		m, _ := v.(map[string]any)
		tok, _ := m["token"].(string)
		if tok == "" {
			continue
		}
		out = append(out, recognize.Match{Module: "terraform_cloud", Fields: module.Fields{"token": tok},
			Secret: tok, Label: "terraform credentials [" + host + "]"})
	}
	return out
}

// ---- Snowflake ~/.snowflake/connections.toml / ~/.snowsql/config ----

func recognizeSnowflakeConnToml(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	f := strings.ToLower(b.File)
	if !strings.Contains(f, "connections.toml") && !strings.Contains(f, "snowsql") && !strings.Contains(f, "snowflake") {
		return nil
	}
	acct := strings.Trim(b.Vars["account"], `"'`)
	tok := strings.Trim(firstNonEmpty(b.Vars["token"], b.Vars["password"]), `"'`)
	if acct == "" || tok == "" {
		return nil
	}
	return []recognize.Match{{Module: "snowflake",
		Fields: module.Fields{"token": tok, "endpoint": "https://" + acct + ".snowflakecomputing.com"},
		Secret: tok, Label: "snowflake connections.toml [" + acct + "]"}}
}

// ---- ~/.vault-token (raw token file) ----

func recognizeVaultTokenFile(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(b.File, ".vault-token") {
		return nil
	}
	tok := strings.TrimSpace(b.Raw)
	if len(tok) < 8 || strings.ContainsAny(tok, " \n") {
		return nil
	}
	f := module.Fields{"token": tok}
	if endpoint != "" {
		f["endpoint"] = endpoint
	}
	return []recognize.Match{{Module: "vault", Fields: f, Secret: tok, Label: ".vault-token"}}
}

// ---- ~/.oci/config (signing key is external; flag offline) ----

func recognizeOCIConfig(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(b.Raw, "ocid1.tenancy") && !strings.Contains(strings.ToLower(b.File), ".oci") {
		return nil
	}
	if b.Vars["fingerprint"] == "" && !strings.Contains(b.Raw, "key_file") {
		return nil
	}
	return []recognize.Match{{Module: "oci_config", Label: "OCI config"}}
}
