package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

func TestGitCredentialsRoutesByHost(t *testing.T) {
	raw := "https://x-access-token:ghp_realtoken0123456789ABCDEFghijkl@github.com\n" +
		"https://oauth2:glpat-realtoken0123456789xy@gitlab.com\n" +
		"https://deploy:supersecretpw1234@git.internal.acme.com\n"
	b := parse.Parse(raw, ".git-credentials")
	matches := recognize.Recognize(b, "", module.Default)
	by := modulesOf(matches)
	if m, ok := by["github_pat"]; !ok || !strings.HasPrefix(m.Secret, "ghp_") {
		t.Errorf("github line not routed to github_pat: %+v", by)
	}
	if m, ok := by["gitlab"]; !ok || !strings.HasPrefix(m.Secret, "glpat-") {
		t.Errorf("gitlab line not routed to gitlab: %+v", by)
	}
	found := false
	for _, m := range matches {
		if m.Secret == "supersecretpw1234" {
			found = true
		}
	}
	if !found {
		t.Errorf("internal-host plaintext token not surfaced: %+v", matches)
	}
}

func TestOCIConfigOfflineFlag(t *testing.T) {
	raw := "[DEFAULT]\nuser=ocid1.user.oc1..aaa\nfingerprint=aa:bb:cc\ntenancy=ocid1.tenancy.oc1..bbb\nkey_file=~/.oci/key.pem\nregion=us-ashburn-1\n"
	b := parse.Parse(raw, "config")
	by := modulesOf(recognize.Recognize(b, "", module.Default))
	m, ok := by["oci_config"]
	if !ok {
		t.Fatalf("OCI config not recognized: %+v", by)
	}
	mod, _ := module.Default.ByName("oci_config")
	fs, _ := mod.Recon(context.Background(), nil, module.Token{}, m.Fields)
	got := indexByKey(fs)
	if got["impact"].Flag != module.FlagForceMultiplier || got["validation"].Flag != module.FlagCantCharacterize {
		t.Errorf("OCI flags wrong: %+v", got)
	}
}

func TestLocalStoreRecognizers(t *testing.T) {
	cases := []struct {
		name, file, raw, module, secret, endpoint string
	}{
		{"gh hosts.yml", "hosts.yml", "github.com:\n  oauth_token: gho_abcdef0123456789\n  user: octo\n", "github_pat", "gho_abcdef0123456789", ""},
		{"fly config", ".fly/config.yml", "access_token: FlyV1 fm2_abcdef123456\n", "flyio", "FlyV1 fm2_abcdef123456", ""},
		{"databricks cfg", ".databrickscfg", "[DEFAULT]\nhost = https://acme.cloud.databricks.com\ntoken = dapiabcdef0123\n", "databricks", "dapiabcdef0123", "https://acme.cloud.databricks.com"},
		{"terraform tfrc", "credentials.tfrc.json", `{"credentials":{"app.terraform.io":{"token":"AAAA.atlasv1.BBBBCCCCDDDD"}}}`, "terraform_cloud", "AAAA.atlasv1.BBBBCCCCDDDD", ""},
		{"snowflake conn toml", "connections.toml", "[connections.dev]\naccount = \"acme-xy12345\"\nuser = \"svc\"\npassword = \"Sn0wPass1234\"\n", "snowflake", "Sn0wPass1234", "https://acme-xy12345.snowflakecomputing.com"},
		{"vault-token file", ".vault-token", "hvs.CAESIabcdef0123456789\n", "vault", "hvs.CAESIabcdef0123456789", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := parse.Parse(tc.raw, tc.file)
			by := modulesOf(recognize.Recognize(b, "", module.Default))
			m, ok := by[tc.module]
			if !ok {
				t.Fatalf("%s not recognized: %+v", tc.module, by)
			}
			if m.Secret != tc.secret {
				t.Errorf("secret = %q, want %q", m.Secret, tc.secret)
			}
			if tc.endpoint != "" && m.Fields["endpoint"] != tc.endpoint {
				t.Errorf("endpoint = %q, want %q", m.Fields["endpoint"], tc.endpoint)
			}
		})
	}
}
