package module

import "sort"

// Machine-readable module listing — the data behind `geiger --list-modules`.
//
// WHY THIS EXISTS
// geiger recognizes credentials; it does NOT enumerate host stores. It triages
// what it is handed (a path, stdin, a scanner report), so whatever walks the
// endpoint decides which credentials geiger ever gets a chance to see. That
// makes the walker's path catalog and this registry two halves of one coverage
// claim, with nothing holding them together: a file-store module the walker has
// no path for is a permanent blind spot, and the failure is invisible from both
// ends — geiger reports nothing because it was handed nothing, and the walker
// reports nothing because geiger said nothing.
//
// This listing is what a downstream consumer (puck's credential-discovery
// catalog) joins against, so refreshing its vendored copy is the moment that
// drift surfaces.

// Listing is the JSON view of one registered module.
type Listing struct {
	Name string `json:"name"`
	// FileStore marks a module whose credential is discovered by locating its
	// store on disk: the recognizer keys on the file's name or its format, not
	// on a token pattern, so geiger only ever sees the credential when it is
	// handed that file. A consumer walking an endpoint MUST have a path for it.
	//
	// False means the credential is recognised from a pattern in arbitrary text
	// (ghp_…, xoxb-…, an env var name) and so rides along inside whatever file
	// the walker already opened for some other reason — a dedicated config file
	// may also exist, but no coverage is lost when the walker lacks its path.
	FileStore bool `json:"file_store"`
}

// fileStores maps every registered module whose credential is found by locating
// a file to that file — the value is documentation for whoever has to keep this
// honest, the key is what ships in the JSON.
//
// The test in list_test.go asserts every key here is a registered module, so a
// rename cannot silently drop a module's mark. Nothing can assert the reverse
// (a NEW file-store module that nobody marked), which is why the listing emits
// every module, marked or not: a consumer refreshing the snapshot sees the new
// name appear in the diff and can judge it.
var fileStores = map[string]string{
	"ai_ide_store":         "Cursor / VS Code state.vscdb (plaintext SQLite ItemTable)",
	"aws":                  "~/.aws/credentials, ~/.aws/config (INI profiles)",
	"aws_sso":              "~/.aws/sso/cache/*.json (portal accessToken)",
	"aws_sso_registration": "~/.aws/sso/cache/*.json (OIDC client registration)",
	"azure_msal":           "~/.azure/msal_token_cache.json (MSAL access/refresh tokens)",
	"bitwarden_vault":      "Bitwarden data.json / encrypted vault export",
	"databricks":           "~/.databrickscfg (INI host+token)",
	"docker_registry":      "~/.docker/config.json (auths)",
	"firefox_logins":       "Firefox profile logins.json + key4.db",
	"flyio":                "~/.fly/config.yml (access_token)",
	"gcp_adc":              "~/.config/gcloud/application_default_credentials.json (type=authorized_user)",
	"gcp_service_account":  "GCP service-account key JSON (type=service_account), incl. ~/.config/gcloud/legacy_credentials/",
	"kubeconfig":           "~/.kube/config (cluster users/tokens/client certs)",
	"keepass_db":           "*.kdbx / *.kdb (KDBX signature)",
	"mcp_config":           "claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json",
	"npm":                  "~/.npmrc, ~/.netrc (registry auth tokens)",
	"oci_config":           "~/.oci/config (OCIDs + key_file reference)",
	"snowflake":            "~/.snowflake/connections.toml",
	"ssh_private_key":      "~/.ssh/id_* and any PEM/OpenSSH private key file",
	"terraform_cloud":      "~/.terraform.d/credentials.tfrc.json",
	"vault":                "~/.vault-token (bare token — only the filename identifies it)",
}

// FileStoreNames returns the names the file-store table declares, whether or not
// they are registered. Exported so a test can assert the table has not drifted
// from the registry: a renamed module would otherwise silently lose its mark and
// the consumer's coverage guard would go quiet instead of failing.
func FileStoreNames() []string {
	out := make([]string, 0, len(fileStores))
	for name := range fileStores {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Listings returns every registered module as a Listing, sorted by name.
//
// Sorted rather than in registration order: the output is meant to be vendored
// by a consumer and diffed on refresh, and registration order changes whenever
// an unrelated init() moves, which would churn the diff and bury the real
// change.
func (r *Registry) Listings() []Listing {
	out := make([]Listing, 0, len(r.order))
	for _, name := range r.order {
		_, isStore := fileStores[name]
		out = append(out, Listing{Name: name, FileStore: isStore})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
