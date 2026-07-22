package modules

import (
	"context"
	"encoding/csv"
	"net/url"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Password-manager artifacts split three ways by what Geiger can honestly say
// about them:
//
//   - Recovery material (1Password Secret Key, KeePass .kdbx, an encrypted
//     Bitwarden vault) — recognizable and high-impact, but NOT exercisable
//     read-only: it's half of a pair, or ciphertext that needs the master
//     password. Reported as a can't-characterize force multiplier.
//   - Plaintext exports (unencrypted Bitwarden JSON, LastPass/Dashlane CSV) —
//     a cleartext credential dump. The headline (count + cleartext) is reported
//     directly, and each contained password is fanned out as its own candidate
//     so it triages recursively; any prefixed API key inside is caught by the
//     gitleaks scan of the whole blob independently.
//   - A live machine credential (Bitwarden personal/org API key) — validatable
//     via the client_credentials grant, like onepassword_connect.
//
// Not fingerprinted: Proton Pass and Apple iCloud Keychain recovery is a
// human-readable recovery phrase / recovery key with no stable on-disk format
// to key on; a 1Password Emergency Kit is a PDF/QR, so the Secret Key inside is
// only seen once it's extracted to text (then the gitleaks rule below fires).

func init() {
	// Bucket 1 — recovery material (recognize, can't characterize read-only).
	add("1password-secret-key", staticModule{
		name:    "onepassword_secret_key",
		summary: "1Password Secret Key — vault-unlock half; dangerous with the master password",
		findings: []module.Finding{
			{Key: "type", Value: "1Password Secret Key (A3-…) — the device-secret half of 1Password's master-password + Secret-Key login", Flag: infoFlag},
			{Key: "validation", Value: "cannot sign in on its own: 1Password's SRP login also needs the master password, which the Emergency Kit leaves blank — no read-only call can exercise it", Flag: cantFlag},
			{Key: "impact", Value: "with a phished/keylogged/reused master password it unlocks every vault item, and it's often stored right beside that password (Emergency Kit PDF, screenshot)", Flag: fmFlag},
		},
	})
	add("", staticModule{
		name:    "keepass_db",
		summary: "KeePass vault — offline-crackable to every secret with the master password",
		findings: []module.Finding{
			{Key: "type", Value: "KeePass database (.kdbx) — an encrypted credential vault", Flag: infoFlag},
			{Key: "validation", Value: "opaque without the master password (and any .key/.keyx keyfile) — nothing to exercise read-only", Flag: cantFlag},
			{Key: "impact", Value: "offline-crackable: a weak master password yields every stored secret at attacker speed, with no server rate limit", Flag: fmFlag},
		},
	})
	add("", staticModule{
		name:    "bitwarden_vault",
		summary: "Bitwarden encrypted vault — offline-crackable with the master password",
		findings: []module.Finding{
			{Key: "type", Value: "Bitwarden encrypted vault material (password-protected export or local data.json) — AES-256-CBC ciphertext", Flag: infoFlag},
			{Key: "validation", Value: "needs the master password (KDF-derived key) to decrypt — no read-only call exercises it", Flag: cantFlag},
			{Key: "impact", Value: "offline-crackable against the embedded KDF parameters; a weak master password decrypts every item, TOTP seeds included", Flag: fmFlag},
		},
	})
	recognize.RegisterRecognizer(recognizeKeePass)
	recognize.RegisterRecognizer(recognizeBitwardenVault)

	// Bucket 2 — plaintext exports (headline + per-login fan-out).
	module.Register(vaultExport{})
	recognize.RegisterRecognizer(recognizePlaintextExport)

	// Bucket 3 — Bitwarden API key (live, client_credentials).
	registerBitwardenAPI()
}

// ---- staticModule: an offline module with fixed findings (no network) ----

// staticModule reports a constant set of findings and makes no calls. It backs
// the recovery-material recognizers, which Geiger can identify but never
// validate read-only.
type staticModule struct {
	module.Base
	name     string
	summary  string
	findings []module.Finding
}

func (s staticModule) Name() string { return s.name }

func (s staticModule) Recon(context.Context, *recon.Client, module.Token, module.Fields) ([]module.Finding, error) {
	return append([]module.Finding(nil), s.findings...), nil
}

func (s staticModule) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: s.summary}
}

// ---- KeePass database (.kdbx) ----

func recognizeKeePass(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !looksKeePass(b) {
		return nil
	}
	label := "keepass database"
	if b.File != "" {
		label = b.File
	}
	return []recognize.Match{{Module: "keepass_db", Label: label}}
}

// looksKeePass matches by extension or by the KDBX/KDB file signature
// (base signature 0x9AA2D903, little-endian → 03 D9 A2 9A).
func looksKeePass(b parse.Blob) bool {
	f := strings.ToLower(b.File)
	if strings.HasSuffix(f, ".kdbx") || strings.HasSuffix(f, ".kdb") {
		return true
	}
	return strings.HasPrefix(b.Raw, "\x03\xd9\xa2\x9a")
}

// ---- Bitwarden encrypted vault / data.json ----

func recognizeBitwardenVault(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil {
		return nil
	}
	enc, _ := b.JSON["encrypted"].(bool)
	_, hasItems := b.JSON["items"]
	// encKeyValidation_DO_NOT_EDIT appears in account-restricted exports and the
	// local data.json — a strong, Bitwarden-specific marker.
	marker := strings.Contains(b.Raw, "encKeyValidation_DO_NOT_EDIT")
	recognized := marker || (enc && hasItems)
	if !recognized {
		return nil
	}
	return []recognize.Match{{Module: "bitwarden_vault", Label: "bitwarden vault"}}
}

// ---- Plaintext vault exports (Bitwarden JSON, LastPass/Dashlane CSV) ----

// exportItem is one decoded login row from a plaintext export.
type exportItem struct {
	name, username, password, totp, uri string
}

type vaultExport struct{ module.Base }

func (vaultExport) Name() string { return "vault_export_plaintext" }

func (vaultExport) Recon(_ context.Context, _ *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	src := f["source"]
	if src == "" {
		src = "password manager"
	}
	out := []module.Finding{
		{Key: "type", Value: "plaintext " + src + " export — every entry is stored in cleartext (no master password required)", Flag: fmFlag},
	}
	if c := f["count"]; c != "" && c != "0" {
		out = append(out, module.Finding{Key: "logins", Value: c + " credentials exposed in cleartext", Flag: fmFlag})
	}
	if t := f["totp"]; t != "" && t != "0" {
		out = append(out, module.Finding{Key: "2fa", Value: t + " TOTP/2FA seed(s) included — the second factor is bypassable too", Flag: warnFlag})
	}
	if s := f["sample"]; s != "" {
		out = append(out, module.Finding{Key: "includes", Value: s, Flag: infoFlag})
	}
	return out, nil
}

func (vaultExport) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "plaintext credential dump — full account takeover across every listed site"}
}

// fanCap bounds how many contained passwords are emitted as candidates, so a
// huge export doesn't drown the report (the headline still reports the total).
const fanCap = 60

func recognizePlaintextExport(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	source, items := vaultExportContents(b)
	if source == "" || len(items) == 0 {
		return nil
	}

	totp := 0
	var sample []string
	for _, it := range items {
		if it.totp != "" {
			totp++
		}
		if len(sample) < 3 {
			if s := firstNonEmpty(it.name, it.uri, it.username); s != "" {
				sample = append(sample, s)
			}
		}
	}

	out := []recognize.Match{{
		Module: "vault_export_plaintext",
		Fields: module.Fields{
			"source": source,
			"count":  strconv.Itoa(len(items)),
			"totp":   strconv.Itoa(totp),
			"sample": strings.Join(sample, ", "),
		},
		Label: source + " export",
	}}

	// Fan out each contained password so it triages on its own. gitleaks scans
	// the whole blob in parallel, so prefixed API keys inside route to their real
	// modules; this catches the rest (site passwords) as generic secrets.
	seen := map[string]bool{}
	for _, it := range items {
		if len(out) > fanCap {
			break
		}
		if it.password == "" || seen[it.password] || !valueLooksSecret(it.password) {
			continue
		}
		seen[it.password] = true
		out = append(out, recognize.Match{
			Module: "generic_secret",
			Fields: module.Fields{"token": it.password},
			Secret: it.password,
			Label:  source + ": " + firstNonEmpty(it.name, it.uri, it.username, "login"),
		})
	}
	return out
}

// vaultExportContents returns the export's source label and its decoded login
// rows, or ("", nil) if the blob isn't a recognizable plaintext export.
func vaultExportContents(b parse.Blob) (string, []exportItem) {
	if b.JSON != nil {
		enc, _ := b.JSON["encrypted"].(bool)
		rawItems, ok := b.JSON["items"].([]any)
		if !ok || enc { // encrypted Bitwarden exports are handled as recovery material
			return "", nil
		}
		var items []exportItem
		for _, ri := range rawItems {
			im, _ := ri.(map[string]any)
			login, _ := im["login"].(map[string]any)
			if login == nil {
				continue
			}
			it := exportItem{}
			it.name, _ = im["name"].(string)
			it.username, _ = login["username"].(string)
			it.password, _ = login["password"].(string)
			it.totp, _ = login["totp"].(string)
			if uris, ok := login["uris"].([]any); ok && len(uris) > 0 {
				if u0, ok := uris[0].(map[string]any); ok {
					it.uri, _ = u0["uri"].(string)
				}
			}
			items = append(items, it)
		}
		return "bitwarden", items
	}
	return csvExportContents(b.Raw)
}

func csvExportContents(raw string) (string, []exportItem) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, ",") {
		return "", nil
	}
	rd := csv.NewReader(strings.NewReader(raw))
	rd.FieldsPerRecord = -1
	rd.LazyQuotes = true
	rows, err := rd.ReadAll()
	if err != nil || len(rows) < 2 {
		return "", nil
	}
	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	col := func(names ...string) int {
		for _, n := range names {
			if i, ok := idx[n]; ok {
				return i
			}
		}
		return -1
	}
	pw := col("password", "login_password")
	user := col("username", "login_username")
	urlc := col("url", "login_uri", "uri")
	totp := col("totp", "login_totp", "otpsecret", "otpauth")
	name := col("name", "title")
	// Require a password column plus at least one corroborating column, so an
	// unrelated CSV that merely has a "password" header isn't mistaken for a vault.
	if pw < 0 || (user < 0 && urlc < 0 && totp < 0) {
		return "", nil
	}
	source := "password manager"
	switch {
	case col("login_password") >= 0:
		source = "bitwarden"
	case col("otpsecret") >= 0:
		source = "dashlane"
	case len(rows[0]) >= 3 && eqFold(rows[0][0], "url") && eqFold(rows[0][1], "username") && eqFold(rows[0][2], "password"):
		source = "lastpass"
	}
	get := func(row []string, i int) string {
		if i < 0 || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	var items []exportItem
	for _, row := range rows[1:] {
		it := exportItem{
			name:     get(row, name),
			username: get(row, user),
			password: get(row, pw),
			totp:     get(row, totp),
			uri:      get(row, urlc),
		}
		if it.password == "" && it.totp == "" {
			continue
		}
		items = append(items, it)
	}
	return source, items
}

// ---- Bitwarden API key (personal/org) — client_credentials grant ----

func registerBitwardenAPI() {
	add("", r.HTTP{
		ModuleName: "bitwarden", Endpoint: selfHosted, Base: "{endpoint}", Auth: r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			// Bitwarden's identity endpoint wants the api scope plus device fields.
			extra := url.Values{
				"scope":            {"api"},
				"deviceType":       {"21"}, // SDK
				"deviceIdentifier": {"geiger-recon"},
				"deviceName":       {"geiger"},
			}
			return auth.ClientCredentials(ctx, c, f["identity"]+"/connect/token", f["client_id"], f["client_secret"], extra)
		},
		// /sync authenticates the token and sizes the vault in one read-only call.
		// Items come back ENCRYPTED — the API key alone never yields the vault key.
		Whoami: r.GET("/sync?excludeDomains=true").
			Field("account", "profile.email").
			CountArrayFlag("ciphers", "vault items (encrypted)", warnFlag).
			Signal(r.Signal{Path: "profile.organizations.0.name", Regex: ".+", Key: "organizations",
				Value: "member of one or more organizations — shared org vault collections in reach", Flag: warnFlag}),
		Static: []module.Finding{
			{Key: "validation", Value: "API key is valid: can sync the account read-only (item count, org membership) but items stay encrypted — the master password is still required to decrypt", Flag: infoFlag},
		},
		Summarize: func([]module.Finding) string {
			return "Bitwarden API key — valid; enumerates the vault (items stay encrypted without the master password)"
		},
	}.Module())
	recognize.RegisterRecognizer(recognizeBitwardenAPIKey)
}

func recognizeBitwardenAPIKey(b parse.Blob, endpoint string, _ *module.Registry) []recognize.Match {
	id := firstVar(b.Vars, "BW_CLIENTID", "BW_CLIENT_ID")
	secret := firstVar(b.Vars, "BW_CLIENTSECRET", "BW_CLIENT_SECRET")
	if id == "" || secret == "" {
		return nil
	}
	// Bitwarden client_ids are user.<guid> (personal) or organization.<guid>.
	if !strings.HasPrefix(id, "user.") && !strings.HasPrefix(id, "organization.") {
		return nil
	}
	api, identity := "https://api.bitwarden.com", "https://identity.bitwarden.com"
	if endpoint != "" { // self-hosted: <host>/api and <host>/identity
		base := strings.TrimRight(endpoint, "/")
		api, identity = base+"/api", base+"/identity"
	}
	return []recognize.Match{{
		Module: "bitwarden",
		Fields: module.Fields{"client_id": id, "client_secret": secret, "endpoint": api, "identity": identity},
		Secret: secret, Label: "BW_CLIENTSECRET",
	}}
}

// ---- small helpers ----

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func eqFold(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), b) }
