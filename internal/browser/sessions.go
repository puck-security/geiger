package browser

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"

	_ "modernc.org/sqlite" // read-only cookie-metadata queries
)

// scanSessions reads the profile's Cookies DB metadata (host_key + name only —
// never the encrypted value) and reports the live sessions an in-browser
// attacker (malicious extension, infostealer, CursedChrome proxy) would reach,
// grouped by blast radius. IdP/SSO sessions are crown jewels: one hijacked Okta
// or Google session unlocks everything federated behind it.
func scanSessions(p profile) []module.Note {
	db := cookiesDBPath(p.dir)
	if db == "" {
		return nil
	}
	hosts, err := readCookieHosts(db)
	if err != nil || len(hosts) == 0 {
		return nil
	}
	tiers := classifySessions(hosts)
	if len(tiers.findings()) == 0 {
		return nil
	}
	return []module.Note{{
		Title:    "browser sessions: " + p.browser + "/" + p.name,
		Findings: tiers.findings(),
		Summary:  "live sessions a malicious extension / infostealer would hijack",
	}}
}

// cookiesDBPath returns the profile's Cookies SQLite file (newer Chrome moved it
// under Network/), or "" if absent.
func cookiesDBPath(profileDir string) string {
	for _, rel := range []string{filepath.Join("Network", "Cookies"), "Cookies"} {
		p := filepath.Join(profileDir, rel)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// readCookieHosts returns the (host_key, name) pairs. immutable=1 opens the DB
// read-only even while Chrome holds a lock, and never writes.
func readCookieHosts(path string) ([]cookie, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT host_key, name FROM cookies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cookie
	for rows.Next() {
		var c cookie
		if rows.Scan(&c.host, &c.name) == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

type cookie struct{ host, name string }

// sessionTiers buckets reachable sessions by blast radius.
type sessionTiers struct {
	idp    map[string]bool // IdP / SSO — crown jewels
	cloud  map[string]bool // cloud consoles
	vcs    map[string]bool // source control
	collab map[string]bool // collaboration / comms
}

// domain → tier. Suffix-matched against the cookie host_key.
var (
	idpDomains    = []string{"accounts.google.com", "login.microsoftonline.com", "okta.com", "onelogin.com", "auth0.com", "login.live.com", "duosecurity.com", "id.atlassian.com", "pingidentity.com", "jumpcloud.com"}
	cloudDomains  = []string{"console.aws.amazon.com", "signin.aws.amazon.com", "console.cloud.google.com", "portal.azure.com", "cloud.digitalocean.com", "dashboard.heroku.com"}
	vcsDomains    = []string{"github.com", "gitlab.com", "bitbucket.org"}
	collabDomains = []string{"slack.com", "atlassian.net", "zoom.us", "notion.so", "linear.app"}
)

// authCookie reports whether a cookie name looks like a session/auth cookie
// (filters out analytics/pref cookies so a bare visited-once domain isn't
// mistaken for a live session).
func authCookie(name string) bool {
	l := strings.ToLower(name)
	if strings.HasPrefix(name, "__Secure-") || strings.HasPrefix(name, "__Host-") {
		return true
	}
	for _, s := range []string{"sess", "sid", "auth", "token", "login", "csrf", "xsrf"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func classifySessions(cookies []cookie) sessionTiers {
	t := sessionTiers{idp: map[string]bool{}, cloud: map[string]bool{}, vcs: map[string]bool{}, collab: map[string]bool{}}
	for _, c := range cookies {
		host := strings.TrimPrefix(c.host, ".")
		// IdP domains count on presence (a cookie for an IdP domain ≈ a session);
		// others require an auth-shaped cookie name to avoid false positives.
		if d := matchDomain(host, idpDomains); d != "" {
			t.idp[d] = true
			continue
		}
		if !authCookie(c.name) {
			continue
		}
		if d := matchDomain(host, cloudDomains); d != "" {
			t.cloud[d] = true
		} else if d := matchDomain(host, vcsDomains); d != "" {
			t.vcs[d] = true
		} else if d := matchDomain(host, collabDomains); d != "" {
			t.collab[d] = true
		}
	}
	return t
}

func matchDomain(host string, domains []string) string {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) || strings.HasSuffix(host, d) {
			return d
		}
	}
	return ""
}

func (t sessionTiers) findings() []module.Finding {
	var out []module.Finding
	add := func(key, note string, flag module.FlagLevel, m map[string]bool) {
		if len(m) == 0 {
			return
		}
		ks := keys(m)
		out = append(out, module.Finding{Key: key, Value: note + ": " + strings.Join(ks, ", "), Flag: flag, Detail: ks})
	}
	add("idp/sso", "identity-provider sessions — hijacking one federates into everything behind it", module.FlagForceMultiplier, t.idp)
	add("cloud console", "cloud console sessions", module.FlagForceMultiplier, t.cloud)
	add("source control", "VCS sessions (push access / source)", module.FlagWarn, t.vcs)
	add("collaboration", "collab/comms sessions", module.FlagWarn, t.collab)
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
