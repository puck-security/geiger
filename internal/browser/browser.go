// Package browser models the impact of a malicious Chromium browser extension
// (CursedChrome-style browser proxy, infostealer, sideloaded MV3 extension). It
// answers two questions a responder cares about:
//
//   - Which installed extension has the reach to do it? (capability): the
//     manifest permission union — cookies + broad host access + request
//     interception / script injection / proxy — plus whether it was sideloaded
//     (unsigned, not content-verified).
//   - What would it reach? (blast radius): the live SaaS/IdP sessions present in
//     the browser's cookie store.
//
// It never decrypts cookie VALUES (Chromium wraps them with an OS keychain / App-
// Bound key — infeasible offline), so the session inventory is metadata only:
// which domains have a live auth session, grouped by blast radius. That is the
// honest signal — an extension bypasses the keychain in-browser; geiger's job is
// to say what is reachable, not to steal it.
package browser

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// Options configures a scan. Home and GOOS are injectable for tests.
type Options struct {
	Intrusive bool   // read the Cookies DB metadata (the sensitive session inventory)
	Home      string // override home dir (tests); defaults to os.UserHomeDir
	GOOS      string // override runtime.GOOS (tests)
}

// Scan discovers local Chrome/Edge profiles and returns a Note per risky
// extension plus, under Intrusive, a session-inventory Note per profile.
func Scan(o Options) []module.Note {
	if o.Home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			o.Home = h
		}
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	var notes []module.Note
	for _, p := range discoverProfiles(o) {
		notes = append(notes, scanExtensions(p)...)
		if o.Intrusive {
			notes = append(notes, scanSessions(p)...)
		}
	}
	return notes
}

type profile struct{ browser, name, dir string }

// discoverProfiles finds every Chrome/Edge profile (a dir holding a Preferences
// file) under the platform's user-data roots.
func discoverProfiles(o Options) []profile {
	var roots []struct{ browser, dir string }
	switch o.GOOS {
	case "darwin":
		roots = []struct{ browser, dir string }{
			{"Chrome", filepath.Join(o.Home, "Library", "Application Support", "Google", "Chrome")},
			{"Edge", filepath.Join(o.Home, "Library", "Application Support", "Microsoft Edge")},
		}
	case "windows":
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(o.Home, "AppData", "Local")
		}
		roots = []struct{ browser, dir string }{
			{"Chrome", filepath.Join(local, "Google", "Chrome", "User Data")},
			{"Edge", filepath.Join(local, "Microsoft Edge", "User Data")},
		}
	default: // linux and others
		roots = []struct{ browser, dir string }{
			{"Chrome", filepath.Join(o.Home, ".config", "google-chrome")},
			{"Edge", filepath.Join(o.Home, ".config", "microsoft-edge")},
		}
	}
	var out []profile
	for _, r := range roots {
		entries, err := os.ReadDir(r.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := e.Name()
			if n != "Default" && !strings.HasPrefix(n, "Profile ") {
				continue
			}
			if _, err := os.Stat(filepath.Join(r.dir, n, "Preferences")); err != nil {
				continue
			}
			out = append(out, profile{browser: r.browser, name: n, dir: filepath.Join(r.dir, n)})
		}
	}
	return out
}

// chromeLocation maps the ManifestLocation enum to a label and whether it's a
// sideload/unverified provenance (higher risk). Component/policy/webstore are
// lower-concern; unpacked and the external registry/pref mechanisms are not.
func chromeLocation(loc float64) (label string, sideloaded bool) {
	switch int(loc) {
	case 1:
		return "webstore", false
	case 4:
		return "unpacked (developer mode)", true
	case 5:
		return "component (built-in)", false
	case 2, 3, 6:
		return "external (registry/pref)", true
	case 7, 9, 10:
		return "enterprise policy", false
	case 8:
		return "--load-extension (command line)", true
	default:
		return "unknown", true
	}
}
