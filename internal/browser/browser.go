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
	Live      bool   // permit the network Web Store liveness check on store extensions
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
		notes = append(notes, scanExtensions(p, o.Live, o.Intrusive)...)
		if o.Intrusive {
			notes = append(notes, scanSessions(p)...)
		}
	}
	return notes
}

type profile struct{ browser, name, dir string }

// browserRoots is every Chromium-family user-data root for the platform. They
// all share the same Default/Profile-N layout with Preferences / Extensions /
// Cookies, so one code path covers Chrome, Edge, Brave, Chromium, and Vivaldi.
func browserRoots(o Options) []struct{ browser, dir string } {
	type spec struct{ browser, mac, linux, win string }
	specs := []spec{
		{"Chrome", "Google/Chrome", "google-chrome", "Google/Chrome/User Data"},
		{"Edge", "Microsoft Edge", "microsoft-edge", "Microsoft Edge/User Data"},
		{"Brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser/User Data"},
		{"Chromium", "Chromium", "chromium", "Chromium/User Data"},
		{"Vivaldi", "Vivaldi", "vivaldi", "Vivaldi/User Data"},
	}
	out := make([]struct{ browser, dir string }, 0, len(specs))
	for _, s := range specs {
		var dir string
		switch o.GOOS {
		case "darwin":
			dir = filepath.Join(o.Home, "Library", "Application Support", filepath.FromSlash(s.mac))
		case "windows":
			local := os.Getenv("LOCALAPPDATA")
			if local == "" {
				local = filepath.Join(o.Home, "AppData", "Local")
			}
			dir = filepath.Join(local, filepath.FromSlash(s.win))
		default: // linux and others
			dir = filepath.Join(o.Home, ".config", filepath.FromSlash(s.linux))
		}
		out = append(out, struct{ browser, dir string }{s.browser, dir})
	}
	return out
}

// discoverProfiles finds every Chrome/Edge profile (a dir holding a Preferences
// file) under the platform's user-data roots.
func discoverProfiles(o Options) []profile {
	var out []profile
	for _, r := range browserRoots(o) {
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
