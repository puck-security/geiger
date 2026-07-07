package browser

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/puck-security/geiger/internal/module"
)

// triageInput carries what triageFindings needs to build the responder bundle
// for a flagged sideloaded / unknown-origin extension.
type triageInput struct {
	profileDir string         // the browser profile dir (for storage paths)
	id         string         // extension id (a SIEM IOC)
	srcDir     string         // the extension's code dir (unpacked path, or Extensions/<id>/<ver>)
	external   bool           // srcDir is an on-disk checkout outside the profile (unpacked)
	manifest   map[string]any // parsed manifest (may be nil if unreadable)
	intrusive  bool           // also byte-scan the extension's persisted storage
}

// triageFindings assembles the responder triage bundle for a flagged sideloaded
// extension: provenance context (age / UI surface / dev-project markers), the
// extension id as a SIEM IOC, and a low-false-positive grep of its on-disk files
// (and, under --intrusive, its persisted storage) for hardcoded remote hosts —
// the one artifact that points at network egress, where the legit/malicious
// truth actually lives. Context lines are FlagNone (shown, but they never move
// the tier); a host hit is FlagWarn ("verify," never "confirmed malicious").
func triageFindings(in triageInput) []module.Finding {
	var out []module.Finding

	// id — a clean pivot for a SIEM (full 32-char id; the title shows only 8).
	out = append(out, module.Finding{Key: "id", Value: in.id, Flag: module.FlagNone, Detail: []string{in.id}})

	srcExists := false
	if in.srcDir != "" {
		if fi, err := os.Stat(in.srcDir); err == nil {
			srcExists = true
			// age — a folder that appeared during the incident window is a lead.
			out = append(out, module.Finding{Key: "installed", Value: fi.ModTime().Format("2006-01-02 (Mon)"), Flag: module.FlagNone})
		}
	}
	// UI surface — a broad extension with no user-facing surface is more suspicious.
	if in.manifest != nil {
		out = append(out, module.Finding{Key: "ui", Value: uiSurface(in.manifest), Flag: module.FlagNone})
	}
	// dev-project markers — only meaningful for an unpacked on-disk checkout.
	if in.external && srcExists {
		out = append(out, module.Finding{Key: "project", Value: projectMarkers(in.srcDir), Flag: module.FlagNone})
	}

	// The IOC grep — the point of the bundle. Source dir always; persisted
	// storage only under --intrusive (it may hold user data).
	var dirs []string
	if srcExists {
		dirs = append(dirs, in.srcDir)
	}
	if in.intrusive {
		dirs = append(dirs, storageDirs(in.profileDir, in.id)...)
	}
	if hosts := grepHosts(dirs); len(hosts) > 0 {
		out = append(out, module.Finding{
			Key:    "indicators",
			Value:  "remote host(s) hardcoded in extension code/storage — verify in egress/DNS/proxy logs: " + strings.Join(hosts, ", "),
			Flag:   module.FlagWarn,
			Detail: hosts,
		})
	}
	return out
}

// uiSurface reports the extension's user-facing surface, or "none (headless)".
func uiSurface(m map[string]any) string {
	var present []string
	for _, k := range []string{"action", "browser_action", "page_action", "options_page", "options_ui", "devtools_page", "side_panel"} {
		if _, ok := m[k]; ok {
			present = append(present, k)
		}
	}
	if len(present) == 0 {
		return "none (headless — no popup/options/devtools surface)"
	}
	return strings.Join(present, ", ")
}

// projectMarkers looks for dev-checkout markers at/above srcDir: a real project
// (git/package.json) is far less suspicious than a bare dropped folder.
func projectMarkers(srcDir string) string {
	var found []string
	if _, err := os.Stat(filepath.Join(srcDir, "package.json")); err == nil {
		found = append(found, "package.json")
	}
	if _, err := os.Stat(filepath.Join(srcDir, "src")); err == nil {
		found = append(found, "src/")
	}
	dir := srcDir
	for range 3 {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			found = append(found, ".git")
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if len(found) == 0 {
		return "no project markers (a bare folder, not a dev checkout)"
	}
	return "dev project (" + strings.Join(found, ", ") + ")"
}

// extensionCodeDir returns the newest version subdir under Extensions/<id> (where
// an installed extension's code lives), or "".
func extensionCodeDir(profileDir, id string) string {
	base := filepath.Join(profileDir, "Extensions", id)
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	var newest string
	for _, e := range entries {
		if e.IsDir() {
			newest = e.Name() // ReadDir is sorted; last version-named dir wins
		}
	}
	if newest == "" {
		return ""
	}
	return filepath.Join(base, newest)
}

// storageDirs returns the extension's persisted-storage directories (LevelDB).
func storageDirs(profileDir, id string) []string {
	var dirs []string
	les := filepath.Join(profileDir, "Local Extension Settings", id)
	if _, err := os.Stat(les); err == nil {
		dirs = append(dirs, les)
	}
	if matches, _ := filepath.Glob(filepath.Join(profileDir, "IndexedDB", "chrome-extension_"+id+"_*")); len(matches) > 0 {
		dirs = append(dirs, matches...)
	}
	return dirs
}

var (
	wsHostRe = regexp.MustCompile(`\bwss?://([a-zA-Z0-9._-]+)(?::\d+)?`)
	ipURLRe  = regexp.MustCompile(`\bhttps?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?`)
)

// hostAllowlist: first-party infra where a hardcoded ws host is unremarkable.
var hostAllowlist = []string{
	"google.com", "gstatic.com", "googleapis.com", "firebaseio.com", "gvt1.com",
	"github.com", "githubusercontent.com", "cloudflare.com", "cloudflareinsights.com",
	"jsdelivr.net", "mozilla.org", "sentry.io",
}

// grepHosts byte-scans the given dirs (source + LevelDB storage — no LevelDB
// parser; string values sit in plaintext in the SST/log) for hardcoded remote
// hosts worth a look: websocket URLs (rare in benign code) and HTTP endpoints to
// a public IP literal. First-party infra and private/loopback IPs are filtered
// out. Bounded so it stays cheap.
func grepHosts(dirs []string) []string {
	const maxFile = 2 << 20   // 2 MB per file
	const maxTotal = 12 << 20 // 12 MB overall
	seen := map[string]bool{}
	var total int64
	for _, root := range dirs {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if skipExt(p) {
				return nil
			}
			if total >= maxTotal {
				return filepath.SkipAll
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > maxFile {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			total += int64(len(b))
			scanHosts(b, seen)
			return nil
		})
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func scanHosts(b []byte, seen map[string]bool) {
	for _, m := range wsHostRe.FindAllSubmatch(b, -1) {
		if host := string(m[1]); suspiciousHost(host) {
			seen[host] = true
		}
	}
	for _, m := range ipURLRe.FindAllSubmatch(b, -1) {
		if ip := net.ParseIP(string(m[1])); isPublicIP(ip) {
			seen[string(m[1])] = true
		}
	}
}

// suspiciousHost reports whether a ws/wss host is worth flagging: a public IP, or
// a domain not on the first-party allowlist. localhost/private IPs are ignored.
func suspiciousHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isPublicIP(ip)
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	for _, a := range hostAllowlist {
		if h == a || strings.HasSuffix(h, "."+a) {
			return false
		}
	}
	return true
}

// isPublicIP reports whether ip is a routable public address (mirrors the
// allow-internal / block-nothing-private philosophy of recon/dialguard.go, but
// inverted: here we only care about *public* egress targets).
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func skipExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".wasm",
		".mp3", ".mp4", ".webm", ".zip", ".gz":
		return true
	}
	return false
}
