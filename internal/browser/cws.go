package browser

import (
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/puck-security/geiger/internal/recon"
)

// extID is a 32-char a–p Chrome extension id.
var extID = regexp.MustCompile(`^[a-p]{32}$`)

// webStoreClient builds the HTTP client for the Web Store liveness check. Egress
// routes through --proxy when set (red-team OPSEC — no direct connection to
// Google) and uses recon.GuardedDial so the check can't be redirected at a
// metadata/loopback target, matching the rest of geiger's recon.
func webStoreClient(proxy string) *http.Client {
	tr := &http.Transport{DialContext: recon.GuardedDial}
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 6 * time.Second, Transport: tr}
}

// webStoreStatus reports whether an extension is still listed in the public
// Chrome Web Store. A store-claimed extension that now 404s was removed
// (policy/malware takedown) — or unlisted/private — either way worth a look. A
// network error returns "listed" so we never penalize on a failed check. Only
// called under --live.
func webStoreStatus(id string, client *http.Client) (listed bool, note string) {
	if !extID.MatchString(id) {
		return true, "" // not a store id (e.g. an unpacked path-derived id)
	}
	if client == nil {
		client = webStoreClient("")
	}
	req, err := http.NewRequest(http.MethodGet, "https://chromewebstore.google.com/detail/"+id, nil)
	if err != nil {
		return true, ""
	}
	req.Header.Set("User-Agent", recon.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return true, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, ""
	}
	return false, "not found in the public Chrome Web Store (removed for policy/malware, or unlisted/private)"
}
