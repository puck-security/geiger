package browser

import (
	"net/http"
	"regexp"
	"time"
)

// extID is a 32-char a–p Chrome extension id.
var extID = regexp.MustCompile(`^[a-p]{32}$`)

// webStoreStatus reports whether an extension is still listed in the public
// Chrome Web Store. A store-claimed extension that now 404s was removed
// (policy/malware takedown) — or unlisted/private — either way worth a look. A
// network error returns "listed" so we never penalize on a failed check. Only
// called under --live. Note: does not route through --proxy (a follow-on).
func webStoreStatus(id string) (listed bool, note string) {
	if !extID.MatchString(id) {
		return true, "" // not a store id (e.g. an unpacked path-derived id)
	}
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://chromewebstore.google.com/detail/"+id, nil)
	if err != nil {
		return true, ""
	}
	req.Header.Set("User-Agent", "geiger")
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
