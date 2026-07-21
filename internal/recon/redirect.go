package recon

import (
	"fmt"
	"net/http"
	"strings"
)

// maxRedirects bounds a redirect chain. Matches Go's own default; stated here so
// the limit survives the custom CheckRedirect that replaces Go's.
const maxRedirects = 10

// safeRedirectHeaders are the headers that may cross a host boundary: content
// negotiation and geiger's honest self-identification. Everything else is
// dropped, because everything else may carry the credential.
//
// This is an allowlist, not a denylist of known credential headers. Modules
// attach secrets under many names (X-Vault-Token, api-key, SSWS, X-Auth-Token,
// session, Authtoken, X-Shopify-Access-Token, X-Authentication…), and a new
// module adding another one must not silently reopen the leak.
var safeRedirectHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Encoding": true,
	"Content-Type":    true,
	"User-Agent":      true,
}

// CheckRedirect is the redirect policy for every geiger HTTP client.
//
// Go's own policy drops Authorization and Cookie when the host changes but
// forwards custom headers, which is exactly where geiger carries most of its
// credentials. An endpoint read out of scanned data — or any endpoint that has
// been compromised — could therefore 302 a credential to an attacker-chosen
// host. Here a change of hostname strips every header outside the allowlist, so
// a redirect can move the request but never the secret.
//
// Only the hostname is compared: a redirect that upgrades http→https or changes
// port on the same host is routine and keeps its headers.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("recon: stopped after %d redirects", maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	if prev == nil || req.URL == nil {
		return nil
	}
	if strings.EqualFold(prev.Hostname(), req.URL.Hostname()) {
		return nil
	}
	for k := range req.Header {
		if !safeRedirectHeaders[http.CanonicalHeaderKey(k)] {
			req.Header.Del(k)
		}
	}
	return nil
}
