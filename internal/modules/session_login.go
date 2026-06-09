package modules

import (
	"context"
	"fmt"
	"net/http"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// sessionLogin performs a single read-only credentials→token POST (the only
// auth POST these session-based services make) and returns the token as a
// Bearer. The token is read from a dotted JSON path in the response body, or —
// when respHeader is non-empty — from a response header (SaltStack's
// X-Auth-Token, Veeam Enterprise Manager's X-RestSvcSessionId). It backs the
// backup/monitoring/config-mgmt modules that exchange a username+password for a
// session token (Cohesity, NetBackup, Commvault, Jamf, Puppet, SaltStack,
// Splunk, Zabbix). Wire it via recipe Authenticate + Auth.Kind PreAuthed (set
// HeaderName/ValuePrefix when the token rides a non-Authorization header).
func sessionLogin(ctx context.Context, c *recon.Client, loginURL string, body []byte, contentType, tokenPath, respHeader string) (module.Token, error) {
	req, err := recon.NewRequest(ctx, http.MethodPost, loginURL, body)
	if err != nil {
		return module.Token{}, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "session login (read-only token exchange)"})
	if err != nil {
		return module.Token{}, err
	}
	if resp.DryRun {
		return module.Token{Bearer: "<dry-run-token>"}, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return module.Token{}, errStatus(resp.Status)
	}
	if respHeader != "" {
		if v := resp.Header.Get(respHeader); v != "" {
			return module.Token{Bearer: v}, nil
		}
		return module.Token{}, fmt.Errorf("session login: no %s response header", respHeader)
	}
	if tok := jsonPath(resp.Body, tokenPath); tok != "" {
		return module.Token{Bearer: tok}, nil
	}
	return module.Token{}, fmt.Errorf("session login: no token at %q", tokenPath)
}
