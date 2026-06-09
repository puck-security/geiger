// Package auth implements the four headless OAuth grants Geiger supports. Each
// is exactly one POST to a module-declared token endpoint — the only auth POST
// Geiger makes by design — returning a bearer (and sometimes an instance URL).
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// tokenResponse is the common OAuth token endpoint shape.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
	InstanceURL string `json:"instance_url"` // Salesforce
	IDToken     string `json:"id_token"`
}

func postForm(ctx context.Context, c *recon.Client, tokenURL string, form url.Values, hdrs map[string]string) (module.Token, error) {
	req, err := recon.NewRequest(ctx, http.MethodPost, tokenURL, []byte(form.Encode()))
	if err != nil {
		return module.Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "auth token exchange"})
	if err != nil {
		return module.Token{}, err
	}
	if resp.DryRun {
		return module.Token{Bearer: "<dry-run-token>"}, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return module.Token{}, fmt.Errorf("auth: token endpoint returned %d: %s", resp.Status, strings.TrimSpace(string(resp.Body)))
	}
	var tr tokenResponse
	if err := json.Unmarshal(resp.Body, &tr); err != nil {
		return module.Token{}, fmt.Errorf("auth: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return module.Token{}, fmt.Errorf("auth: no access_token in response")
	}
	return module.Token{
		Bearer:      tr.AccessToken,
		InstanceURL: tr.InstanceURL,
		Extra: map[string]string{
			"scope":      tr.Scope,
			"token_type": tr.TokenType,
		},
	}, nil
}

// Exchange performs an arbitrary single token-endpoint POST (form body + extra
// headers, e.g. Basic client auth) and returns the resulting bearer. It backs
// the non-standard grants (Zoom account_credentials, …).
func Exchange(ctx context.Context, c *recon.Client, tokenURL string, form url.Values, hdrs map[string]string) (module.Token, error) {
	return postForm(ctx, c, tokenURL, form, hdrs)
}

// ClientCredentials performs the client_credentials grant (Entra, Auth0,
// Okta-OAuth, Atlas SA, …). Pass scope/audience/resource as needed via extra.
func ClientCredentials(ctx context.Context, c *recon.Client, tokenURL, clientID, clientSecret string, extra url.Values) (module.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	return postForm(ctx, c, tokenURL, form, nil)
}

// RefreshToken performs the refresh_token grant (GCP user creds, GitHub App
// refresh, Salesforce, …).
func RefreshToken(ctx context.Context, c *recon.Client, tokenURL, clientID, clientSecret, refreshToken string, extra url.Values) (module.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	return postForm(ctx, c, tokenURL, form, nil)
}

// JWTBearer performs the urn:ietf:params:oauth:grant-type:jwt-bearer grant
// (GCP service accounts, Salesforce JWT, Snowflake key-pair). assertion is the
// pre-signed RS256 JWT.
func JWTBearer(ctx context.Context, c *recon.Client, tokenURL, assertion string, extra url.Values) (module.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	return postForm(ctx, c, tokenURL, form, nil)
}

// Password performs the password grant (legacy ROPC, e.g. some Salesforce/Okta
// integrations). Included for completeness of the headless grant set.
func Password(ctx context.Context, c *recon.Client, tokenURL, clientID, clientSecret, username, password string, extra url.Values) (module.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	return postForm(ctx, c, tokenURL, form, nil)
}

// BasicAuthExtra returns a header map adding HTTP Basic auth, for token
// endpoints that require client auth in the header rather than the body
// (e.g. MongoDB Atlas SA, some OAuth servers).
func BasicAuthExtra(clientID, clientSecret string) map[string]string {
	cred := clientID + ":" + clientSecret
	return map[string]string{"Authorization": "Basic " + basicEncode(cred)}
}
