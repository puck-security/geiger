package modules

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Filestack is a file upload/transform/delivery API. Two very different secrets:
//   - api key: a ~20-char base62 value with no prefix. Marketed as a public
//     client id, but on a Security-DISABLED app (the default) it alone allows
//     uploading files, running transforms, and fetching+processing remote URLs
//     (an SSRF primitive) — all billed to and served from the victim's account
//     on cdn.filestackcontent.com (malware/phishing hosting under their brand).
//   - app secret: signs security policies (HMAC-SHA256). Whoever holds it can
//     mint a policy granting read/write/remove/convert on ANY handle → full
//     account file control. This is the crown jewel.
//
// The api key has no distinctive shape, so recognition anchors on the
// "filestack" keyword (a var/config/SDK reference) or a filestackcontent.com URL
// rather than the too-generic 20-char base62 body.

const filestackHost = "https://www.filestackapi.com"

// a plausible-but-nonexistent handle: probes validate the credential without any
// side effect (no upload; the read just 404s).
const filestackSentinel = "geigerProbe0000000000"

var (
	// filestack … api_key/apikey/app_key/key = <value>
	fsApikeyRe = regexp.MustCompile("(?i)filestack[\\w.\\- ]{0,20}?(?:api[_-]?key|apikey|app[_-]?key|key)[\"'`:=\\s]{1,4}([A-Za-z0-9]{18,40})")
	// the SDK constructor's first arg is the api key: filestack.init("<key>"),
	// filestack("<key>"), new Filestack.Client("<key>").
	fsSDKRe = regexp.MustCompile("(?i)filestack(?:\\.[a-z]+)?\\s*\\(\\s*[\"'`]([A-Za-z0-9]{18,40})[\"'`]")
	// filestack … secret/app_secret = <value>
	fsSecretRe = regexp.MustCompile("(?i)filestack[\\w.\\- ]{0,20}?(?:app[_-]?secret|secret)[\"'`:=\\s]{1,4}([A-Za-z0-9]{20,80})")
	// the api key embedded in a CDN/API URL: cdn.filestackcontent.com/<apikey>
	fsURLRe = regexp.MustCompile(`(?i)filestackcontent\.com/([A-Za-z0-9]{18,40})`)
)

func init() {
	module.Register(filestack{})
	recognize.RegisterRecognizer(recognizeFilestack)
}

func recognizeFilestack(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	apikey := firstSubmatch(fsApikeyRe, b.Raw)
	if apikey == "" {
		apikey = firstSubmatch(fsSDKRe, b.Raw)
	}
	if apikey == "" {
		apikey = firstSubmatch(fsURLRe, b.Raw)
	}
	if apikey == "" {
		apikey = firstVar(b.Vars, "FILESTACK_API_KEY", "FILESTACK_APIKEY", "FILESTACK_KEY")
	}
	if apikey == "" {
		return nil
	}
	fields := module.Fields{"apikey": apikey}
	if secret := firstSubmatch(fsSecretRe, b.Raw); secret != "" {
		fields["secret"] = secret
	} else if secret := firstVar(b.Vars, "FILESTACK_APP_SECRET", "FILESTACK_SECRET"); secret != "" {
		fields["secret"] = secret
	}
	return []recognize.Match{{Module: "filestack", Fields: fields, Secret: apikey, Label: "FILESTACK_API_KEY"}}
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

type filestack struct{ module.Base }

func (filestack) Name() string { return "filestack" }

func (m filestack) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	apikey, secret := f["apikey"], f["secret"]
	c.RegisterSecret(apikey)
	c.RegisterSecret(secret)
	var out []module.Finding

	// Capability is inherent to a live Filestack api key — state it regardless of
	// what the probe can introspect.
	out = append(out, module.Finding{Key: "capability",
		Value: "upload files, run transforms, and fetch+process remote URLs (SSRF vector) — billed to and served from cdn.filestackcontent.com under this account",
		Flag:  module.FlagWarn})

	// Probe validity + whether the app's Security feature is on. An unsigned
	// metadata read on a nonexistent handle: if the app accepts it (404, not a
	// policy demand) Security is off and the api key alone is dangerous.
	req, _ := recon.NewRequest(ctx, http.MethodGet, filestackHost+"/api/file/"+filestackSentinel+"/metadata?key="+apikey, nil)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil {
		return out, nil
	}
	if !resp.DryRun {
		body := strings.ToLower(string(resp.Body))
		switch {
		case resp.Status == http.StatusUnauthorized, badFilestackKey(resp.Status, body):
			// api key not recognized → nothing else is live.
			return nil, errStatus(resp.Status)
		case resp.Status == http.StatusForbidden || strings.Contains(body, "policy") || strings.Contains(body, "signature"):
			out = append(out, module.Finding{Key: "security", Value: "enabled — unsigned operations require the app secret (api key alone is limited)", Flag: module.FlagInfo})
		default:
			// the unsigned read was accepted → Security is off.
			out = append(out, module.Finding{Key: "security", Value: "DISABLED — the api key alone allows uploads, transforms, and remote-URL fetch (no signature needed)", Flag: module.FlagForceMultiplier})
		}
	}

	if secret != "" {
		out = append(out, m.probeSecret(ctx, c, secret)...)
	}
	return out, nil
}

// probeSecret signs a minimal, short-lived stat policy for a nonexistent handle
// and confirms the app secret is accepted (a valid signature verifies even
// though the handle 404s). Holding it means full file control.
func (filestack) probeSecret(ctx context.Context, c *recon.Client, secret string) []module.Finding {
	policy, _ := json.Marshal(map[string]any{
		"expiry": time.Now().Add(60 * time.Second).Unix(),
		"call":   []string{"stat"},
		"handle": filestackSentinel,
	})
	p := base64.RawURLEncoding.EncodeToString(policy)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(p))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, _ := recon.NewRequest(ctx, http.MethodGet, filestackHost+"/api/file/"+filestackSentinel+"/metadata?policy="+p+"&signature="+sig, nil)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun {
		return []module.Finding{{Key: "app secret", Value: "present — signs security policies (HMAC-SHA256): mint a policy for read/write/remove/convert on ANY handle → full account file control", Flag: module.FlagForceMultiplier}}
	}
	fin := module.Finding{Key: "app secret", Flag: module.FlagForceMultiplier}
	if resp.Status == http.StatusForbidden && strings.Contains(strings.ToLower(string(resp.Body)), "signature") {
		fin.Value = "present but the signed-policy probe was rejected — the secret may be stale or for another app"
		fin.Flag = module.FlagCantCharacterize
	} else {
		fin.Value = "confirmed — signs security policies (HMAC-SHA256): a minted policy grants read/write/remove/convert on ANY handle → full account file control"
	}
	return []module.Finding{fin}
}

func (filestack) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs, Summary: "Filestack API key — file upload/transform on this account"}
	for _, f := range fs {
		switch {
		case f.Key == "app secret" && f.Flag == module.FlagForceMultiplier:
			n.Summary = "Filestack app secret — full file control (read/write/delete any handle)"
		case f.Key == "security" && strings.HasPrefix(f.Value, "DISABLED"):
			n.Summary = "Filestack API key — Security disabled: upload/transform/SSRF on this account"
		}
	}
	return n
}

// badFilestackKey spots an "unknown application/api key" error even when the
// status isn't a clean 401.
func badFilestackKey(status int, lowerBody string) bool {
	if status < 400 {
		return false
	}
	return strings.Contains(lowerBody, "invalid") && (strings.Contains(lowerBody, "apikey") || strings.Contains(lowerBody, "api key") || strings.Contains(lowerBody, "application"))
}
