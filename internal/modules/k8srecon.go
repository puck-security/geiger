package modules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// k8sRecon performs read-only recon against a Kubernetes API server using a
// bearer token from a kubeconfig. It runs through a recon.Client so the
// read-only enforcement (GET + the one allowlisted SelfSubjectRulesReview POST)
// and secret scrubbing apply. The cluster CA, if present, is trusted; otherwise
// the system roots are used (we never disable verification).
func k8sRecon(ctx context.Context, live, intrusive bool, server, token, caData string) ([]module.Finding, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caData != "" {
		if pem, err := base64.StdEncoding.DecodeString(caData); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tlsConf.RootCAs = pool
			}
		}
	}
	hc := &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf, DialContext: recon.GuardedDial},
	}
	c := recon.New(hc, live)
	c.SetIntrusive(intrusive)
	c.RegisterSecret(token)
	server = strings.TrimRight(server, "/")

	var out []module.Finding

	// version (cheap identity)
	if v := k8sGetField(ctx, c, server+"/version", token, "gitVersion"); v != "" {
		out = append(out, module.Finding{Key: "kubernetes", Value: v, Flag: module.FlagInfo})
	}

	// namespace inventory
	if n, ok := k8sCount(ctx, c, server+"/api/v1/namespaces", token); ok {
		out = append(out, module.Finding{Key: "namespaces", Value: itoaInt(n), Flag: module.FlagInfo})
	}

	// RBAC reach via SelfSubjectRulesReview (the standard read-only POST)
	if admin, summary, ok := k8sRBAC(ctx, c, server, token); ok {
		flag := module.FlagInfo
		if admin {
			flag = module.FlagForceMultiplier
		}
		out = append(out, module.Finding{Key: "rbac reach", Value: summary, Flag: flag})
	}
	return out, nil
}

func k8sGetField(ctx context.Context, c *recon.Client, url, token, field string) string {
	req, _ := recon.NewRequest(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return ""
	}
	return jsonField(resp.Body, field)
}

func k8sCount(ctx context.Context, c *recon.Client, url, token string) (int, bool) {
	req, _ := recon.NewRequest(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req, recon.CallOpts{})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return 0, false
	}
	d := jsonDecode(resp.Body)
	if items, ok := d["items"].([]any); ok {
		return len(items), true
	}
	return 0, false
}

// k8sRBAC issues a SelfSubjectRulesReview for the default namespace and reports
// whether the principal holds wildcard (cluster-admin-class) permissions.
func k8sRBAC(ctx context.Context, c *recon.Client, server, token string) (admin bool, summary string, ok bool) {
	body := []byte(`{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}`)
	url := server + "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
	req, _ := recon.NewRequest(ctx, http.MethodPost, url, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "SelfSubjectRulesReview (read-only introspection)"})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return false, "", false
	}
	d := jsonDecode(resp.Body)
	status, _ := d["status"].(map[string]any)
	if status == nil {
		return false, "", false
	}
	rules, _ := status["resourceRules"].([]any)
	wildcard := false
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		if hasWildcard(rm["verbs"]) && hasWildcard(rm["resources"]) {
			wildcard = true
			break
		}
	}
	if wildcard {
		return true, "wildcard (*) on resources — cluster-admin class", true
	}
	return false, "scoped permissions (" + itoaInt(len(rules)) + " resource rules)", true
}

func hasWildcard(v any) bool {
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
