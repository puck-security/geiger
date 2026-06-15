package imds

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
)

// k8sTokenPath / k8sCAPath are overridable in tests. The in-cluster SA token and
// CA are mounted by the kubelet; the apiserver address comes from env.
var (
	k8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// fetchK8s reads the projected in-cluster service-account token (local files + env,
// no HTTP) and produces an apiserver + bearer + CA bundle for the kubeconfig module.
func fetchK8s(_ context.Context, _ *http.Client) []Cred {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return nil
	}
	tokB, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return nil
	}
	token := strings.TrimSpace(string(tokB))
	if token == "" {
		return nil
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	blob := "KUBERNETES_SERVER=https://" + net.JoinHostPort(host, port) + "\nKUBERNETES_SA_TOKEN=" + token + "\n"
	if caB, err := os.ReadFile(k8sCAPath); err == nil && len(caB) > 0 {
		blob += "KUBERNETES_CA_DATA=" + base64.StdEncoding.EncodeToString(caB) + "\n"
	}
	return []Cred{{Cloud: "kubernetes", Label: "metadata: kubernetes in-cluster SA", Blob: blob, Secret: token}}
}
