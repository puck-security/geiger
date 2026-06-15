package imds

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchK8sInCluster(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenFile, []byte("eyJhbGci.sa-token.sig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origT, origCA := k8sTokenPath, k8sCAPath
	k8sTokenPath, k8sCAPath = tokenFile, caFile
	defer func() { k8sTokenPath, k8sCAPath = origT, origCA }()
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	creds := fetchK8s(context.Background(), nil)
	if len(creds) != 1 {
		t.Fatalf("want 1 k8s cred, got %d", len(creds))
	}
	c := creds[0]
	if !strings.Contains(c.Blob, "KUBERNETES_SERVER=https://10.0.0.1:443") {
		t.Errorf("server wrong in blob: %q", c.Blob)
	}
	if c.Secret != "eyJhbGci.sa-token.sig" {
		t.Errorf("secret = %q", c.Secret)
	}
	if !strings.Contains(c.Blob, "KUBERNETES_CA_DATA=") {
		t.Errorf("CA data missing from blob: %q", c.Blob)
	}
	if !recognizesAs(t, c, "kubeconfig") {
		t.Error("harvested k8s in-cluster SA did not recognize as kubeconfig")
	}
}

func TestFetchK8sAbsentWhenNotInCluster(t *testing.T) {
	origT := k8sTokenPath
	k8sTokenPath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { k8sTokenPath = origT }()
	t.Setenv("KUBERNETES_SERVICE_HOST", "") // not in a cluster
	if creds := fetchK8s(context.Background(), nil); creds != nil {
		t.Errorf("expected no k8s creds off-cluster, got %+v", creds)
	}
}
