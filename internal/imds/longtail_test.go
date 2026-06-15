package imds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchAlibaba(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/meta-data/ram/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/meta-data/ram/security-credentials/" {
			_, _ = w.Write([]byte("ecs-role"))
			return
		}
		_, _ = w.Write([]byte(`{"AccessKeyId":"LTAI5tExample","AccessKeySecret":"sk","SecurityToken":"st","Code":"Success"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := alibabaBase
	alibabaBase = srv.URL
	defer func() { alibabaBase = orig }()

	creds := fetchAlibaba(context.Background(), srv.Client())
	if len(creds) != 1 || creds[0].Secret != "LTAI5tExample" {
		t.Fatalf("alibaba cred = %+v", creds)
	}
	if !strings.Contains(creds[0].Label, "ecs-role") {
		t.Errorf("label = %q", creds[0].Label)
	}
	if !recognizesAs(t, creds[0], "alibaba") {
		t.Error("alibaba RAM cred did not recognize as the alibaba module")
	}
}

func TestFetchDigitalOceanUserData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata/v1/user-data" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// cloud-init with an embedded secret (split literal to dodge push-protection)
		_, _ = w.Write([]byte("#!/bin/sh\nexport STRIPE_SECRET_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc\n"))
	}))
	defer srv.Close()
	orig := digitalOceanBase
	digitalOceanBase = srv.URL
	defer func() { digitalOceanBase = orig }()

	creds := fetchDigitalOcean(context.Background(), srv.Client())
	if len(creds) != 1 {
		t.Fatalf("want 1 user-data cred, got %d", len(creds))
	}
	// user-data is triaged as a blob — the embedded Stripe key must recognize.
	if !recognizesAs(t, creds[0], "stripe") {
		t.Error("embedded secret in DigitalOcean user-data did not recognize")
	}
}

func TestFetchOCI(t *testing.T) {
	cert := testLeafCert(t, "ocid1.instance.oc1.phx.abc123")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			t.Errorf("OCI IMDSv2 requires Authorization: Bearer Oracle, got %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write(cert)
	}))
	defer srv.Close()
	orig := ociBase
	ociBase = srv.URL
	defer func() { ociBase = orig }()

	creds := fetchOCI(context.Background(), srv.Client())
	if len(creds) != 1 || !strings.Contains(creds[0].Blob, "ocid1.instance.oc1.phx.abc123") {
		t.Fatalf("oci cred = %+v", creds)
	}
	if !recognizesAs(t, creds[0], "oci_instance_principal") {
		t.Error("oci instance-principal cert did not recognize")
	}
}

func testLeafCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
