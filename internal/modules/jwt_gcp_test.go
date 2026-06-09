package modules

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recon"
)

func makeJWT(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pb, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(pb)
	return hdr + "." + payload + ".sig"
}

func TestJWTDecodeOfflineExpired(t *testing.T) {
	tok := makeJWT(map[string]any{
		"iss":   "https://login.microsoftonline.com/abc/v2.0",
		"sub":   "user-1",
		"aud":   "api://app",
		"scope": "Directory.Read.All",
		"exp":   float64(time.Now().Add(-time.Hour).Unix()),
	})
	fs, err := genericJWT{}.Recon(context.Background(), recon.New(nil, false), module.Token{}, module.Fields{"token": tok})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if !strings.Contains(got["issuer"].Value, "Entra") {
		t.Errorf("issuer hint missing: %q", got["issuer"].Value)
	}
	if !strings.Contains(got["expires"].Value, "EXPIRED") {
		t.Errorf("should be expired: %q", got["expires"].Value)
	}
}

func saKeyJSON(t *testing.T) string {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(k)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
	obj := map[string]any{
		"type":           "service_account",
		"project_id":     "acme-production",
		"private_key_id": "kid123",
		"private_key":    pemStr,
		"client_email":   "ci@acme-production.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	b, _ := json.Marshal(obj)
	return string(b)
}

func TestGCPServiceAccountRecognizeAndAuth(t *testing.T) {
	raw := saKeyJSON(t)
	b := parse.Parse(raw, "key.json")
	matches := recognizeGCPSA(b, "", nil)
	if len(matches) != 1 || matches[0].Fields["client_email"] == "" {
		t.Fatalf("recognize failed: %+v", matches)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"GCPTOKEN","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer GCPTOKEN" {
			t.Errorf("recon not using exchanged token: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"projects":[{"projectId":"a"},{"projectId":"b"}]}`))
	})
	mux.HandleFunc("/buckets", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"name":"acme-pii-exports"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	orig := gcpEndpoints
	gcpEndpoints.Token = srv.URL + "/token"
	gcpEndpoints.ResourceManager = srv.URL + "/projects"
	gcpEndpoints.Storage = srv.URL + "/buckets"
	defer func() { gcpEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	m := gcpServiceAccount{}
	tok, err := m.Authenticate(context.Background(), c, matches[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Bearer != "GCPTOKEN" {
		t.Fatalf("token = %q", tok.Bearer)
	}
	fs, err := m.Recon(context.Background(), c, tok, matches[0].Fields)
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["reachable projects"].Value != "2" {
		t.Errorf("projects = %q", got["reachable projects"].Value)
	}
	if got["project"].Flag != module.FlagWarn {
		t.Errorf("prod project should warn")
	}
	if !strings.Contains(got["buckets"].Value, "pii") {
		t.Errorf("buckets = %q", got["buckets"].Value)
	}
}
