package sign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func genKeyPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return p, k
}

func TestRS256AssertionRoundTrip(t *testing.T) {
	pemBytes, key := genKeyPEM(t)
	tok, err := RS256Assertion(pemBytes, "kid-1", map[string]any{
		"iss":   "sa@proj.iam.gserviceaccount.com",
		"scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
		"aud":   "https://oauth2.googleapis.com/token",
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("assertion did not verify: %v", err)
	}
	if parsed.Header["kid"] != "kid-1" {
		t.Errorf("kid not set: %v", parsed.Header["kid"])
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("iss wrong: %v", claims["iss"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("exp not set")
	}
}

func TestAzureSharedKey(t *testing.T) {
	// base64("0123456789012345678901234567890123456789012=") style key.
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got, err := AzureSharedKey("acct", key, "GET\n\n\n\nx-ms-date:Mon\nx-ms-version:2021-08-06\n/acct/?comp=list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "SharedKey acct:") {
		t.Errorf("unexpected header: %q", got)
	}
}

func TestDigestRoundTrip(t *testing.T) {
	ch := ParseDigestChallenge(`Digest realm="cloud.mongodb.com", nonce="abc123", qop="auth", algorithm=MD5`)
	if ch.Realm != "cloud.mongodb.com" || ch.Nonce != "abc123" || ch.QOP != "auth" {
		t.Fatalf("parse failed: %+v", ch)
	}
	hdr := DigestAuthHeader("pub", "priv", "GET", "/api/atlas/v2/groups", ch, "00000001", "deadbeef")
	if !strings.HasPrefix(hdr, "Digest ") || !strings.Contains(hdr, `response=`) {
		t.Errorf("bad digest header: %q", hdr)
	}
}
