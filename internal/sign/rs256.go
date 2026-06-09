// Package sign holds the request/assertion signing schemes Geiger modules need:
// RS256 JWT assertions (GCP, Salesforce, Snowflake), Azure SharedKey, HTTP
// Digest (MongoDB Atlas), and generic HMAC. AWS SigV4 lives in sigv4.go.
package sign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseRSAPrivateKey accepts PKCS#1 or PKCS#8 PEM.
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sign: no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sign: parse RSA key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("sign: PEM is not an RSA private key")
	}
	return rk, nil
}

// RS256Assertion builds a signed JWT for an OAuth jwt-bearer grant.
// kid may be empty. claims is the full claim set (iss, sub, aud, scope, …);
// iat/exp are set here if absent.
func RS256Assertion(pemBytes []byte, kid string, claims map[string]any, ttl time.Duration) (string, error) {
	key, err := ParseRSAPrivateKey(pemBytes)
	if err != nil {
		return "", err
	}
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	now := time.Now()
	if _, ok := mc["iat"]; !ok {
		mc["iat"] = now.Unix()
	}
	if _, ok := mc["exp"]; !ok {
		if ttl <= 0 {
			ttl = time.Hour
		}
		mc["exp"] = now.Add(ttl).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, mc)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	return tok.SignedString(key)
}
