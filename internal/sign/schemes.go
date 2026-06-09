package sign

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// AzureSharedKey computes the Authorization header value for the Azure Storage
// Shared Key scheme: "SharedKey {account}:{base64(HMAC-SHA256(key, StringToSign))}".
// stringToSign must already be assembled per the storage REST contract.
func AzureSharedKey(account string, accountKeyB64 string, stringToSign string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(accountKeyB64)
	if err != nil {
		return "", fmt.Errorf("sign: bad account key: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("SharedKey %s:%s", account, sig), nil
}

// HMACSHA256Hex returns hex(HMAC-SHA256(key, msg)), used by exchange-style APIs
// (e.g. Coinbase legacy signing).
func HMACSHA256Hex(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACSHA1Hex returns hex(HMAC-SHA1(key, msg)), used by the Duo Admin API's
// canonical-request signing scheme.
func HMACSHA1Hex(key, msg []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// DigestChallenge holds the fields parsed from a WWW-Authenticate: Digest header.
type DigestChallenge struct {
	Realm, Nonce, QOP, Opaque, Algorithm string
}

// DigestAuthHeader builds an RFC 2617 Digest Authorization header value
// (MD5, qop=auth) for MongoDB Atlas-style HTTP Digest auth. nc/cnonce make the
// response unique per request.
func DigestAuthHeader(user, pass, method, uri string, ch DigestChallenge, nc, cnonce string) string {
	h := func(s string) string { sum := md5.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }
	ha1 := h(user + ":" + ch.Realm + ":" + pass)
	ha2 := h(method + ":" + uri)
	qop := ch.QOP
	if strings.Contains(qop, "auth") {
		qop = "auth"
	}
	resp := h(strings.Join([]string{ha1, ch.Nonce, nc, cnonce, qop, ha2}, ":"))
	parts := []string{
		fmt.Sprintf("username=%q", user),
		fmt.Sprintf("realm=%q", ch.Realm),
		fmt.Sprintf("nonce=%q", ch.Nonce),
		fmt.Sprintf("uri=%q", uri),
		fmt.Sprintf("response=%q", resp),
		fmt.Sprintf("qop=%s", qop),
		fmt.Sprintf("nc=%s", nc),
		fmt.Sprintf("cnonce=%q", cnonce),
	}
	if ch.Opaque != "" {
		parts = append(parts, fmt.Sprintf("opaque=%q", ch.Opaque))
	}
	if ch.Algorithm != "" {
		parts = append(parts, fmt.Sprintf("algorithm=%s", ch.Algorithm))
	}
	return "Digest " + strings.Join(parts, ", ")
}

// ParseDigestChallenge extracts fields from a WWW-Authenticate Digest header.
func ParseDigestChallenge(header string) DigestChallenge {
	header = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(header), "Digest"))
	ch := DigestChallenge{}
	for _, kv := range splitParams(header) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.TrimSpace(k) {
		case "realm":
			ch.Realm = v
		case "nonce":
			ch.Nonce = v
		case "qop":
			ch.QOP = v
		case "opaque":
			ch.Opaque = v
		case "algorithm":
			ch.Algorithm = v
		}
	}
	return ch
}

func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// CanonicalizeHeaders is a small helper for signing schemes that need sorted
// canonical header strings (e.g. x-ms-* for Azure).
func CanonicalizeHeaders(prefix string, headers map[string]string) string {
	var keys []string
	for k := range headers {
		if strings.HasPrefix(strings.ToLower(k), prefix) {
			keys = append(keys, strings.ToLower(k))
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(strings.TrimSpace(headers[k]))
		b.WriteString("\n")
	}
	return b.String()
}
