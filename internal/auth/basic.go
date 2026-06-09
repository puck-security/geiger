package auth

import "encoding/base64"

func basicEncode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
