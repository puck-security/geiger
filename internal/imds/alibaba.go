package imds

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// alibabaBase is overridable in tests.
var alibabaBase = "http://100.100.100.200"

// fetchAlibaba reads RAM-role STS credentials from Alibaba Cloud's metadata service.
func fetchAlibaba(ctx context.Context, hc *http.Client) []Cred {
	roleBody, ok := get(ctx, hc, alibabaBase+"/latest/meta-data/ram/security-credentials/", nil)
	if !ok {
		return nil
	}
	role := strings.TrimSpace(string(roleBody))
	if i := strings.IndexByte(role, '\n'); i >= 0 {
		role = strings.TrimSpace(role[:i])
	}
	if role == "" {
		return nil
	}
	credBody, ok := get(ctx, hc, alibabaBase+"/latest/meta-data/ram/security-credentials/"+role, nil)
	if !ok {
		return nil
	}
	var d struct {
		AccessKeyID     string `json:"AccessKeyId"`
		AccessKeySecret string `json:"AccessKeySecret"`
		SecurityToken   string `json:"SecurityToken"`
	}
	if json.Unmarshal(credBody, &d) != nil || d.AccessKeyID == "" {
		return nil
	}
	blob := "ALIBABA_ACCESS_KEY_ID=" + d.AccessKeyID + "\nALIBABA_ACCESS_KEY_SECRET=" + d.AccessKeySecret + "\n"
	if d.SecurityToken != "" {
		blob += "ALIBABA_SECURITY_TOKEN=" + d.SecurityToken + "\n"
	}
	return []Cred{{Cloud: "alibaba", Label: "metadata: alibaba ram role " + role, Blob: blob, Secret: d.AccessKeyID}}
}
