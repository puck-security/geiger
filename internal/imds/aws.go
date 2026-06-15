package imds

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// awsIMDSBase / awsECSBase are overridable in tests.
var (
	awsIMDSBase = "http://169.254.169.254"
	awsECSBase  = "http://169.254.170.2"
)

// fetchAWS pulls instance-role credentials: ECS/EKS container creds first (env
// -pointed, cheapest), then EC2 IMDS (v2 token dance, v1 fallback).
func fetchAWS(ctx context.Context, hc *http.Client) []Cred {
	if c := fetchAWSContainer(ctx, hc); c != nil {
		return []Cred{*c}
	}
	if c := fetchAWSInstance(ctx, hc); c != nil {
		return []Cred{*c}
	}
	return nil
}

// fetchAWSContainer reads ECS/EKS task-role creds from the container credentials
// endpoint named by AWS_CONTAINER_CREDENTIALS_{RELATIVE,FULL}_URI.
func fetchAWSContainer(ctx context.Context, hc *http.Client) *Cred {
	var uri string
	switch {
	case os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "":
		uri = awsECSBase + os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	case os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "":
		uri = os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	default:
		return nil
	}
	auth := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	if auth == "" {
		if f := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				auth = strings.TrimSpace(string(b))
			}
		}
	}
	body, ok := get(ctx, hc, uri, func(req *http.Request) {
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
	})
	if !ok {
		return nil
	}
	return awsCredFromJSON(body, "metadata: aws ecs/eks container credentials")
}

// fetchAWSInstance does the EC2 IMDS flow: mint an IMDSv2 session token (PUT — works
// because this is a plain client, not the read-only recon client), then read the
// role name and its credentials. Falls back to IMDSv1 (no token) if the PUT fails.
func fetchAWSInstance(ctx context.Context, hc *http.Client) *Cred {
	token := imdsv2Token(ctx, hc)
	hdr := func(req *http.Request) {
		if token != "" {
			req.Header.Set("X-aws-ec2-metadata-token", token)
		}
	}
	roleBody, ok := get(ctx, hc, awsIMDSBase+"/latest/meta-data/iam/security-credentials/", hdr)
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
	credBody, ok := get(ctx, hc, awsIMDSBase+"/latest/meta-data/iam/security-credentials/"+role, hdr)
	if !ok {
		return nil
	}
	return awsCredFromJSON(credBody, "metadata: aws instance role "+role)
}

// imdsv2Token requests an IMDSv2 session token (PUT). Returns "" if IMDSv2 is
// disabled, so the caller falls back to IMDSv1.
func imdsv2Token(ctx context.Context, hc *http.Client) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, awsIMDSBase+"/latest/api/token", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	b, ok := do(hc, req)
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// awsCredFromJSON turns an IMDS/ECS credential document into a synthetic dotenv
// blob the existing aws recognizer (recognizeAWS, env-name keyed) consumes.
func awsCredFromJSON(body []byte, label string) *Cred {
	var d struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if json.Unmarshal(body, &d) != nil || d.AccessKeyID == "" || d.SecretAccessKey == "" {
		return nil
	}
	blob := "AWS_ACCESS_KEY_ID=" + d.AccessKeyID + "\nAWS_SECRET_ACCESS_KEY=" + d.SecretAccessKey + "\n"
	if d.Token != "" {
		blob += "AWS_SESSION_TOKEN=" + d.Token + "\n"
	}
	return &Cred{Cloud: "aws", Label: label, Blob: blob, Secret: d.AccessKeyID}
}
