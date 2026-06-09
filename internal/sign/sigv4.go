package sign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// SigV4 signs an AWS request in place using the aws-sdk-go-v2 signer.
// session may be empty for long-term keys. body is the exact request body
// (nil for empty). It mutates req's headers to carry the signature.
func SigV4(ctx context.Context, req *http.Request, accessKey, secretKey, session, service, region string, body []byte) error {
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    session,
	}
	signer := v4.NewSigner()
	return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, time.Now())
}
