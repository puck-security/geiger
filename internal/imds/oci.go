package imds

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
)

// ociBase is overridable in tests.
var ociBase = "http://169.254.169.254"

// fetchOCI reads the instance-principal leaf certificate and extracts the instance
// OCID (the cert subject) offline. The cert+key can federate to an OCI security
// token; geiger flags the principal and its identity (full federation is a
// follow-on). OCI's IMDSv2 requires the "Authorization: Bearer Oracle" header.
func fetchOCI(ctx context.Context, hc *http.Client) []Cred {
	certPEM, ok := get(ctx, hc, ociBase+"/opc/v2/identity/cert.pem", ociHdr)
	if !ok {
		return nil
	}
	subject := ociCertSubject(certPEM)
	if !strings.HasPrefix(subject, "ocid1.") {
		return nil
	}
	return []Cred{{
		Cloud:  "oci",
		Label:  "metadata: oci instance principal",
		Blob:   "OCI_INSTANCE_PRINCIPAL=" + subject + "\n",
		Secret: subject,
	}}
}

func ociHdr(req *http.Request) { req.Header.Set("Authorization", "Bearer Oracle") }

func ociCertSubject(certPEM []byte) string {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}
