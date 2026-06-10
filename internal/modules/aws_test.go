package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recon"
)

func TestAWSRecognizeFromINI(t *testing.T) {
	raw := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	b := parse.Parse(raw, "credentials")
	matches := recognizeAWS(b, "", nil)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Fields["access_key"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("access_key = %q", matches[0].Fields["access_key"])
	}
}

func TestAWSReconProdAndSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		body := readAll(r)
		switch {
		case strings.Contains(body, "GetCallerIdentity"):
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::1234567890:user/ci-deploy</Arn><Account>1234567890</Account><UserId>AID</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		case strings.Contains(body, "ListAccountAliases"):
			_, _ = w.Write([]byte(`<ListAccountAliasesResponse><ListAccountAliasesResult><AccountAliases><member>acme-production</member></AccountAliases></ListAccountAliasesResult></ListAccountAliasesResponse>`))
		case strings.Contains(target, "ListSecrets"):
			_, _ = w.Write([]byte(`{"SecretList":[{"Name":"a"},{"Name":"b"},{"Name":"c"}]}`))
		default: // S3 ListBuckets (GET)
			_, _ = w.Write([]byte(`<ListAllMyBucketsResult><Buckets><Bucket><Name>acme-prod-customer-backups</Name></Bucket><Bucket><Name>logs</Name></Bucket></Buckets></ListAllMyBucketsResult>`))
		}
	}))
	defer srv.Close()

	// point all AWS endpoints at the test server
	orig := awsEndpoints
	awsEndpoints.STS = srv.URL + "/"
	awsEndpoints.IAM = srv.URL + "/"
	awsEndpoints.S3 = srv.URL + "/"
	awsEndpoints.Secrets = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fs, err := awsKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{
		"access_key": "AKIAIOSFODNN7EXAMPLE",
		"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if !strings.Contains(got["identity"].Value, "IAM user") {
		t.Errorf("identity = %q", got["identity"].Value)
	}
	if got["alias"].Flag != module.FlagWarn {
		t.Errorf("prod alias should warn, got %v", got["alias"].Flag)
	}
	if got["buckets"].Flag != module.FlagWarn || !strings.Contains(got["buckets"].Value, "customer-backups") {
		t.Errorf("buckets = %+v", got["buckets"])
	}
	if got["secrets"].Flag != module.FlagForceMultiplier {
		t.Errorf("secrets should be force multiplier, got %v", got["secrets"].Flag)
	}
}

func TestAWSReconLimitedKeyStatesNegativeSpace(t *testing.T) {
	// Valid key, but every reach probe is denied. The result must say so explicitly
	// rather than render as a bare identity that reads as "narrow and safe".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(readAll(r), "GetCallerIdentity") {
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::939645541139:user/apigateway-prox</Arn><Account>939645541139</Account><UserId>AID</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`))
			return
		}
		w.WriteHeader(http.StatusForbidden) // alias / buckets / secrets / privesc all denied
	}))
	defer srv.Close()

	orig := awsEndpoints
	awsEndpoints.STS = srv.URL + "/"
	awsEndpoints.IAM = srv.URL + "/"
	awsEndpoints.S3 = srv.URL + "/"
	awsEndpoints.Secrets = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fs, err := awsKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{
		"access_key": "AKIAIOSFODNN7EXAMPLE",
		"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["identity"].Value == "" {
		t.Fatal("identity should be confirmed")
	}
	reach, ok := got["reach"]
	if !ok || !strings.Contains(reach.Value, "identity only") {
		t.Errorf("a valid-but-scopeless key must state the negative space, got %+v", fs)
	}
}

func readAll(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return string(buf[:n])
}
