package imds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gmodule "github.com/puck-security/geiger/internal/module"
	_ "github.com/puck-security/geiger/internal/modules" // register the catalog for the recognition check
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
)

// recognizesAs reports whether a harvested cred's synthetic blob is recognized as
// the given module by the real pipeline — the end-to-end guarantee.
func recognizesAs(t *testing.T, c Cred, module string) bool {
	t.Helper()
	for _, m := range recognize.Recognize(parse.Parse(c.Blob, c.Label), "", gmodule.Default) {
		if m.Module == module {
			return true
		}
	}
	return false
}

func awsIMDSServer(t *testing.T, v2 bool) (gotToken *string, srv *httptest.Server) {
	tok := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if !v2 {
			w.WriteHeader(http.StatusForbidden) // IMDSv2 disabled → caller falls back to v1
			return
		}
		if r.Method != http.MethodPut {
			t.Errorf("IMDSv2 token must be minted with PUT, got %s", r.Method)
		}
		_, _ = w.Write([]byte("TOKEN123"))
	})
	mux.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		tok = r.Header.Get("X-aws-ec2-metadata-token")
		if r.URL.Path == "/latest/meta-data/iam/security-credentials/" {
			_, _ = w.Write([]byte("ec2-app-role\n"))
			return
		}
		_, _ = w.Write([]byte(`{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"secretkey","Token":"sessiontoken"}`))
	})
	srv = httptest.NewServer(mux)
	orig := awsIMDSBase
	awsIMDSBase = srv.URL
	t.Cleanup(func() { awsIMDSBase = orig })
	return &tok, srv
}

func TestFetchAWSIMDSv2(t *testing.T) {
	gotToken, srv := awsIMDSServer(t, true)
	defer srv.Close()

	creds := fetchAWS(context.Background(), srv.Client())
	if len(creds) != 1 {
		t.Fatalf("want 1 cred, got %d", len(creds))
	}
	c := creds[0]
	if *gotToken != "TOKEN123" {
		t.Errorf("IMDSv2 token not carried on the metadata GET: %q", *gotToken)
	}
	if !strings.Contains(c.Label, "ec2-app-role") || c.Secret != "ASIAEXAMPLE" {
		t.Errorf("cred = %+v", c)
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID=ASIAEXAMPLE", "AWS_SECRET_ACCESS_KEY=secretkey", "AWS_SESSION_TOKEN=sessiontoken"} {
		if !strings.Contains(c.Blob, want) {
			t.Errorf("blob missing %q:\n%s", want, c.Blob)
		}
	}
	if !recognizesAs(t, c, "aws") {
		t.Error("harvested AWS blob did not recognize as the aws module")
	}
}

func TestFetchAWSIMDSv1Fallback(t *testing.T) {
	_, srv := awsIMDSServer(t, false) // PUT /token → 403
	defer srv.Close()
	creds := fetchAWS(context.Background(), srv.Client())
	if len(creds) != 1 || creds[0].Secret != "ASIAEXAMPLE" {
		t.Fatalf("IMDSv1 fallback failed: %+v", creds)
	}
}

func TestFetchAWSContainerCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer-xyz" {
			t.Errorf("container auth token not sent: %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"AccessKeyId":"ASIACONTAINER","SecretAccessKey":"sk","Token":"tok"}`))
	}))
	defer srv.Close()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", srv.URL+"/creds")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "bearer-xyz")

	creds := fetchAWS(context.Background(), srv.Client())
	if len(creds) != 1 || creds[0].Secret != "ASIACONTAINER" {
		t.Fatalf("container creds not harvested: %+v", creds)
	}
	if !strings.Contains(creds[0].Label, "container") {
		t.Errorf("label = %q", creds[0].Label)
	}
}
