package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

func TestAWSSSORecognizesTokenCache(t *testing.T) {
	raw := `{"startUrl":"https://d-123.awsapps.com/start","region":"us-east-1","accessToken":"aoaAAAAAopaque","expiresAt":"2099-01-01T00:00:00Z"}`
	b := parse.Parse(raw, "639f.json")
	ms := recognizeAWSSSO(b, "", nil)
	if len(ms) != 1 || ms[0].Module != "aws_sso" || ms[0].Fields["access_token"] != "aoaAAAAAopaque" {
		t.Fatalf("token cache not recognized: %+v", ms)
	}
}

func TestAWSSSOEnumeratesAccountsAndAdmin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/assignment/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-amz-sso_bearer_token") != "TOK" {
			t.Errorf("missing bearer header: %q", r.Header.Get("x-amz-sso_bearer_token"))
		}
		_, _ = w.Write([]byte(`{"accountList":[{"accountId":"111","accountName":"acme-production"},{"accountId":"222","accountName":"sandbox"}]}`))
	})
	mux.HandleFunc("/assignment/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("account_id") == "111" {
			_, _ = w.Write([]byte(`{"roleList":[{"roleName":"AdministratorAccess"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"roleList":[{"roleName":"ReadOnly"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	awsSSOPortalBase = srv.URL
	defer func() { awsSSOPortalBase = "" }()

	c := recon.New(srv.Client(), true)
	fs, err := awsSSO{}.Recon(context.Background(), c, module.Token{}, module.Fields{
		"access_token": "TOK", "region": "us-east-1", "expires_at": "2099-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["accounts"].Value != "2 assumable" {
		t.Errorf("accounts = %q", got["accounts"].Value)
	}
	if got["prod accounts"].Flag != module.FlagWarn {
		t.Errorf("prod account not flagged: %+v", got["prod accounts"])
	}
	if got["admin"].Flag != module.FlagForceMultiplier || !strings.Contains(got["admin"].Value, "acme-production") {
		t.Errorf("admin force-multiplier wrong: %+v", got["admin"])
	}
}

func TestAWSSSOExpiredIsInvalid(t *testing.T) {
	fs, _ := awsSSO{}.Recon(context.Background(), recon.New(nil, false), module.Token{},
		module.Fields{"access_token": "x", "expires_at": "2000-01-01T00:00:00Z"})
	note := awsSSO{}.Summarize("t", fs)
	if !note.Invalid {
		t.Errorf("expired session should be invalid: %+v", note)
	}
}

// The registration file's clientSecret is also a valid JWT; the structured
// recognizer must win and the bare-JWT match must be suppressed.
func TestAWSSSORegistrationSuppressesJWT(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS384"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"sso.amazonaws.com","exp":` + itoaInt(int(time.Now().Add(time.Hour).Unix())) + `}`))
	jwt := hdr + "." + pl + ".c2lnbmF0dXJlZGF0YWxvbmdlbm91Z2g"
	reg := map[string]any{"clientId": "abc", "clientSecret": jwt, "expiresAt": "2099-01-01T00:00:00Z"}
	rb, _ := json.Marshal(reg)
	b := parse.Parse(string(rb), "registration.json")

	matches := recognize.Recognize(b, "", module.Default)
	var sawReg, sawJWT bool
	for _, m := range matches {
		switch m.Module {
		case "aws_sso_registration":
			sawReg = true
		case "jwt":
			sawJWT = true
		}
	}
	if !sawReg {
		t.Errorf("registration not recognized: %+v", matches)
	}
	if sawJWT {
		t.Errorf("bare JWT should be suppressed when claimed by SSO registration")
	}
}

func TestResolveTargetsExplicitPairs(t *testing.T) {
	c := recon.New(nil, false)
	got := awsSSO{}.resolveTargets(context.Background(), c, "", "", nil, "111/AdminRole, 222/ReadOnly, 111/AdminRole")
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped pairs, got %+v", got)
	}
	if got[0] != (assumeTarget{"111", "AdminRole"}) || got[1] != (assumeTarget{"222", "ReadOnly"}) {
		t.Errorf("pairs = %+v", got)
	}
}

func TestAWSSSOAssumeMintsAndCharacterizes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/assignment/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accountList":[{"accountId":"111","accountName":"acme-production"}]}`))
	})
	mux.HandleFunc("/assignment/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"roleList":[{"roleName":"AdministratorAccess"}]}`))
	})
	mux.HandleFunc("/federation/credentials", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("account_id") != "111" || r.URL.Query().Get("role_name") != "AdministratorAccess" {
			t.Errorf("unexpected assume target: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"roleCredentials":{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":"minted-secret","sessionToken":"minted-token"}}`))
	})
	// awsKey recon calls land at "/": identity succeeds, everything else denied.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(readAll(r), "GetCallerIdentity") {
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::111:assumed-role/AdministratorAccess/geiger</Arn><Account>111</Account><UserId>AID</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	awsSSOPortalBase = srv.URL
	defer func() { awsSSOPortalBase = "" }()
	orig := awsEndpoints
	awsEndpoints.STS = srv.URL + "/"
	awsEndpoints.IAM = srv.URL + "/"
	awsEndpoints.S3 = srv.URL + "/"
	awsEndpoints.Secrets = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	c.SetAWSIntrusive(true)
	c.SetAWSAssume("111/AdministratorAccess")

	fs, err := awsSSO{}.Recon(context.Background(), c, module.Token{}, module.Fields{
		"access_token": "TOK", "region": "us-east-1", "expires_at": "2099-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawPlan, sawLabeledIdentity bool
	for _, f := range fs {
		if f.Key == "assume" && strings.Contains(f.Value, "1 account/role target") {
			sawPlan = true
		}
		if f.Key == "identity" && strings.Contains(f.Value, "[AdministratorAccess@111]") && strings.Contains(f.Value, "assumed-role/AdministratorAccess") {
			sawLabeledIdentity = true
		}
	}
	if !sawPlan {
		t.Errorf("expected assume plan finding, got %+v", fs)
	}
	if !sawLabeledIdentity {
		t.Errorf("expected labeled identity from minted creds, got %+v", fs)
	}
}

func TestAWSSSOAssumeRequiresAWSIntrusive(t *testing.T) {
	// --aws-assume set but --aws-intrusive not: no minting should occur.
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/assignment/accounts", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accountList":[{"accountId":"111","accountName":"prod"}]}`))
	})
	mux.HandleFunc("/assignment/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"roleList":[{"roleName":"ReadOnly"}]}`))
	})
	mux.HandleFunc("/federation/credentials", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	awsSSOPortalBase = srv.URL
	defer func() { awsSSOPortalBase = "" }()

	c := recon.New(srv.Client(), true)
	c.SetAWSAssume("all") // intentionally without SetAWSIntrusive
	_, _ = awsSSO{}.Recon(context.Background(), c, module.Token{}, module.Fields{
		"access_token": "TOK", "expires_at": "2099-01-01T00:00:00Z",
	})
	if called {
		t.Error("GetRoleCredentials must not be called without --aws-intrusive")
	}
}
