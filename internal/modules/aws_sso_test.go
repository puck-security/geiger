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
