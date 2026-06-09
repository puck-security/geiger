package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoSecretLeaksIntoRecordedCall covers secrets carried anywhere in the
// request — URL path, query, or header — not just the Authorization header.
func TestNoSecretLeaksIntoRecordedCall(t *testing.T) {
	const secret = "123456789:AAFakeBotTokenValue1234567890abcdef"
	c := New(nil, false)
	c.RegisterSecret(secret)

	// secret in the URL path (Telegram-style)
	req, _ := NewRequest(context.Background(), http.MethodGet, "https://api.telegram.org/bot"+secret+"/getMe", nil)
	// and in a header
	req.Header.Set("Authorization", "Bearer "+secret)
	if _, err := c.Do(req, CallOpts{}); err != nil {
		t.Fatal(err)
	}
	p := c.Planned()[0]
	if strings.Contains(p.URL, secret) {
		t.Errorf("secret leaked into recorded URL: %q", p.URL)
	}
	for k, v := range p.Headers {
		if strings.Contains(v, secret) {
			t.Errorf("secret leaked into recorded header %s: %q", k, v)
		}
	}
}

func TestPlannedCallCurl(t *testing.T) {
	p := PlannedCall{
		Method:  "POST",
		URL:     "https://sts.amazonaws.com/",
		Headers: map[string]string{"Authorization": "Bearer …JV3Q", "Content-Type": "application/x-www-form-urlencoded"},
		Body:    "Action=GetCallerIdentity&Version=2011-06-15",
	}
	got := p.Curl()
	for _, want := range []string{"curl -sS", "-X POST", "-H 'Authorization: Bearer …JV3Q'", "--data 'Action=GetCallerIdentity", "'https://sts.amazonaws.com/'"} {
		if !strings.Contains(got, want) {
			t.Errorf("curl missing %q in: %s", want, got)
		}
	}
	// Authorization header must come before Content-Type
	if strings.Index(got, "Authorization") > strings.Index(got, "Content-Type") {
		t.Errorf("Authorization should sort first: %s", got)
	}
}

func TestCurlUsesVarRefAndExpands(t *testing.T) {
	c := New(nil, false)
	c.RegisterSecretRef("xoxb-realtokenvalue-12345", "$SLACK_BOT_TOKEN")
	req, _ := NewRequest(context.Background(), "GET", "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer xoxb-realtokenvalue-12345")
	_, _ = c.Do(req, CallOpts{})
	curl := c.Planned()[0].Curl()
	if !strings.Contains(curl, `"Authorization: Bearer $SLACK_BOT_TOKEN"`) {
		t.Errorf("expected double-quoted $VAR header, got: %s", curl)
	}
	if strings.Contains(curl, "realtokenvalue") {
		t.Errorf("raw secret leaked: %s", curl)
	}
	if !strings.Contains(curl, "'https://slack.com/api/auth.test'") {
		t.Errorf("URL should be intact and single-quoted: %s", curl)
	}
}

func TestTraceCapturesMaskedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"user":"bob","downstream_token":"ghp_supersecretsecretsecret1234"}`))
	}))
	defer srv.Close()
	c := New(srv.Client(), true)
	c.SetTrace(true)
	c.RegisterSecret("ghp_supersecretsecretsecret1234")
	req, _ := NewRequest(context.Background(), "GET", srv.URL, nil)
	if _, err := c.Do(req, CallOpts{}); err != nil {
		t.Fatal(err)
	}
	p := c.Planned()[0]
	if p.RespStatus != 200 {
		t.Errorf("status not captured: %d", p.RespStatus)
	}
	if !strings.Contains(p.RespBody, `"user":"bob"`) {
		t.Errorf("response not captured: %q", p.RespBody)
	}
	if strings.Contains(p.RespBody, "supersecretsecret") {
		t.Errorf("secret not masked in traced response: %q", p.RespBody)
	}
}

func TestNoTraceNoResponseCapture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"x":1}`))
	}))
	defer srv.Close()
	c := New(srv.Client(), true) // trace off
	req, _ := NewRequest(context.Background(), "GET", srv.URL, nil)
	_, _ = c.Do(req, CallOpts{})
	if c.Planned()[0].RespBody != "" {
		t.Errorf("response captured without --trace")
	}
}
