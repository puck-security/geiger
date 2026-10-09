package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestSnowflakeIdentityAndIntrusive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/statements", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Snowflake-Authorization-Token-Type") != "PROGRAMMATIC_ACCESS_TOKEN" {
			t.Errorf("missing token-type header")
		}
		body := readAll(r)
		switch {
		case strings.Contains(body, "CURRENT_USER"):
			_, _ = w.Write([]byte(`{"data":[["SVC_ETL","ACCOUNTADMIN"]]}`))
		case strings.Contains(body, "SHOW DATABASES"):
			_, _ = w.Write([]byte(`{"data":[["db1"],["db2"],["db3"]]}`))
		case strings.Contains(body, "SHOW GRANTS TO USER"):
			_, _ = w.Write([]byte(`{"data":[["2020","ACCOUNTADMIN","ROLE","SVC_ETL"],["2020","PUBLIC","ROLE","SVC_ETL"]]}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := recon.New(srv.Client(), true)
	c.SetSnowflakeIntrusive(true)
	fs, err := snowflakeKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "pat", "endpoint": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got := indexByKey(fs)
	if got["user"].Value != "SVC_ETL" {
		t.Errorf("user = %q", got["user"].Value)
	}
	if got["role"].Flag != module.FlagForceMultiplier || got["role"].Value != "ACCOUNTADMIN" {
		t.Errorf("role finding wrong: %+v", got["role"])
	}
	if got["databases"].Value != "3 reachable" {
		t.Errorf("databases = %q", got["databases"].Value)
	}
	if got["roles"].Flag != module.FlagForceMultiplier || !strings.Contains(got["roles"].Value, "ACCOUNTADMIN") {
		t.Errorf("roles finding wrong: %+v", got["roles"])
	}
}

func TestSnowflakeGateOff(t *testing.T) {
	deep := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/statements", func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r)
		if strings.Contains(body, "CURRENT_USER") {
			_, _ = w.Write([]byte(`{"data":[["U","PUBLIC"]]}`))
			return
		}
		deep = true
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := recon.New(srv.Client(), true) // not snowflake-intrusive
	_, _ = snowflakeKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "pat", "endpoint": srv.URL})
	if deep {
		t.Error("SHOW DATABASES/GRANTS must not run without --snowflake-intrusive")
	}
}

func TestSnowflakeDeadTokenIsInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer srv.Close()
	c := recon.New(srv.Client(), true)
	c.SetSnowflakeIntrusive(true)
	fs, _ := snowflakeKey{}.Recon(context.Background(), c, module.Token{}, module.Fields{"token": "dead", "endpoint": srv.URL})
	if n := (snowflakeKey{}).Summarize("t", fs); !n.Invalid {
		t.Errorf("a revoked Snowflake token must be invalid (not a high-sev reach note), got %+v", fs)
	}
}
