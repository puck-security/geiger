package dbrecon

import (
	"errors"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestIsAuthError(t *testing.T) {
	auth := []string{ // server reached us and rejected the credential → dead
		`FATAL: password authentication failed for user "x" (SQLSTATE 28P01)`,
		"Error 1045: Access denied for user 'a'@'h' (using password: YES)",
		"WRONGPASS invalid username-password pair or user is disabled.",
		"(AuthenticationFailed) Authentication failed.",
		"mssql: Login failed for user 'sa'.",
		"ORA-01017: invalid username/password; logon denied",
		"code: 516, message: db: Authentication failed: password is incorrect",
		"gocql: Authentication error: ...",
	}
	for _, m := range auth {
		if !IsAuthError(errors.New(m)) {
			t.Errorf("should be auth error: %q", m)
		}
	}
	notAuth := []string{ // reach failures, or valid-but-unprivileged → NOT dead
		"dial tcp 10.0.0.5:5432: connect: connection refused",
		"context deadline exceeded",
		"dial tcp: lookup db.invalid: no such host",
		"(Unauthorized) not authorized on admin to execute command", // valid cred, no perm
		"i/o timeout",
	}
	for _, m := range notAuth {
		if IsAuthError(errors.New(m)) {
			t.Errorf("should NOT be auth error: %q", m)
		}
	}
	if IsAuthError(nil) {
		t.Error("nil must not be an auth error")
	}
}

func TestSupported(t *testing.T) {
	cases := map[string]bool{
		"postgres://u:p@h/db":   true,
		"postgresql://u:p@h/db": true,
		"mysql://u:p@h/db":      true,
		"redis://h:6379":        true,
		"rediss://h:6379":       true,
		"mongodb://h/db":        true,
		"mongodb+srv://h/db":    true,
		"sqlserver://h:1/db":    true,
		"mssql://h:1/db":        true,
		"oracle://h:1/svc":      true,
		"clickhouse://h:1/db":   true,
		"cassandra://h:1/ks":    true,
		"sqlite:///x":           false, // handled in the module (local file), not here
		"ftp://h/x":             false,
	}
	for dsn, want := range cases {
		if got := Supported(dsn); got != want {
			t.Errorf("Supported(%q)=%v want %v", dsn, got, want)
		}
	}
}

func TestMySQLDSN(t *testing.T) {
	got, err := mysqlDSN("mysql://app:secret@db.prod.internal:3307/orders")
	if err != nil {
		t.Fatal(err)
	}
	// must be user:pass@tcp(host:port)/db?... with no leading scheme
	if got[:len("app:secret@tcp(db.prod.internal:3307)/orders")] != "app:secret@tcp(db.prod.internal:3307)/orders" {
		t.Errorf("unexpected DSN: %q", got)
	}
}

func TestMySQLDSNDefaultPort(t *testing.T) {
	got, _ := mysqlDSN("mysql://u:p@host/db")
	if want := "u:p@tcp(host:3306)/db"; got[:len(want)] != want {
		t.Errorf("default port not applied: %q", got)
	}
}

func TestInfoField(t *testing.T) {
	info := "# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
	if v := infoField(info, "redis_version"); v != "7.2.4" {
		t.Errorf("infoField = %q", v)
	}
}

func TestStripFileParams(t *testing.T) {
	// File-referencing options must be removed (read/exfil of a host file).
	gone := map[string]string{
		"mongodb://h/db?tls=true&tlsCAFile=/etc/passwd":                        "/etc/passwd",
		"mongodb://h/db?tlsCertificateKeyFile=/home/x/id.pem&authSource=admin": "id.pem",
		"sqlserver://sa:p@h:1433?database=x&certificate=/etc/shadow":           "/etc/shadow",
		"oracle://u:p@h:1521/svc?wallet=/secret/wallet":                        "/secret/wallet",
	}
	for dsn, secret := range gone {
		if strings.Contains(stripFileParams(dsn), secret) {
			t.Errorf("stripFileParams(%q) still leaks %q: %s", dsn, secret, stripFileParams(dsn))
		}
	}
	// Legitimate TLS-mode and auth params (and the host/user/db) must survive.
	keep := stripFileParams("mongodb://u:p@h:27017/db?tls=true&authSource=admin&tlsCAFile=/etc/passwd")
	for _, want := range []string{"tls=true", "authSource=admin", "u:p@h", "/db"} {
		if !strings.Contains(keep, want) {
			t.Errorf("stripFileParams dropped legitimate part %q: %s", want, keep)
		}
	}
	// No dangerous params → returned unchanged (no re-encode side effects).
	clean := "postgres://u:p@h:5432/db?sslmode=require"
	if stripFileParams(clean) != clean {
		t.Errorf("clean DSN altered: %s", stripFileParams(clean))
	}
}

func TestMySQLDSNDropsAttackerParams(t *testing.T) {
	got, _ := mysqlDSN("mysql://u:p@host:3306/db?allowAllFiles=true&allowLoadLocalInfile=true")
	if strings.Contains(got, "allowAllFiles=true") || strings.Contains(got, "allowLoadLocalInfile") {
		t.Errorf("attacker params leaked into DSN: %q", got)
	}
	cfg, err := mysqldriver.ParseDSN(got)
	if err != nil {
		t.Fatalf("driver can't parse our DSN %q: %v", got, err)
	}
	if cfg.AllowAllFiles {
		t.Errorf("AllowAllFiles must be false (LOAD DATA LOCAL guard): %q", got)
	}
}

func TestMySQLDSNSpecialCharPassword(t *testing.T) {
	// A password with @ / : ! must round-trip — a string-built DSN would mangle it.
	got, err := mysqlDSN("mysql://app:p%40ss%2Fw0rd%3A%21@db.prod:3307/orders")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysqldriver.ParseDSN(got)
	if err != nil {
		t.Fatalf("special-char DSN unparseable %q: %v", got, err)
	}
	if cfg.Passwd != "p@ss/w0rd:!" {
		t.Errorf("password mangled: %q want %q", cfg.Passwd, "p@ss/w0rd:!")
	}
	if cfg.User != "app" || cfg.Addr != "db.prod:3307" || cfg.DBName != "orders" {
		t.Errorf("target wrong: user=%q addr=%q db=%q", cfg.User, cfg.Addr, cfg.DBName)
	}
}
