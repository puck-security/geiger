// Package dbrecon runs read-only data-plane recon against a database
// connection string. Enforcement is structural: each engine runs ONLY a fixed
// allowlist of catalog/metadata queries (no user input is ever interpolated),
// and the session is put into read-only mode where the engine supports it.
//
// This path is separate from the HTTP recon client because it speaks native DB
// protocols; the consent gate (--intrusive) and dry-run check live in the
// calling module, which only invokes Recon when both Live and Intrusive hold.
package dbrecon

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/puck-security/geiger/internal/module"
	"github.com/redis/go-redis/v9"

	mysqldriver "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

// go-redis logs connection-pool dial failures to a global logger, which would
// otherwise spew into geiger's output for every unreachable host. Silence it —
// we report the failure ourselves as a finding.
type silentRedisLog struct{}

func (silentRedisLog) Printf(context.Context, string, ...any) {}

func init() { redis.SetLogger(silentRedisLog{}) }

// Supported reports whether dbrecon can exercise the given DSN scheme live.
func Supported(dsn string) bool {
	switch scheme(dsn) {
	case "postgres", "postgresql", "mysql", "redis", "rediss", "mongodb", "mongodb+srv",
		"sqlserver", "mssql", "oracle", "clickhouse", "cassandra":
		return true
	}
	return false
}

func scheme(dsn string) string {
	if i := strings.Index(dsn, "://"); i > 0 {
		return strings.ToLower(dsn[:i])
	}
	return ""
}

// Recon connects read-only and returns live catalog findings. The caller must
// have already confirmed Live && Intrusive.
func Recon(ctx context.Context, dsn string) ([]module.Finding, error) {
	switch scheme(dsn) {
	case "postgres", "postgresql":
		return reconPostgres(ctx, dsn)
	case "mysql":
		return reconMySQL(ctx, dsn)
	case "redis", "rediss":
		return reconRedis(ctx, dsn)
	case "mongodb", "mongodb+srv":
		return reconMongo(ctx, dsn)
	case "sqlserver", "mssql":
		return reconMSSQL(ctx, dsn)
	case "oracle":
		return reconOracle(ctx, dsn)
	case "clickhouse":
		return reconClickHouseDSN(ctx, dsn)
	case "cassandra":
		return reconCassandra(ctx, dsn)
	default:
		return nil, fmt.Errorf("dbrecon: unsupported engine %q", scheme(dsn))
	}
}

// IsAuthError reports whether a recon error is an authentication rejection (the
// server reached us and refused the credential) as opposed to a network/reach
// failure (which says nothing about the credential's validity). It is used to
// classify a credential as DEAD only when it was actually rejected.
//
// We deliberately do NOT treat "unauthorized"/"not authorized" as an auth
// failure: those mean the credential authenticated but lacks privilege — i.e.
// it is valid. Matching is on stable SQLSTATE/driver codes plus engine-specific
// rejection phrases.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, sig := range []string{
		"password authentication failed", "28p01", "28000", // postgres
		"access denied for user", "error 1045", // mysql
		"wrongpass", "noauth", "invalid password", // redis
		"authentication failed", "authenticationfailed", "auth error", // mongo / clickhouse
		"authentication_failed", // clickhouse code 516
		"login failed for user", // mssql 18456
		"ora-01017",             // oracle invalid username/password
		"authentication error",  // cassandra
		"bad credentials", "invalid credentials",
	} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

// ---- Postgres ----

func reconPostgres(ctx context.Context, dsn string) ([]module.Finding, error) {
	db, err := sql.Open("pgx", pgSafeDSN(dsn))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		return nil, err // surface connection refused / DNS failure (don't silently report nothing)
	}
	// Belt-and-suspenders read-only: nothing below writes, but make the session
	// reject writes outright.
	_, _ = db.ExecContext(cctx, "SET default_transaction_read_only = on")
	return pgReconDB(cctx, db), nil
}

// pgReconDB runs the read-only catalog queries and maps results to impact
// findings. Split from connection so it can be tested with a mock *sql.DB.
func pgReconDB(ctx context.Context, db *sql.DB) []module.Finding {
	var out []module.Finding
	var user, dbName string
	if err := db.QueryRowContext(ctx, "SELECT current_user, current_database()").Scan(&user, &dbName); err == nil {
		out = append(out, module.Finding{Key: "connected as", Value: user, Flag: pgUserFlag(user)})
		out = append(out, module.Finding{Key: "current database", Value: dbName, Flag: module.FlagInfo})
	}
	var super bool
	if err := db.QueryRowContext(ctx, "SELECT usesuper FROM pg_user WHERE usename = current_user").Scan(&super); err == nil && super {
		out = append(out, module.Finding{Key: "superuser", Value: "yes — full data-plane control", Flag: module.FlagForceMultiplier})
	}
	var dbs int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM pg_database WHERE datistemplate = false").Scan(&dbs); err == nil {
		out = append(out, module.Finding{Key: "databases", Value: itoa(dbs), Flag: module.FlagInfo})
	}
	var tables int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')").Scan(&tables); err == nil {
		out = append(out, module.Finding{Key: "tables (current db)", Value: itoa(tables), Flag: module.FlagInfo})
	}
	return out
}

// pgDangerousParams reference local files or external programs; a malicious DSN
// pointed at a hostile server could use them to exfiltrate files (the cert/key
// is presented to the server) or read arbitrary paths.
var pgDangerousParams = map[string]bool{
	"sslcert": true, "sslkey": true, "sslrootcert": true, "sslpassword": true,
	"passfile": true, "service": true, "servicefile": true, "options": true,
	"krbsrvname": true, "sslsni": true,
}

// pgSafeDSN strips local-file / program-reference parameters from a postgres
// connection string before it reaches the driver.
func pgSafeDSN(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k := range q {
		if pgDangerousParams[strings.ToLower(k)] {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// dsnFileParams are connection-string options (across mongo / mssql / oracle)
// that point the driver at a local file — a CA/cert/key/wallet/trace path. A
// malicious DSN in an untrusted dump could use them to read an arbitrary host
// file or present a host file to an attacker-controlled server.
var dsnFileParams = map[string]bool{
	"tlscafile": true, "tlscertificatekeyfile": true, "tlscertificatekeyfilepassword": true,
	"sslclientcertificatekeyfile": true, "sslcertificateauthorityfile": true,
	"certificate": true,                    // go-mssqldb: CA certificate file path
	"wallet":      true,                    // go-ora: wallet directory
	"trace file":  true, "tracefile": true, // go-ora: trace output file
}

// stripFileParams removes file-referencing query parameters from a URI-style
// DSN before it reaches the driver. TLS *mode* flags (tls=true, secure,
// skip_verify) are intentionally preserved so legitimate TLS connections — and
// triage of internal DBs with self-signed certs — still work; only the
// file-path options that enable host-file read/exfil are dropped.
func stripFileParams(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	changed := false
	for k := range q {
		if dsnFileParams[strings.ToLower(k)] {
			q.Del(k)
			changed = true
		}
	}
	if !changed {
		return raw // avoid re-encoding side effects when nothing is stripped
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func pgUserFlag(u string) module.FlagLevel {
	if u == "postgres" {
		return module.FlagWarn
	}
	return module.FlagInfo
}

// ---- MySQL ----

func reconMySQL(ctx context.Context, dsn string) ([]module.Finding, error) {
	driverDSN, err := mysqlDSN(dsn)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", driverDSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		return nil, err // surface connection refused / DNS failure
	}
	_, _ = db.ExecContext(cctx, "SET SESSION TRANSACTION READ ONLY") // best-effort; some managed variants reject it
	return mysqlReconDB(cctx, db), nil
}

// mysqlReconDB runs the read-only queries and maps results to impact findings.
// Split from connection for mockable testing.
func mysqlReconDB(ctx context.Context, db *sql.DB) []module.Finding {
	var out []module.Finding
	var user string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err == nil {
		flag := module.FlagInfo
		if strings.HasPrefix(user, "root@") {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "connected as", Value: user, Flag: flag})
	}
	if rows, err := db.QueryContext(ctx, "SHOW DATABASES"); err == nil {
		n := 0
		for rows.Next() {
			n++
		}
		rows.Close()
		out = append(out, module.Finding{Key: "databases", Value: itoa(n), Flag: module.FlagInfo})
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err == nil {
		out = append(out, module.Finding{Key: "version", Value: version, Flag: module.FlagInfo})
	}
	return out
}

// mysqlDSN converts a mysql:// URL into the go-sql-driver DSN form using the
// driver's own Config.FormatDSN, which escapes special characters in the
// user/password/db (a string-built DSN breaks on a password containing @, /, or
// :). It deliberately passes NO query params from the input and forces
// AllowAllFiles=false: a malicious DSN pointed at a hostile MySQL server could
// otherwise enable local-infile and read files off the Geiger host via
// LOAD DATA LOCAL INFILE.
func mysqlDSN(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":3306"
	}
	pass, _ := u.User.Password()
	cfg := mysqldriver.NewConfig()
	cfg.User = u.User.Username()
	cfg.Passwd = pass
	cfg.Net = "tcp"
	cfg.Addr = host
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.AllowAllFiles = false // never let a hostile server pull local files
	return cfg.FormatDSN(), nil
}

// ---- Redis ----

func reconRedis(ctx context.Context, dsn string) ([]module.Finding, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}
	opt.DialTimeout = 3 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.MaxRetries = -1 // fail fast and quiet on an unreachable host
	opt.PoolSize = 1
	client := redis.NewClient(opt)
	defer client.Close()

	var out []module.Finding
	if who, err := client.Do(ctx, "ACL", "WHOAMI").Text(); err == nil {
		flag := module.FlagInfo
		if who == "default" {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "connected as", Value: who, Flag: flag})
	}
	if size, err := client.DBSize(ctx).Result(); err == nil {
		out = append(out, module.Finding{Key: "keys (db)", Value: itoa(int(size)), Flag: module.FlagInfo})
	}
	if info, err := client.Info(ctx, "server").Result(); err == nil {
		if v := infoField(info, "redis_version"); v != "" {
			out = append(out, module.Finding{Key: "version", Value: v, Flag: module.FlagInfo})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("redis: no read-only command succeeded")
	}
	return out, nil
}

// ---- SQLite (local file, read-only) ----

var sensitiveTable = regexp.MustCompile(`(?i)\b(users?|accounts?|customers?|members?|employees?|people|persons?|credentials?|secrets?|tokens?|sessions?|auth|passwords?|payments?|cards?|invoices?|ssn|emails?|profiles?|api[_-]?keys?)\b`)

// ReconSQLiteFile opens a SQLite database file read-only and reports what's in
// it: the table count, and a row count for any sensitively-named table. The
// path must already be absolute (the caller resolves it against the source
// file's directory). Read-only by construction: opened mode=ro with query_only,
// and only SELECT/metadata queries run.
func ReconSQLiteFile(ctx context.Context, path string) ([]module.Finding, error) {
	if path == "" {
		return nil, fmt.Errorf("no file path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("file not found: %s", filepath.Base(path))
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("not a file: %s", filepath.Base(path))
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(cctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err // not a SQLite DB, or unreadable
	}
	var tables []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			tables = append(tables, n)
		}
	}
	rows.Close()

	out := []module.Finding{
		{Key: "sqlite file", Value: filepath.Base(path) + " (read locally)", Flag: module.FlagInfo},
		{Key: "tables", Value: itoa(len(tables)), Flag: module.FlagInfo},
	}
	var sensitive []string
	for _, t := range tables {
		if !sensitiveTable.MatchString(t) {
			continue
		}
		// Identifier comes from the file's own schema; quote it and strip any
		// embedded quote so it can't break out (query_only blocks writes regardless).
		q := `"` + strings.ReplaceAll(t, `"`, "") + `"`
		var n int64 = -1
		_ = db.QueryRowContext(cctx, "SELECT COUNT(*) FROM "+q).Scan(&n)
		if n >= 0 {
			sensitive = append(sensitive, fmt.Sprintf("%s(%d)", t, n))
		} else {
			sensitive = append(sensitive, t)
		}
	}
	if len(sensitive) > 0 {
		v := strings.Join(sensitive, ", ")
		if len(v) > 240 {
			v = v[:240] + "…"
		}
		out = append(out, module.Finding{Key: "sensitive tables", Value: v + " — local data readable", Flag: module.FlagForceMultiplier})
	}
	return out, nil
}

// ---- AI-IDE token store (VS Code / Cursor state.vscdb, read-only) ----

// KVSecret is one plaintext key/value row pulled from an IDE token store.
type KVSecret struct{ Key, Value string }

// tokenKeyRe matches ItemTable keys that hold a credential value (not e.g. a
// cached email), so harvest extracts only token-bearing rows.
var tokenKeyRe = regexp.MustCompile(`(?i)(access[_-]?token|refresh[_-]?token|\btoken\b|secret|api[_-]?key|password|credential)`)

// ReconVSCDBFile reads a VS Code / Cursor "state.vscdb" — a plaintext SQLite
// key/value store (ItemTable) that AI IDEs use to hold OAuth/access tokens with
// no isolation — and reports which credential keys it holds, returning the
// plaintext token values for re-triage. Read-only by construction (mode=ro,
// query_only) against a fixed key allowlist (no user input interpolated).
// Encrypted/binary values are skipped: plaintext stores only, never OS-keychain
// decryption.
func ReconVSCDBFile(ctx context.Context, path string) ([]module.Finding, []KVSecret, error) {
	if path == "" {
		return nil, nil, fmt.Errorf("no file path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("file not found: %s", filepath.Base(path))
	}
	if fi.IsDir() {
		return nil, nil, fmt.Errorf("not a file: %s", filepath.Base(path))
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := db.QueryContext(cctx, `SELECT key, value FROM ItemTable WHERE `+
		`key LIKE 'cursorAuth/%' OR key LIKE 'secret://%' OR key LIKE '%token%' OR `+
		`key LIKE '%secret%' OR key LIKE '%apiKey%' OR key LIKE '%api_key%' OR key LIKE '%password%' ORDER BY key`)
	if err != nil {
		return nil, nil, err // not a state.vscdb, or no ItemTable
	}
	defer rows.Close()
	var keys []string
	var harv []KVSecret
	for rows.Next() {
		var k string
		var v []byte
		if rows.Scan(&k, &v) != nil {
			continue
		}
		keys = append(keys, k)
		if sv := strings.TrimSpace(string(v)); tokenKeyRe.MatchString(k) && vscdbPlaintext(sv) {
			harv = append(harv, KVSecret{Key: k, Value: sv})
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no credential keys in ItemTable")
	}
	out := []module.Finding{
		{Key: "ide token store", Value: filepath.Base(path) + " — " + itoa(len(keys)) + " credential key(s) stored in plaintext", Flag: module.FlagForceMultiplier},
		{Key: "keys", Value: joinCapped(keys, 240), Flag: module.FlagInfo},
	}
	return out, harv, nil
}

// vscdbPlaintext reports whether a stored value is a usable plaintext credential
// (printable, sane length) rather than an OS-keychain-encrypted binary blob.
func vscdbPlaintext(v string) bool {
	if len(v) < 8 || len(v) > 8192 {
		return false
	}
	for _, r := range v {
		if r == 0 || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
			return false
		}
	}
	return true
}

func infoField(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+":"))
		}
	}
	return ""
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
