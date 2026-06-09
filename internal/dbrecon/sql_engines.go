package dbrecon

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/module"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers "clickhouse"
	_ "github.com/microsoft/go-mssqldb"        // registers "sqlserver"
	_ "github.com/sijms/go-ora/v2"             // registers "oracle"
)

// Each function runs ONLY fixed catalog SELECTs (no user input interpolated) and
// pings first so an unreachable host surfaces as a connection error rather than
// an empty result.

// ---- Microsoft SQL Server ----

func reconMSSQL(ctx context.Context, dsn string) ([]module.Finding, error) {
	dsn = strings.Replace(stripFileParams(dsn), "mssql://", "sqlserver://", 1) // driver wants the sqlserver scheme
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		return nil, err
	}
	var out []module.Finding
	var login, dbName string
	if err := db.QueryRowContext(cctx, "SELECT SUSER_SNAME(), DB_NAME()").Scan(&login, &dbName); err == nil {
		out = append(out, module.Finding{Key: "connected as", Value: login, Flag: module.FlagInfo})
		out = append(out, module.Finding{Key: "current database", Value: dbName, Flag: module.FlagInfo})
	}
	var sysadmin int
	if err := db.QueryRowContext(cctx, "SELECT IS_SRVROLEMEMBER('sysadmin')").Scan(&sysadmin); err == nil && sysadmin == 1 {
		out = append(out, module.Finding{Key: "sysadmin", Value: "yes — full server control", Flag: module.FlagForceMultiplier})
	}
	var n int
	if err := db.QueryRowContext(cctx, "SELECT COUNT(*) FROM sys.databases").Scan(&n); err == nil {
		out = append(out, module.Finding{Key: "databases", Value: itoa(n), Flag: module.FlagInfo})
	}
	return out, nil
}

// ---- Oracle (pure-Go go-ora) ----

func reconOracle(ctx context.Context, dsn string) ([]module.Finding, error) {
	db, err := sql.Open("oracle", stripFileParams(dsn))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		return nil, err
	}
	var out []module.Finding
	var user string
	if err := db.QueryRowContext(cctx, "SELECT USER FROM DUAL").Scan(&user); err == nil {
		out = append(out, module.Finding{Key: "connected as", Value: user, Flag: module.FlagInfo})
	}
	var dba int
	if err := db.QueryRowContext(cctx, "SELECT COUNT(*) FROM session_roles WHERE role = 'DBA'").Scan(&dba); err == nil && dba > 0 {
		out = append(out, module.Finding{Key: "DBA role", Value: "yes — full database control", Flag: module.FlagForceMultiplier})
	}
	var n int
	if err := db.QueryRowContext(cctx, "SELECT COUNT(*) FROM all_tables").Scan(&n); err == nil {
		out = append(out, module.Finding{Key: "tables (visible)", Value: itoa(n), Flag: module.FlagInfo})
	}
	return out, nil
}

// ---- ClickHouse (native protocol via clickhouse-go) ----

func reconClickHouseDSN(ctx context.Context, dsn string) ([]module.Finding, error) {
	db, err := sql.Open("clickhouse", stripFileParams(dsn))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(cctx); err != nil {
		return nil, err
	}
	var out []module.Finding
	var user string
	if err := db.QueryRowContext(cctx, "SELECT currentUser()").Scan(&user); err == nil {
		out = append(out, module.Finding{Key: "connected as", Value: user, Flag: module.FlagInfo})
	}
	var ndb int
	if err := db.QueryRowContext(cctx, "SELECT count() FROM system.databases").Scan(&ndb); err == nil {
		out = append(out, module.Finding{Key: "databases", Value: itoa(ndb), Flag: module.FlagInfo})
	}
	var ntab int
	if err := db.QueryRowContext(cctx, "SELECT count() FROM system.tables").Scan(&ntab); err == nil {
		out = append(out, module.Finding{Key: "tables", Value: itoa(ntab), Flag: module.FlagWarn})
	}
	return out, nil
}
