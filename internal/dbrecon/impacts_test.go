package dbrecon

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"

	"github.com/puck-security/geiger/internal/module"
)

func TestPostgresImpacts(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT current_user, current_database()").
		WillReturnRows(sqlmock.NewRows([]string{"u", "d"}).AddRow("postgres", "orders"))
	mock.ExpectQuery("SELECT usesuper FROM pg_user WHERE usename = current_user").
		WillReturnRows(sqlmock.NewRows([]string{"s"}).AddRow(true))
	mock.ExpectQuery("SELECT count(*) FROM pg_database WHERE datistemplate = false").
		WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(12))
	mock.ExpectQuery("SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')").
		WillReturnRows(sqlmock.NewRows([]string{"c"}).AddRow(345))

	out := pgReconDB(context.Background(), db)
	got := map[string]module.Finding{}
	for _, f := range out {
		got[f.Key] = f
	}
	if got["superuser"].Flag != module.FlagForceMultiplier {
		t.Errorf("superuser force-multiplier not surfaced: %+v", out)
	}
	if got["connected as"].Flag != module.FlagWarn { // 'postgres' user
		t.Errorf("postgres superuser-name should warn: %+v", got["connected as"])
	}
	if got["current database"].Value != "orders" || got["databases"].Value != "12" || got["tables (current db)"].Value != "345" {
		t.Errorf("impact values wrong: %+v", got)
	}
}

func TestMySQLImpacts(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT CURRENT_USER()").
		WillReturnRows(sqlmock.NewRows([]string{"u"}).AddRow("root@localhost"))
	mock.ExpectQuery("SHOW DATABASES").
		WillReturnRows(sqlmock.NewRows([]string{"d"}).AddRow("information_schema").AddRow("app").AddRow("billing"))
	mock.ExpectQuery("SELECT VERSION()").
		WillReturnRows(sqlmock.NewRows([]string{"v"}).AddRow("8.0.36"))

	out := mysqlReconDB(context.Background(), db)
	got := map[string]module.Finding{}
	for _, f := range out {
		got[f.Key] = f
	}
	if got["connected as"].Value != "root@localhost" || got["connected as"].Flag != module.FlagWarn {
		t.Errorf("root user not flagged: %+v", got["connected as"])
	}
	if got["databases"].Value != "3" || got["version"].Value != "8.0.36" {
		t.Errorf("impact values wrong: %+v", got)
	}
}

func TestRedisImpactsMiniredis(t *testing.T) {
	s := miniredis.RunT(t)
	s.Set("k1", "v1")
	s.Set("k2", "v2")
	s.Set("k3", "v3")

	out, err := reconRedis(context.Background(), "redis://"+s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range out {
		got[f.Key] = f.Value
	}
	if got["keys (db)"] != "3" {
		t.Errorf("key count wrong: %+v", got)
	}
}

func TestPostgresDSNStripsFileParams(t *testing.T) {
	got := pgSafeDSN("postgres://u:p@host:5432/db?sslmode=require&sslcert=/etc/passwd&sslkey=/etc/shadow&passfile=/x&options=-c%20foo")
	for _, bad := range []string{"sslcert", "sslkey", "passfile", "options", "/etc/passwd"} {
		if strings.Contains(got, bad) {
			t.Errorf("dangerous param %q leaked into DSN: %q", bad, got)
		}
	}
	if !strings.Contains(got, "sslmode=require") {
		t.Errorf("safe sslmode dropped: %q", got)
	}
}
