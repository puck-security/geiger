package dbrecon

import (
	"context"
	"testing"
	"time"

	"github.com/puck-security/geiger/internal/module"
)

func TestNetworkedEnginesSupported(t *testing.T) {
	for _, dsn := range []string{
		"sqlserver://h:1/db", "mssql://h:1/db", "oracle://h:1/svc",
		"clickhouse://h:1/db", "cassandra://h:1/ks",
	} {
		if !Supported(dsn) {
			t.Errorf("%s should be Supported", dsn)
		}
	}
}

func TestNetworkedEnginesFailFast(t *testing.T) {
	tests := []struct {
		name string
		fn   func(context.Context, string) ([]module.Finding, error)
		dsn  string
	}{
		{"mssql", reconMSSQL, "sqlserver://sa:p@127.0.0.1:1?database=x"},
		{"oracle", reconOracle, "oracle://u:p@127.0.0.1:1/svc"},
		{"clickhouse", reconClickHouseDSN, "clickhouse://u:p@127.0.0.1:1/db"},
		{"cassandra", reconCassandra, "cassandra://u:p@127.0.0.1:1/ks"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			start := time.Now()
			if _, err := tc.fn(ctx, tc.dsn); err == nil {
				t.Errorf("expected a connection error to an unreachable host")
			}
			if time.Since(start) > 9*time.Second {
				t.Errorf("should fail fast, took %s", time.Since(start))
			}
		})
	}
}
