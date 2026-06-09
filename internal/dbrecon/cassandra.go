package dbrecon

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/gocql/gocql"
	"github.com/puck-security/geiger/internal/module"
)

// reconCassandra connects to a Cassandra cluster (cassandra://user:pass@host:port/keyspace)
// and reports the cluster identity plus reachable keyspaces via read-only queries
// against the system schema. gocql has no URL DSN of its own, so we parse one.
func reconCassandra(ctx context.Context, dsn string) ([]module.Finding, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	cluster := gocql.NewCluster(u.Hostname())
	if p := u.Port(); p != "" {
		if n, e := strconv.Atoi(p); e == nil {
			cluster.Port = n
		}
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		cluster.Authenticator = gocql.PasswordAuthenticator{Username: u.User.Username(), Password: pw}
	}
	cluster.ConnectTimeout = 5 * time.Second
	cluster.Timeout = 5 * time.Second
	cluster.ProtoVersion = 4
	cluster.DisableInitialHostLookup = true

	sess, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	var out []module.Finding
	var version, clusterName string
	if err := sess.Query("SELECT release_version, cluster_name FROM system.local").WithContext(ctx).Scan(&version, &clusterName); err == nil {
		if clusterName != "" {
			out = append(out, module.Finding{Key: "cluster", Value: clusterName, Flag: module.FlagInfo})
		}
		if version != "" {
			out = append(out, module.Finding{Key: "version", Value: version, Flag: module.FlagInfo})
		}
	}

	iter := sess.Query("SELECT keyspace_name FROM system_schema.keyspaces").WithContext(ctx).Iter()
	var ks string
	n := 0
	for iter.Scan(&ks) {
		switch ks {
		case "system", "system_schema", "system_auth", "system_distributed", "system_traces", "system_views", "system_virtual_schema":
			continue
		}
		n++
	}
	_ = iter.Close()
	out = append(out, module.Finding{Key: "keyspaces (non-system)", Value: itoa(n), Flag: module.FlagWarn})

	if len(out) == 0 {
		return nil, errNoCassandra
	}
	return out, nil
}

var errNoCassandra = errStr("cassandra: no read-only query succeeded")

type errStr string

func (e errStr) Error() string { return string(e) }
