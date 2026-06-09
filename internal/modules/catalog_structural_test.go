package modules

import (
	"path/filepath"
	"testing"
)

// resolveSQLitePath must CONFINE reads to the source file's directory tree, so
// an untrusted DSN can't make --intrusive read an arbitrary host file.
func TestResolveSQLitePathConfinement(t *testing.T) {
	src := filepath.Join("/work/dump", ".env")
	// Within the source tree → allowed.
	if got := resolveSQLitePath("sqlite:///./data/app.db", src); got != filepath.Clean("/work/dump/data/app.db") {
		t.Errorf("relative-in-tree resolved wrong: %q", got)
	}
	if got := resolveSQLitePath("sqlite:////work/dump/app.db", src); got != filepath.Clean("/work/dump/app.db") {
		t.Errorf("absolute-in-tree should be allowed: %q", got)
	}
	// Escapes / unanchored → refused (empty).
	refuse := []struct{ dsn, source string }{
		{"sqlite:////etc/passwd", src},                         // absolute outside tree
		{"sqlite:///../../../../etc/passwd", src},              // traversal
		{"sqlite:///./app.db", "stdin"},                        // no on-disk anchor
		{"sqlite:///./app.db", "environment"},                  // no on-disk anchor
		{"sqlite:////root/.config/google-chrome/Cookies", src}, // browser DB
	}
	for _, c := range refuse {
		if got := resolveSQLitePath(c.dsn, c.source); got != "" {
			t.Errorf("resolveSQLitePath(%q, %q) should be refused, got %q", c.dsn, c.source, got)
		}
	}
}

// looksTemplateDSN must err toward KEEPING real credentials. The earlier
// version dropped any DSN whose user/host/db was a generic word (user, db,
// database, ...), which silently discarded real dev/prod creds — the worst
// outcome for a triage tool. A real password means it's a real credential.
func TestLooksTemplateDSN(t *testing.T) {
	keep := []string{ // real credentials — must survive (false)
		"postgresql://user:realsecret99@postgres:5432/mydb", // generic user, real pw
		"postgres://app:Sup3rSecret@db:5432/appdb",          // docker host "db", real pw
		"mysql://root:Hunter2xx@10.0.0.5:3306/orders",
		"postgresql://postgres:Backup!Pass99@localhost/ntsb_digest",
		"mongodb://admin:longpassword123@mongo:27017/admin",
		"postgres://svc:Str0ng-P_ss@prod.db.internal/database", // db named "database", real pw
	}
	for _, dsn := range keep {
		if looksTemplateDSN(dsn) {
			t.Errorf("real credential dropped as template: %q", dsn)
		}
	}

	drop := []string{ // documentation/templates — must be dropped (true)
		"postgresql://user:password@localhost/dbname",   // placeholder pw + user
		"postgres://user:pass@host:port/db",             // non-numeric :port
		"postgresql://${DB_USER}:${DB_PASS}@host/db",    // shell markers
		"mongodb://localhost:27017/<database>",          // angle markers
		"mysql://youruser:pw@localhost/yourdb",          // short pw + placeholder user
		"postgres://user:@host/db",                      // empty pw + placeholder user/host
		"postgresql://user:changeme@db.example.com/app", // placeholder pw + user
	}
	for _, dsn := range drop {
		if !looksTemplateDSN(dsn) {
			t.Errorf("template/example NOT dropped: %q", dsn)
		}
	}
}
