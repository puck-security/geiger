package modules

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/dbrecon"
	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
	"github.com/puck-security/geiger/internal/redact"
	"golang.org/x/crypto/ssh"
)

func init() {
	module.Register(dbConnString{})
	module.Register(sshKey{})
	module.Register(kubeConfig{})
	recognize.RegisterRecognizer(recognizeDB)
	recognize.RegisterRecognizer(recognizeSSH)
	recognize.RegisterRecognizer(recognizeKube)
}

// ---- Database connection strings (offline characterization) ----

type dbConnString struct{ module.Base }

func (dbConnString) Name() string { return "db_connection_string" }

func (dbConnString) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	u, err := url.Parse(f["dsn"])
	if err != nil {
		return nil, err
	}
	pw, _ := u.User.Password() // scrub the password out of any surfaced driver error
	var out []module.Finding
	out = append(out, module.Finding{Key: "engine", Value: strings.SplitN(u.Scheme, "+", 2)[0], Flag: module.FlagInfo})
	if host := u.Hostname(); host != "" { // SQLite/file DSNs have no host
		hflag := module.FlagInfo
		if isProd(host) {
			hflag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "host", Value: host, Flag: hflag})
	}
	if user := u.User.Username(); user != "" {
		flag := module.FlagInfo
		if user == "root" || user == "admin" || user == "postgres" {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "user", Value: user, Flag: flag})
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		out = append(out, module.Finding{Key: "database", Value: db, Flag: module.FlagInfo})
	}

	// Live data-plane recon is intrusive (a real DB connection, or reading a
	// local SQLite file) and gated behind --live --intrusive.
	eng := strings.SplitN(u.Scheme, "+", 2)[0]
	switch {
	case eng == "sqlite" || eng == "sqlite3":
		switch {
		case !c.Live() || !c.Intrusive():
			out = append(out, module.Finding{Key: "data access",
				Value: "local SQLite file — read its tables with --live --intrusive", Flag: module.FlagCantCharacterize})
		default:
			switch path := resolveSQLitePath(f["dsn"], f["source"]); path {
			case "":
				out = append(out, module.Finding{Key: "data access",
					Value: "not read: SQLite path is unanchored (stdin/env) or resolves outside the scanned directory — refused", Flag: module.FlagInfo})
			default:
				if live, err := dbrecon.ReconSQLiteFile(ctx, path); err != nil {
					out = append(out, module.Finding{Key: "data access", Value: "not read: " + dbErr(err, f["dsn"]), Flag: module.FlagInfo})
				} else {
					out = append(out, live...)
				}
			}
		}
	case !dbrecon.Supported(f["dsn"]):
		out = append(out, module.Finding{Key: "data access",
			Value: "live recon not implemented for this engine — characterize the connection string offline",
			Flag:  module.FlagCantCharacterize})
	case !c.Live() || !c.Intrusive():
		out = append(out, module.Finding{Key: "data access",
			Value: "live catalog/row recon available with --live --intrusive (connects to the database)",
			Flag:  module.FlagCantCharacterize})
	default:
		live, err := dbrecon.Recon(ctx, f["dsn"])
		switch {
		case err == nil:
			out = append(out, live...)
		case dbrecon.IsAuthError(err):
			// Server reached us and rejected the credential — it's dead.
			out = append(out, module.Finding{Key: "rejected",
				Value: "authentication failed — credential rejected: " + dbErr(err, f["dsn"], pw), Flag: module.FlagCantCharacterize})
		default:
			// Network/reach failure says nothing about validity — not dead.
			out = append(out, module.Finding{Key: "data access",
				Value: "host unreachable: " + dbErr(err, f["dsn"], pw), Flag: module.FlagInfo})
		}
	}
	return out, nil
}

// looksTemplateDSN reports whether a DSN is a documentation/template/example
// rather than a real credential. It errs toward KEEPING credentials: a real,
// non-placeholder password means it's a real cred even if it uses a generic
// user like "user" or a docker host like "db" — so the word-based match only
// fires when the password is itself empty/placeholder. Unambiguous markers
// (<>${}) and a non-numeric ":port" are dropped regardless.
func looksTemplateDSN(dsn string) bool {
	if strings.ContainsAny(dsn, "<>${}") {
		return true
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return true
	}
	if p := u.Port(); p != "" {
		if _, e := strconv.Atoi(p); e != nil {
			return true // ":port" literal
		}
	}
	// A realistic secret => this is a real credential; don't second-guess it.
	if pw, _ := u.User.Password(); realisticSecret(pw) {
		return false
	}
	return isPlaceholderWord(u.Hostname()) || isPlaceholderWord(u.User.Username()) ||
		isPlaceholderWord(strings.TrimPrefix(u.Path, "/"))
}

func isPlaceholderWord(s string) bool {
	switch strings.ToLower(s) {
	case "host", "hostname", "your-host", "yourhost", "your_host", "...",
		"user", "username", "youruser", "your-user", "your_user",
		"db", "dbname", "database", "name", "mydb", "yourdb":
		return true
	}
	return false
}

// realisticSecret reports whether a DSN password looks like a real secret rather
// than a placeholder (empty, too short, or a common example word).
func realisticSecret(pw string) bool {
	if len(pw) < 6 {
		return false
	}
	switch strings.ToLower(pw) {
	case "password", "passwd", "secret", "changeme", "change_me",
		"your-password", "yourpassword", "your_password", "example", "examplepass":
		return false
	}
	return true
}

// resolveSQLitePath turns a sqlite DSN into a concrete file path, CONFINED to
// the directory tree of the source file it was found in. The DSN is untrusted
// scanned content, so an absolute path or a ../ traversal could otherwise make
// --intrusive read an arbitrary file off the responder's host (browser DBs,
// other sqlite stores). Returns "" when the path can't be safely confined: no
// on-disk source to anchor it (stdin/env), or it resolves outside that source
// directory.
func resolveSQLitePath(dsn, source string) string {
	p := dsn
	for _, pre := range []string{"sqlite3://", "sqlite://", "file:"} {
		p = strings.TrimPrefix(p, pre)
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	// SQLAlchemy convention: sqlite:///x = relative "x"; sqlite:////x = absolute "/x".
	switch {
	case strings.HasPrefix(p, "//"):
		p = p[1:]
	case strings.HasPrefix(p, "/"):
		p = p[1:]
	}
	if p == "" {
		return ""
	}
	// Confinement needs a real on-disk anchor; stdin/env can't be confined.
	if source == "" || source == "stdin" || source == "environment" {
		return ""
	}
	dir, err := filepath.Abs(filepath.Dir(source))
	if err != nil {
		return ""
	}
	abs := filepath.Clean(p)
	if !filepath.IsAbs(abs) {
		abs = filepath.Clean(filepath.Join(dir, p))
	}
	// The resolved file must live within the source directory tree.
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return abs
}

// dbErr trims a driver/cluster error to a short message and scrubs credentials
// before they can leak into a finding. It first removes the exact known secrets
// (the DSN and password — drivers often echo the connection string, and
// redact.Line alone misses short passwords), then applies redact.Line for any
// other token-shaped substring.
func dbErr(err error, secrets ...string) string {
	s := err.Error()
	for _, sec := range secrets {
		if len(sec) >= 3 {
			s = strings.ReplaceAll(s, sec, "…")
		}
	}
	s = redact.Line(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func (dbConnString) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	for _, f := range fs {
		if f.Key == "rejected" {
			n.Invalid = true
			n.Reason = "authentication failed — credential rejected"
			return n
		}
	}
	for _, f := range fs {
		if f.Key == "host" && f.Flag == module.FlagWarn {
			n.Summary = "production database credential"
			return n
		}
	}
	n.Summary = "database credential"
	return n
}

var dbRe = regexp.MustCompile(`\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|sqlite(?:3)?|sqlserver|mssql|oracle|clickhouse|cassandra)://[^\s"']+`)

func recognizeDB(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	seen := map[string]bool{}
	var out []recognize.Match
	add := func(dsn, label string) {
		// Skip documentation/template DSNs (host/user/db placeholders, :port,
		// ${VARS}) — they're not credentials and otherwise flood a repo scan.
		if dsn == "" || seen[dsn] || looksTemplateDSN(dsn) {
			return
		}
		seen[dsn] = true
		out = append(out, recognize.Match{Module: "db_connection_string",
			Fields: module.Fields{"dsn": dsn, "source": b.File}, Secret: dsn, Label: label})
	}
	for _, k := range []string{"DATABASE_URL", "REDIS_URL", "MONGO_URL", "MONGODB_URI", "POSTGRES_URL"} {
		add(b.Vars[k], k)
	}
	for _, m := range dbRe.FindAllString(b.Raw, -1) {
		add(m, "connection string")
	}
	return out
}

// ---- SSH private key (offline fingerprint) ----

type sshKey struct{ module.Base }

func (sshKey) Name() string { return "ssh_private_key" }

func (sshKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	raw := []byte(f["key"])
	var out []module.Finding

	signer, err := ssh.ParsePrivateKey(raw)
	var passErr *ssh.PassphraseMissingError
	encrypted := strings.Contains(f["key"], "ENCRYPTED") || errors.As(err, &passErr)

	switch {
	case err == nil:
		pub := signer.PublicKey()
		out = append(out, module.Finding{Key: "type", Value: pub.Type(), Flag: module.FlagInfo})
		out = append(out, module.Finding{Key: "fingerprint", Value: ssh.FingerprintSHA256(pub), Flag: module.FlagInfo})
	case encrypted:
		// Encrypted ≠ dead: the key is valid, just locked at rest. It's usable
		// right now if the passphrase is weak, sits in a nearby file, or is
		// already loaded in ssh-agent.
		out = append(out, module.Finding{
			Key:   "encrypted",
			Value: "passphrase-protected — can't exercise without the passphrase (still usable if it's weak or already in ssh-agent)",
			Flag:  module.FlagCantCharacterize,
		})
		// OpenSSH-format keys store the public key unencrypted; recover it.
		if errors.As(err, &passErr) && passErr.PublicKey != nil {
			out = append(out, module.Finding{Key: "type", Value: passErr.PublicKey.Type(), Flag: module.FlagInfo})
			out = append(out, module.Finding{Key: "fingerprint", Value: ssh.FingerprintSHA256(passErr.PublicKey), Flag: module.FlagInfo})
		} else {
			out = append(out, module.Finding{Key: "fingerprint", Value: "unavailable (encrypted; no embedded public key)", Flag: module.FlagInfo})
		}
	default:
		out = append(out, module.Finding{Key: "key", Value: "private key present (unparseable)", Flag: module.FlagInfo})
	}
	if c.Correlate() {
		if home, err := os.UserHomeDir(); err == nil {
			if hosts := sshCandidateHosts(home); len(hosts) > 0 {
				out = append(out, module.Finding{
					Key:   "candidate targets",
					Value: strings.Join(hosts, ", ") + "  (from local ~/.ssh + history — not confirmed)",
					Flag:  module.FlagWarn,
				})
			}
		}
	}
	// The key's #1 use is git remotes, so on --live confirm whether it actually
	// authenticates to the major git hosts and surface the account it logs in as.
	switch {
	case signer != nil && c.Live():
		out = append(out, sshGitProbe(ctx, signer)...)
	case signer == nil:
		out = append(out, module.Finding{Key: "host acceptance",
			Value: "can't test host access — key is locked (needs the passphrase)", Flag: module.FlagCantCharacterize})
	default:
		out = append(out, module.Finding{Key: "host acceptance",
			Value: "re-run with --live to test GitHub/GitLab/Bitbucket access", Flag: module.FlagCantCharacterize})
	}
	return out, nil
}

func (sshKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs, Summary: "SSH private key — local fingerprint only"}
	for _, f := range fs {
		if f.Key == "reach" || strings.Contains(f.Value, "authenticated as") {
			n.Summary = "SSH private key — confirmed git host access"
			break
		}
	}
	return n
}

// gitSSHHosts are the well-known git-over-SSH endpoints whose post-auth banner
// reveals the account, letting us confirm a key's primary use (repo access).
var gitSSHHosts = []string{"github.com", "gitlab.com", "bitbucket.org"}

// sshGitProbe attempts an SSH login with the key against each git host and
// reports which accept it and as whom. Read-only (an auth test — no repo writes),
// but it is a real, logged login from this host; gated behind --live by the
// caller.
func sshGitProbe(ctx context.Context, signer ssh.Signer) []module.Finding {
	var out []module.Finding
	userKey := false
	for _, h := range gitSSHHosts {
		accepted, banner, transportErr := probeGitHost(ctx, signer, h+":22")
		if transportErr || !accepted {
			continue
		}
		id, deploy := gitIdentity(h, banner)
		val := "authenticated"
		switch {
		case deploy:
			val = "authenticated as deploy key for " + id
		case id != "":
			val = "authenticated as " + id
			userKey = true
		}
		out = append(out, module.Finding{Key: h, Value: val, Flag: module.FlagWarn})
	}
	if userKey {
		out = append(out, module.Finding{Key: "reach",
			Value: "git push access — read private source and push commits to any repo this account can write (supply-chain risk)",
			Flag:  module.FlagForceMultiplier})
	}
	if len(out) == 0 {
		out = append(out, module.Finding{Key: "host acceptance",
			Value: "not accepted by GitHub/GitLab/Bitbucket (key may target another host)", Flag: module.FlagInfo})
	}
	return out
}

// probeGitHost dials addr and attempts public-key auth as "git". A successful
// handshake proves the host accepts the key; the session banner carries the
// identity. A 401-equivalent auth rejection is "not accepted" (the host was
// reached); a dial/handshake failure is a transport error (no verdict on the
// key). Host-key verification is intentionally relaxed for this recon probe —
// pinning would break on the providers' key rotations; the auth result, not the
// channel's confidentiality, is what we report.
func probeGitHost(ctx context.Context, signer ssh.Signer, addr string) (accepted bool, banner string, transportErr bool) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := recon.GuardedDial(dctx, "tcp", addr)
	if err != nil {
		return false, "", true
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "no supported methods") {
			return false, "", false // reached the host; key rejected
		}
		return false, "", true // handshake/transport failure — not a verdict on the key
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return true, "", false // authenticated; couldn't open a session for the banner
	}
	defer sess.Close()
	// git hosts print an identity banner then exit non-zero; CombinedOutput
	// captures it (and ignores the expected non-zero exit).
	b, _ := sess.CombinedOutput("")
	return true, string(b), false
}

// gitIdentity pulls the account (or deploy-key "owner/repo") out of each host's
// post-auth banner.
func gitIdentity(host, banner string) (id string, deploy bool) {
	switch host {
	case "github.com":
		if m := regexp.MustCompile(`Hi ([^!]+)!`).FindStringSubmatch(banner); m != nil {
			id = strings.TrimSpace(m[1])
			deploy = strings.Contains(id, "/") // deploy keys read "Hi owner/repo!"
		}
	case "gitlab.com":
		if m := regexp.MustCompile(`Welcome to GitLab, @?([^!]+)!`).FindStringSubmatch(banner); m != nil {
			id = strings.TrimSpace(m[1])
		}
	case "bitbucket.org":
		if m := regexp.MustCompile(`(?:logged in as|authenticated as) ([^\s.,!]+)`).FindStringSubmatch(banner); m != nil {
			id = strings.TrimSpace(m[1])
		}
	}
	return id, deploy
}

func recognizeSSH(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	// A standalone SSH key is a PEM file, not a JSON object. When the whole blob
	// is JSON (a GCP service-account key, MSAL cache, …), an embedded private key
	// belongs to that structure — don't double-report it as a separate SSH key.
	if b.JSON != nil {
		return nil
	}
	if !strings.Contains(b.Raw, "PRIVATE KEY-----") {
		return nil
	}
	re := regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	var out []recognize.Match
	for _, m := range re.FindAllString(b.Raw, -1) {
		out = append(out, recognize.Match{Module: "ssh_private_key",
			Fields: module.Fields{"key": m}, Secret: "", Label: "private key"})
	}
	return out
}

// ---- kubeconfig (offline characterization) ----

type kubeConfig struct{ module.Base }

func (kubeConfig) Name() string { return "kubeconfig" }

func (kubeConfig) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	var out []module.Finding
	if s := f["server"]; s != "" {
		flag := module.FlagInfo
		if isProd(s) {
			flag = module.FlagWarn
		}
		out = append(out, module.Finding{Key: "api server", Value: s, Flag: flag})
	}
	if cx := f["context"]; cx != "" {
		out = append(out, module.Finding{Key: "context", Value: cx, Flag: module.FlagInfo})
	}

	switch {
	case f["token"] == "" || f["server"] == "":
		out = append(out, module.Finding{Key: "rbac reach",
			Value: "client-cert or no-token kubeconfig — live RBAC enumeration not exercised; cluster-admin = max force multiplier",
			Flag:  module.FlagCantCharacterize})
	case !c.Live() || !c.Intrusive():
		out = append(out, module.Finding{Key: "rbac reach",
			Value: "live RBAC enumeration (SelfSubjectRulesReview) available with --live --intrusive (hits the cluster API)",
			Flag:  module.FlagCantCharacterize})
	default:
		live, err := k8sRecon(ctx, c.Live(), c.Intrusive(), f["server"], f["token"], f["ca_data"])
		if err != nil {
			out = append(out, module.Finding{Key: "rbac reach", Value: "cluster API error: " + dbErr(err, f["token"]), Flag: module.FlagInfo})
		} else {
			out = append(out, live...)
		}
	}
	return out, nil
}

func (kubeConfig) Summarize(title string, fs []module.Finding) module.Note {
	return module.Note{Title: title, Findings: fs, Summary: "kubeconfig — cluster credential"}
}

var kubeServerRe = regexp.MustCompile(`server:\s*(\S+)`)
var kubeContextRe = regexp.MustCompile(`current-context:\s*(\S+)`)
var kubeTokenRe = regexp.MustCompile(`(?m)^\s*token:\s*(\S+)`)
var kubeCARe = regexp.MustCompile(`certificate-authority-data:\s*(\S+)`)

func recognizeKube(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	if !strings.Contains(b.Raw, "apiVersion") || !strings.Contains(b.Raw, "clusters:") {
		return nil
	}
	f := module.Fields{}
	if m := kubeServerRe.FindStringSubmatch(b.Raw); m != nil {
		f["server"] = m[1]
	}
	if m := kubeContextRe.FindStringSubmatch(b.Raw); m != nil {
		f["context"] = m[1]
	}
	secret := ""
	if m := kubeTokenRe.FindStringSubmatch(b.Raw); m != nil {
		f["token"] = m[1]
		secret = m[1]
	}
	if m := kubeCARe.FindStringSubmatch(b.Raw); m != nil {
		f["ca_data"] = m[1]
	}
	return []recognize.Match{{Module: "kubeconfig", Fields: f, Secret: secret, Label: "kubeconfig"}}
}
