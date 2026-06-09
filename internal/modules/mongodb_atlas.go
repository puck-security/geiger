package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/puck-security/geiger/internal/auth"
	"github.com/puck-security/geiger/internal/module"
	r "github.com/puck-security/geiger/internal/module/recipe"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// MongoDB Atlas Service Account (the 2024+ OAuth2 model): a client_id/secret
// pair, prefixed mdb_sa_id_ / mdb_sa_sk_, exchanged for a bearer via the
// client_credentials grant with HTTP Basic client auth, then used against the
// Atlas Administration API. (The legacy Programmatic API Keys use HTTP Digest —
// see internal/sign — and are not yet wired up here.)

func init() { registerMongoDBAtlas() }

func registerMongoDBAtlas() {
	add("", r.HTTP{
		ModuleName: "mongodb_atlas", Base: "https://cloud.mongodb.com",
		// The Admin API requires a versioned media type or it returns 406.
		Accept: "application/vnd.atlas.2023-11-15+json",
		Auth:   r.AuthSpec{Kind: r.PreAuthed},
		Authenticate: func(ctx context.Context, c *recon.Client, f module.Fields) (module.Token, error) {
			// grant_type in the body; client_id:client_secret as HTTP Basic.
			return auth.Exchange(ctx, c, "https://cloud.mongodb.com/api/oauth/token",
				url.Values{"grant_type": {"client_credentials"}},
				auth.BasicAuthExtra(f["client_id"], f["client_secret"]))
		},
		Whoami: r.GET("/api/atlas/v2/orgs").
			Field("org", "results.0.name").
			CountFlag("totalCount", "organizations", warnFlag),
		Calls: []r.Call{
			r.GET("/api/atlas/v2/groups").CountFlag("totalCount", "projects", warnFlag),
		},
		Static: []module.Finding{
			{Key: "reach", Value: "Atlas Admin API: can manage clusters, create database users, and open network access (0.0.0.0/0) — a path to full database compromise", Flag: fmFlag},
		},
		Summarize: func([]module.Finding) string {
			return "MongoDB Atlas service account — Admin API access to orgs/projects/clusters"
		},
	}.Module())
	recognize.RegisterRecognizer(recognizeMongoDBAtlasSA)
}

// recognizeMongoDBAtlasSA pairs the service-account id and secret by their value
// prefixes, so it matches regardless of the variable names they're stored under
// (MONGODB_ATLAS_CLIENT_ID, ATLAS_SA_*, plain client_id, …).
func recognizeMongoDBAtlasSA(b parse.Blob, _ string, _ *module.Registry) []recognize.Match {
	var id, secret, secretKey string
	for k, v := range b.Vars {
		switch {
		case strings.HasPrefix(v, "mdb_sa_id_"):
			id = v
		case strings.HasPrefix(v, "mdb_sa_sk_"):
			secret, secretKey = v, k
		}
	}
	// A secret pasted alone (stdin) still gets the prefix treatment.
	if secret == "" && strings.HasPrefix(strings.TrimSpace(b.Raw), "mdb_sa_sk_") {
		secret = strings.TrimSpace(b.Raw)
	}
	if id == "" || secret == "" {
		return nil // need both halves to exercise the client_credentials grant
	}
	label := secretKey
	if label == "" {
		label = "MongoDB Atlas service account"
	}
	return []recognize.Match{{
		Module: "mongodb_atlas",
		Fields: module.Fields{"client_id": id, "client_secret": secret},
		Secret: secret, Label: label,
	}}
}
