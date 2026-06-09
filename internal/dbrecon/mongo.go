package dbrecon

import (
	"context"
	"fmt"
	"time"

	"github.com/puck-security/geiger/internal/module"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// reconMongo connects read-only and reports the databases/collections in reach
// plus any sensitively-named collection's document count. Only read operations
// (listDatabases, listCollections, estimatedDocumentCount) are issued.
func reconMongo(ctx context.Context, dsn string) ([]module.Finding, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cl, err := mongo.Connect(cctx, options.Client().ApplyURI(stripFileParams(dsn)).
		SetConnectTimeout(5*time.Second).SetServerSelectionTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	defer func() { _ = cl.Disconnect(context.Background()) }()
	if err := cl.Ping(cctx, nil); err != nil {
		return nil, err
	}

	dbs, err := cl.ListDatabaseNames(cctx, bson.D{})
	if err != nil {
		// Connected, but the user can't list databases — still a valid credential.
		return []module.Finding{{Key: "connected", Value: "authenticated; listDatabases denied (scoped user)", Flag: module.FlagWarn}}, nil
	}
	out := []module.Finding{{Key: "databases", Value: itoa(len(dbs)), Flag: module.FlagInfo}}

	var sensitive []string
	scanned := 0
	for _, dbn := range dbs {
		switch dbn {
		case "admin", "local", "config":
			continue
		}
		if scanned >= 8 || len(sensitive) >= 20 {
			break
		}
		scanned++
		cols, err := cl.Database(dbn).ListCollectionNames(cctx, bson.D{})
		if err != nil {
			continue
		}
		for _, col := range cols {
			if !sensitiveTable.MatchString(col) {
				continue
			}
			n, _ := cl.Database(dbn).Collection(col).EstimatedDocumentCount(cctx)
			sensitive = append(sensitive, fmt.Sprintf("%s.%s(%d)", dbn, col, n))
		}
	}
	if len(sensitive) > 0 {
		v := joinCapped(sensitive, 240)
		out = append(out, module.Finding{Key: "sensitive collections", Value: v + " — readable", Flag: module.FlagForceMultiplier})
	}
	return out, nil
}

func joinCapped(parts []string, max int) string {
	s := ""
	for i, p := range parts {
		if i > 0 {
			s += ", "
		}
		if len(s)+len(p) > max {
			return s + "…"
		}
		s += p
	}
	return s
}
