package modules

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

// snowflakeKey characterizes a Snowflake programmatic access token via the SQL
// API. A fixed SELECT proves identity and current role (ACCOUNTADMIN and the
// other system roles reach the whole account). --snowflake-intrusive adds the
// data blast radius: the databases the role can see and the roles the user
// holds. Every statement is a fixed read-only query (SELECT / SHOW).
type snowflakeKey struct{ module.Base }

func (snowflakeKey) Name() string { return "snowflake" }

func (snowflakeKey) EndpointPolicy() module.EndpointPolicy {
	return saasOnly("snowflakecomputing.com", "snowflakecomputing.cn")
}

var snowflakePrivRole = regexp.MustCompile(`(?i)^(ACCOUNTADMIN|SECURITYADMIN|SYSADMIN|ORGADMIN)$`)

func (m snowflakeKey) Recon(ctx context.Context, c *recon.Client, _ module.Token, f module.Fields) ([]module.Finding, error) {
	base := f["endpoint"]
	if base == "" {
		return nil, nil
	}
	tok := f["token"]
	var out []module.Finding
	lv := &liveness{}

	// A valid token can always run SELECT CURRENT_USER(); a failure means the
	// token is dead, so the reach/identity findings (and the force-multiplier
	// reach note) are added only on success — otherwise an invalid token would
	// render as live, high-severity access.
	rows, resp := m.sql(ctx, c, base, tok, "SELECT CURRENT_USER(), CURRENT_ROLE()")
	if resp != nil {
		lv.observe(resp, nil, true)
	}
	if len(rows) > 0 && len(rows[0]) >= 2 {
		out = append(out, module.Finding{
			Key:   "reach",
			Value: "query/modify warehouses, databases, and schemas; ACCOUNTADMIN reaches the whole account (all data, users, network policies)",
			Flag:  module.FlagForceMultiplier,
		})
		user, _ := rows[0][0].(string)
		role, _ := rows[0][1].(string)
		if user != "" {
			out = append(out, module.Finding{Key: "user", Value: user, Flag: module.FlagInfo})
		}
		if role != "" {
			flag := module.FlagInfo
			if snowflakePrivRole.MatchString(role) {
				flag = module.FlagForceMultiplier
			}
			out = append(out, module.Finding{Key: "role", Value: role, Flag: flag})
		}
	}

	if c.MinFootprint() {
		return withLiveness(out, 0, lv), nil
	}
	// Deeper reach only when the identity query already confirmed the token lives.
	if c.SnowflakeIntrusive() && len(out) > 0 {
		out = append(out, m.deepReach(ctx, c, base, tok)...)
	}
	return withLiveness(out, 0, lv), nil
}

// deepReach reports the databases the current role can see and the roles the
// user holds.
func (m snowflakeKey) deepReach(ctx context.Context, c *recon.Client, base, tok string) []module.Finding {
	var out []module.Finding

	if rows, _ := m.sql(ctx, c, base, tok, "SHOW DATABASES"); len(rows) > 0 {
		out = append(out, module.Finding{Key: "databases", Value: strconv.Itoa(len(rows)) + " reachable", Flag: module.FlagWarn})
	}

	if rows, _ := m.sql(ctx, c, base, tok, "SHOW GRANTS TO USER CURRENT_USER()"); len(rows) > 0 {
		var priv []string
		seen := map[string]bool{}
		for _, r := range rows {
			for _, cell := range r {
				if s, ok := cell.(string); ok && snowflakePrivRole.MatchString(s) && !seen[s] {
					seen[s] = true
					priv = append(priv, s)
				}
			}
		}
		if len(priv) > 0 {
			out = append(out, module.Finding{Key: "roles", Value: "holds privileged roles: " + strings.Join(priv, ", "), Flag: module.FlagForceMultiplier})
		} else {
			out = append(out, module.Finding{Key: "roles", Value: strconv.Itoa(len(rows)) + " role grant(s)", Flag: module.FlagInfo})
		}
	}
	return out
}

// sql runs a fixed read-only statement and returns the result rows.
func (m snowflakeKey) sql(ctx context.Context, c *recon.Client, base, tok, statement string) ([][]any, *recon.Response) {
	body := []byte(`{"statement":` + jsonQuote(statement) + `,"timeout":60}`)
	req, err := recon.NewRequest(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/v2/statements", body)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Snowflake-Authorization-Token-Type", "PROGRAMMATIC_ACCESS_TOKEN")
	resp, err := c.Do(req, recon.CallOpts{ReadOnlyPOST: true, Note: "snowflake SQL (read-only): " + statement})
	if err != nil || resp.DryRun || resp.Status >= 300 {
		return nil, resp
	}
	data, _ := jsonDecode(resp.Body)["data"].([]any)
	var rows [][]any
	for _, r := range data {
		if cells, ok := r.([]any); ok {
			rows = append(rows, cells)
		}
	}
	return rows, resp
}

func (snowflakeKey) Summarize(title string, fs []module.Finding) module.Note {
	n := module.Note{Title: title, Findings: fs}
	if len(fs) == 0 {
		n.Invalid, n.Reason = true, "Snowflake SQL API returned no result"
		return n
	}
	for _, f := range fs {
		if (f.Key == "role" || f.Key == "roles") && f.Flag == module.FlagForceMultiplier {
			n.Summary = "Snowflake — account-wide access (system role)"
			return n
		}
	}
	n.Summary = "Snowflake — data-warehouse access"
	return n
}

func init() {
	module.Register(snowflakeKey{})
}
