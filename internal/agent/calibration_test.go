package agent

import (
	"testing"

	"github.com/puck-security/geiger/internal/score"
)

// Tier calibration.
//
// Severity has to mean something across a fleet, so the ladder is pinned here
// rather than left to emerge from whatever findings happen to be added later.
// The rule these cases encode: a config file says what an agent is wired to, not
// whether that is appropriate for the machine it is on, so an ordinary developer
// setup stays at INFO. The scale is spent on what the file does establish — a
// filesystem root that is not scoped, several capabilities meeting in one
// context, and no approval prompt in front of them.
func TestTierCalibration(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want score.Tier
	}{
		{
			// One filesystem server scoped to a project. The most common MCP
			// setup there is; nothing here says anything went wrong.
			name: "one scoped filesystem server",
			raw: `{"mcpServers":{
				"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","./project"]}}}`,
			want: score.TierInfo,
		},
		{
			// A working developer laptop: a scoped project directory, a local
			// database, a clock. Reach, but no two halves of anything meet.
			name: "ordinary developer laptop",
			raw: `{"mcpServers":{
				"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","./project"]},
				"db":{"command":"uvx","args":["mcp-server-sqlite","--db-path","./app.db"]},
				"clock":{"command":"npx","args":["-y","@modelcontextprotocol/server-time"]}}}`,
			want: score.TierInfo,
		},
		{
			// The filesystem server is rooted at the whole disk. That is in the
			// file, and it is the difference between a project helper and a
			// credential sweep, so it is worth a mark on its own.
			name: "filesystem server rooted at /",
			raw: `{"mcpServers":{
				"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}}}`,
			want: score.TierLow,
		},
		{
			// Untrusted content, private data and an outbound channel now share
			// one context. A poisoned page is enough.
			name: "wiki plus web fetch",
			raw: `{"mcpServers":{
				"wiki":{"command":"uvx","args":["mcp-atlassian"]},
				"web":{"command":"uvx","args":["mcp-server-fetch"]}}}`,
			want: score.TierHigh,
		},
		{
			// Everything at once, and no prompt in front of any of it.
			name: "wide open",
			raw: `{
				"mcpServers":{
					"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]},
					"sh":{"command":"uvx","args":["mcp-server-shell"]},
					"vault":{"command":"uvx","args":["mcp-vault"]},
					"slack":{"command":"npx","args":["-y","@modelcontextprotocol/server-slack"]}},
				"permissions":{"defaultMode":"bypassPermissions"}}`,
			want: score.TierCritical,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := parse(t, "mcp.json", tc.raw).Summarize(tc.name)
			got := score.TierFor(n, score.Context{})
			if got != tc.want {
				t.Errorf("tier = %s (score %d), want %s", got, score.BlastRadius(n, score.Context{}), tc.want)
				for _, f := range n.Findings {
					t.Logf("  [%d] %s: %s", f.Flag, f.Key, f.Value)
				}
			}
		})
	}
}
