package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/puck-security/geiger/internal/recon"
)

// Live enumeration: ask the server what it actually exposes.
//
// tools/list, resources/list and prompts/list are pure reads — they are the
// protocol's own inventory methods, they mutate nothing, and under the 2026-07-28
// specification they do not even open a session. They go through recon's
// ReadOnlyPOST carve-out alongside sts:GetCallerIdentity and k8s
// SelfSubjectRulesReview. tools/call is NEVER issued: that is the line between
// enumerating reach and exercising it.
//
// Enumeration replaces what the catalog says a package does with the server's
// own account of what it exposes. It also surfaces what no config can show: a
// tool surface open to anyone who can route to it, the authorization server
// behind a 401, and the real tool and resource counts.

// Protocol versions geiger will speak, newest first. The wire protocol changed
// materially at 2026-07-28 — sessions and the initialize/initialized handshake
// were removed, every request now carries its version in _meta, and servers MUST
// implement server/discover — so a probe has to try both shapes.
const (
	protoStateless = "2026-07-28" // stateless: server/discover, no handshake
	protoLegacy    = "2025-06-18" // handshake required before any list call
)

// jsonRPCReq is one request. The 2026 spec carries the protocol version and
// client identity in _meta rather than in a session established up front.
type jsonRPCReq struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
	Meta    map[string]any `json:"_meta,omitempty"`
}

type jsonRPCResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type toolsListResult struct {
	Tools []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"tools"`
}

type countResult struct {
	Resources []json.RawMessage `json:"resources"`
	Prompts   []json.RawMessage `json:"prompts"`
}

// clientMeta is the _meta block identifying geiger to a 2026-spec server.
// Honest attribution, consistent with the rest of geiger's recon: a defender
// reading their MCP access log sees exactly who enumerated them.
func clientMeta(version string) map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    version,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name": "geiger", "version": strings.TrimPrefix(recon.UserAgent, "geiger/"),
		},
	}
}

// EnumerateRemote lists a remote server's tools read-only. It tries the
// stateless 2026 shape first and falls back to the 2025 handshake, so a server
// on either side of the break is enumerated by the same call.
func EnumerateRemote(ctx context.Context, c *recon.Client, s *Server) {
	if !c.Live() {
		// Dry-run still records the planned calls, so an operator sees exactly
		// what --live would send before sending it.
		_, _ = rpc(ctx, c, s.URL, "tools/list", nil, protoStateless)
		s.EnumErr = "dry-run: re-run with --live to enumerate the tool surface"
		return
	}

	s.Asked = true
	body, err := rpc(ctx, c, s.URL, "tools/list", nil, protoStateless)
	if err != nil {
		// A 2025-era server rejects a bare list call until the handshake has
		// run. Do the handshake and retry once.
		if handshake(ctx, c, s.URL) {
			body, err = rpc(ctx, c, s.URL, "tools/list", nil, protoLegacy)
		}
	}
	if err != nil {
		s.EnumErr = err.Error()
		if as := authServerFrom(err); as != "" {
			s.AuthServer = as
		}
		return
	}

	var tl toolsListResult
	if err := json.Unmarshal(body, &tl); err != nil {
		s.EnumErr = "unparseable tools/list result"
		return
	}
	tools := make([]Tool, 0, len(tl.Tools))
	for _, t := range tl.Tools {
		tools = append(tools, Tool{Name: t.Name, Description: t.Description})
	}
	applyEnumeration(s, tools)

	// The credential that reached the server is the one in the config. If we
	// sent none and still got a tool list, the surface is open to anyone who can
	// route to it — a finding in its own right, independent of any credential.
	if len(s.HeaderNames) == 0 {
		s.Unauthenticated = true
	}

	// Resource and prompt counts size the reachable content behind the tools.
	if raw, err := rpc(ctx, c, s.URL, "resources/list", nil, protoStateless); err == nil {
		var cr countResult
		if json.Unmarshal(raw, &cr) == nil {
			s.ResourceCount = len(cr.Resources)
		}
	}
	if raw, err := rpc(ctx, c, s.URL, "prompts/list", nil, protoStateless); err == nil {
		var cr countResult
		if json.Unmarshal(raw, &cr) == nil {
			s.PromptCount = len(cr.Prompts)
		}
	}
}

// applyEnumeration records an observed tool list and folds its classification
// into the server's capabilities. This is the only place Enumerated is set: the
// flag means "a server told us what it does", which is what the note's evidence
// line reports and what sharpens a catalog guess into the real tool set.
func applyEnumeration(s *Server, tools []Tool) {
	s.Enumerated = true
	s.Tools = ToolNames(tools)
	observed, unclassified := ClassifyTools(tools)
	s.Caps = s.Caps.Merge(observed)
	s.Caps = refineFSScope(s.Caps, s)
	s.Caps = demoteRedundantDataRead(s.Caps)
	if unclassified > 0 {
		s.EnumErr = fmt.Sprintf("%d of %d tools matched no capability rule", unclassified, len(tools))
	}
}

// handshake runs the 2025-era initialize exchange. It is a POST that creates no
// resource and returns the server's capabilities — read-only in the same sense
// as the list calls it unlocks.
func handshake(ctx context.Context, c *recon.Client, endpoint string) bool {
	_, err := rpc(ctx, c, endpoint, "initialize", map[string]any{
		"protocolVersion": protoLegacy,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "geiger", "version": strings.TrimPrefix(recon.UserAgent, "geiger/")},
	}, protoLegacy)
	return err == nil
}

// rpc issues one JSON-RPC call and returns its result payload.
func rpc(ctx context.Context, c *recon.Client, endpoint, method string, params map[string]any, version string) (json.RawMessage, error) {
	payload, err := json.Marshal(jsonRPCReq{
		JSONRPC: "2.0", ID: 1, Method: method, Params: params, Meta: clientMeta(version),
	})
	if err != nil {
		return nil, err
	}
	req, err := recon.NewRequest(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// A 2026 server may stream the response; a 2025 one may reply over SSE.
	req.Header.Set("Accept", "application/json, text/event-stream")
	// Required on Streamable HTTP POSTs since 2026-07-28 so gateways can route
	// and meter without parsing the body. Harmless to older servers.
	req.Header.Set("Mcp-Method", method)
	req.Header.Set("Mcp-Name", method)
	req.Header.Set("MCP-Protocol-Version", version)

	resp, err := c.Do(req, recon.CallOpts{
		ReadOnlyPOST: true,
		Note:         "mcp " + method + " (read-only capability enumeration; never tools/call)",
	})
	if err != nil {
		return nil, err
	}
	if resp.DryRun {
		return nil, errDryRun
	}
	if resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
		return nil, &authError{status: resp.Status, header: resp.Header.Get("WWW-Authenticate")}
	}
	if resp.Status >= 300 {
		return nil, fmt.Errorf("%s returned HTTP %d", method, resp.Status)
	}
	return decodeRPC(resp.Body)
}

// errDryRun marks a call that was recorded rather than sent.
var errDryRun = fmt.Errorf("dry-run")

// authError carries a 401/403 plus the challenge, so the note can name the
// authorization server that actually gates this reach.
type authError struct {
	status int
	header string
}

func (e *authError) Error() string {
	if e.header == "" {
		return fmt.Sprintf("authentication required (HTTP %d)", e.status)
	}
	return fmt.Sprintf("authentication required (HTTP %d): %s", e.status, e.header)
}

// authServerFrom pulls the authorization-server hint out of a 401 challenge.
// RFC 9728 protected-resource metadata is how a 2025+ MCP server points a client
// at its issuer, so the challenge names which IdP holds the keys to this surface.
func authServerFrom(err error) string {
	ae, ok := err.(*authError)
	if !ok || ae.header == "" {
		return ""
	}
	// A challenge is `<scheme> k="v", k2="v2"`, so the parameters are separated
	// from each other by commas AND from the scheme by a space. Split on both.
	for _, part := range strings.FieldsFunc(ae.header, func(r rune) bool { return r == ',' || r == ' ' }) {
		for _, k := range []string{"resource_metadata=", "as_uri=", "realm="} {
			if !strings.HasPrefix(part, k) {
				continue
			}
			return strings.Trim(strings.TrimPrefix(part, k), `"`)
		}
	}
	return ""
}

// decodeRPC extracts the result from a JSON-RPC body, tolerating an SSE-framed
// reply (a server may answer a POST with a text/event-stream containing one
// data: line, which is still a single JSON-RPC response).
func decodeRPC(body []byte) (json.RawMessage, error) {
	body = bytes.TrimSpace(body)
	if bytes.HasPrefix(body, []byte("event:")) || bytes.HasPrefix(body, []byte("data:")) {
		for _, line := range bytes.Split(body, []byte("\n")) {
			if after, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:")); ok {
				body = bytes.TrimSpace(after)
				break
			}
		}
	}
	var r jsonRPCResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("unparseable JSON-RPC response")
	}
	if r.Error != nil {
		return nil, fmt.Errorf("server error %d: %s", r.Error.Code, r.Error.Message)
	}
	if len(r.Result) == 0 {
		return nil, fmt.Errorf("empty result")
	}
	return r.Result, nil
}
