package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/puck-security/geiger/internal/recon"
)

// Enumerating a stdio server means RUNNING the command in the config.
//
// That is categorically different from every other thing geiger does. --intrusive
// connects to services and leaves a trail; this executes an argv that came out of
// a scanned file. `npx -y some-package` in a config geiger was pointed at is
// arbitrary code execution against the operator running geiger — the exact
// primitive this package exists to warn about. So it gets its own flag rather
// than riding on --intrusive, and the guarantees below are not optional:
//
//   - never without --live AND --spawn-stdio
//   - the exact argv is recorded in the audit trail before the process starts
//   - a scrubbed environment: the child gets no inherited credentials, so
//     enumerating a server cannot hand it the secrets it was configured to use
//   - a hard timeout with the process killed on expiry
//   - only initialize + tools/list are written; the pipe is closed immediately
//
// Even so, this is the one geiger operation that runs third-party code, and the
// CLI says so before doing it.

// ErrSpawnNotPermitted is returned when stdio enumeration was not authorized.
var ErrSpawnNotPermitted = errors.New("stdio enumeration requires --live --spawn-stdio")

// spawnTimeout bounds a stdio server's startup and reply. A server that cannot
// list its tools in this long is not going to.
const spawnTimeout = 10 * time.Second

// SpawnOptions controls local stdio enumeration.
type SpawnOptions struct {
	// Permitted is the --spawn-stdio gate. False means no process is started.
	Permitted bool
	// Live mirrors --live; both must hold.
	Live bool
	// Timeout overrides spawnTimeout (tests).
	Timeout time.Duration
	// Record receives the argv about to be executed, for the audit trail. It is
	// called BEFORE the process starts so a killed or hanging spawn is still
	// attributable.
	Record func(argv string)
}

// EnumerateStdio starts a local stdio server, asks it for its tool list, and
// tears it down. It is a no-op unless both gates are open.
func EnumerateStdio(ctx context.Context, s *Server, o SpawnOptions) {
	if s.Command == "" {
		s.EnumErr = "no command to run"
		return
	}
	argv := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
	if !o.Live || !o.Permitted {
		s.EnumErr = "not enumerated: --spawn-stdio would RUN `" + argv + "`"
		return
	}
	s.Asked = true
	if o.Record != nil {
		o.Record(argv)
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = spawnTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tools, err := runStdioProbe(ctx, s, timeout)
	if err != nil {
		s.EnumErr = err.Error()
		return
	}
	applyEnumeration(s, tools)
}

// runStdioProbe executes the server and returns its advertised tools.
func runStdioProbe(ctx context.Context, s *Server, timeout time.Duration) ([]Tool, error) {
	cmd := exec.CommandContext(ctx, s.Command, s.Args...)
	// A scrubbed environment. The config's env block names the credentials this
	// server is meant to receive; geiger deliberately does NOT pass them, so
	// enumeration cannot hand a token to a server it is in the middle of
	// assessing. PATH and HOME are kept because a launcher needs them to resolve
	// at all, and neither is a credential.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"MCP_CLIENT=geiger",
	}
	// Kill the whole group on timeout: npx/uvx fork a child that would otherwise
	// outlive the launcher geiger is waiting on.
	setPgid(cmd)
	cmd.WaitDelay = time.Second

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout: %w", err)
	}
	cmd.Stderr = nil // a server's diagnostics are not geiger's output

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not run %q: %w", s.Command, err)
	}
	defer func() {
		if cmd.Process != nil {
			killGroup(cmd)
		}
		_ = cmd.Wait()
	}()

	// A stdio server may be on either side of the 2026 break, and unlike HTTP
	// there is no status code to distinguish them. Sending the handshake first
	// satisfies a 2025 server and is ignored as an unknown method by a 2026 one,
	// so one sequence covers both.
	write := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = stdin.Write(append(b, '\n'))
		return err
	}
	_ = write(jsonRPCReq{JSONRPC: "2.0", ID: 1, Method: "initialize", Meta: clientMeta(protoStateless),
		Params: map[string]any{
			"protocolVersion": protoLegacy,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "geiger", "version": strings.TrimPrefix(recon.UserAgent, "geiger/")},
		}})
	_ = write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err := write(jsonRPCReq{JSONRPC: "2.0", ID: 2, Method: "tools/list", Meta: clientMeta(protoStateless)}); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	_ = stdin.Close()

	// Read until the response to id 2 arrives, the pipe ends, or the context
	// expires. Lines are bounded so a hostile server cannot balloon memory.
	type framed struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	done := make(chan []Tool, 1)
	errc := make(chan error, 1)
	go func() {
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var f framed
			if json.Unmarshal([]byte(line), &f) != nil || f.ID != 2 {
				continue
			}
			if f.Error != nil {
				errc <- fmt.Errorf("server error: %s", f.Error.Message)
				return
			}
			var tl toolsListResult
			if err := json.Unmarshal(f.Result, &tl); err != nil {
				errc <- fmt.Errorf("unparseable tools/list result")
				return
			}
			out := make([]Tool, 0, len(tl.Tools))
			for _, t := range tl.Tools {
				out = append(out, Tool{Name: t.Name, Description: t.Description})
			}
			done <- out
			return
		}
		errc <- fmt.Errorf("server exited without listing tools")
	}()

	select {
	case tools := <-done:
		return tools, nil
	case err := <-errc:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out after %s waiting for tools/list", timeout)
	}
}
