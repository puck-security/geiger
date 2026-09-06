//go:build windows

package agent

import "os/exec"

// Windows has no process groups in the POSIX sense that exec exposes portably;
// CommandContext's own kill plus WaitDelay is the available guarantee.
func setPgid(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
