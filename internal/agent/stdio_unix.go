//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// setPgid puts the child in its own process group so the whole tree can be
// killed together. npx and uvx exec a child of their own; killing only the
// launcher leaves the real server running after geiger has moved on.
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup signals the child's entire process group.
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil && pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}
