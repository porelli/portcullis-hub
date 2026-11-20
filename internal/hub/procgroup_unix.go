//go:build unix

package hub

import (
	"os/exec"
	"syscall"
)

// killProcessGroup runs cmd in its own process group and makes its
// context's cancellation kill the whole group (git's helpers too).
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
