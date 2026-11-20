//go:build !unix

package hub

import "os/exec"

// killProcessGroup: cancellation kills the process only (the Hub runs on
// Linux).
func killProcessGroup(*exec.Cmd) {}
