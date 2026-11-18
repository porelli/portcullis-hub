//go:build !windows

package host

import "syscall"

func hup(pid int) error { return syscall.Kill(pid, syscall.SIGHUP) }
