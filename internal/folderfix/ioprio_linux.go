//go:build linux

package folderfix

import "golang.org/x/sys/unix"

// setIdleIO lowers the process's IO priority to the idle class
// (ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13); no
// capability needed), best effort: false when the kernel refused.
func setIdleIO() bool {
	const whoProcess, classIdle, classShift = 1, 3, 13
	_, _, errno := unix.Syscall(unix.SYS_IOPRIO_SET, whoProcess, 0, classIdle<<classShift)
	return errno == 0
}
