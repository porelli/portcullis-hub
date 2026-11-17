//go:build !linux

package folderfix

// setIdleIO: only Linux has ioprio_set.
func setIdleIO() bool { return false }
