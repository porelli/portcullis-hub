//go:build !windows

package host

import (
	"io/fs"
	"syscall"
)

func fileUID(st fs.FileInfo) (int, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(s.Uid), true
}
