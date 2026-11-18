//go:build !windows

package host

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// readUserFile opens path without following a symlink and without
// blocking (a FIFO), and reads at most max bytes of a regular file (M3):
// the root agent reads files people control (their authorized_keys).
func readUserFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, max))
}
