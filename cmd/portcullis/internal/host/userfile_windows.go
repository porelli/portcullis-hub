//go:build windows

package host

import (
	"errors"
	"io"
	"os"
)

// readUserFile reads at most max bytes of a regular file that isn't a
// symlink (M3; Windows hosts are by hand, this keeps the build whole).
func readUserFile(path string, max int64) ([]byte, error) {
	if st, err := os.Lstat(path); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
