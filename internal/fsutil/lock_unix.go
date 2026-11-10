//go:build unix

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("locked by another process")

// TryLock takes an advisory, exclusive flock on path (created 0600 when
// missing) without waiting: ErrLocked when another process holds it. The
// lock lasts until release is called or the process ends.
func TryLock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", path, ErrLocked)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
