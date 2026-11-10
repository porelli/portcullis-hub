//go:build !unix

package fsutil

import "errors"

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("locked by another process")

// TryLock is unsupported here: the Hub runs on Linux.
func TryLock(path string) (release func(), err error) {
	return nil, errors.New("advisory locks need a unix system")
}
