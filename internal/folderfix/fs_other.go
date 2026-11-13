//go:build unix && !linux

package folderfix

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/portcullis/hub/internal/idmap"
)

// Other unix systems (developer machines): the same fd-relative walk, but no
// POSIX ACLs, no mount ids and no mountinfo. The fixer only runs on Linux.

func lstatAt(dirfd int, name string) (fileStat, error) {
	var st unix.Stat_t
	if err := ignoringEINTR(func() error { return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return fileStat{}, err
	}
	return fromStat(&st), nil
}

func fstatFD(fd int) (fileStat, error) {
	var st unix.Stat_t
	if err := ignoringEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		return fileStat{}, err
	}
	return fromStat(&st), nil
}

func fromStat(st *unix.Stat_t) fileStat {
	return fileStat{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Mode: uint32(st.Mode), Nlink: uint64(st.Nlink),
		UID: st.Uid, GID: st.Gid}
}

func ignoringEINTR(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY

func openFlags(dirfd int, name string, flags int) (int, error) {
	var fd int
	err := ignoringEINTR(func() (err error) { fd, err = unix.Openat(dirfd, name, flags, 0); return err })
	return fd, err
}

func openRootDir(path string) (int, error) { return openFlags(unix.AT_FDCWD, path, dirFlags) }

func openAt(dirfd int, name string, dir bool) (int, error) {
	if dir {
		return openFlags(dirfd, name, dirFlags)
	}
	return openFlags(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY)
}

func closeFD(fd int) { _ = unix.Close(fd) }

func dupFD(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0) }

func readNames(fd int) ([]string, error) {
	d, err := dupFD(fd)
	if err != nil {
		return nil, err
	}
	defer unix.Close(d)
	buf := make([]byte, 64<<10)
	var names []string
	for {
		var n int
		err := ignoringEINTR(func() (err error) { n, err = unix.ReadDirent(d, buf); return err })
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
		if len(names) > maxDirNames {
			return names[:maxDirNames], errTooManyNames
		}
	}
}

var errNoXattr = errors.New("no POSIX ACLs on this system")

func getXattr(int, string) ([]byte, error) { return nil, errNoXattr }

// hasFileCaps: file capabilities are Linux-only.
func hasFileCaps(int) (bool, error)        { return false, nil }
func setXattr(int, string, []byte) error   { return errNoXattr }
func removeXattr(int, string) error        { return errNoXattr }
func support(int) (acl, xattr bool)        { return false, false }
func readMountinfo() ([]mountEntry, error) { return nil, nil }
func procIDMaps() (uid, gid idmap.Map, err error) {
	id := idmap.Map{{Container: 0, Host: 0, Size: 4294967295}}
	return id, id, nil
}
func selinuxLabel(int) string { return "" }

func fchown(fd int, uid, gid uint32) error {
	return ignoringEINTR(func() error { return unix.Fchown(fd, int(uid), int(gid)) })
}

func fchmod(fd int, mode uint32) error {
	return ignoringEINTR(func() error { return unix.Fchmod(fd, mode&07777) })
}

// atFDCWD: openPathDir relative to the working directory (an absolute
// path).
const atFDCWD = unix.AT_FDCWD

// openPathDir / chownPathFD / chmodPathFD: no O_PATH here (developer
// machines): a plain directory fd.
func openPathDir(dirfd int, name string) (int, error) { return openFlags(dirfd, name, dirFlags) }

func chownPathFD(fd int, uid, gid uint32) error { return fchown(fd, uid, gid) }

func chmodPathFD(fd int, mode uint32) error { return fchmod(fd, mode) }

func mkdirAt(dirfd int, name string, mode uint32) error {
	return ignoringEINTR(func() error { return unix.Mkdirat(dirfd, name, mode) })
}

func fsInfo(fd int) (name string, free, total uint64, err error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd, &s); err != nil {
		return "", 0, 0, err
	}
	return "other", s.Bavail * uint64(s.Bsize), s.Blocks * uint64(s.Bsize), nil
}

const syscallNoFollow = unix.O_NOFOLLOW
