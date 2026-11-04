//go:build linux

package folderfix

import (
	"errors"
	"os"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Linux syscalls of the walk. Every call is relative to an fd the walk
// opened itself, never a path the kernel would resolve through a symlink.

var noStatx atomic.Bool // statx returned ENOSYS once: fstatat from then on

const statxWant = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID |
	unix.STATX_GID | unix.STATX_INO | unix.STATX_MNT_ID

const statxNeed = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_UID |
	unix.STATX_GID | unix.STATX_INO

// statAt is fstatat(dirfd, name, flags) through statx, so the mount id comes
// with it (a bind mount of the same filesystem has the root's st_dev).
func statAt(dirfd int, name string, flags int) (fileStat, error) {
	if !noStatx.Load() {
		var x unix.Statx_t
		err := ignoringEINTR(func() error {
			return unix.Statx(dirfd, name, flags|unix.AT_STATX_SYNC_AS_STAT, statxWant, &x)
		})
		if err == nil {
			if x.Mask&statxNeed != statxNeed {
				return fileStat{}, errors.New("statx: basic fields missing")
			}
			s := fileStat{Dev: unix.Mkdev(x.Dev_major, x.Dev_minor), Ino: x.Ino, Mode: uint32(x.Mode),
				Nlink: uint64(x.Nlink), UID: x.Uid, GID: x.Gid}
			if x.Mask&unix.STATX_MNT_ID != 0 {
				s.MntID = x.Mnt_id
			}
			return s, nil
		}
		if !errors.Is(err, unix.ENOSYS) {
			return fileStat{}, err
		}
		noStatx.Store(true)
	}
	var st unix.Stat_t
	if err := ignoringEINTR(func() error { return unix.Fstatat(dirfd, name, &st, flags) }); err != nil {
		return fileStat{}, err
	}
	return fileStat{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Mode: st.Mode, Nlink: uint64(st.Nlink),
		UID: st.Uid, GID: st.Gid}, nil
}

func lstatAt(dirfd int, name string) (fileStat, error) {
	return statAt(dirfd, name, unix.AT_SYMLINK_NOFOLLOW)
}

func fstatFD(fd int) (fileStat, error) { return statAt(fd, "", unix.AT_EMPTY_PATH) }

func ignoringEINTR(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// openNoatime opens with O_NOATIME, falling back without it where the
// kernel refuses it (EPERM: neither the owner nor CAP_FOWNER).
func openNoatime(dirfd int, name string, flags int) (int, error) {
	var fd int
	err := ignoringEINTR(func() (err error) {
		fd, err = rawOpenat(dirfd, name, flags|unix.O_NOATIME, 0)
		return err
	})
	if errors.Is(err, unix.EPERM) {
		err = ignoringEINTR(func() (err error) {
			fd, err = rawOpenat(dirfd, name, flags, 0)
			return err
		})
	}
	return fd, err
}

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY

func openRootDir(path string) (int, error) { return openNoatime(unix.AT_FDCWD, path, dirFlags) }

// openAt opens a directory (O_DIRECTORY: a non-directory fails before any
// driver open) or a regular file. A regular file is first opened O_PATH
// (no driver open, no permission check) and only re-opened, through its
// /proc/self/fd magic link — the same inode, no path lookup — once fstat on
// that fd says it is a regular file: a device or FIFO swapped in after the
// walk's fstatat is never opened.
func openAt(dirfd int, name string, dir bool) (int, error) {
	if dir {
		return openNoatime(dirfd, name, dirFlags)
	}
	var pfd int
	err := ignoringEINTR(func() (err error) {
		pfd, err = rawOpenat(dirfd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return err
	})
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	ps, err := fstatFD(pfd)
	if err != nil {
		return -1, err
	}
	if ps.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, errNotRegular
	}
	fd, err := openNoatime(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(pfd),
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func closeFD(fd int) { _ = unix.Close(fd) }

func dupFD(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0) }

// readNames lists a directory's entries by getdents on the walk's own fd
// ("." and ".." left out). os.File.ReadDir would lstat by path where the
// filesystem gives no d_type.
func readNames(fd int) ([]string, error) {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10)
	var names []string
	for {
		var n int
		err := ignoringEINTR(func() (err error) { n, err = unix.ReadDirent(fd, buf); return err })
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

const maxXattr = 64 << 10

// xattrCapability is the file capabilities xattr (R54).
const xattrCapability = "security.capability"

// hasFileCaps reports whether the file carries security.capability. A
// filesystem without xattrs has none.
func hasFileCaps(fd int) (bool, error) {
	_, err := unix.Fgetxattr(fd, xattrCapability, nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP):
		return false, nil
	}
	return false, err
}

// getXattr reads an xattr through the fd; nil when the entry has none.
func getXattr(fd int, name string) ([]byte, error) {
	buf := make([]byte, 256)
	for {
		n, err := unix.Fgetxattr(fd, name, buf)
		switch {
		case errors.Is(err, unix.ENODATA):
			return nil, nil
		case errors.Is(err, unix.ERANGE):
			size, err := unix.Fgetxattr(fd, name, nil)
			if err != nil {
				return nil, err
			}
			if size > maxXattr {
				return nil, errors.New("xattr too large")
			}
			buf = make([]byte, size+64)
			continue
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return nil, err
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
}

func setXattr(fd int, name string, b []byte) error {
	return ignoringEINTR(func() error { return unix.Fsetxattr(fd, name, b, 0) })
}

func removeXattr(fd int, name string) error {
	err := ignoringEINTR(func() error { return unix.Fremovexattr(fd, name) })
	if errors.Is(err, unix.ENODATA) {
		return nil
	}
	return err
}

func fchown(fd int, uid, gid uint32) error {
	return ignoringEINTR(func() error { return unix.Fchown(fd, int(uid), int(gid)) })
}

func fchmod(fd int, mode uint32) error {
	return ignoringEINTR(func() error { return unix.Fchmod(fd, mode&07777) })
}

func mkdirAt(dirfd int, name string, mode uint32) error {
	return ignoringEINTR(func() error { return unix.Mkdirat(dirfd, name, mode) })
}

// support reports whether the root's filesystem takes POSIX ACLs and xattrs.
func support(fd int) (acl, xattr bool) {
	_, err := unix.Fgetxattr(fd, XattrAccess, nil)
	acl = err == nil || errors.Is(err, unix.ENODATA)
	_, err = unix.Fgetxattr(fd, "user.portcullis.probe", nil)
	xattr = err == nil || errors.Is(err, unix.ENODATA)
	return acl, xattr
}

func fsInfo(fd int) (name string, free, total uint64, err error) {
	var s unix.Statfs_t
	if err := ignoringEINTR(func() error { return unix.Fstatfs(fd, &s) }); err != nil {
		return "", 0, 0, err
	}
	return FSName(int64(s.Type)), s.Bavail * uint64(s.Bsize), s.Blocks * uint64(s.Bsize), nil
}

func readMountinfo() ([]mountEntry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountinfo(f)
}

// idMapsIdentity: the fixer refuses to change owners under a user
// namespace whose ids aren't the host's (userns-remap, rootless).
func idMapsIdentity() (bool, error) {
	for _, p := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		b, err := os.ReadFile(p)
		if err != nil {
			return false, err
		}
		if !identityMap(string(b)) {
			return false, nil
		}
	}
	return true, nil
}

const syscallNoFollow = unix.O_NOFOLLOW

// rawOpenat is every openat the walk makes (a seam for tests).
var rawOpenat = unix.Openat
