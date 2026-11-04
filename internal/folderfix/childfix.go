package folderfix

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// childfix (contract §6, §14.6 person_tree_owner; plan 3 F33): one
// per-person tree's top-level directory <root>/<rel>/<name> given to
// uid:uid with mode 0700. Not recursive: nothing inside it changes. The
// tree is followed below root one component at a time (O_NOFOLLOW, as
// probe does); the child is opened O_NOFOLLOW|O_DIRECTORY relative to the
// tree; a symlink, a non-directory, another mount, another inode than the
// preview's or another mount root is refused (exit 2) before anything
// changes. The change is fchown then fchmod through that fd.
//
// The fixer runs with CHOWN and FOWNER only (no DAC_READ_SEARCH): every
// directory is opened O_PATH (Linux), which needs search permission on
// its parent only — the tree's path must be searchable by "others", as
// bind roots and trees are — so a person's 0700 directory is reached
// without reading it, and the chown / chmod go through that fd
// (fchownat AT_EMPTY_PATH, chmod of its /proc/self/fd link).

// ChildMode is the mode childfix gives a person's directory.
const ChildMode = 0o700

// ChildFix is the child childfix changes: its name (one path component)
// and the uid it gets (owner and group).
type ChildFix struct {
	Name string
	UID  int
}

// validChildName: one component, no ':' (the --child separator), no
// control character, at most 255 bytes.
func validChildName(n string) error {
	if n == "" || n == "." || n == ".." || strings.ContainsRune(n, '/') {
		return fmt.Errorf("child %q: want one directory name", clip(n, 80))
	}
	return validSubpath(n)
}

func formatChild(c ChildFix) string { return fmt.Sprintf("%s:%d", c.Name, c.UID) }

func parseChild(s string) (ChildFix, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return ChildFix{}, fmt.Errorf("--child %q: want name:uid", clip(s, 80))
	}
	c := ChildFix{Name: s[:i]}
	if err := validChildName(c.Name); err != nil {
		return ChildFix{}, err
	}
	uid, err := parseID(s[i+1:])
	if err != nil || uid == 0 {
		return ChildFix{}, fmt.Errorf("--child %q: want a uid above 0", clip(s, 80))
	}
	c.UID = uid
	return c, nil
}

// FixChild runs childfix: o.Root the bind root, rel the tree below it, c
// the child; o.ExpectDev / ExpectIno the child's device and inode and
// o.ExpectMountRoot its mount root, as the preview's probe saw them. The
// report: Dev, Ino and MountRoot of the child, Changed 1 (0: it already
// was uid:uid 0700) and Children the child as it is afterwards.
func FixChild(o Options, rel string, c ChildFix) (*Report, error) {
	r := &Report{Version: 1, Mode: "childfix", Root: o.Root}
	if err := validRoot(o.Root); err != nil {
		return r, err
	}
	if err := validSubpath(rel); err != nil {
		return r, err
	}
	if err := validChildName(c.Name); err != nil {
		return r, err
	}
	if c.UID <= 0 || c.UID >= 0xFFFFFFFF {
		return r, fmt.Errorf("uid %d out of range", c.UID)
	}
	if o.ExpectDev == 0 || o.ExpectIno == 0 || o.ExpectMountRoot == "" {
		return r, refuse("childfix needs the child's device, inode and mount root")
	}
	fd, err := openPathDir(atFDCWD, o.Root)
	if err != nil {
		return r, refuse("open %s: %v", o.Root, err)
	}
	defer func() { closeFD(fd) }()
	// The tree, one component at a time (never a path the kernel
	// resolves through a symlink).
	at := "."
	for _, comp := range strings.Split(rel, "/") {
		crel := joinRel(at, comp)
		st, err := lstatAt(fd, comp)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return r, refuse("%s doesn't exist", crel)
		case err != nil:
			return r, err
		case st.isLink():
			return r, refuse("%s is a symlink", crel)
		case !st.isDir():
			return r, refuse("%s is not a directory", crel)
		}
		nfd, err := openPathDir(fd, comp)
		if err != nil {
			return r, refuse("%s changed: %v", crel, err)
		}
		if fst, err := fstatFD(nfd); err != nil || !fst.same(st) {
			closeFD(nfd)
			return r, refuse("%s changed", crel)
		}
		closeFD(fd)
		fd, at = nfd, crel
	}
	tree, err := fstatFD(fd)
	if err != nil {
		return r, err
	}
	crel := joinRel(rel, c.Name)
	st, err := lstatAt(fd, c.Name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return r, refuse("%s doesn't exist", crel)
	case err != nil:
		return r, err
	case st.isLink():
		return r, refuse("%s is a symlink: nothing changed", crel)
	case !st.isDir():
		return r, refuse("%s is not a directory: nothing changed", crel)
	}
	cfd, err := openPathDir(fd, c.Name)
	if err != nil {
		return r, refuse("%s changed: %v", crel, err)
	}
	defer closeFD(cfd)
	fst, err := fstatFD(cfd)
	if err != nil {
		return r, err
	}
	// Still that name in the tree (the walk's check for a file: its
	// ".." can't be read without searching it).
	again, err := lstatAt(fd, c.Name)
	if err != nil || !fst.isDir() || !fst.same(st) || !again.same(fst) {
		return r, refuse("%s changed while it was opened: nothing changed", crel)
	}
	r.Dev, r.Ino = fst.Dev, fst.Ino
	ms, err := readMountinfo()
	if err != nil {
		return r, fmt.Errorf("mountinfo: %w", err)
	}
	full := path.Join(o.Root, crel)
	_, isMount := mountRootOf(ms, full)
	if isMount || fst.Dev != tree.Dev || (fst.MntID != 0 && tree.MntID != 0 && fst.MntID != tree.MntID) {
		return r, refuse("%s is another mount: nothing changed", crel)
	}
	r.MountRoot = effectiveMountRoot(ms, full)
	if fst.Dev != o.ExpectDev || fst.Ino != o.ExpectIno {
		return r, refuse("%s is not the directory the preview saw (device %d inode %d, want %d/%d): preview it again", crel, fst.Dev, fst.Ino, o.ExpectDev, o.ExpectIno)
	}
	if r.MountRoot != o.ExpectMountRoot {
		return r, refuse("%s is mounted from %q, want %q: preview it again", crel, r.MountRoot, o.ExpectMountRoot)
	}
	ok, err := idMapsIdentity()
	if err != nil {
		return r, refuse("read the id maps: %v", err)
	}
	if !ok {
		return r, refuse("the fixer runs in a user namespace with translated ids (userns-remap or rootless Docker): the owner would be wrong")
	}
	if r.FSType, r.FreeBytes, r.TotalBytes, err = fsInfo(fd); err != nil {
		return r, err
	}
	if !writableFS[r.FSType] {
		return r, refuse("%s is on %s: the Hub changes ownership only on ext4, xfs, btrfs and zfs", crel, r.FSType)
	}
	uid := uint32(c.UID)
	if fst.UID != uid || fst.GID != uid || fst.Mode&modePerm != ChildMode {
		// fchown clears setuid / setgid, so the mode is set after it.
		if err := chownPathFD(cfd, uid, uid); err != nil {
			return r, fmt.Errorf("chown %s: %w", crel, err)
		}
		if err := chmodPathFD(cfd, ChildMode); err != nil {
			return r, fmt.Errorf("chmod %s: %w", crel, err)
		}
		r.Changed = 1
	}
	after, err := fstatFD(cfd)
	if err != nil {
		return r, err
	}
	r.Entries, r.Dirs = 1, 1
	r.Children = []ChildOwner{childOwnerOf(c.Name, after)}
	return r, nil
}

// childOwnerOf is a first-level entry's owner, group, mode and type.
func childOwnerOf(name string, st fileStat) ChildOwner {
	return ChildOwner{Name: clip(name, maxPathRunes), UID: int(st.UID), GID: int(st.GID), Mode: st.Mode & modePerm, Dir: st.isDir()}
}
