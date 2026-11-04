package folderfix

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// ProbeReport is what probe answers about a path below a bind root.
type ProbeReport struct {
	Version   int      `json:"version"`
	Mode      string   `json:"mode"`
	Root      string   `json:"root"`
	Rel       string   `json:"rel"`
	Dev       uint64   `json:"dev"`
	Ino       uint64   `json:"ino"`
	Symlink   string   `json:"symlink"` // the first symlink component ("" = none)
	Exists    bool     `json:"exists"`
	Created   bool     `json:"created"`
	MountRoot string   `json:"mount_root"` // of the bind root (root)
	FSType    string   `json:"fs_type"`    // of the path, when it exists
	Errors    []string `json:"errors,omitempty"`
}

// Probe follows rel below root one component at a time (openat
// O_DIRECTORY|O_NOFOLLOW from an O_NOFOLLOW fd of root, never a path the
// kernel resolves): it reports the first symlink component, or the device
// and inode of the directory. With create, missing components are made with
// mkdirat under their parent's fd (0755, owned by the caller); nothing is
// created past a symlink or a non-directory.
func Probe(root, rel string, create bool) (*ProbeReport, error) {
	p := &ProbeReport{Version: 1, Mode: "probe", Root: root, Rel: rel}
	if err := validRoot(root); err != nil {
		return p, err
	}
	if err := validSubpath(rel); err != nil {
		return p, err
	}
	fd, err := openRootDir(root)
	if err != nil {
		return p, refuse("open %s: %v", root, err)
	}
	defer func() { closeFD(fd) }()
	if ms, err := readMountinfo(); err != nil {
		return p, fmt.Errorf("mountinfo: %w", err)
	} else {
		p.MountRoot, _ = mountRootOf(ms, root)
	}
	at := "."
	var last fileStat
	for _, c := range strings.Split(rel, "/") {
		crel := joinRel(at, c)
		st, err := lstatAt(fd, c)
		if errors.Is(err, fs.ErrNotExist) {
			if !create {
				return p, nil
			}
			if err := mkdirAt(fd, c, 0o755); err != nil {
				return p, refuse("create %s: %v", crel, err)
			}
			p.Created = true
			st, err = lstatAt(fd, c)
		}
		if err != nil {
			return p, err
		}
		if st.isLink() {
			p.Symlink = crel
			return p, nil
		}
		if !st.isDir() {
			return p, refuse("%s is not a directory", crel)
		}
		nfd, err := openAt(fd, c, true)
		if err != nil {
			return p, refuse("%s changed during the probe: %v", crel, err)
		}
		fst, err := fstatFD(nfd)
		if err != nil || !fst.same(st) {
			closeFD(nfd)
			return p, refuse("%s changed during the probe", crel)
		}
		closeFD(fd)
		fd, at, last = nfd, crel, fst
	}
	p.Exists, p.Dev, p.Ino = true, last.Dev, last.Ino
	if name, _, _, err := fsInfo(fd); err == nil {
		p.FSType = name
	}
	return p, nil
}
