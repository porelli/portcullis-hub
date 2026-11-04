package folderfix

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// ProbeReport is what probe answers about a path below a bind root.
type ProbeReport struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	Root    string `json:"root"`
	Rel     string `json:"rel"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	// UID / GID: the path's owner and group, when it exists (the
	// person_tree_owner preview binds the owner, fix round 1).
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	Symlink   string `json:"symlink"` // the first symlink component ("" = none)
	Exists    bool   `json:"exists"`
	Created   bool   `json:"created"`
	MountRoot string `json:"mount_root"` // of the bind root (root)
	FSType    string `json:"fs_type"`    // of the path, when it exists
	// RelMountRoot: rel's own mount root (the deepest mount at or above
	// root/rel: its root field + the rest of the path), what a scan of
	// rel bound alone reports as mount_root; "" = unknown.
	RelMountRoot string `json:"rel_mount_root,omitempty"`
	// Subs: each --sub below rel, walked from rel's fd (H1: one run
	// probes a folder root and every subpath an up mounts). Empty when
	// rel is missing or a symlink.
	Subs   []SubProbe `json:"subs,omitempty"`
	Errors []string   `json:"errors,omitempty"`
}

// SubProbe is one subpath below the probed directory.
type SubProbe struct {
	Rel     string `json:"rel"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Symlink string `json:"symlink"` // the first symlink component below Rel's parent ("" = none)
	Exists  bool   `json:"exists"`
}

// Probe follows rel below root one component at a time (openat
// O_DIRECTORY|O_NOFOLLOW from an O_NOFOLLOW fd of root, never a path the
// kernel resolves): it reports the first symlink component, or the device
// and inode of the directory. With create, missing components are made with
// mkdirat under their parent's fd (0755, owned by the caller); nothing is
// created past a symlink or a non-directory.
func Probe(root, rel string, create bool) (*ProbeReport, error) {
	return probe(root, rel, create, nil)
}

// ProbeSubs probes rel below root, then (rel an existing directory) each
// of subs below rel, every one walked from rel's own fd: a subpath is
// judged below the very directory whose device and inode were reported.
func ProbeSubs(root, rel string, subs []string) (*ProbeReport, error) {
	for _, s := range subs {
		if err := validSubpath(s); err != nil {
			return &ProbeReport{Version: 1, Mode: "probe", Root: root, Rel: rel}, err
		}
	}
	return probe(root, rel, false, subs)
}

func probe(root, rel string, create bool, subs []string) (*ProbeReport, error) {
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
	ms, err := readMountinfo()
	if err != nil {
		return p, fmt.Errorf("mountinfo: %w", err)
	}
	p.MountRoot, _ = mountRootOf(ms, root)
	p.RelMountRoot = effectiveMountRoot(ms, path.Join(root, rel))
	at := "."
	var last fileStat
	for _, c := range strings.Split(rel, "/") {
		crel := joinRel(at, c)
		st, err := lstatAt(fd, c)
		if errors.Is(err, fs.ErrNotExist) {
			if !create {
				return p, nil
			}
			if testHookMkdir != nil {
				testHookMkdir(crel)
			}
			if err := mkdirAt(fd, c, 0o755); err != nil {
				return p, p.failed(refuse("create %s: %v", crel, err))
			}
			p.Created = true
			st, err = lstatAt(fd, c)
		}
		if err != nil {
			return p, p.failed(err)
		}
		if st.isLink() {
			p.Symlink = crel
			return p, nil
		}
		if !st.isDir() {
			return p, p.failed(refuse("%s is not a directory", crel))
		}
		nfd, err := openAt(fd, c, true)
		if err != nil {
			return p, p.failed(refuse("%s changed during the probe: %v", crel, err))
		}
		fst, err := fstatFD(nfd)
		if err != nil || !fst.same(st) {
			closeFD(nfd)
			return p, p.failed(refuse("%s changed during the probe", crel))
		}
		closeFD(fd)
		fd, at, last = nfd, crel, fst
	}
	p.Exists, p.Dev, p.Ino, p.UID, p.GID = true, last.Dev, last.Ino, int(last.UID), int(last.GID)
	if name, _, _, err := fsInfo(fd); err == nil {
		p.FSType = name
	}
	for _, sub := range subs {
		sp, err := walkSub(fd, sub)
		if err != nil {
			return p, err
		}
		p.Subs = append(p.Subs, sp)
	}
	return p, nil
}

// walkSub follows sub below the directory fd (never closed here) one
// component at a time, as probe does, creating nothing.
func walkSub(dirfd int, sub string) (SubProbe, error) {
	sp := SubProbe{Rel: sub}
	fd, err := dupFD(dirfd)
	if err != nil {
		return sp, err
	}
	defer func() { closeFD(fd) }()
	at := "."
	var last fileStat
	for _, c := range strings.Split(sub, "/") {
		crel := joinRel(at, c)
		st, err := lstatAt(fd, c)
		if errors.Is(err, fs.ErrNotExist) {
			return sp, nil
		}
		if err != nil {
			return sp, err
		}
		if st.isLink() {
			sp.Symlink = crel
			return sp, nil
		}
		if !st.isDir() {
			return sp, refuse("%s is not a directory", crel)
		}
		nfd, err := openAt(fd, c, true)
		if err != nil {
			return sp, refuse("%s changed during the probe: %v", crel, err)
		}
		fst, err := fstatFD(nfd)
		if err != nil || !fst.same(st) {
			closeFD(nfd)
			return sp, refuse("%s changed during the probe", crel)
		}
		closeFD(fd)
		fd, at, last = nfd, crel, fst
	}
	sp.Exists, sp.Dev, sp.Ino = true, last.Dev, last.Ino
	return sp, nil
}

// failed: once probe --create made a directory, no error is a refusal (M3).
func (p *ProbeReport) failed(err error) error {
	if p.Created {
		return unrefuse(err)
	}
	return err
}

// effectiveMountRoot is p's mount root: the topmost of the deepest mounts
// at or above p, its root field joined with the rest of p ("" = none).
func effectiveMountRoot(ms []mountEntry, p string) string {
	best, rest := -1, ""
	for i, m := range ms {
		var r string
		switch {
		case m.Point == p:
		case m.Point == "/":
			r = p
		case strings.HasPrefix(p, m.Point+"/"):
			r = p[len(m.Point):]
		default:
			continue
		}
		if best < 0 || len(m.Point) >= len(ms[best].Point) {
			best, rest = i, r
		}
	}
	if best < 0 {
		return ""
	}
	return path.Join(ms[best].Root, rest)
}
