package folderfix

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// fileStat is the part of struct stat the walk uses.
type fileStat struct {
	Dev, Ino uint64
	Mode     uint32 // S_IFMT | permission bits
	Nlink    uint64
	UID, GID uint32
	MntID    uint64 // 0 = unknown
}

// File types (S_IFMT values, the same on every unix).
const (
	sIFMT  uint32 = 0o170000
	sIFDIR uint32 = 0o040000
	sIFREG uint32 = 0o100000
	sIFLNK uint32 = 0o120000
)

func (s fileStat) typ() uint32  { return s.Mode & sIFMT }
func (s fileStat) isDir() bool  { return s.typ() == sIFDIR }
func (s fileStat) isReg() bool  { return s.typ() == sIFREG }
func (s fileStat) isLink() bool { return s.typ() == sIFLNK }
func (s fileStat) same(o fileStat) bool {
	return s.Dev == o.Dev && s.Ino == o.Ino && s.typ() == o.typ()
}

var errNotRegular = errors.New("not a regular file")

// maxDepth bounds the directories the walk holds open at once.
const maxDepth = 512

// Test hooks: called with an entry's relative path after its fstatat and
// before its open, and after its open (checks passed) before any change.
var (
	testHookBeforeOpen func(rel string)
	testHookAfterOpen  func(rel string)
	// noACLForTest makes the walk behave as on a filesystem without ACLs.
	noACLForTest bool
)

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	ID    uint64
	Root  string // the root of the mount within its filesystem
	Point string // the mount point
}

// parseMountinfo reads proc(5) mountinfo: "id parent maj:min root point …",
// with space, tab, newline and backslash written as octal escapes.
func parseMountinfo(r io.Reader) ([]mountEntry, error) {
	var out []mountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("mountinfo: bad mount id %q", f[0])
		}
		out = append(out, mountEntry{ID: id, Root: unescapeMount(f[3]), Point: unescapeMount(f[4])})
	}
	return out, sc.Err()
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountRootOf is the root field of the topmost mount at point.
func mountRootOf(ms []mountEntry, point string) (string, bool) {
	root, ok := "", false
	for _, m := range ms {
		if m.Point == point {
			root, ok = m.Root, true
		}
	}
	return root, ok
}

// identityMap: a uid_map / gid_map that maps every id to itself.
func identityMap(s string) bool {
	f := strings.Fields(s)
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}

// validRel checks a relative path below the root as the walk would build
// it: "." or clean, relative, no "..", no empty or NUL component, ≤ 4096
// bytes, each component ≤ 255 bytes.
func validRel(p string) error {
	if p == "." {
		return nil
	}
	if p == "" || len(p) > 4096 || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("path %q is not a clean relative path", clip(p, 80))
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." || c == "." || c == "" || len(c) > 255 {
			return fmt.Errorf("path %q has a bad component", clip(p, 80))
		}
	}
	return nil
}

// validSubpath is a --mkdir / --rel value (the global path value rules):
// validRel, not ".", ≤ 255 bytes, no ':' and no control characters.
func validSubpath(p string) error {
	if p == "." || len(p) > 255 {
		return fmt.Errorf("subpath %q: want a relative path of at most 255 bytes", clip(p, 80))
	}
	if err := validRel(p); err != nil {
		return err
	}
	if strings.ContainsRune(p, ':') || !utf8.ValidString(p) || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }) {
		return fmt.Errorf("subpath %q has ':' or a control character", clip(p, 80))
	}
	return nil
}

func validRoot(p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("root %q: want an absolute, clean path", clip(p, 80))
	}
	return nil
}

func joinRel(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// node is one regular file or directory the walk opened and checked.
type node struct {
	rel   string
	fd    int
	st    fileStat
	cur   state
	raw   rawState
	child string // first-level child it is under ("" for the root)
	skip  bool   // a hard link: counted, never changed
}

// rawState is the xattr bytes as read (nil = none).
type rawState struct{ access, def []byte }

type principalTally struct {
	p   Principal
	out *PrincipalAccess
}

// walker is one walk of the folder, from an fd of its root.
type walker struct {
	o        Options
	r        Report
	t        target
	hasT     bool
	rootfd   int
	root     fileStat
	acl      bool
	sub      map[string]bool // relative paths of mount points below the root (mountinfo)
	start    time.Time
	children map[string]*ChildOwner
	owners   map[[2]uint32]int64
	pt       []principalTally
	stopped  bool
	visit    func(*node)
}

// openWalker opens the root (O_DIRECTORY|O_NOFOLLOW), checks it is the
// expected directory and mount, and reads the filesystem's facts.
func openWalker(o Options, mode string) (*walker, error) {
	w := &walker{o: o, rootfd: -1, start: time.Now()}
	w.r = Report{Version: 1, Mode: mode, Root: o.Root}
	if err := validRoot(o.Root); err != nil {
		return w, err
	}
	if o.Target.GID < 0 || o.Target.GID >= 0xFFFFFFFF {
		return w, fmt.Errorf("gid %d out of range", o.Target.GID)
	}
	if o.Target.GID != 0 {
		if o.Target.Files != "rw" && o.Target.Files != "r" {
			return w, fmt.Errorf("files %q: want rw or r", o.Target.Files)
		}
		w.hasT = true
		w.t = target{GID: uint32(o.Target.GID), Write: o.Target.Files == "rw"}
		if o.Target.OwnerUID != nil {
			u := *o.Target.OwnerUID
			if u < 0 || u >= 0xFFFFFFFF {
				return w, fmt.Errorf("owner uid %d out of range", u)
			}
			w.t.HasOwner, w.t.Owner = true, uint32(u)
		}
	} else if o.Target.OwnerUID != nil {
		return w, errors.New("an owner needs a gid")
	}
	fd, err := openRootDir(o.Root)
	if err != nil {
		return w, refuse("open %s: %v", o.Root, err)
	}
	w.rootfd = fd
	st, err := fstatFD(fd)
	if err != nil {
		return w, err
	}
	w.root = st
	w.r.Dev, w.r.Ino = st.Dev, st.Ino
	if (o.ExpectDev != 0 || o.ExpectIno != 0) && (st.Dev != o.ExpectDev || st.Ino != o.ExpectIno) {
		return w, refuse("%s is not the folder's directory (device %d inode %d, want %d/%d): re-check the folder's path",
			o.Root, st.Dev, st.Ino, o.ExpectDev, o.ExpectIno)
	}
	ms, err := readMountinfo()
	if err != nil {
		return w, fmt.Errorf("mountinfo: %w", err)
	}
	root, found := mountRootOf(ms, o.Root)
	w.r.MountRoot = root
	if o.ExpectMountRoot != "" && (!found || root != o.ExpectMountRoot) {
		return w, refuse("%s is mounted from %q, want %q: the folder's path changed on the host", o.Root, root, o.ExpectMountRoot)
	}
	prefix := o.Root + "/"
	if o.Root == "/" {
		prefix = "/"
	}
	w.sub = map[string]bool{}
	for _, m := range ms {
		if strings.HasPrefix(m.Point, prefix) && len(m.Point) > len(prefix) {
			w.sub[m.Point[len(prefix):]] = true
		}
	}
	w.r.FSType, w.r.FreeBytes, w.r.TotalBytes, err = fsInfo(fd)
	if err != nil {
		return w, err
	}
	w.r.ACL, w.r.Xattr = support(fd)
	w.acl = w.r.ACL && !noACLForTest
	if noACLForTest {
		w.r.ACL = false
	}
	w.t.ACL = w.acl
	if w.hasT {
		w.r.Expected = &Conformance{}
		w.r.Plan = &PlanCounts{KeepGroup: map[int]int64{}, KeepUser: map[int]int64{}}
	}
	if o.Children {
		w.children = map[string]*ChildOwner{}
	}
	w.owners = map[[2]uint32]int64{}
	for _, p := range o.Principals {
		w.pt = append(w.pt, principalTally{p: p, out: &PrincipalAccess{Name: p.Name, UID: p.UID}})
	}
	return w, nil
}

func (w *walker) close() {
	if w.rootfd >= 0 {
		closeFD(w.rootfd)
		w.rootfd = -1
	}
}

func (w *walker) report() *Report { r := w.r; r.Elapsed = time.Since(w.start); return &r }

// reset clears the counts for a second walk over the same root.
func (w *walker) reset() {
	keep := w.r
	w.r = Report{Version: 1, Mode: keep.Mode, Root: keep.Root, Dev: keep.Dev, Ino: keep.Ino, MountRoot: keep.MountRoot,
		FSType: keep.FSType, ACL: keep.ACL, Xattr: keep.Xattr, FreeBytes: keep.FreeBytes, TotalBytes: keep.TotalBytes}
	if w.hasT {
		w.r.Expected = &Conformance{}
		w.r.Plan = &PlanCounts{KeepGroup: map[int]int64{}, KeepUser: map[int]int64{}}
	}
	if w.children != nil {
		w.children = map[string]*ChildOwner{}
	}
	w.owners = map[[2]uint32]int64{}
	for i := range w.pt {
		w.pt[i].out = &PrincipalAccess{Name: w.pt[i].p.Name, UID: w.pt[i].p.UID}
	}
	w.stopped = false
}

// finish fills the aggregated parts of the report.
func (w *walker) finish() *Report {
	for k, n := range w.owners {
		w.r.Owners = append(w.r.Owners, OwnerCount{UID: int(k[0]), GID: int(k[1]), N: n})
	}
	slices.SortFunc(w.r.Owners, func(a, b OwnerCount) int {
		if a.N != b.N {
			if a.N > b.N {
				return -1
			}
			return 1
		}
		if a.UID != b.UID {
			return a.UID - b.UID
		}
		return a.GID - b.GID
	})
	if len(w.r.Owners) > maxOwners {
		w.r.Owners = w.r.Owners[:maxOwners]
	}
	if w.children != nil {
		names := make([]string, 0, len(w.children))
		for n := range w.children {
			names = append(names, n)
		}
		slices.Sort(names)
		if len(names) > maxChildren {
			w.r.errorf("%d first-level entries: only the first %d listed", len(names), maxChildren)
			names = names[:maxChildren]
		}
		w.r.Children = []ChildOwner{}
		for _, n := range names {
			w.r.Children = append(w.r.Children, *w.children[n])
		}
	}
	w.r.Principals = nil
	for _, p := range w.pt {
		w.r.Principals = append(w.r.Principals, *p.out)
	}
	return w.report()
}

// capped: true once the walk must stop (entry or time cap).
func (w *walker) capped() bool {
	if w.stopped {
		return true
	}
	switch {
	case w.o.MaxEntries > 0 && w.r.Entries >= w.o.MaxEntries:
		w.r.Partial, w.r.PartialReason = true, "entries"
	case w.o.MaxTime > 0 && time.Since(w.start) > w.o.MaxTime:
		w.r.Partial, w.r.PartialReason = true, "time"
	default:
		return false
	}
	w.stopped = true
	return true
}

// otherMount: an entry on another device, another mount of the same
// filesystem (a bind mount: same st_dev, other mount id), or listed as a
// mount point below the root in mountinfo.
func (w *walker) otherMount(st fileStat, rel string) bool {
	return st.Dev != w.root.Dev || (st.MntID != 0 && w.root.MntID != 0 && st.MntID != w.root.MntID) || w.sub[rel]
}

// readState reads the entry's ownership through its fd.
func (w *walker) readState(n *node) error {
	n.cur = state{Dir: n.st.isDir(), UID: n.st.UID, GID: n.st.GID, Mode: n.st.Mode & modePerm}
	if !w.acl {
		return nil
	}
	var err error
	if n.raw.access, err = getXattr(n.fd, XattrAccess); err != nil {
		return fmt.Errorf("read access ACL: %w", err)
	}
	if n.cur.Dir {
		if n.raw.def, err = getXattr(n.fd, XattrDefault); err != nil {
			return fmt.Errorf("read default ACL: %w", err)
		}
	}
	if len(n.raw.access) > 0 {
		if n.cur.Access, err = DecodeACL(n.raw.access); err != nil {
			return fmt.Errorf("%w: access ACL: %v", errBadACL, err)
		}
	}
	if len(n.raw.def) > 0 {
		if n.cur.Default, err = DecodeACL(n.raw.def); err != nil {
			return fmt.Errorf("%w: default ACL: %v", errBadACL, err)
		}
	}
	if len(n.cur.Access) == 0 {
		n.cur.Access = nil
	}
	if len(n.cur.Default) == 0 {
		n.cur.Default = nil
	}
	return nil
}

func (w *walker) fail(rel string, err error) {
	w.r.Failed.add(rel)
	w.r.errorf("%s: %v", rel, err)
}

// run walks the tree depth-first from the root, calling visit for every
// regular file and directory that passed the checks (hard links included,
// marked skip), its fd open. Symlinks, specials, other mounts and entries
// that changed between fstatat and open are counted and never opened (the
// first two) or never touched.
func (w *walker) run(visit func(*node)) {
	w.visit = visit
	w.r.Entries++
	n := &node{rel: ".", fd: w.rootfd, st: w.root}
	w.r.Dirs++
	anc := make([]bool, len(w.pt))
	for i := range anc {
		anc[i] = true
	}
	if ok := w.handle(n, anc); ok {
		w.dir(w.rootfd, ".", 0, w.childAnc(n, anc))
	}
}

// childAnc: per principal, whether it can traverse every directory down to
// and including n.
func (w *walker) childAnc(n *node, anc []bool) []bool {
	out := make([]bool, len(anc))
	for i, p := range w.pt {
		out[i] = anc[i] && Allowed(Stat{UID: int(n.cur.UID), GID: int(n.cur.GID), Mode: n.cur.Mode, Dir: true, Access: n.cur.Access}, p.p, X)
	}
	return out
}

// handle reads the node's state, tallies it and calls visit. false = the
// node couldn't be read (a directory isn't entered).
func (w *walker) handle(n *node, anc []bool) bool {
	if err := w.readState(n); err != nil {
		if errors.Is(err, errBadACL) {
			w.r.BadACL.add(n.rel)
			w.r.errorf("%s: %v", n.rel, err)
			n.skip = true
			n.cur.Access, n.cur.Default = nil, nil
		} else {
			w.fail(n.rel, err)
			return false
		}
	}
	w.owners[[2]uint32{n.st.UID, n.st.GID}]++
	if w.children != nil && n.child != "" {
		c := w.children[n.child]
		if c == nil {
			c = &ChildOwner{Name: clip(n.child, maxPathRunes), UID: int(n.st.UID), GID: int(n.st.GID)}
			w.children[n.child] = c
		}
		c.Entries++
		if int(n.st.UID) != c.UID {
			c.Foreign++
		}
	}
	for i, p := range w.pt {
		s := Stat{UID: int(n.cur.UID), GID: int(n.cur.GID), Mode: n.cur.Mode, Dir: n.cur.Dir, Access: n.cur.Access}
		rd, wr := R, W
		if n.cur.Dir {
			rd, wr = R|X, W|X
		}
		if !anc[i] || !Allowed(s, p.p, rd) {
			p.out.CantRead.add(n.rel)
		}
		if p.p.Write && (!anc[i] || !Allowed(s, p.p, wr)) {
			p.out.CantWrite.add(n.rel)
		}
	}
	if w.visit != nil {
		w.visit(n)
	}
	return true
}

func (w *walker) dir(fd int, rel string, depth int, anc []bool) {
	names, err := readNames(fd)
	if err != nil {
		w.fail(rel, fmt.Errorf("list: %w", err))
		return
	}
	slices.Sort(names)
	for _, name := range names {
		if w.capped() {
			return
		}
		crel := joinRel(rel, name)
		child := ""
		if depth == 0 {
			child = name
		} else {
			child, _, _ = strings.Cut(rel, "/")
		}
		w.r.Entries++
		st, err := lstatAt(fd, name)
		if errors.Is(err, fs.ErrNotExist) {
			w.r.Races.add(crel) // gone since the listing
			continue
		}
		if err != nil {
			w.fail(crel, err)
			continue
		}
		switch {
		case st.isLink():
			w.r.Symlinks.add(crel)
			continue
		case !st.isDir() && !st.isReg():
			w.r.Specials.add(crel)
			continue
		}
		if w.otherMount(st, crel) {
			w.r.MountPoints.add(crel)
			continue
		}
		isDir := st.isDir()
		if isDir {
			w.r.Dirs++
		} else {
			w.r.Files++
		}
		if testHookBeforeOpen != nil {
			testHookBeforeOpen(crel)
		}
		cfd, err := openAt(fd, name, isDir)
		if err != nil {
			w.r.Races.add(crel)
			w.r.errorf("%s: changed during the walk: %v", crel, err)
			continue
		}
		fst, err := fstatFD(cfd)
		if err != nil || !fst.same(st) || w.otherMount(fst, crel) {
			closeFD(cfd)
			w.r.Races.add(crel)
			continue
		}
		n := &node{rel: crel, fd: cfd, st: fst, child: child}
		if !isDir && fst.Nlink > 1 {
			// Its inode may be reachable outside the folder: never changed.
			w.r.HardLinks.add(crel)
			n.skip = true
		}
		if testHookAfterOpen != nil {
			testHookAfterOpen(crel)
		}
		if ok := w.handle(n, anc); ok && isDir {
			if depth+1 >= maxDepth {
				w.r.Partial, w.r.PartialReason = true, "depth"
				w.r.errorf("%s: deeper than %d levels: not entered", crel, maxDepth)
			} else {
				w.dir(cfd, crel, depth+1, w.childAnc(n, anc))
			}
		}
		closeFD(cfd)
	}
}
