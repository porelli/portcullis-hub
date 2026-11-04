//go:build linux && fixerroot

package folderfix

// Root tests: real ownership, ACLs, mounts and device nodes. Run with
// sudo -E env "PATH=$PATH" go test -tags fixerroot ./internal/folderfix/
// They skip without root or ACL support locally and fail under CI.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		setfaclUnavailable(t, "root tests need uid 0")
	}
	dir := t.TempDir()
	if _, err := unix.Getxattr(dir, XattrAccess, nil); err != nil && !errors.Is(err, unix.ENODATA) {
		setfaclUnavailable(t, "the temp filesystem has no ACLs: %v", err)
	}
	t.Cleanup(func() { testHookBeforeOpen, testHookAfterOpen, noACLForTest = nil, nil, false })
}

// folderRoot is <tempdir>/folder with the temp chain 0755 (other uids
// traverse it), owned 1000:1000 mode 0750.
func folderRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	for _, p := range []string{base, filepath.Dir(base)} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(base, "folder")
	mkdirOwned(t, root, 0o750, 1000, 1000)
	return root
}

func mkdirOwned(t *testing.T, p string, mode os.FileMode, uid, gid int) {
	t.Helper()
	mkdir(t, p, mode)
	chownMode(t, p, uid, gid, mode)
}

func fileOwned(t *testing.T, p string, mode os.FileMode, uid, gid int) {
	t.Helper()
	writeFile(t, p, 0o600)
	chownMode(t, p, uid, gid, mode)
}

func chownMode(t *testing.T, p string, uid, gid int, mode os.FileMode) {
	t.Helper()
	if err := os.Lchown(p, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(p, uint32(mode.Perm())|modeBits(mode)); err != nil {
		t.Fatal(err)
	}
}

func modeBits(m os.FileMode) uint32 {
	var b uint32
	if m&os.ModeSetuid != 0 {
		b |= modeSetuid
	}
	if m&os.ModeSetgid != 0 {
		b |= modeSetgid
	}
	return b
}

func setACL(t *testing.T, p, name string, a ACL) {
	t.Helper()
	b, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(p, name, b, 0); err != nil {
		t.Fatal(err)
	}
}

// disk is one entry as the kernel has it.
type disk struct {
	UID, GID, Mode uint32
	Ino            uint64
	Ctime          unix.Timespec
	Acc, Def       []byte
}

func lxattr(p, name string) []byte {
	buf := make([]byte, 4096)
	n, err := unix.Lgetxattr(p, name, buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func diskOf(t *testing.T, p string) disk {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return disk{UID: st.Uid, GID: st.Gid, Mode: st.Mode, Ino: st.Ino, Ctime: st.Ctim, Acc: lxattr(p, XattrAccess), Def: lxattr(p, XattrDefault)}
}

// diskTree is every entry below root (symlinks not followed).
func diskTree(t *testing.T, root string) map[string]disk {
	t.Helper()
	out := map[string]disk{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out[p] = diskOf(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stateOf is the entry's state as Allowed and planEntry see it.
func stateOf(t *testing.T, p string) state {
	t.Helper()
	d := diskOf(t, p)
	s := state{Dir: d.Mode&sIFMT == sIFDIR, UID: d.UID, GID: d.GID, Mode: d.Mode & modePerm}
	if len(d.Acc) > 0 {
		a, err := DecodeACL(d.Acc)
		if err != nil {
			t.Fatal(err)
		}
		s.Access = canon(a)
	}
	if len(d.Def) > 0 {
		a, err := DecodeACL(d.Def)
		if err != nil {
			t.Fatal(err)
		}
		s.Default = canon(a)
	}
	return s
}

func allowed(t *testing.T, p string, pr Principal, want Perm) bool {
	t.Helper()
	s := stateOf(t, p)
	return Allowed(Stat{UID: int(s.UID), GID: int(s.GID), Mode: s.Mode, Dir: s.Dir, Access: s.Access}, pr, want)
}

func ids(t *testing.T, p string) (uint64, uint64) { return rootIDs(t, p) }

func opts(t *testing.T, root string, tg Target) Options {
	t.Helper()
	dev, ino := ids(t, root)
	return Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: tg}
}

// apply scans for the count, then applies with it.
func apply(t *testing.T, o Options) *Report {
	t.Helper()
	s, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(o, s.Plan.Changes)
	if err != nil {
		t.Fatalf("apply: %v (%v)", err, r.Errors)
	}
	return r
}

// verify: the Hub's verify scan finds every conformance count 0.
func verify(t *testing.T, o Options) {
	t.Helper()
	r, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	e := r.Expected
	if e.Group.N+e.Setgid.N+e.DefaultACL.N+e.Mode.N+e.Owner.N != 0 || r.Plan.Changes != 0 {
		t.Fatalf("verify scan: conformance %+v plan %d", e, r.Plan.Changes)
	}
}

// getfaclText is getfacl's numeric listing as "user::rwx,…" (access) and
// "default:user::rwx,…".
func getfaclText(t *testing.T, p string) (acc, def string) {
	t.Helper()
	g, err := exec.LookPath("getfacl")
	if err != nil {
		setfaclUnavailable(t, "getfacl not installed")
		return "", ""
	}
	out, err := exec.Command(g, "--omit-header", "--numeric", "--absolute-names", "--no-effective", p).Output()
	if err != nil {
		t.Fatalf("getfacl: %v", err)
	}
	var a, d []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(l, "default:"); ok {
			d = append(d, rest)
		} else {
			a = append(a, l)
		}
	}
	return strings.Join(a, ","), strings.Join(d, ",")
}

func TestRootApplyInheritance(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	mkdirOwned(t, filepath.Join(root, "sub"), 0o750, 1000, 1000)
	fileOwned(t, filepath.Join(root, "sub", "f"), 0o640, 1000, 1000)
	o := opts(t, root, Target{GID: 60001, Files: "rw"})
	r := apply(t, o)
	if r.Changed != 3 || r.Plan.KeepGroup[1000] != 3 {
		t.Fatalf("changed %d keep %v", r.Changed, r.Plan.KeepGroup)
	}
	verify(t, o)

	// uid 2001 (an app with the folder gid as a supplementary group), umask 022.
	cmd := exec.Command("sh", "-c", `umask 022 && : > sub/new && mkdir sub/newdir && : > sub/newdir/deeper`)
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 2001, Gid: 2001, Groups: []uint32{60001}}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("as uid 2001: %v: %s", err, out)
	}
	member := Principal{UID: 3999, GIDs: []int{60001}}
	for _, p := range []string{"sub/new", "sub/newdir", "sub/newdir/deeper"} {
		full := filepath.Join(root, p)
		d := diskOf(t, full)
		if d.GID != 60001 || d.UID != 2001 {
			t.Errorf("%s: owner %d:%d, want 2001:60001", p, d.UID, d.GID)
		}
		want := R | W
		if d.Mode&sIFMT == sIFDIR {
			want = R | W | X
			if d.Mode&modeSetgid == 0 || len(d.Def) == 0 {
				t.Errorf("%s: a new directory without setgid or default ACL", p)
			}
		}
		if !allowed(t, full, member, want) {
			t.Errorf("%s: a folder group member can't %s: %s", p, want, describe(stateOf(t, full)))
		}
	}
	// getfacl agrees with DecodeACL.
	for _, p := range []string{".", "sub", "sub/f", "sub/new", "sub/newdir"} {
		full := filepath.Join(root, p)
		s := stateOf(t, full)
		acc := s.Access
		if acc == nil {
			acc = FromMode(s.Mode)
		}
		ga, gd := getfaclText(t, full)
		if ga != aclText(acc) || gd != aclText(s.Default) {
			t.Errorf("%s: getfacl %q / %q, DecodeACL %q / %q", p, ga, gd, aclText(acc), aclText(s.Default))
		}
	}
	// Files the app made are consistent as they are (inherited ACLs).
	verify(t, o)
	// A second apply changes nothing.
	if r := apply(t, o); r.Changed != 0 {
		t.Fatalf("second apply changed %d", r.Changed)
	}
}

func TestRootApplyKeepsAccess(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	d := filepath.Join(root, "d")
	f := filepath.Join(d, "f")
	mkdirOwned(t, d, 0o750, 1000, 1000)
	fileOwned(t, f, 0o640, 1000, 1000)
	setACL(t, f, XattrAccess, acl(uo(R|W), us(3000, R|W|X), go_(R), mk(R), ot(0)))
	plain := filepath.Join(root, "plain")
	fileOwned(t, plain, 0o644, 1000, 1000)
	principals := []Principal{{UID: 4000, GIDs: []int{1000}}, {UID: 1000, GIDs: []int{1000}}, {UID: 3000, GIDs: []int{3000}}, {UID: 5000, GIDs: []int{5000}}}
	paths := []string{root, d, f, plain}
	type key struct {
		p    string
		i    int
		want Perm
	}
	before := map[key]bool{}
	for _, p := range paths {
		for i, pr := range principals {
			for _, w := range []Perm{R, W, X, R | W, R | X, R | W | X} {
				before[key{p, i, w}] = allowed(t, p, pr, w)
			}
		}
	}
	o := opts(t, root, Target{GID: 60001, Files: "rw"})
	s, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	if s.Plan.Narrowed.N != 1 || !slices.Equal(s.Plan.Narrowed.Sample, []string{"d/f"}) {
		t.Fatalf("narrowed %+v, want d/f", s.Plan.Narrowed)
	}
	r, err := Apply(o, s.Plan.Changes)
	if err != nil {
		t.Fatal(err)
	}
	if r.Changed != 4 {
		t.Fatalf("changed %d", r.Changed)
	}
	for k, b := range before {
		if a := allowed(t, k.p, principals[k.i], k.want); a != b {
			t.Errorf("%s: principal %+v %s: %v → %v", k.p, principals[k.i], k.want, b, a)
		}
	}
	sf := stateOf(t, f)
	if !slices.Contains(sf.Access, us(3000, R)) || !slices.Contains(sf.Access, gr(1000, R)) {
		t.Errorf("d/f: %s, want user:3000:r-- and group:1000:r--", aclText(sf.Access))
	}
	sd := stateOf(t, d)
	if !slices.Contains(sd.Access, gr(1000, R|X)) || !slices.Contains(sd.Default, gr(1000, R|X)) || !slices.Contains(sd.Default, go_(R|W|X)) {
		t.Errorf("d: %s / %s, want group:1000:r-x in both", aclText(sd.Access), aclText(sd.Default))
	}
	verify(t, o)
}

func TestRootMustOwn(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	chownMode(t, root, 2000, 1000, 0o750)
	for i, uid := range []int{1000, 1001, 1002} {
		fileOwned(t, filepath.Join(root, "f"+string(rune('0'+i))), 0o640, uid, 1000)
	}
	owner := 2000
	o := opts(t, root, Target{GID: 60001, Files: "rw", OwnerUID: &owner})
	s, _ := Scan(o)
	if !reflect.DeepEqual(s.Plan.KeepUser, map[int]int64{1000: 1, 1001: 1, 1002: 1}) || s.Plan.ChangeOwner.N != 3 {
		t.Fatalf("keep user %v change owner %d", s.Plan.KeepUser, s.Plan.ChangeOwner.N)
	}
	apply(t, o)
	for i, uid := range []int{1000, 1001, 1002} {
		p := filepath.Join(root, "f"+string(rune('0'+i)))
		st := stateOf(t, p)
		if st.UID != 2000 || !slices.Contains(st.Access, us(uint32(uid), R|W)) {
			t.Errorf("%s: %s", p, describe(st))
		}
		if !allowed(t, p, Principal{UID: uid, GIDs: []int{9999}}, R|W) || !allowed(t, p, Principal{UID: 2000, GIDs: []int{2000}}, R|W) {
			t.Errorf("%s: previous owner %d or the new owner lost rw", p, uid)
		}
	}
	verify(t, o)
}

func TestRootSkips(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	mkdirOwned(t, outside, 0o755, 1000, 1000)
	fileOwned(t, filepath.Join(outside, "secret"), 0o600, 1000, 1000)
	fileOwned(t, filepath.Join(root, "hl1"), 0o644, 1000, 1000)
	must(t, os.Link(filepath.Join(root, "hl1"), filepath.Join(root, "hl2")))
	must(t, os.Link(filepath.Join(outside, "secret"), filepath.Join(root, "outlink"))) // a hard link to a file outside the tree
	must(t, os.Symlink(outside, filepath.Join(root, "sym")))
	must(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "symfile")))
	must(t, unix.Mkfifo(filepath.Join(root, "fifo"), 0o644))
	must(t, unix.Mknod(filepath.Join(root, "dev"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))))
	l, err := net.Listen("unix", filepath.Join(root, "sock"))
	must(t, err)
	defer l.Close()
	mnt := filepath.Join(root, "mnt")
	mkdirOwned(t, mnt, 0o755, 1000, 1000)
	if err := unix.Mount("tmpfs", mnt, "tmpfs", 0, "mode=0755"); err != nil {
		setfaclUnavailable(t, "mount tmpfs: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(mnt, unix.MNT_DETACH) })
	fileOwned(t, filepath.Join(mnt, "inner"), 0o644, 1000, 1000)
	bind := filepath.Join(root, "bind")
	mkdirOwned(t, bind, 0o755, 1000, 1000)
	if err := unix.Mount(outside, bind, "", unix.MS_BIND, ""); err != nil { // same filesystem: same st_dev
		setfaclUnavailable(t, "bind mount: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(bind, unix.MNT_DETACH) })

	before := diskTree(t, filepath.Dir(root))
	o := opts(t, root, Target{GID: 60001, Files: "rw"})
	r := apply(t, o)
	if r.HardLinks.N != 3 || r.Symlinks.N != 2 || r.Specials.N != 3 || r.MountPoints.N != 2 || r.Races.N != 0 {
		t.Fatalf("hard links %v symlinks %v specials %v mounts %v races %v", r.HardLinks, r.Symlinks, r.Specials, r.MountPoints, r.Races)
	}
	if !slices.Equal(r.MountPoints.Sample, []string{"bind", "mnt"}) {
		t.Fatalf("mount points %v", r.MountPoints.Sample)
	}
	after := diskTree(t, filepath.Dir(root))
	for p, b := range before {
		if p == root {
			continue // the root itself is fixed
		}
		if a := after[p]; !reflect.DeepEqual(a, b) {
			t.Errorf("%s touched: %+v → %+v", p, b, a)
		}
	}
	if r.Changed != 1 {
		t.Fatalf("changed %d, want only the root", r.Changed)
	}
}

func TestRootSetuidKept(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	p := filepath.Join(root, "suid")
	fileOwned(t, p, 0o4755|os.ModeSetuid, 1000, 1000)
	apply(t, opts(t, root, Target{GID: 60001, Files: "rw"}))
	d := diskOf(t, p)
	if d.Mode&modeSetuid == 0 || d.GID != 60001 || d.UID != 1000 {
		t.Fatalf("setuid file after the group change: %d:%d %o", d.UID, d.GID, d.Mode)
	}
	if rd := diskOf(t, root); rd.Mode&modeSetgid == 0 {
		t.Fatalf("root without setgid: %o", rd.Mode)
	}
}

func TestRootSetgidFileSkipped(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	sg := filepath.Join(root, "sgid")
	fileOwned(t, sg, 0o2755|os.ModeSetgid, 1000, 1000)
	su := filepath.Join(root, "suid")
	fileOwned(t, su, 0o4755|os.ModeSetuid, 1000, 1000)
	before := diskTree(t, root)
	owner := 2000
	o := opts(t, root, Target{GID: 60001, Files: "rw", OwnerUID: &owner})
	r := apply(t, o)
	if r.SetID.N != 2 || !slices.Equal(r.SetID.Sample, []string{"sgid", "suid"}) {
		t.Fatalf("setid %+v", r.SetID)
	}
	after := diskTree(t, root)
	for _, p := range []string{sg, su} {
		if !reflect.DeepEqual(before[p], after[p]) {
			t.Errorf("%s touched", p)
		}
	}
	verify(t, o) // skipped entries don't count against conformance
}

func TestRootNoACLExplainOnly(t *testing.T) {
	needRoot(t)
	noACLForTest = true
	root := folderRoot(t) // 0750 1000:1000: group 1000 has r-x, others nothing
	fileOwned(t, filepath.Join(root, "f"), 0o640, 1000, 1000)
	o := opts(t, root, Target{GID: 60001, Files: "rw"})
	s, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	if s.ACL || s.Plan.LoseAccess.N != 2 {
		t.Fatalf("acl %v lose %+v", s.ACL, s.Plan.LoseAccess)
	}
	before := diskTree(t, root)
	if _, err := Apply(o, s.Plan.Changes); !IsRefused(err) {
		t.Fatalf("apply: %v, want a refusal", err)
	}
	if !reflect.DeepEqual(before, diskTree(t, root)) {
		t.Fatal("changed")
	}

	// With no previous group bits to lose: chgrp + setgid + mode only.
	root2 := folderRoot(t)
	chownMode(t, root2, 1000, 1000, 0o700)
	fileOwned(t, filepath.Join(root2, "f"), 0o600, 1000, 1000)
	r := apply(t, opts(t, root2, Target{GID: 60001, Files: "rw"}))
	if r.Changed != 2 {
		t.Fatalf("changed %d", r.Changed)
	}
	for p, d := range diskTree(t, root2) {
		if d.Acc != nil || d.Def != nil || d.GID != 60001 {
			t.Errorf("%s: %+v, want gid 60001 and no ACL xattr", p, d)
		}
	}
	if d := diskOf(t, root2); d.Mode&07777 != 0o2770 {
		t.Errorf("root %o, want 2770", d.Mode&07777)
	}
	if d := diskOf(t, filepath.Join(root2, "f")); d.Mode&07777 != 0o660 {
		t.Errorf("f %o, want 0660", d.Mode&07777)
	}
}

// richTree: dirs with and without ACLs, files with named entries, setuid.
func richTree(t *testing.T) string {
	t.Helper()
	root := folderRoot(t)
	mkdirOwned(t, filepath.Join(root, "a"), 0o755, 1000, 1000)
	mkdirOwned(t, filepath.Join(root, "a", "b"), 0o750, 1001, 1000)
	setACL(t, filepath.Join(root, "a", "b"), XattrAccess, acl(uo(R|W|X), us(3000, R|W|X), go_(R|X), mk(R|X), ot(0)))
	setACL(t, filepath.Join(root, "a", "b"), XattrDefault, acl(uo(R|W|X), go_(R|X), mk(R|X), ot(0)))
	fileOwned(t, filepath.Join(root, "a", "f1"), 0o644, 1000, 1000)
	fileOwned(t, filepath.Join(root, "a", "b", "f2"), 0o600, 1001, 1001)
	setACL(t, filepath.Join(root, "a", "b", "f2"), XattrAccess, acl(uo(R|W), us(3000, R|W), go_(0), mk(R), ot(0)))
	fileOwned(t, filepath.Join(root, "suid"), 0o4755|os.ModeSetuid, 1000, 1000)
	fileOwned(t, filepath.Join(root, "gone"), 0o640, 1000, 1000)
	fileOwned(t, filepath.Join(root, "edited"), 0o640, 1000, 1000)
	return root
}

func TestRootSnapshotRestore(t *testing.T) {
	needRoot(t)
	root := richTree(t)
	before := diskTree(t, root)
	o := opts(t, root, Target{GID: 60001, Files: "rw"})
	var snap bytes.Buffer
	sr, err := WriteSnapshot(o, &snap)
	if err != nil {
		t.Fatalf("snapshot: %v %v", err, sr.Errors)
	}
	h := snapshotHeader(t, snap.Bytes())
	if h.Kind != "apply" || h.GID != 60001 || h.Files != "rw" || h.OwnerUID != nil || h.Entries != sr.Plan.Changes || h.Entries != int64(len(before)) {
		t.Fatalf("header %+v, %d entries in the tree", h, len(before))
	}
	if r, err := Apply(o, h.Entries); err != nil {
		t.Fatalf("apply: %v %v", err, r.Errors)
	}
	verify(t, o)

	// Since the fix: one path replaced (a new inode), one entry edited by
	// someone (chmod): both are left alone.
	gone := filepath.Join(root, "gone")
	must(t, os.Remove(gone))
	fileOwned(t, gone, 0o640, 1000, 1000)
	edited := filepath.Join(root, "edited")
	must(t, unix.Chmod(edited, 0o600))
	replaced, editedNow := diskOf(t, gone), diskOf(t, edited)

	// The undo snapshot: every entry the restore will rewrite, as it is now.
	var undo bytes.Buffer
	ur, err := WriteUndoSnapshot(o, bytes.NewReader(snap.Bytes()), &undo)
	if err != nil {
		t.Fatalf("undo snapshot: %v %v", err, ur.Errors)
	}
	uh := snapshotHeader(t, undo.Bytes())
	if uh.Kind != "undo" || uh.GID != 60001 || uh.Entries != h.Entries-2 || uh.Files != "rw" {
		t.Fatalf("undo header %+v", uh)
	}
	// An undo snapshot is never restored.
	if _, err := Restore(o, bytes.NewReader(undo.Bytes())); !IsRefused(err) {
		t.Fatalf("restore of an undo snapshot: %v", err)
	}

	r, err := Restore(o, bytes.NewReader(snap.Bytes()))
	if err != nil {
		t.Fatalf("restore: %v %v", err, r.Errors)
	}
	if r.ChangedSince.N != 2 || !slices.Equal(r.ChangedSince.Sample, []string{"edited", "gone"}) || r.Changed != h.Entries-2 {
		t.Fatalf("changed %d, changed since %+v", r.Changed, r.ChangedSince)
	}
	after := diskTree(t, root)
	for p, b := range before {
		a := after[p]
		switch p {
		case gone:
			b = replaced
		case edited:
			b = editedNow
		}
		a.Ctime, b.Ctime = unix.Timespec{}, unix.Timespec{}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: before %+v after the restore %+v", p, b, a)
		}
	}
}

func snapshotHeader(t *testing.T, b []byte) snapHeader {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var h snapHeader
	if err := json.NewDecoder(gz).Decode(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRootMkdir(t *testing.T) {
	needRoot(t)
	root := folderRoot(t)
	o := opts(t, root, Target{GID: 60001, Files: "rw", Mkdir: []string{"movies/hd"}})
	r := apply(t, o)
	if r.Created != 2 {
		t.Fatalf("created %d", r.Created)
	}
	for _, p := range []string{"movies", "movies/hd"} {
		s := stateOf(t, filepath.Join(root, p))
		if !s.Dir || s.GID != 60001 || s.Mode&modeSetgid == 0 || !slices.Contains(s.Default, go_(R|W|X)) || s.UID != 1000 {
			t.Errorf("%s: %s", p, describe(s))
		}
	}
	verify(t, o)
	// A symlink in place of an existing component: refused, nothing created.
	root2 := folderRoot(t)
	outside := filepath.Join(filepath.Dir(root2), "elsewhere")
	mkdirOwned(t, outside, 0o755, 0, 0)
	must(t, os.Symlink(outside, filepath.Join(root2, "movies")))
	o2 := opts(t, root2, Target{GID: 60001, Files: "rw", Mkdir: []string{"movies/hd"}})
	s, _ := Scan(o2)
	before := diskTree(t, filepath.Dir(root2))
	if _, err := Apply(o2, s.Plan.Changes); !IsRefused(err) {
		t.Fatalf("mkdir through a symlink: %v", err)
	}
	if !reflect.DeepEqual(before, diskTree(t, filepath.Dir(root2))) {
		t.Fatal("changed")
	}
}

// onSecond runs f the second time the hook sees rel: the first is the
// apply's planning walk, the second its change walk.
func onSecond(rel string, f func()) func(string) {
	n := 0
	return func(r string) {
		if r == rel {
			if n++; n == 2 {
				f()
			}
		}
	}
}

func TestRootRaces(t *testing.T) {
	needRoot(t)
	var planted disk // the node a hook planted, as it was created
	type setup struct {
		name  string
		build func(t *testing.T, root, outside string)
		hook  func(root, outside string) (before, after func(string))
		check func(t *testing.T, r *Report, root, outside string)
	}
	outsideUntouched := func(t *testing.T, outside string, was map[string]disk) {
		t.Helper()
		if now := diskTree(t, outside); !reflect.DeepEqual(was, now) {
			t.Errorf("outside the tree touched:\n%v\n%v", was, now)
		}
	}
	cases := []setup{
		{
			name: "dir swapped for a symlink before open",
			build: func(t *testing.T, root, _ string) {
				mkdirOwned(t, filepath.Join(root, "v"), 0o755, 1000, 1000)
			},
			hook: func(root, outside string) (func(string), func(string)) {
				return onSecond("v", func() {
					must(t, os.Rename(filepath.Join(root, "v"), filepath.Join(root, "v.moved")))
					must(t, os.Symlink(outside, filepath.Join(root, "v")))
				}), nil
			},
			check: func(t *testing.T, r *Report, root, _ string) {
				if r.Races.N != 1 {
					t.Errorf("races %+v", r.Races)
				}
			},
		},
		{
			name: "dir swapped for a symlink after open",
			build: func(t *testing.T, root, _ string) {
				mkdirOwned(t, filepath.Join(root, "v"), 0o755, 1000, 1000)
				fileOwned(t, filepath.Join(root, "v", "in"), 0o644, 1000, 1000)
			},
			hook: func(root, outside string) (func(string), func(string)) {
				return nil, onSecond("v", func() {
					must(t, os.Rename(filepath.Join(root, "v"), filepath.Join(root, "v.moved")))
					must(t, os.Symlink(outside, filepath.Join(root, "v")))
				})
			},
			check: func(t *testing.T, r *Report, root, _ string) {
				// The walk kept its fd: the changes went to the moved directory.
				for _, p := range []string{"v.moved", "v.moved/in"} {
					if d := diskOf(t, filepath.Join(root, p)); d.GID != 60001 {
						t.Errorf("%s: gid %d", p, d.GID)
					}
				}
			},
		},
		{
			name: "file swapped for another file before open",
			build: func(t *testing.T, root, _ string) {
				fileOwned(t, filepath.Join(root, "f"), 0o644, 1000, 1000)
			},
			hook: func(root, _ string) (func(string), func(string)) {
				return onSecond("f", func() {
					// Renamed, not removed: the old inode stays alive, so the
					// new file can't get its number.
					must(t, os.Rename(filepath.Join(root, "f"), filepath.Join(root, "f.old")))
					fileOwned(t, filepath.Join(root, "f"), 0o600, 1000, 1000)
					planted = diskOf(t, filepath.Join(root, "f"))
				}), nil
			},
			check: func(t *testing.T, r *Report, root, _ string) {
				if r.Races.N != 1 {
					t.Errorf("races %+v", r.Races)
				}
				if d := diskOf(t, filepath.Join(root, "f")); !reflect.DeepEqual(d, planted) {
					t.Errorf("the new file was changed: %+v, planted %+v", d, planted)
				}
			},
		},
		{
			name: "file swapped for a FIFO before open",
			build: func(t *testing.T, root, _ string) {
				fileOwned(t, filepath.Join(root, "f"), 0o644, 1000, 1000)
			},
			hook: func(root, _ string) (func(string), func(string)) {
				return onSecond("f", func() {
					must(t, os.Remove(filepath.Join(root, "f")))
					must(t, unix.Mkfifo(filepath.Join(root, "f"), 0o644))
					planted = diskOf(t, filepath.Join(root, "f"))
				}), nil
			},
			check: func(t *testing.T, r *Report, root, _ string) {
				if r.Races.N != 1 {
					t.Errorf("races %+v", r.Races)
				}
				if d := diskOf(t, filepath.Join(root, "f")); !reflect.DeepEqual(d, planted) || d.Mode&sIFMT != unix.S_IFIFO {
					t.Errorf("fifo touched: %+v, planted %+v", d, planted)
				}
			},
		},
		{
			name: "file swapped for a device node before open",
			build: func(t *testing.T, root, _ string) {
				fileOwned(t, filepath.Join(root, "f"), 0o644, 1000, 1000)
			},
			hook: func(root, _ string) (func(string), func(string)) {
				return onSecond("f", func() {
					must(t, os.Remove(filepath.Join(root, "f")))
					must(t, unix.Mknod(filepath.Join(root, "f"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))))
					planted = diskOf(t, filepath.Join(root, "f"))
				}), nil
			},
			check: func(t *testing.T, r *Report, root, _ string) {
				if r.Races.N != 1 {
					t.Errorf("races %+v", r.Races)
				}
				if d := diskOf(t, filepath.Join(root, "f")); !reflect.DeepEqual(d, planted) || d.Mode&sIFMT != unix.S_IFCHR {
					t.Errorf("device touched: %+v, planted %+v", d, planted)
				}
			},
		},
		{
			name: "hard link to outside made while open",
			build: func(t *testing.T, root, _ string) {
				fileOwned(t, filepath.Join(root, "f"), 0o640, 1000, 1000)
			},
			hook: func(root, outside string) (func(string), func(string)) {
				return nil, onSecond("f", func() {
					must(t, os.Link(filepath.Join(root, "f"), filepath.Join(outside, "f-link")))
				})
			},
			check: func(t *testing.T, r *Report, root, outside string) {
				d := diskOf(t, filepath.Join(root, "f"))
				if d.GID != 1000 || d.Mode&07777 != 0o640 || d.Acc != nil {
					t.Errorf("f not put back: %+v", d)
				}
				if r.HardLinks.N != 1 || r.Failed.N != 1 {
					t.Errorf("hard links %+v failed %+v", r.HardLinks, r.Failed)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := folderRoot(t)
			outside := filepath.Join(filepath.Dir(root), "outside")
			mkdirOwned(t, outside, 0o755, 1000, 1000)
			fileOwned(t, filepath.Join(outside, "secret"), 0o600, 1000, 1000)
			c.build(t, root, outside)
			was := diskTree(t, outside)
			o := opts(t, root, Target{GID: 60001, Files: "rw"})
			s, err := Scan(o)
			if err != nil {
				t.Fatal(err)
			}
			testHookBeforeOpen, testHookAfterOpen = c.hook(root, outside)
			r, _ := Apply(o, s.Plan.Changes)
			testHookBeforeOpen, testHookAfterOpen = nil, nil
			if c.name != "hard link to outside made while open" {
				outsideUntouched(t, outside, was)
			}
			c.check(t, r, root, outside)
			if d := diskOf(t, filepath.Join(outside, "secret")); d.GID != 1000 || d.Acc != nil {
				t.Errorf("outside secret touched: %+v", d)
			}
		})
	}
}

// TestRootMountRoot: a bind mount reports its mount root, and a mount of a
// symlinked path (Docker resolves it) shows the target's root: refused.
func TestRootMountRoot(t *testing.T) {
	needRoot(t)
	base := folderRoot(t)
	src := filepath.Join(base, "src")
	other := filepath.Join(base, "other")
	mkdirOwned(t, src, 0o755, 1000, 1000)
	mkdirOwned(t, other, 0o755, 1000, 1000)
	must(t, os.Symlink(other, filepath.Join(base, "lnk")))
	mp := filepath.Join(filepath.Dir(base), "mp")
	mkdirOwned(t, mp, 0o755, 0, 0)
	if err := unix.Mount(src, mp, "", unix.MS_BIND, ""); err != nil {
		setfaclUnavailable(t, "bind mount: %v", err)
	}
	r, err := Scan(Options{Root: mp})
	unix.Unmount(mp, unix.MNT_DETACH)
	if err != nil || r.MountRoot == "" || !strings.HasSuffix(r.MountRoot, "/folder/src") {
		t.Fatalf("mount root %q: %v", r.MountRoot, err)
	}
	want := r.MountRoot
	if err := unix.Mount(filepath.Join(base, "lnk"), mp, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(mp, unix.MNT_DETACH)
	if _, err := Scan(Options{Root: mp, ExpectMountRoot: want}); !IsRefused(err) {
		t.Fatalf("symlinked mount: %v, want a refusal", err)
	}
	r, err = Scan(Options{Root: mp, ExpectMountRoot: strings.TrimSuffix(want, "src") + "other"})
	if err != nil {
		t.Fatalf("exact mount root: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
