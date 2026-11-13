package folderfix

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// openRestoreWalker opens the folder for a restore or an undo snapshot:
// the folder gid is checked against the snapshot's header, files and owner
// come from the header.
func openRestoreWalker(o Options, mode string) (*walker, error) {
	if o.Target.GID <= 0 {
		return &walker{r: Report{Version: 1, Mode: mode, Root: o.Root}, rootfd: -1}, errors.New("a restore needs the folder gid")
	}
	o2 := o
	o2.Target = Target{GID: o.Target.GID, Files: "rw"}
	o2.Principals, o2.Children, o2.MaxEntries, o2.MaxTime = nil, false, 0, 0
	w, err := openWalker(o2, mode)
	if err != nil {
		return w, err
	}
	w.r.Expected, w.r.Plan = nil, nil
	return w, nil
}

// checkHeader: an apply snapshot of this folder (root device and inode and
// gid). It sets the walker's target to the header's: the one the apply
// used.
func (w *walker) checkHeader(h snapHeader) error {
	if h.Kind != "apply" {
		return refuse("snapshot kind %q: only an apply snapshot can be restored", h.Kind)
	}
	if h.Rules != planRules {
		return refuse("the snapshot was made under rules %d, this fixer has %d", h.Rules, planRules)
	}
	wantDev, wantIno := w.root.Dev, w.root.Ino
	if w.o.SnapshotRootDev != 0 || w.o.SnapshotRootIno != 0 {
		// A device-only re-check since the snapshot: the same directory
		// (inode), recorded on its old device number.
		if w.o.SnapshotRootIno != w.root.Ino {
			return refuse("the snapshot's recorded root inode %d is not the folder's %d: it is of another directory", w.o.SnapshotRootIno, w.root.Ino)
		}
		wantDev, wantIno = w.o.SnapshotRootDev, w.o.SnapshotRootIno
	}
	if h.RootDev != wantDev || h.RootIno != wantIno {
		return refuse("the snapshot is of another directory (device %d inode %d, the folder is %d/%d)", h.RootDev, h.RootIno, wantDev, wantIno)
	}
	if uint32(h.GID) != w.t.GID {
		return refuse("the snapshot is for gid %d, the folder's is %d", h.GID, w.t.GID)
	}
	w.t.Write = h.Files == "rw"
	w.t.HasOwner = h.OwnerUID != nil
	if h.OwnerUID != nil {
		w.t.Owner = uint32(*h.OwnerUID)
	}
	return nil
}

// Restore puts back the entries of an apply snapshot, each only while it is
// still the recorded inode and type and holds exactly what the apply
// produced from its line (recomputed from the header's target): anything
// else is skipped and counted (ChangedSince), so a restore never takes away
// access granted since. A snapshot that is also an io.Seeker is validated
// completely before the first change.
func Restore(o Options, snapshot io.Reader) (*Report, error) {
	w, err := openRestoreWalker(o, "restore")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	if err := w.mayChange(); err != nil {
		return w.report(), err
	}
	if s, ok := snapshot.(io.Seeker); ok {
		// The whole snapshot first; under a non-identity map also every
		// entry's current owner (an unmapped one refuses the restore
		// before anything changes).
		if err := readSnapshot(snapshot, w.checkHeader, func(l snapLine, s state, p string) error {
			w.checkUnmapped(l, s, p)
			return nil
		}); err != nil {
			return w.report(), err
		}
		if w.r.Unmapped.N > 0 {
			return w.report(), refuse(UnmappedMsg, w.r.Unmapped.Sample[0])
		}
		if _, err := s.Seek(0, io.SeekStart); err != nil {
			return w.report(), err
		}
	}
	err = readSnapshot(snapshot, w.checkHeader, func(l snapLine, s state, p string) error {
		w.restoreLine(l, s, p, nil)
		return nil
	})
	r := w.report()
	if err != nil {
		if r.Changed > 0 && IsRefused(err) {
			err = errors.New(err.Error()) // something changed: a failure, not a refusal
		}
		return r, err
	}
	if r.Failed.N > 0 {
		return r, fmt.Errorf("%d entries couldn't be restored", r.Failed.N)
	}
	return r, nil
}

// RestoreDryRun is Restore without a single write (R56): ToRestore counts
// the entries a restore would rewrite now, ChangedSince those it would
// leave alone. The undo's preview shows it; run again after a restore, it
// must find 0 still to rewrite (the undo's verify). It needs no write
// capability and refuses nothing a read-only scan wouldn't.
func RestoreDryRun(o Options, snapshot io.Reader) (*Report, error) {
	w, err := openRestoreWalker(o, "restore")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	err = readSnapshot(snapshot, w.checkHeader, func(l snapLine, s state, p string) error {
		if w.restoreLine(l, s, p, func(*node) error { return nil }) {
			w.r.ToRestore++
		}
		return nil
	})
	r := w.report()
	if err != nil {
		return r, err
	}
	if r.Failed.N > 0 {
		return r, fmt.Errorf("%d entries couldn't be read", r.Failed.N)
	}
	return r, nil
}

// WriteUndoSnapshot writes, from an apply snapshot, the undo snapshot
// (header kind "undo"): every entry Restore would rewrite, in its current
// state. It changes nothing.
func WriteUndoSnapshot(o Options, apply io.ReadSeeker, out io.Writer) (*Report, error) {
	w, err := openRestoreWalker(o, "snapshot")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	var hdr snapHeader
	var count int64
	err = readSnapshot(apply, func(h snapHeader) error { hdr = h; return w.checkHeader(h) }, func(l snapLine, s state, p string) error {
		if w.restoreLine(l, s, p, func(*node) error { return nil }) {
			count++
		}
		return nil
	})
	if err != nil {
		return w.report(), err
	}
	if _, err := apply.Seek(0, io.SeekStart); err != nil {
		return w.report(), err
	}
	w.reset()
	t := Target{GID: hdr.GID, Files: hdr.Files, OwnerUID: hdr.OwnerUID}
	sw, err := newSnapWriter(out, w.header("undo", count, t))
	if err != nil {
		return w.report(), err
	}
	var werr error
	err = readSnapshot(apply, w.checkHeader, func(l snapLine, s state, p string) error {
		w.restoreLine(l, s, p, func(n *node) error {
			if werr == nil {
				werr = sw.line(n)
			}
			return werr
		})
		return nil
	})
	if cerr := sw.close(); werr == nil {
		werr = cerr
	}
	r := w.report()
	switch {
	case err != nil:
		return r, err
	case werr != nil:
		return r, werr
	case r.Failed.N > 0:
		return r, fmt.Errorf("%d entries couldn't be read", r.Failed.N)
	case sw.n != count:
		return r, fmt.Errorf("the folder changed during the undo snapshot (%d entries, then %d)", count, sw.n)
	}
	return r, nil
}

// restoreLine restores one entry (emit nil) or hands it to emit (undo
// snapshot). true = the entry is one a restore rewrites.
func (w *walker) restoreLine(l snapLine, rec state, p string, emit func(*node) error) bool {
	fd, st, ok := w.resolve(p, rec.Dir, l.Ino)
	if !ok {
		w.r.ChangedSince.add(p)
		return false
	}
	defer closeFD(fd)
	n := &node{rel: p, fd: fd, st: st}
	if err := w.readState(n); err != nil {
		if errors.Is(err, errBadACL) {
			w.r.ChangedSince.add(p)
		} else {
			w.fail(p, err)
		}
		return false
	}
	if emit == nil && unmappedID(w.idm, n.st.UID, n.st.GID) {
		// A snapshot read once (no seeking): left alone, counted.
		w.r.Unmapped.add(p)
		w.r.ChangedSince.add(p)
		return false
	}
	o, err := planEntry(rec, w.t)
	// A file that has file capabilities now is left alone too (R54): the
	// restore's chown would drop them.
	if err != nil || o.setid || o.filecaps || n.cur.FileCaps || !o.change || !stateEqual(n.cur, o.want) {
		w.r.ChangedSince.add(p)
		return false
	}
	if emit != nil {
		if err := emit(n); err != nil {
			w.fail(p, err)
		}
		return true
	}
	acc, def, err := encodeState(rec)
	if err != nil {
		w.fail(p, err)
		return false
	}
	if err := writeState(fd, n.cur, rec, acc, def, w.acl); err != nil {
		w.fail(p, err)
		if rerr := w.revert(n, rec); rerr != nil {
			w.r.errorf("%s: putting it back failed: %v", p, rerr)
		}
		return false
	}
	if err := w.after(n, rec); err != nil {
		w.fail(p, err)
		return false
	}
	w.r.Changed++
	return true
}

// checkUnmapped counts the snapshot entry p when it still resolves to the
// recorded inode and its owner is unmapped (the validation pass).
func (w *walker) checkUnmapped(l snapLine, rec state, p string) {
	if w.idm == nil {
		return
	}
	fd, st, ok := w.resolve(p, rec.Dir, l.Ino)
	if !ok {
		return
	}
	closeFD(fd)
	if testHookOwnerOf != nil {
		st.UID, st.GID = testHookOwnerOf(p, st.UID, st.GID)
	}
	if unmappedID(w.idm, st.UID, st.GID) {
		w.r.Unmapped.add(p)
	}
}

// resolve walks to p from the root fd, one openat(O_NOFOLLOW) per
// component, never a joined path: every directory on the way is a plain
// directory on the root's mount, and the entry is the recorded inode and
// type (a regular file with one link). ok false = skip.
func (w *walker) resolve(p string, dir bool, ino uint64) (int, fileStat, bool) {
	if p == "." {
		if !dir || w.root.Ino != ino {
			return -1, fileStat{}, false
		}
		fd, err := dupFD(w.rootfd)
		if err != nil {
			return -1, fileStat{}, false
		}
		return fd, w.root, true
	}
	parent, last := ".", p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		parent, last = p[:i], p[i+1:]
	}
	var dfd int
	if parent == "." {
		var err error
		if dfd, err = dupFD(w.rootfd); err != nil {
			return -1, fileStat{}, false
		}
	} else {
		var missing []string
		var err error
		dfd, missing, err = w.walkDirs(parent)
		if err != nil {
			return -1, fileStat{}, false
		}
		if len(missing) > 0 {
			closeFD(dfd)
			return -1, fileStat{}, false
		}
	}
	defer closeFD(dfd)
	st, err := lstatAt(dfd, last)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			w.r.errorf("%s: %v", p, err)
		}
		return -1, fileStat{}, false
	}
	if st.Ino != ino || w.otherMount(st, p) || (dir && !st.isDir()) || (!dir && (!st.isReg() || st.Nlink > 1)) {
		return -1, fileStat{}, false
	}
	fd, err := openAt(dfd, last, dir)
	if err != nil {
		return -1, fileStat{}, false
	}
	fst, err := fstatFD(fd)
	if err != nil || !fst.same(st) || (!dir && fst.Nlink > 1) {
		closeFD(fd)
		return -1, fileStat{}, false
	}
	return fd, fst, true
}
