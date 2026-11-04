package folderfix

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// planNode plans one walked node: false when the fix leaves it alone
// (hard link, setid, an ACL it can't carry), counted here.
func (w *walker) planNode(n *node) (outcome, bool) {
	if n.skip || !w.hasT {
		return outcome{}, false
	}
	o, err := planEntry(n.cur, w.t)
	if err != nil {
		w.r.BadACL.add(n.rel)
		w.r.errorf("%s: %v", n.rel, err)
		return o, false
	}
	if o.setid {
		w.r.SetID.add(n.rel)
		return o, false
	}
	if !o.change {
		return o, true
	}
	// R49: what a snapshot can't record is never changed.
	if len(n.rel) > maxPathBytes {
		w.r.Skipped.PathTooLong.add(n.rel)
		return o, false
	}
	if b, err := snapshotLine(n); err != nil || len(b) > maxSnapLine {
		w.r.Skipped.ACLTooLarge.add(n.rel)
		return o, false
	}
	return o, true
}

// tally counts what an apply would do to the node (scan, and an apply's
// planning walk).
func (w *walker) tally(n *node) {
	o, ok := w.planNode(n)
	if !ok || !o.change {
		return
	}
	e, p := w.r.Expected, w.r.Plan
	p.Changes++
	digestEntry(w.digest, n)
	if w.planned != nil {
		w.planned[entryKey(n)] = struct{}{}
	}
	if o.group {
		e.Group.add(n.rel)
		p.ChangeGroup.add(n.rel)
	}
	if o.setgid {
		e.Setgid.add(n.rel)
		p.AddSetgid.add(n.rel)
	}
	if o.defACL {
		e.DefaultACL.add(n.rel)
		p.AddDefaultACL.add(n.rel)
	}
	if o.mode {
		e.Mode.add(n.rel)
	}
	if o.owner {
		e.Owner.add(n.rel)
		p.ChangeOwner.add(n.rel)
	}
	if o.narrowed {
		p.Narrowed.add(n.rel)
	}
	if o.keepGroup {
		p.KeepGroup[int(n.cur.GID)]++
	}
	if o.keepUser {
		p.KeepUser[int(n.cur.UID)]++
	}
	if o.lose {
		p.LoseAccess.add(n.rel)
	}
}

// mayChange: the checks before any run that writes (apply, restore).
func (w *walker) mayChange() error {
	if w.o.ExpectDev == 0 || w.o.ExpectIno == 0 {
		return refuse("a run that changes the folder needs its device and inode")
	}
	ok, err := idMapsIdentity()
	if err != nil {
		return refuse("read the id maps: %v", err)
	}
	if !ok {
		return refuse("the fixer runs in a user namespace with translated ids (userns-remap or rootless Docker): owners and ACLs would be wrong")
	}
	if !writableFS[w.r.FSType] {
		return refuse("the folder is on %s: the Hub changes ownership only on ext4, xfs, btrfs and zfs", w.r.FSType)
	}
	return nil
}

// Apply re-plans the folder and, when the plan changes exactly expect
// entries (the count the admin previewed and the snapshot holds), applies
// it. Any refusal comes before the first change.
func Apply(o Options, expect int64) (*Report, error) {
	o.MaxEntries, o.MaxTime = 0, 0 // M4: a plan accepted is applied whole
	w, err := openWalker(o, "apply")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	if !w.hasT {
		return w.report(), errors.New("apply needs the folder gid and files")
	}
	for _, m := range o.Target.Mkdir {
		if err := validSubpath(m); err != nil {
			return w.report(), err
		}
	}
	if err := w.mayChange(); err != nil {
		return w.report(), err
	}
	w.planned = map[[16]byte]struct{}{}
	w.run(w.tally)
	switch {
	case w.r.Partial:
		return w.finish(), refuse("the plan is incomplete (%s): nothing changed", w.r.PartialReason)
	case w.r.Failed.N > 0:
		return w.finish(), refuse("%d entries couldn't be read: nothing changed", w.r.Failed.N)
	case w.r.Plan.LoseAccess.N > 0:
		return w.finish(), refuse("%d entries would change a previous group's or owner's access on a filesystem without ACLs: nothing changed", w.r.Plan.LoseAccess.N)
	}
	for _, m := range o.Target.Mkdir {
		if err := w.checkMkdir(m); err != nil {
			return w.finish(), err
		}
	}
	if w.r.Plan.Changes != expect {
		return w.finish(), refuse("the folder changed since the preview: %d entries to change, expected %d: nothing changed", w.r.Plan.Changes, expect)
	}
	r := w.finish()
	if o.ExpectDigest != "" && r.Plan.Digest != o.ExpectDigest {
		return r, refuse("the folder changed since the snapshot (another digest of the entries to change): nothing changed")
	}
	plan, exp := r.Plan, w.r.Expected
	w.reset()
	var created int64
	for _, m := range o.Target.Mkdir {
		c, err := w.mkdir(m)
		created += c
		if err != nil {
			r := w.finish()
			r.Plan, r.Expected, r.Created = plan, exp, created
			if created > 0 {
				err = unrefuse(err) // M3: something was made: a failure
			}
			return r, fmt.Errorf("create %s: %w", m, err)
		}
	}
	w.run(w.change)
	r = w.finish()
	r.Plan, r.Expected, r.Created = plan, exp, created
	if r.Failed.N > 0 || r.Partial {
		return r, fmt.Errorf("%d entries couldn't be changed", r.Failed.N)
	}
	return r, nil
}

// change applies the plan to one node through its fd, in the contract's
// order, then checks the result.
func (w *walker) change(n *node) {
	o, ok := w.planNode(n)
	if !ok || !o.change {
		return
	}
	// R52: only an entry the plan recorded, exactly as recorded (path,
	// inode, state): one altered or added since is left alone.
	k := entryKey(n)
	if _, ok := w.planned[k]; !ok {
		w.r.Races.add(n.rel)
		w.r.errorf("%s: changed since the plan: left alone", n.rel)
		return
	}
	delete(w.planned, k)
	if o.lose { // the planning walk refused these; a backstop
		w.fail(n.rel, errors.New("would change a previous group's access"))
		return
	}
	acc, def, err := encodeState(o.want)
	if err != nil {
		w.r.BadACL.add(n.rel)
		w.r.errorf("%s: %v", n.rel, err)
		return
	}
	if err := writeState(n.fd, n.cur, o.want, acc, def, w.acl); err != nil {
		w.fail(n.rel, err)
		if rerr := w.revert(n, o.want); rerr != nil {
			w.r.errorf("%s: putting it back failed: %v", n.rel, rerr)
		}
		return
	}
	if err := w.after(n, o.want); err != nil {
		w.fail(n.rel, err)
		return
	}
	w.r.Changed++
}

// after checks an entry just written: still one link (a hard link made
// while it was open puts it back as it was), and the kernel holds what was
// written.
func (w *walker) after(n *node, want state) error {
	st, err := fstatFD(n.fd)
	if err != nil {
		return err
	}
	if !n.cur.Dir && st.Nlink > 1 {
		w.r.HardLinks.add(n.rel)
		if err := w.revert(n, want); err != nil {
			return fmt.Errorf("a hard link appeared while it was changed, and putting it back failed: %w", err)
		}
		return errors.New("a hard link appeared while it was changed: put back as it was")
	}
	got := &node{rel: n.rel, fd: n.fd, st: st}
	if err := w.readState(got); err != nil {
		return err
	}
	if !stateEqual(got.cur, want) {
		return fmt.Errorf("after the change the entry is %s, want %s", describe(got.cur), describe(want))
	}
	return nil
}

// revert writes the node's state as first read back; onDisk is what it was
// changed to (or partly: every attribute that may differ is written).
func (w *walker) revert(n *node, onDisk state) error {
	from := onDisk
	from.UID = ^n.cur.UID // force the chown: a failed write may have done it
	return writeState(n.fd, from, n.cur, n.raw.access, n.raw.def, w.acl)
}

// unrefuse turns a refusal into a plain failure: something already changed.
func unrefuse(err error) error {
	if IsRefused(err) {
		return errors.New(err.Error())
	}
	return err
}

func encodeState(s state) (acc, def []byte, err error) {
	if s.Access != nil {
		if acc, err = s.Access.Encode(); err != nil {
			return nil, nil, fmt.Errorf("access ACL: %w", err)
		}
	}
	if s.Default != nil {
		if def, err = s.Default.Encode(); err != nil {
			return nil, nil, fmt.Errorf("default ACL: %w", err)
		}
	}
	return acc, def, nil
}

// writeState makes the entry behind fd hold want: fchown → access ACL →
// fchmod (it sets the setuid/setgid bits a chown clears, and the group
// bits = the mask) → default ACL (directories). from is its current state.
// acc / def nil = no xattr (removed if there is one).
func writeState(fd int, from, want state, acc, def []byte, acl bool) error {
	if from.UID != want.UID || from.GID != want.GID {
		if err := fchown(fd, want.UID, want.GID); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	if acl {
		var err error
		if acc != nil {
			err = setXattr(fd, XattrAccess, acc)
		} else if from.Access != nil {
			err = removeXattr(fd, XattrAccess)
		}
		if err != nil {
			return fmt.Errorf("access ACL: %w", err)
		}
	}
	if err := fchmod(fd, want.Mode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if acl && want.Dir {
		var err error
		if def != nil {
			err = setXattr(fd, XattrDefault, def)
		} else if from.Default != nil {
			err = removeXattr(fd, XattrDefault)
		}
		if err != nil {
			return fmt.Errorf("default ACL: %w", err)
		}
	}
	return nil
}

func stateEqual(a, b state) bool {
	return a.UID == b.UID && a.GID == b.GID && a.Mode&modePerm == b.Mode&modePerm &&
		aclEqual(a.Access, b.Access) && aclEqual(a.Default, b.Default)
}

func describe(s state) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:%d %04o", s.UID, s.GID, s.Mode&modePerm)
	if s.Access != nil {
		b.WriteString(" acl " + aclText(s.Access))
	}
	if s.Default != nil {
		b.WriteString(" default " + aclText(s.Default))
	}
	return b.String()
}

// aclText is the getfacl -n short form, e.g. "u::rwx,g:1000:r--,m::rwx,o::---".
func aclText(a ACL) string {
	var parts []string
	for _, e := range canon(a) {
		var tag, id string
		switch e.Tag {
		case TagUserObj:
			tag = "user"
		case TagUser:
			tag, id = "user", fmt.Sprint(e.ID)
		case TagGroupObj:
			tag = "group"
		case TagGroup:
			tag, id = "group", fmt.Sprint(e.ID)
		case TagMask:
			tag = "mask"
		case TagOther:
			tag = "other"
		}
		parts = append(parts, tag+":"+id+":"+e.Perm.String())
	}
	return strings.Join(parts, ",")
}

// walkDirs follows rel's components from the root fd, every one a
// directory on the root's mount (O_NOFOLLOW per component). It stops at the
// first missing one: fd is then its parent, missing the rest.
func (w *walker) walkDirs(rel string) (fd int, missing []string, err error) {
	fd, err = dupFD(w.rootfd)
	if err != nil {
		return -1, nil, err
	}
	comps := strings.Split(rel, "/")
	at := "."
	for i, c := range comps {
		crel := joinRel(at, c)
		st, err := lstatAt(fd, c)
		if errors.Is(err, fs.ErrNotExist) {
			return fd, comps[i:], nil
		}
		if err == nil {
			switch {
			case st.isLink():
				err = refuse("%s is a symlink: refused", crel)
			case !st.isDir():
				err = refuse("%s exists and is not a directory: refused", crel)
			case w.otherMount(st, crel):
				err = refuse("%s is another mount: refused", crel)
			}
		}
		if err != nil {
			closeFD(fd)
			return -1, nil, err
		}
		nfd, err := openAt(fd, c, true)
		if err != nil {
			closeFD(fd)
			return -1, nil, refuse("%s changed: %v", crel, err)
		}
		if fst, err := fstatFD(nfd); err != nil || !fst.same(st) {
			closeFD(nfd)
			closeFD(fd)
			return -1, nil, refuse("%s changed during the check", crel)
		}
		closeFD(fd)
		fd, at = nfd, crel
	}
	return fd, nil, nil
}

// checkMkdir: every existing component of a --mkdir path is a plain
// directory on the folder's mount.
func (w *walker) checkMkdir(rel string) error {
	fd, _, err := w.walkDirs(rel)
	if err != nil {
		return err
	}
	closeFD(fd)
	return nil
}

// mkdir creates the missing components of rel (mkdirat under the parent's
// fd), each owned like its parent with the folder gid, the parent's user
// and other bits, group rwx and setgid; the walk that follows sets the
// ACLs.
func (w *walker) mkdir(rel string) (int64, error) {
	fd, missing, err := w.walkDirs(rel)
	if err != nil {
		return 0, err
	}
	defer func() { closeFD(fd) }()
	comps := strings.Split(rel, "/")
	at := strings.Join(comps[:len(comps)-len(missing)], "/")
	if at == "" {
		at = "."
	}
	var created int64
	for _, c := range missing {
		crel := joinRel(at, c)
		at = crel
		parent, err := fstatFD(fd)
		if err != nil {
			return created, err
		}
		if testHookMkdir != nil {
			testHookMkdir(crel)
		}
		if err := mkdirAt(fd, c, 0o700); err != nil {
			return created, err
		}
		created++
		st, err := lstatAt(fd, c)
		if err != nil || !st.isDir() || w.otherMount(st, crel) {
			return created, fmt.Errorf("%s changed after it was created", c)
		}
		nfd, err := openAt(fd, c, true)
		if err != nil {
			return created, err
		}
		if fst, err := fstatFD(nfd); err != nil || !fst.same(st) {
			closeFD(nfd)
			return created, fmt.Errorf("%s changed after it was created", c)
		}
		closeFD(fd)
		fd = nfd
		if err := fchown(fd, parent.UID, w.t.GID); err != nil {
			return created, err
		}
		if err := fchmod(fd, parent.Mode&0o707|0o070|modeSetgid); err != nil {
			return created, err
		}
		// The change walk sets its ACLs: it is planned as it is now (R52).
		nst, err := fstatFD(fd)
		if err != nil {
			return created, err
		}
		n := &node{rel: crel, fd: fd, st: nst}
		if err := w.readState(n); err != nil {
			return created, err
		}
		w.planned[entryKey(n)] = struct{}{}
	}
	return created, nil
}
