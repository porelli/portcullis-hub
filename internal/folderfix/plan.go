package folderfix

import (
	"errors"
	"fmt"
	"slices"
)

// Mode bits beyond the permissions (the same values on every unix).
const (
	modeSetuid uint32 = 04000
	modeSetgid uint32 = 02000
	modeSticky uint32 = 01000
	modePerm   uint32 = 07777
)

// state is an entry's ownership as the fixer reads and writes it.
type state struct {
	Dir      bool
	UID, GID uint32
	Mode     uint32 // permission and setuid/setgid/sticky bits (07777)
	Access   ACL    // the access ACL xattr as decoded; nil when there is none
	Default  ACL    // directories: the default ACL xattr as decoded; nil when none
	// FileCaps: a security.capability xattr is present (R54; never
	// written, never part of a snapshot line).
	FileCaps bool
}

// target is Target in the form planEntry needs, plus whether the
// filesystem takes ACLs.
type target struct {
	GID      uint32
	Write    bool // files "rw"
	HasOwner bool
	Owner    uint32
	ACL      bool
}

// outcome is what an apply does to one entry.
type outcome struct {
	want  state
	setid bool // skipped: setgid file under a group change, setuid file under an owner change
	// filecaps: skipped, a regular file with file capabilities (R54).
	filecaps bool
	change   bool

	group, setgid, defACL, mode, owner bool // the attributes that differ
	narrowed                           bool // an existing named entry is narrowed to what it grants
	keepGroup, keepUser                bool // the previous group / owner gets a named entry
	lose                               bool // no ACLs: the previous group or owner's access changes
}

var errBadACL = errors.New("acl the fix can't carry exactly")

func badACL(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errBadACL, fmt.Sprintf(format, args...))
}

func permOf(a ACL, tag uint16) Perm {
	for _, e := range a {
		if e.Tag == tag {
			return e.Perm
		}
	}
	return 0
}

func namedEntry(a ACL, tag uint16, id uint32) (Perm, bool) {
	for _, e := range a {
		if e.Tag == tag && e.ID == id {
			return e.Perm, true
		}
	}
	return 0, false
}

func hasNamed(a ACL) bool {
	return slices.ContainsFunc(a, func(e Entry) bool { return named(e.Tag) })
}

// canon is the ACL in canonical order, nil when empty.
func canon(a ACL) ACL {
	if len(a) == 0 {
		return nil
	}
	s := slices.Clone(a)
	slices.SortStableFunc(s, less)
	return s
}

func aclEqual(a, b ACL) bool { return slices.Equal(canon(a), canon(b)) }

// keepPerm is the perm of the named entry that keeps a previous group's (or
// owner's) effective rights eff, when the ACL may already hold a named entry
// for that id. A member matching two entries gets what any one of them
// grants, so one entry can stand for both only when one is a superset of the
// other; otherwise the rights can't be kept exactly (errBadACL).
func keepPerm(a ACL, tag uint16, id uint32, eff Perm) (Perm, error) {
	p, ok := namedEntry(a, tag, id)
	switch {
	case !ok || p&eff == p:
		return eff, nil
	case p&eff == eff:
		return p, nil
	}
	return 0, badACL("id %d has %s through an entry and %s through the owner class", id, p, eff)
}

// planEntry computes the consistent-ownership state of contract §14.2 for one
// entry and how it differs from cur (rules version planRules). Nobody's effective rights shrink, and
// nobody but the folder group and the must_own uid gains any:
//   - named entries are narrowed to entry ∧ old mask before the mask is raised;
//   - the owning group class is narrowed the same way (group_obj ∧ old mask);
//   - a previous owning group gets a named entry with its effective bits
//     (also "---": without it its members would fall through to "others");
//   - under must_own the previous owner gets a named entry with its user bits;
//   - "others" and the user bits are never changed, nothing is removed;
//   - setuid / setgid regular files are skipped (setid), and so are
//     regular files with file capabilities (filecaps, R54);
//   - a directory's default ACL grants new files to the folder group only.
//
// An ACL on disk that isn't valid (unsorted, duplicate ids) is errBadACL:
// the entry is reported and left alone.
func planEntry(cur state, t target) (outcome, error) {
	o := outcome{want: cur}
	file := !cur.Dir
	// R47: a regular file with setuid or setgid is never touched: a new
	// group, owner or group x on it would let the folder group or the app
	// act as its owner or group.
	if file && cur.Mode&(modeSetuid|modeSetgid) != 0 {
		o.setid = true
		return o, nil
	}
	// R54: a regular file with file capabilities is never touched either:
	// any chown (a new group included) makes the kernel drop its
	// security.capability xattr, which "nothing is ever removed" forbids.
	if file && cur.FileCaps {
		o.filecaps = true
		return o, nil
	}
	if len(cur.Access) > 0 {
		if err := cur.Access.Valid(); err != nil {
			return o, badACL("access ACL on disk: %v", err)
		}
	}
	if len(cur.Default) > 0 {
		if err := cur.Default.Valid(); err != nil {
			return o, badACL("default ACL on disk: %v", err)
		}
	}
	hadAccess := len(cur.Access) > 0
	acc := canon(cur.Access)
	if acc == nil {
		acc = FromMode(cur.Mode)
	}
	userP, otherP, gobjP := permOf(acc, TagUserObj), permOf(acc, TagOther), permOf(acc, TagGroupObj)
	oldMask, has := acc.Mask()
	if !has {
		oldMask = permAll
	}
	groupEff := gobjP & oldMask

	desired := permAll
	if file {
		desired = R
		if t.Write {
			desired |= W
		}
		// The folder group class never has less than "others": its members
		// stop falling through to "others" once it is the owning group.
		desired |= otherP
	}
	changeGroup := cur.GID != t.GID
	changeOwner := t.HasOwner && cur.UID != t.Owner

	w := state{Dir: cur.Dir, UID: cur.UID, GID: t.GID}
	if changeOwner {
		w.UID = t.Owner
	}
	// Under must_own the new owner (the folder's app) gets the old user bits
	// plus what it could already do through a named entry, a group entry or
	// "others", and the folder group's bits: the owner class decides alone,
	// so without them it could lose rights it had.
	userNew := userP
	if changeOwner {
		// Which groups it holds is unknown here, so every group-class entry
		// counts; an owner can chmod its file anyway, so nothing it gets
		// here is beyond its reach.
		userNew |= desired | otherP
		for _, e := range acc {
			switch e.Tag {
			case TagGroupObj, TagGroup:
				userNew |= e.Perm & oldMask
			case TagUser:
				if e.ID == t.Owner {
					userNew |= e.Perm & oldMask
				}
			}
		}
	}
	if file {
		desired |= userNew & X // g+x only where the (new) user bits have x
	}
	setid := cur.Mode & (modeSetuid | modeSetgid | modeSticky)
	if cur.Dir {
		setid |= modeSetgid
	}

	if !t.ACL {
		// Group, setgid and mode only. After a group change the previous
		// group's members fall back to "others", after an owner change the
		// previous owner too: unless those bits are equal, their access
		// changes, which only an ACL could prevent.
		if changeGroup && groupEff != otherP {
			o.lose = true
		}
		if changeOwner && userP != otherP {
			o.lose = true
		}
		g := desired
		if !changeGroup {
			g |= groupEff
		}
		w.Mode = setid | uint32(userNew)<<6 | uint32(g)<<3 | uint32(otherP)
	} else {
		a := acc.Clamp()
		if !slices.Equal(a, acc) {
			o.narrowed = true
		}
		if changeGroup {
			keep, err := keepPerm(a, TagGroup, cur.GID, groupEff)
			if err != nil {
				return o, err
			}
			a = a.Set(TagGroup, cur.GID, keep)
			a = a.Set(TagGroupObj, 0, desired)
			o.keepGroup = true
		} else {
			a = a.Set(TagGroupObj, 0, groupEff|desired)
		}
		if changeOwner {
			// A named entry for the owner was inactive (the owner class
			// decides): replacing it changes nobody's rights.
			a = a.Set(TagUser, cur.UID, userP).Set(TagUserObj, 0, userNew)
			o.keepUser = true
		}
		needXattr := cur.Dir || hasNamed(a) || hadAccess
		switch {
		case cur.Dir:
			a = a.Set(TagMask, 0, permAll)
		case needXattr:
			a = a.RecalcMask()
		}
		gbits := permOf(a, TagGroupObj)
		if m, ok := a.Mask(); ok {
			gbits = m
		}
		w.Mode = setid | uint32(userNew)<<6 | uint32(gbits)<<3 | uint32(otherP)
		if needXattr {
			w.Access = a
		}
		if cur.Dir {
			// R51: the default ACL is what files made later get: the
			// creator (USER_OBJ), the folder group rwx, mask rwx, and only
			// what an existing default ACL already granted (its named
			// entries narrowed to its mask, its "others"). Never an entry for
			// the previous group or owner, and "others" --- when there was
			// none: with a default ACL the umask no longer narrows new files.
			var d ACL
			if len(cur.Default) > 0 {
				d = canon(cur.Default)
				if c := d.Clamp(); !slices.Equal(c, d) {
					o.narrowed = true
					d = c
				}
			} else {
				d = ACL{{Tag: TagUserObj, Perm: userNew}, {Tag: TagGroupObj}, {Tag: TagOther}}
			}
			w.Default = d.Set(TagGroupObj, 0, permAll).Set(TagMask, 0, permAll)
		}
	}

	o.want = w
	o.owner = w.UID != cur.UID
	o.group = w.GID != cur.GID
	o.setgid = cur.Dir && cur.Mode&modeSetgid == 0
	o.mode = w.Mode != cur.Mode&modePerm || !equivalent(w.Access, cur.Access, w.Mode, cur.Mode)
	o.defACL = cur.Dir && !equivalentDefault(w.Default, cur.Default)
	o.change = o.owner || o.group || o.mode || o.defACL
	if !o.change {
		o.narrowed, o.keepGroup, o.keepUser, o.lose = false, false, false, false
	}
	return o, nil
}

// equivalent: two access ACLs (nil = the mode's) grant exactly the same
// rights: the same entries, the same mask, user and other, and every
// group-class entry the same once masked. A file an app creates inherits
// the default ACL as it is (group::rwx under mask::rw-, say): consistent,
// though not in the form an apply writes.
func equivalent(a, b ACL, amode, bmode uint32) bool {
	if a = canon(a); a == nil {
		a = FromMode(amode)
	}
	if b = canon(b); b == nil {
		b = FromMode(bmode)
	}
	return sameRights(a, b)
}

func equivalentDefault(a, b ACL) bool {
	a, b = canon(a), canon(b)
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return sameRights(a, b)
}

func sameRights(a, b ACL) bool {
	if len(a) != len(b) {
		return false
	}
	ma, hasA := a.Mask()
	mb, hasB := b.Mask()
	if hasA != hasB || ma != mb {
		return false
	}
	if !hasA {
		ma = permAll
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Tag != y.Tag || x.ID != y.ID {
			return false
		}
		switch x.Tag {
		case TagGroupObj, TagUser, TagGroup:
			if x.Perm&ma != y.Perm&ma {
				return false
			}
		default:
			if x.Perm != y.Perm {
				return false
			}
		}
	}
	return true
}
