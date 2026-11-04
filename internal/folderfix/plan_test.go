package folderfix

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

func acl(es ...Entry) ACL { return canon(ACL(es)) }

func uo(p Perm) Entry            { return Entry{Tag: TagUserObj, Perm: p} }
func us(id uint32, p Perm) Entry { return Entry{Tag: TagUser, ID: id, Perm: p} }
func go_(p Perm) Entry           { return Entry{Tag: TagGroupObj, Perm: p} }
func gr(id uint32, p Perm) Entry { return Entry{Tag: TagGroup, ID: id, Perm: p} }
func mk(p Perm) Entry            { return Entry{Tag: TagMask, Perm: p} }
func ot(p Perm) Entry            { return Entry{Tag: TagOther, Perm: p} }

func TestPlanKeepsAccess(t *testing.T) {
	// A file 1000:1000 with user:3000:rwx under mask::r (it grants r today).
	cur := state{UID: 1000, GID: 1000, Mode: 0o644, Access: acl(uo(R|W), us(3000, R|W|X), go_(R), mk(R), ot(R))}
	o, err := planEntry(cur, target{GID: 60001, Write: true, ACL: true})
	if err != nil {
		t.Fatal(err)
	}
	want := acl(uo(R|W), us(3000, R), go_(R|W), gr(1000, R), mk(R|W), ot(R))
	if !slices.Equal(o.want.Access, want) || o.want.Mode != 0o664 || o.want.GID != 60001 || o.want.UID != 1000 {
		t.Fatalf("got %s %o, want %s 0664", aclText(o.want.Access), o.want.Mode, aclText(want))
	}
	if !o.change || !o.narrowed || !o.keepGroup || !o.group || !o.mode || o.owner || o.lose {
		t.Fatalf("flags %+v", o)
	}

	// A directory 0750 1000:1000 without ACLs.
	cur = state{Dir: true, UID: 1000, GID: 1000, Mode: 0o750}
	o, err = planEntry(cur, target{GID: 60001, Write: true, ACL: true})
	if err != nil {
		t.Fatal(err)
	}
	wantA := acl(uo(R|W|X), go_(R|W|X), gr(1000, R|X), mk(R|W|X), ot(0))
	wantD := acl(uo(R|W|X), go_(R|W|X), mk(R|W|X), ot(0)) // R51: no group:1000, others ---
	if !slices.Equal(o.want.Access, wantA) || !slices.Equal(o.want.Default, wantD) || o.want.Mode != 0o2770 {
		t.Fatalf("dir: %s / %s %o", aclText(o.want.Access), aclText(o.want.Default), o.want.Mode)
	}
	if !o.setgid || !o.defACL || o.narrowed {
		t.Fatalf("dir flags %+v", o)
	}

	// A file already in the group, no ACL, files r: g+r only, no xattr.
	o, _ = planEntry(state{UID: 1, GID: 60001, Mode: 0o600}, target{GID: 60001, ACL: true})
	if o.want.Access != nil || o.want.Mode != 0o640 {
		t.Fatalf("plain file: %s %o", aclText(o.want.Access), o.want.Mode)
	}
	// g+x only where the user bits have x.
	o, _ = planEntry(state{UID: 1, GID: 60001, Mode: 0o700}, target{GID: 60001, Write: true, ACL: true})
	if o.want.Mode != 0o770 {
		t.Fatalf("exec file: %o", o.want.Mode)
	}
	// Already consistent: no change.
	o, _ = planEntry(state{UID: 1, GID: 60001, Mode: 0o664}, target{GID: 60001, Write: true, ACL: true})
	if o.change {
		t.Fatalf("consistent file changes: %+v", o)
	}
}

// R51: an existing default ACL keeps its own entries (narrowed to its
// mask) and "others"; it gains the folder group and mask rwx, never an
// entry for the previous group or owner.
func TestPlanDefaultACL(t *testing.T) {
	def := acl(uo(R|W|X), us(3000, R|W|X), go_(R|X), mk(R|X), ot(R))
	cur := state{Dir: true, UID: 1000, GID: 1000, Mode: 0o755, Default: def}
	owner := uint32(2000)
	o, err := planEntry(cur, target{GID: 60001, Write: true, HasOwner: true, Owner: owner, ACL: true})
	if err != nil {
		t.Fatal(err)
	}
	want := acl(uo(R|W|X), us(3000, R|X), go_(R|W|X), mk(R|W|X), ot(R))
	if !slices.Equal(o.want.Default, want) || !o.narrowed {
		t.Fatalf("default %s, want %s", aclText(o.want.Default), aclText(want))
	}
}

func TestPlanMustOwn(t *testing.T) {
	cur := state{UID: 1000, GID: 1000, Mode: 0o640}
	o, err := planEntry(cur, target{GID: 60001, Write: true, HasOwner: true, Owner: 2000, ACL: true})
	if err != nil {
		t.Fatal(err)
	}
	want := acl(uo(R|W), us(1000, R|W), go_(R|W), gr(1000, R), mk(R|W), ot(0))
	if o.want.UID != 2000 || !slices.Equal(o.want.Access, want) || !o.keepUser || !o.owner {
		t.Fatalf("got %d %s %+v", o.want.UID, aclText(o.want.Access), o)
	}
}

// R54: a regular file with file capabilities (security.capability) is
// never touched: a chown makes the kernel drop the xattr.
func TestPlanFileCaps(t *testing.T) {
	tg := target{GID: 60001, Write: true, ACL: true}
	o, err := planEntry(state{UID: 1000, GID: 1000, Mode: 0o755, FileCaps: true}, tg)
	if err != nil || !o.filecaps || o.change || o.setid {
		t.Fatalf("filecaps: %+v, %v", o, err)
	}
	// Already conformant except for nothing: still left alone, no change.
	owner := uint32(2000)
	o, _ = planEntry(state{UID: 1000, GID: 60001, Mode: 0o775, FileCaps: true}, target{GID: 60001, Write: true, ACL: true, HasOwner: true, Owner: owner})
	if !o.filecaps || o.change {
		t.Fatalf("filecaps under must_own: %+v", o)
	}
	// A directory never carries file capabilities that matter: planned.
	if o, _ := planEntry(state{Dir: true, UID: 1000, GID: 1000, Mode: 0o755, FileCaps: true}, tg); o.filecaps || !o.change {
		t.Fatalf("directory: %+v", o)
	}
}

func TestPlanSetID(t *testing.T) {
	tg := target{GID: 60001, Write: true, HasOwner: true, Owner: 2000, ACL: true}
	// setgid file to another group: skipped.
	if o, _ := planEntry(state{UID: 2000, GID: 1000, Mode: 0o2755}, tg); !o.setid || o.change {
		t.Fatalf("setgid: %+v", o)
	}
	// setuid file to another owner under must_own: skipped.
	if o, _ := planEntry(state{UID: 1000, GID: 60001, Mode: 0o4755}, tg); !o.setid {
		t.Fatalf("setuid: %+v", o)
	}
	// R47: a setuid file under a group change only: skipped too (the
	// folder group would get x on a file that runs as its owner).
	o, _ := planEntry(state{UID: 1000, GID: 1000, Mode: 0o4750}, target{GID: 60001, Write: true, ACL: true})
	if !o.setid || o.change {
		t.Fatalf("setuid, group change: %+v", o)
	}
	// Even already in the group and owned right: left alone.
	o, _ = planEntry(state{UID: 2000, GID: 60001, Mode: 0o4750}, target{GID: 60001, Write: true, ACL: true})
	if !o.setid {
		t.Fatalf("setuid in group: %+v", o)
	}
	o, _ = planEntry(state{UID: 1000, GID: 60001, Mode: 0o2750}, target{GID: 60001, Write: true, ACL: true})
	if !o.setid {
		t.Fatalf("setgid in group: %+v", o)
	}
	// A setgid / setuid directory is no executable: planned as usual.
	o, _ = planEntry(state{Dir: true, UID: 1000, GID: 1000, Mode: 0o4755}, target{GID: 60001, Write: true, ACL: true})
	if o.setid || o.want.Mode&modeSetgid == 0 {
		t.Fatalf("setuid dir: %+v", o)
	}
}

func TestPlanBadACL(t *testing.T) {
	tg := target{GID: 60001, Write: true, ACL: true}
	for name, a := range map[string]ACL{
		"unsorted":  {uo(R), gr(5, R), us(3, R), go_(R), mk(R), ot(0)},
		"duplicate": {uo(R), us(3, R), us(3, W), go_(R), mk(R | W), ot(0)},
		"no mask":   {uo(R), us(3, R), go_(R), ot(0)},
	} {
		if _, err := planEntry(state{UID: 1, GID: 1000, Mode: 0o640, Access: a}, tg); !errors.Is(err, errBadACL) {
			t.Errorf("%s: %v, want errBadACL", name, err)
		}
	}
	// The previous group has w through a named entry and r through the
	// owning class: one entry can't stand for both.
	a := acl(uo(R|W), go_(R), gr(1000, W), mk(R|W), ot(0))
	if _, err := planEntry(state{UID: 1, GID: 1000, Mode: 0o660, Access: a}, tg); !errors.Is(err, errBadACL) {
		t.Errorf("ambiguous keep: %v", err)
	}
	// A superset is fine.
	a = acl(uo(R|W), go_(R), gr(1000, R|W), mk(R|W), ot(0))
	o, err := planEntry(state{UID: 1, GID: 1000, Mode: 0o660, Access: a}, tg)
	if err != nil || !slices.Contains(o.want.Access, gr(1000, R|W)) {
		t.Errorf("superset keep: %v %s", err, aclText(o.want.Access))
	}
}

func TestPlanNoACL(t *testing.T) {
	tg := target{GID: 60001, Write: true}
	o, _ := planEntry(state{UID: 1, GID: 1000, Mode: 0o640}, tg) // group 1000 r, others nothing
	if !o.lose {
		t.Fatal("0640 group change without ACLs: want lose")
	}
	o, _ = planEntry(state{UID: 1, GID: 1000, Mode: 0o604}, tg) // group 1000 denied, others r: they'd gain
	if !o.lose {
		t.Fatal("0604: want lose (the group would gain others' bits)")
	}
	o, _ = planEntry(state{UID: 1, GID: 1000, Mode: 0o644}, tg)
	if o.lose || o.want.Mode != 0o664 || o.want.Access != nil {
		t.Fatalf("0644: %+v %o", o, o.want.Mode)
	}
	o, _ = planEntry(state{Dir: true, UID: 1, GID: 1000, Mode: 0o755}, tg)
	if o.lose || o.want.Mode != 0o2775 || o.want.Default != nil || o.defACL {
		t.Fatalf("dir: %+v %o", o, o.want.Mode)
	}
}

// randomACL is a valid ACL drawn from a small id space.
func randomACL(r *rand.Rand, mode uint32) ACL {
	a := FromMode(mode)
	for _, id := range []uint32{1000, 2000, 3000, 3001} {
		if r.IntN(3) == 0 {
			a = a.Set(TagUser, id, Perm(r.IntN(8)))
		}
	}
	for _, id := range []uint32{1000, 1001, 60001, 7000} {
		if r.IntN(3) == 0 {
			a = a.Set(TagGroup, id, Perm(r.IntN(8)))
		}
	}
	if hasNamed(a) || r.IntN(2) == 0 {
		a = a.Set(TagMask, 0, Perm(r.IntN(8)))
	}
	return a
}

// TestPlanNeverWidens checks planEntry against the kernel's access
// algorithm (Allowed) on random entries: after the plan nobody who isn't
// in the folder group and isn't the must_own uid can do anything they
// couldn't before, nobody can do less (except where the no-ACL plan says
// so), the ACLs written are valid, and a second plan changes nothing.
func TestPlanNeverWidens(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	uids := []int{1000, 2000, 3000, 3001, 5000}
	gidSets := [][]int{{1000}, {1001}, {60001}, {7000}, {1000, 60001}, {1001, 7000}, {5000}, {1000, 1001}, {60001, 7000}}
	wants := []Perm{R, W, X, R | W, R | X, W | X, R | W | X}
	stat := func(s state) Stat {
		return Stat{UID: int(s.UID), GID: int(s.GID), Mode: s.Mode, Dir: s.Dir, Access: s.Access}
	}
	checked := 0
	for i := 0; i < 200000; i++ {
		withACL := r.IntN(4) != 0
		cur := state{Dir: r.IntN(2) == 0, UID: []uint32{1000, 2000, 3000}[r.IntN(3)], GID: []uint32{1000, 1001, 60001}[r.IntN(3)],
			Mode: uint32(r.IntN(0o1000)) | []uint32{0, modeSetuid, modeSticky}[r.IntN(3)]}
		if withACL && r.IntN(3) != 0 {
			cur.Access = randomACL(r, cur.Mode)
			if m, ok := cur.Access.Mask(); ok { // the kernel keeps the group bits = mask
				cur.Mode = cur.Mode&^0o070 | uint32(m)<<3
			} else {
				cur.Mode = cur.Mode&^0o070 | uint32(permOf(cur.Access, TagGroupObj))<<3
			}
			if cur.Dir && r.IntN(2) == 0 {
				cur.Default = randomACL(r, uint32(r.IntN(0o1000)))
			}
		}
		tg := target{GID: []uint32{60001, 1000}[r.IntN(2)], Write: r.IntN(2) == 0, ACL: withACL}
		if r.IntN(3) == 0 {
			tg.HasOwner, tg.Owner = true, []uint32{2000, 1000}[r.IntN(2)]
		}
		o, err := planEntry(cur, tg)
		if errors.Is(err, errBadACL) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !cur.Dir && cur.Mode&(modeSetuid|modeSetgid) != 0 && !o.setid {
			t.Fatalf("setid file planned: %s", describe(cur))
		}
		if o.setid {
			continue
		}
		checked++
		// Files made later in the directory (R51): through the default ACL
		// nobody but the creator and the folder group gets anything they
		// didn't get from the old default; with no old default, nothing.
		if cur.Dir && withACL {
			for _, uid := range uids {
				for _, gids := range gidSets {
					if slices.Contains(gids, int(tg.GID)) {
						continue
					}
					p := Principal{UID: uid, GIDs: gids}
					for _, w := range wants {
						after := Allowed(inherited(o.want.Default, 9999, tg.GID), p, w)
						before := cur.Default != nil && Allowed(inherited(cur.Default, 9999, tg.GID), p, w)
						if after && !before {
							t.Fatalf("default widened: uid %d gids %v %s: %s → %s", uid, gids, w, describe(cur), describe(o.want))
						}
					}
				}
			}
		}
		if _, _, err := encodeState(o.want); err != nil {
			t.Fatalf("invalid ACL planned for %s: %v", describe(cur), err)
		}
		if o.change {
			o2, err := planEntry(o.want, tg)
			if err != nil || o2.change {
				t.Fatalf("not idempotent: %s → %s → %s (%v)", describe(cur), describe(o.want), describe(o2.want), err)
			}
		}
		if !withACL && (o.want.Access != nil || o.want.Default != nil) {
			t.Fatal("ACL written without ACL support")
		}
		for _, uid := range uids {
			for _, gids := range gidSets {
				p := Principal{UID: uid, GIDs: gids}
				newOwner := tg.HasOwner && uint32(uid) == tg.Owner
				inGroup := slices.Contains(gids, int(tg.GID))
				for _, w := range wants {
					before, after := Allowed(stat(cur), p, w), Allowed(stat(o.want), p, w)
					if after && !before && !inGroup && !newOwner && !o.lose { // lose: Apply refuses (no ACLs)
						t.Fatalf("widened: uid %d gids %v %s: %s → %s", uid, gids, w, describe(cur), describe(o.want))
					}
					if before && !after && !o.lose {
						t.Fatalf("narrowed: uid %d gids %v %s: %s → %s", uid, gids, w, describe(cur), describe(o.want))
					}
				}
			}
		}
	}
	if checked < 50000 {
		t.Fatalf("only %d entries checked", checked)
	}
}

// inherited is the access check input of a file created 0666 by uid in a
// directory with default ACL def (acl(5): the default entries, the mask ∧
// the create mode's group bits; without a default ACL, umask 022 applies).
func inherited(def ACL, uid, gid uint32) Stat {
	if def == nil {
		return Stat{UID: int(uid), GID: int(gid), Mode: 0o644}
	}
	a := canon(def)
	for i := range a {
		switch a[i].Tag {
		case TagUserObj, TagOther:
			a[i].Perm &= R | W
		case TagMask:
			a[i].Perm &= R | W
		}
	}
	if _, ok := a.Mask(); !ok {
		for i := range a {
			if a[i].Tag == TagGroupObj {
				a[i].Perm &= R | W
			}
		}
	}
	return Stat{UID: int(uid), GID: int(gid), Mode: 0o666, Access: a}
}
