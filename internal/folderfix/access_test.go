package folderfix

import "testing"

func TestAllowed(t *testing.T) {
	// owner 1000, owning group 100, plus named entries behind a mask r-x.
	acl := ACL{
		{Tag: TagUserObj, Perm: R},            // owner: r only (no w, even though others get more)
		{Tag: TagUser, ID: 2000, Perm: R | W}, // masked to r
		{Tag: TagUser, ID: 2001, Perm: R | X}, // masked to r-x
		{Tag: TagGroupObj, Perm: R | W | X},   // masked to r-x
		{Tag: TagGroup, ID: 300, Perm: W},     // masked to nothing
		{Tag: TagGroup, ID: 301, Perm: R | X}, // masked to r-x
		{Tag: TagGroup, ID: 302, Perm: R},     // masked to r
		{Tag: TagMask, Perm: R | X},           //
		{Tag: TagOther, Perm: R | W | X},      // other: everything
	}
	withACL := Stat{UID: 1000, GID: 100, Mode: 0o4757, Access: acl}
	plain := Stat{UID: 1000, GID: 100, Mode: 0o751} // Access nil: FromMode
	dir := Stat{UID: 1000, GID: 100, Mode: 0o750, Dir: true}

	cases := []struct {
		name string
		s    Stat
		p    Principal
		want Perm
		ok   bool
	}{
		// uid 0
		{"root anything", withACL, Principal{UID: 0}, R | W | X, true},
		{"root on 000", Stat{UID: 5, GID: 5, Mode: 0}, Principal{UID: 0}, W, true},

		// owner: USER_OBJ wins, unmasked, no fall-through
		{"owner r", withACL, Principal{UID: 1000, GIDs: []int{100}}, R, true},
		{"owner w denied despite group and other", withACL, Principal{UID: 1000, GIDs: []int{100}}, W, false},
		{"owner not masked", Stat{UID: 1000, GID: 100, Access: ACL{{Tag: TagUserObj, Perm: 7}, {Tag: TagGroupObj}, {Tag: TagMask}, {Tag: TagOther}}}, Principal{UID: 1000}, R | W | X, true},
		{"owner plain rwx", plain, Principal{UID: 1000}, R | W | X, true},

		// named user: masked, no fall-through to groups or other
		{"named user r", withACL, Principal{UID: 2000}, R, true},
		{"named user w masked", withACL, Principal{UID: 2000}, W, false},
		{"named user rx", withACL, Principal{UID: 2001}, R | X, true},
		{"named user no fall-through to group", withACL, Principal{UID: 2000, GIDs: []int{301}}, X, false},
		{"named user no fall-through to other", withACL, Principal{UID: 2000}, X, false},

		// owning group: masked
		{"owning group rx", withACL, Principal{UID: 5000, GIDs: []int{100}}, R | X, true},
		{"owning group w masked", withACL, Principal{UID: 5000, GIDs: []int{100}}, W, false},
		{"owning group plain r-x", plain, Principal{UID: 5000, GIDs: []int{100}}, R | X, true},
		{"owning group plain w", plain, Principal{UID: 5000, GIDs: []int{100}}, W, false},
		{"owning group plain x", plain, Principal{UID: 5000, GIDs: []int{100}}, X, true},
		{"owning group no fall-through to other", Stat{UID: 1, GID: 100, Mode: 0o607}, Principal{UID: 5000, GIDs: []int{100}}, R, false},
		{"owning group no fall-through to other (acl)", Stat{UID: 1, GID: 100, Access: ACL{{Tag: TagUserObj}, {Tag: TagGroupObj}, {Tag: TagOther, Perm: 7}}}, Principal{UID: 5000, GIDs: []int{100}}, R, false},

		// named groups: masked; any matching entry that grants is enough
		{"named group masked to nothing", withACL, Principal{UID: 5000, GIDs: []int{300}}, W, false},
		{"named group no fall-through to other", withACL, Principal{UID: 5000, GIDs: []int{300}}, R, false},
		{"named group rx", withACL, Principal{UID: 5000, GIDs: []int{301}}, R | X, true},
		{"any group: 300 fails, 301 grants", withACL, Principal{UID: 5000, GIDs: []int{300, 301}}, X, true},
		{"any group: order irrelevant", withACL, Principal{UID: 5000, GIDs: []int{301, 300}}, X, true},
		{"no single entry grants rx", withACL, Principal{UID: 5000, GIDs: []int{302, 300}}, R | X, false},
		{"owning or named group grants", withACL, Principal{UID: 5000, GIDs: []int{302, 100}}, X, true},
		{"entries are not combined", Stat{UID: 1, GID: 1, Access: ACL{{Tag: TagUserObj}, {Tag: TagGroupObj}, {Tag: TagGroup, ID: 10, Perm: R}, {Tag: TagGroup, ID: 11, Perm: W}, {Tag: TagMask, Perm: 7}, {Tag: TagOther, Perm: 7}}}, Principal{UID: 9, GIDs: []int{10, 11}}, R | W, false},
		{"mask on owning group without named", Stat{UID: 1, GID: 100, Access: ACL{{Tag: TagUserObj}, {Tag: TagGroupObj, Perm: 7}, {Tag: TagMask, Perm: R}, {Tag: TagOther}}}, Principal{UID: 9, GIDs: []int{100}}, W, false},

		// other
		{"other rwx", withACL, Principal{UID: 5000, GIDs: []int{999}}, R | W | X, true},
		{"other plain x", plain, Principal{UID: 5000}, X, true},
		{"other plain r", plain, Principal{UID: 5000}, R, false},

		// an empty non-nil ACL (DecodeACL of a header alone) is the mode's
		{"empty acl owner", Stat{UID: 1000, GID: 100, Mode: 0o777, Access: ACL{}}, Principal{UID: 1000}, R | W | X, true},
		{"empty acl other", Stat{UID: 1000, GID: 100, Mode: 0o604, Access: ACL{}}, Principal{UID: 5000}, R, true},
		{"empty acl group", Stat{UID: 1000, GID: 100, Mode: 0o604, Access: ACL{}}, Principal{UID: 5000, GIDs: []int{100}}, R, false},

		// want 0 is always granted (nothing asked)
		{"want nothing", Stat{UID: 1, GID: 1}, Principal{UID: 9}, 0, true},

		// directories: the caller asks r|x to list, w|x to create
		{"dir owner list", dir, Principal{UID: 1000}, R | X, true},
		{"dir owner write", dir, Principal{UID: 1000}, W | X, true},
		{"dir group list", dir, Principal{UID: 5000, GIDs: []int{100}}, R | X, true},
		{"dir group write", dir, Principal{UID: 5000, GIDs: []int{100}}, W | X, false},
		{"dir other list", dir, Principal{UID: 5000}, R | X, false},
		{"dir r without x", Stat{UID: 1, GID: 1, Mode: 0o744, Dir: true}, Principal{UID: 9}, R | X, false},
	}
	for _, c := range cases {
		if got := Allowed(c.s, c.p, c.want); got != c.ok {
			t.Errorf("%s: Allowed(uid %d gids %v, %v) = %v, want %v", c.name, c.p.UID, c.p.GIDs, c.want, got, c.ok)
		}
	}
}

func TestPermString(t *testing.T) {
	for p, want := range map[Perm]string{0: "---", R: "r--", R | W: "rw-", R | W | X: "rwx", X: "--x"} {
		if got := p.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", p, got, want)
		}
	}
}
