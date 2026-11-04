package folderfix

import "slices"

// Principal is a process identity an access check is made for: its uid and
// every gid it holds (primary and supplementary). Write and Name are the
// caller's bookkeeping (does the use need write, who to name in a report);
// Allowed doesn't read them.
type Principal struct {
	UID   int
	GIDs  []int
	Write bool
	Name  string
}

// Stat is what the check needs of an entry: owner, owning group, mode and
// its access ACL (nil or empty = the ACL the mode implies, FromMode). Dir tells the
// caller which perms to ask for (r|x to list, w|x to create); Allowed itself
// treats files and directories alike, as the kernel does.
type Stat struct {
	UID, GID int
	Mode     uint32
	Dir      bool
	Access   ACL
}

// Allowed is the POSIX.1e access check (acl(5) "ACCESS CHECK ALGORITHM",
// fs/posix_acl.c posix_acl_permission): uid 0 is always allowed; else the
// owner gets USER_OBJ; else a matching named USER entry ∧ MASK; else, if
// the principal is in the owning group or a named GROUP, access is granted
// when any one matching entry ∧ MASK holds every wanted bit, and denied
// otherwise; else OTHER. The first class that matches decides: there is no
// fall-through. Perms of different entries are never combined.
func Allowed(s Stat, p Principal, want Perm) bool {
	if p.UID == 0 {
		return true
	}
	acl := s.Access
	if len(acl) == 0 { // nil or a header-only xattr: no ACL, the mode decides
		acl = FromMode(s.Mode)
	}
	mask, hasMask := acl.Mask()
	if !hasMask {
		mask = permAll
	}
	grants := func(perm Perm) bool { return perm&want == want }

	if p.UID == s.UID {
		for _, e := range acl {
			if e.Tag == TagUserObj {
				return grants(e.Perm)
			}
		}
		return false
	}
	for _, e := range acl {
		if e.Tag == TagUser && int64(e.ID) == int64(p.UID) {
			return grants(e.Perm & mask)
		}
	}
	found := false
	for _, e := range acl {
		var match bool
		switch e.Tag {
		case TagGroupObj:
			match = slices.Contains(p.GIDs, s.GID)
		case TagGroup:
			match = slices.ContainsFunc(p.GIDs, func(g int) bool { return int64(g) == int64(e.ID) })
		}
		if match {
			found = true
			if grants(e.Perm & mask) {
				return true
			}
		}
	}
	if found {
		return false
	}
	for _, e := range acl {
		if e.Tag == TagOther {
			return grants(e.Perm)
		}
	}
	return false
}
