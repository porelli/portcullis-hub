package sshaccess

import (
	"slices"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// Preview is "who can reach hostID, as which account" (spec §9.8), from
// the same compilation as the bundles. rootOnly keeps root and sudo rows.
// A managed host's sudo is its bundle's (it belongs to the host and the
// account, whichever grant's certificate is used); an unmanaged entry's
// rows say accounts and sudo are unknown.
func (c *Compiled) Preview(hostID string, rootOnly bool) []PreviewRow {
	h, ok := c.in.State.Hosts[hostID]
	if !ok || h.Removed {
		return []PreviewRow{}
	}
	var uses []grantUse
	managed := h.Managed
	if managed {
		for _, us := range c.where[hostID] {
			uses = append(uses, us...)
		}
	} else {
		for _, u := range c.uses() {
			if slices.Contains(h.HostGroups, u.hg) {
				uses = append(uses, u)
			}
		}
	}
	rows := c.rows(uses, func(u grantUse) (sudo bool, status string) {
		if !managed {
			return false, StatusUnmanaged
		}
		if _, _, ok := cliapi.ValidPrincipal(u.account + "@" + u.hg); !ok {
			return false, StatusInvalidName
		}
		return len(c.sudo[hostID][u.account]) > 0, StatusOK
	})
	return filterRoot(rows, rootOnly)
}

// PreviewHostGroup is the preview for every host of a host group: one row
// per person and account, sudo as the grants on that group give it.
func (c *Compiled) PreviewHostGroup(hg string, rootOnly bool) []PreviewRow {
	var uses []grantUse
	for _, u := range c.uses() {
		if u.hg == hg {
			uses = append(uses, u)
		}
	}
	rows := c.rows(uses, func(u grantUse) (bool, string) {
		if _, _, ok := cliapi.ValidPrincipal(u.account + "@" + u.hg); !ok {
			return false, StatusInvalidName
		}
		return u.sudo, StatusOK
	})
	return filterRoot(rows, rootOnly)
}

// PreviewPerson is "where can user log in": per managed host, then per
// host group for unmanaged entries.
func (c *Compiled) PreviewPerson(user string) []PreviewRow {
	out := []PreviewRow{}
	for _, id := range sortedKeys(c.in.State.Hosts) {
		for _, r := range c.Preview(id, false) {
			if r.Person == user {
				r.Host = id
				out = append(out, r)
			}
		}
	}
	return out
}

func (c *Compiled) rows(uses []grantUse, judge func(grantUse) (bool, string)) []PreviewRow {
	type key struct{ person, account string }
	byKey := map[key]*PreviewRow{}
	var keys []key
	for _, u := range uses {
		k := key{u.person, u.account}
		r := byKey[k]
		sudo, status := judge(u)
		if r == nil {
			r = &PreviewRow{Person: u.person, Account: u.account, Root: u.root, Status: status, Via: []string{}}
			byKey[k] = r
			keys = append(keys, k)
		}
		r.Sudo = r.Sudo || sudo
		via := u.group + " → " + u.hg
		if u.priv {
			via += " (privileged)"
		}
		if !slices.Contains(r.Via, via) {
			r.Via = append(r.Via, via)
		}
		if u.end != nil && (r.Until == nil || u.end.Before(*r.Until)) {
			e := *u.end
			r.Until = &e
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].person != keys[j].person {
			return keys[i].person < keys[j].person
		}
		return keys[i].account < keys[j].account
	})
	out := make([]PreviewRow, 0, len(keys))
	for _, k := range keys {
		r := byKey[k]
		sort.Strings(r.Via)
		out = append(out, *r)
	}
	return out
}

func filterRoot(rows []PreviewRow, rootOnly bool) []PreviewRow {
	if !rootOnly {
		return rows
	}
	out := []PreviewRow{}
	for _, r := range rows {
		if r.Root || r.Sudo {
			out = append(out, r)
		}
	}
	return out
}

// Hypothetical compiles in with grant g put in place of its id (or added)
// and returns the compilation: the grant editor's preview of an unsaved
// change.
func Hypothetical(in Input, g stateGrant) (*Compiled, error) {
	cp := in
	cp.State.Grants = nil
	replaced := false
	for _, x := range in.State.Grants {
		if x.ID == g.ID {
			cp.State.Grants = append(cp.State.Grants, g)
			replaced = true
			continue
		}
		cp.State.Grants = append(cp.State.Grants, x)
	}
	if !replaced {
		cp.State.Grants = append(cp.State.Grants, g)
	}
	return Compile(cp)
}

// Until is the earliest end in rows, for "this change gives … until".
func Until(rows []PreviewRow) *time.Time {
	var u *time.Time
	for _, r := range rows {
		if r.Until != nil && (u == nil || r.Until.Before(*u)) {
			u = r.Until
		}
	}
	return u
}
