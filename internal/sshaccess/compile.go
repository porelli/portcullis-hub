package sshaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

// Compile turns in into roles, bundles and plans. Pure and deterministic.
// An invalid state is an error (nothing is compiled: the caller keeps
// what it had).
func Compile(in Input) (*Compiled, error) {
	if err := Validate(in.State); err != nil {
		return nil, err
	}
	st := in.State
	c := &Compiled{
		Roles: map[string]cliapi.RoleSpec{}, Bundles: map[string]*cliapi.Bundle{}, People: map[string]PersonAccess{},
		Hosts: map[string][]string{}, Hints: map[string][]string{},
		in: in, sudo: map[string]map[string][]string{}, where: map[string]map[string][]grantUse{},
	}
	uses := c.uses()
	sortCollisions(c.Collisions)

	// People's plans: per person and host group.
	type acc struct {
		p, e, g map[string]bool
		until   time.Time
	}
	plans := map[string]map[string]*acc{}
	for _, u := range uses {
		if !u.validPrincipal() {
			continue
		}
		if plans[u.person] == nil {
			plans[u.person] = map[string]*acc{}
		}
		a := plans[u.person][u.hg]
		if a == nil {
			a = &acc{p: map[string]bool{}, e: map[string]bool{}, g: map[string]bool{}, until: *u.until}
			plans[u.person][u.hg] = a
		}
		a.p[u.principal()] = true
		a.g[u.grant] = true
		g := c.grant(u.grant)
		for _, x := range cliapi.ExtensionList(g.PortForwarding, g.AgentForwarding) {
			a.e[x] = true
		}
		if u.until.Before(a.until) {
			a.until = *u.until
		}
	}
	for person, hgs := range plans {
		pa := PersonAccess{HostGroups: map[string]CertPlan{}}
		for hg, a := range hgs {
			pa.HostGroups[hg] = CertPlan{Principals: sortedKeys(a.p), Extensions: canonicalOrder(a.e), Until: a.until, Grants: sortedKeys(a.g)}
		}
		c.People[person] = pa
	}

	// Roles: one per host group with at least one principal.
	for _, hg := range sortedKeys(st.HostGroups) {
		var ps []string
		for _, person := range sortedKeys(c.People) {
			ps = append(ps, c.People[person].HostGroups[hg].Principals...)
		}
		ps = dedupSorted(ps)
		if len(ps) == 0 {
			continue
		}
		pf, af, maxH := false, false, 0
		for _, g := range st.Grants {
			if g.HostGroup != hg {
				continue
			}
			pf, af = pf || g.PortForwarding, af || g.AgentForwarding
			maxH = max(maxH, GrantTTLHours(g, st.Settings))
		}
		if len(ps) > cliapi.MaxRolePrincipals {
			return nil, fmt.Errorf("host group %q: more than %d principals", hg, cliapi.MaxRolePrincipals)
		}
		c.Roles[hg] = cliapi.RoleSpec{Principals: ps, Extensions: cliapi.CanonicalExtensions(pf, af),
			SourceAddress: c.sourceAddress(hg), MaxTTLSeconds: maxH * 3600}
	}

	// Client host names and trust hints per host group.
	for _, hg := range sortedKeys(st.HostGroups) {
		var names []string
		for _, id := range sortedKeys(st.Hosts) {
			h := st.Hosts[id]
			if !h.Managed || h.Removed || !inGroup(h, hg) {
				continue
			}
			names = append(names, h.Names...)
			names = append(names, h.Addrs...)
		}
		names = append(names, st.HostGroups[hg].Patterns...)
		c.Hosts[hg] = dedupKeepOrder(names)
		hint := map[string]bool{}
		for _, u := range uses {
			if u.hg == hg && cliapi.ValidAccount(u.account) {
				hint[u.account] = true
			}
		}
		if len(hint) > 0 {
			c.Hints[hg] = sortedKeys(hint)
		}
	}

	// Bundles: every managed host not removed.
	need := map[string]bool{}
	for _, id := range sortedKeys(st.Hosts) {
		h := st.Hosts[id]
		if !h.Managed || h.Removed {
			continue
		}
		b := c.bundle(id, h, uses, need)
		c.Bundles[id] = b
	}
	c.NeedUIDs = sortedKeys(need)
	return c, nil
}

// uses lists every (grant, person, account) that applies now, sorted by
// grant then person then account.
func (c *Compiled) uses() []grantUse {
	in := c.in
	st := in.State
	grants := slices.Clone(st.Grants)
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
	var out []grantUse
	shared, protected := sharedAccounts(st), protectedAccounts(st)
	c.Collisions = nil
	for _, g := range grants {
		priv, _ := Privileged(g)
		ttl := time.Duration(GrantTTLHours(g, st.Settings)) * time.Hour
		for _, user := range sortedKeys(in.Members) {
			gid, ok := in.Members[user][g.Group]
			if !ok || gid != g.GroupID || in.Expired[user][g.Group] {
				continue
			}
			if !cliapi.ValidUsername(user) {
				continue
			}
			until := in.Now.Add(ttl)
			var end *time.Time
			if e, ok := in.Pending[user][g.Group]; ok {
				if !e.After(in.Now) {
					continue
				}
				e := e
				end = &e
				if e.Before(until) {
					until = e
				}
			}
			for _, a := range g.Accounts {
				acct, kind := a, cliapi.PrincipalShared
				if a == cliapi.UsernamePlaceholder {
					acct, kind = user, cliapi.PrincipalPersonal
					if why := reservedFor(user, shared, protected); why != "" {
						c.Collisions = append(c.Collisions, Collision{User: user, Grant: g.ID, Reason: why})
						continue // never a principal for an account that isn't theirs
					}
				}
				u := until
				out = append(out, grantUse{grant: g.ID, group: g.Group, hg: g.HostGroup, person: user, account: acct,
					until: &u, sudo: g.Sudo == state.SudoFull, priv: priv, root: acct == "root", end: end,
					personal: kind == cliapi.PrincipalPersonal, kind: kind})
			}
		}
	}
	return out
}

func (c *Compiled) grant(id string) state.SSHGrant {
	for _, g := range c.in.State.Grants {
		if g.ID == id {
			return g
		}
	}
	return state.SSHGrant{}
}

func (c *Compiled) sourceAddress(hg string) []string {
	g := c.in.State.HostGroups[hg]
	out := slices.Clone(g.SourceCIDRs)
	if g.VPNOnly && c.in.VPNRanges != nil {
		out = append(out, c.in.VPNRanges(g.VPNVia)...)
	}
	return dedupSorted(out)
}

// hostGroups is a managed host's groups: its own plus all.
func hostGroups(h state.SSHHost) []string {
	return dedupSorted(append(slices.Clone(h.HostGroups), cliapi.BuiltinAllHostGroup))
}

func inGroup(h state.SSHHost, hg string) bool {
	if hg == cliapi.BuiltinAllHostGroup && h.Managed {
		return true
	}
	return slices.Contains(h.HostGroups, hg)
}

func (c *Compiled) bundle(id string, h state.SSHHost, uses []grantUse, need map[string]bool) *cliapi.Bundle {
	st := c.in.State
	type acc struct {
		kind  string
		uid   int
		p     map[string]bool
		sudo  bool
		valid bool
	}
	accts := map[string]*acc{}
	c.sudo[id] = map[string][]string{}
	c.where[id] = map[string][]grantUse{}
	hgs := hostGroups(h)
	for _, u := range uses {
		if !slices.Contains(hgs, u.hg) {
			continue
		}
		kind := cliapi.AccountShared
		if u.personal {
			kind = cliapi.AccountPerson
		}
		a := accts[u.account]
		if a == nil {
			a = &acc{kind: kind, p: map[string]bool{}}
			accts[u.account] = a
		}
		if a.kind != kind {
			// Never merge a person and a shared account (collisions are
			// skipped in uses; this is the belt to those braces).
			continue
		}
		c.where[id][u.account] = append(c.where[id][u.account], u)
		if !u.validPrincipal() {
			continue // the host reports ssh_host_account_invalid
		}
		a.valid = true
		a.p[u.principal()] = true
		if u.sudo {
			a.sudo = true
			c.sudo[id][u.account] = dedupSorted(append(c.sudo[id][u.account], u.grant))
		}
	}
	b := &cliapi.Bundle{Version: cliapi.BundleVersion, HostID: id, UserCAs: nonNil(c.in.UserCAs), HostCertificate: h.HostCert,
		Accounts: []cliapi.Account{}, Locked: []string{}, Remove: dedupSorted(slices.Clone(h.RemoveAccounts)),
		RevokedKeys: nonNil(c.in.RevokedKeys), Options: cliapi.BundleOptions{CreateSharedAccounts: c.createShared(hgs)}}
	if b.Remove == nil {
		b.Remove = []string{}
	}
	active := map[string]bool{}
	for _, name := range sortedKeys(accts) {
		a := accts[name]
		out := cliapi.Account{Name: name, Kind: a.kind, Principals: sortedKeys(a.p), Sudo: a.sudo}
		if out.Principals == nil {
			out.Principals = []string{}
		}
		if a.kind == cliapi.AccountPerson && a.valid {
			uid := st.UIDs[name]
			if uid == 0 {
				need[name] = true
				continue // no account until it has a uid
			}
			out.UID = uid
		}
		active[name] = true
		b.Accounts = append(b.Accounts, out)
	}
	for _, user := range sortedKeys(st.UIDs) {
		if !active[user] && !slices.Contains(b.Remove, user) {
			b.Locked = append(b.Locked, user)
		}
	}
	for _, r := range b.Remove {
		if !slices.Contains(b.Locked, r) && !active[r] {
			b.Locked = append(b.Locked, r)
		}
	}
	sort.Strings(b.Locked)
	return b
}

func (c *Compiled) createShared(hgs []string) bool {
	for _, hg := range hgs {
		if c.in.State.HostGroups[hg].CreateShared {
			return true
		}
	}
	return false
}

// BundleHash is the hex SHA-256 of b without its serial and time: what
// decides a serial bump (plan C22).
func BundleHash(b *cliapi.Bundle) string {
	cp := *b
	cp.Serial, cp.Generated = 0, time.Time{}
	raw, _ := json.Marshal(cp)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// ClientConfig is the person's SSH client config for their plans (spec
// §6, cliapi.ClientConfig: a value outside its grammar is an error).
func ClientConfig(domain string, plans map[string]CertPlan, hosts map[string][]string) (string, error) {
	var gs []cliapi.ClientGroup
	for _, hg := range sortedKeys(plans) {
		gs = append(gs, cliapi.ClientGroup{HostGroup: hg, Hosts: hosts[hg]})
	}
	return cliapi.ClientConfig(domain, gs)
}

// ErrNoUID is AllocUID's exhaustion.
var ErrNoUID = fmt.Errorf("no uid left in %d–%d", cliapi.UIDMin, cliapi.UIDMax)

// AllocUID gives user a uid (plan C19): theirs if they have one, else the
// lowest never used ≥ 20000. UIDsUsed never shrinks.
func AllocUID(s *state.SSHState, user string) (int, error) {
	if u, ok := s.UIDs[user]; ok && u != 0 {
		return u, nil
	}
	used := map[int]bool{}
	for _, u := range s.UIDsUsed {
		used[u] = true
	}
	for _, u := range s.UIDs {
		used[u] = true
	}
	for u := cliapi.UIDMin; u <= cliapi.UIDMax; u++ {
		if used[u] {
			continue
		}
		if s.UIDs == nil {
			s.UIDs = map[string]int{}
		}
		s.UIDs[user] = u
		s.UIDsUsed = append(s.UIDsUsed, u)
		sort.Ints(s.UIDsUsed)
		return u, nil
	}
	return 0, ErrNoUID
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupSorted(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	s = slices.Clone(s)
	sort.Strings(s)
	return slices.Compact(s)
}

func dedupKeepOrder(s []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func canonicalOrder(set map[string]bool) []string {
	return cliapi.ExtensionList(set[cliapi.ExtPortForwarding], set[cliapi.ExtAgentForwarding])
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// SortedHostGroups are a person's plan host groups, sorted.
func SortedHostGroups(plans map[string]CertPlan) []string {
	out := sortedKeys(plans)
	if out == nil {
		return []string{}
	}
	return out
}
