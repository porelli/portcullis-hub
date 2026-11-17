package hub

// SSH grants (contract §18.12, spec §9.4–9.5): administrators and
// ssh_access holders, privileged and widening edits, the hypothetical
// preview; revocation on leave.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/sshaccess"
	"github.com/portcullis/hub/internal/state"
)

// TextOnlyAdminsPrivileged is the delegate's refusal (contract §9.6).
const TextOnlyAdminsPrivileged = "only administrators can grant sudo, root, forwarding or server access"

// TextOnlyAdminsWiden refuses a delegate's widening edit.
const TextOnlyAdminsWiden = "only administrators can widen an existing grant"

// SSHDirectory is the directory's SSH checks (directory.Service).
type SSHDirectory interface {
	CheckSSHGrantGroup(ctx context.Context, c *directory.Caller, group string) (int, error)
}

// SetSSHDirectory wires the directory's checks.
func (h *Hub) SetSSHDirectory(d SSHDirectory) {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	h.sshrt.dir = d
}

// SSHGroupsForDirectory is directory.Service.SSHGroups: the groups grants
// use, and those of privileged grants.
func (h *Hub) SSHGroupsForDirectory() directory.SSHGroups {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out directory.SSHGroups
	for _, g := range h.st.SSH.Grants {
		out.Granting = append(out.Granting, g.Group)
		if p, _ := sshaccess.Privileged(g); p {
			out.Privileged = append(out.Privileged, g.Group)
		}
	}
	out.Granting, out.Privileged = dedupStrings(out.Granting), dedupStrings(out.Privileged)
	return out
}

// sshGroupLinesLocked is group's SSH grants in words, by host group:
// "web (own account)", "all (own account, deploy, sudo)" (a grant saved
// for an older group of that name, another id, grants nothing: left out).
func sshGroupLinesLocked(st state.SSHState, group string, gid int) []string {
	out := []string{}
	for _, g := range st.Grants {
		if g.Group != group || (g.GroupID != 0 && gid != 0 && g.GroupID != gid) {
			continue
		}
		var what []string
		for _, a := range g.Accounts {
			if a == cliapi.UsernamePlaceholder {
				what = append(what, "own account")
			} else {
				what = append(what, a)
			}
		}
		if g.Sudo == state.SudoFull {
			what = append(what, "sudo")
		}
		out = append(out, g.HostGroup+" ("+strings.Join(what, ", ")+")")
	}
	sort.Strings(out)
	return out
}

// mergedGrants is the union of the grants of group on hostGroup (nil:
// none): every account, the longest TTL, sudo and forwarding if any has
// them — what a new grant there is compared with (M5).
func mergedGrants(grants []state.SSHGrant, group, hostGroup string) *state.SSHGrant {
	var m *state.SSHGrant
	for _, x := range grants {
		if x.Group != group || x.HostGroup != hostGroup {
			continue
		}
		if m == nil {
			c := x
			c.Accounts = slices.Clone(x.Accounts)
			m = &c
			continue
		}
		for _, a := range x.Accounts {
			if !slices.Contains(m.Accounts, a) {
				m.Accounts = append(m.Accounts, a)
			}
		}
		if x.Sudo == state.SudoFull {
			m.Sudo = state.SudoFull
		}
		if x.TTLHours == 0 || (m.TTLHours != 0 && x.TTLHours > m.TTLHours) {
			m.TTLHours = x.TTLHours
		}
		m.PortForwarding = m.PortForwarding || x.PortForwarding
		m.AgentForwarding = m.AgentForwarding || x.AgentForwarding
	}
	return m
}

func newGrantID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "g-" + hex.EncodeToString(b)
}

func grantDetail(g *state.SSHGrant) string {
	if g == nil {
		return "-"
	}
	return fmt.Sprintf("%s→%s accounts=%s sudo=%s ttl=%d pf=%v af=%v", g.Group, g.HostGroup, strings.Join(g.Accounts, ","), g.Sudo, g.TTLHours, g.PortForwarding, g.AgentForwarding)
}

// SaveGrant creates (empty id) or updates a grant. Administrators: a
// privileged grant needs a fresh sign-in under the hub template and the
// group's name typed again; any widening edit needs the fresh sign-in.
// ssh_access holders: non-privileged grants on delegable host groups
// only, never widening an existing one, never to a group they're in, a
// permission, protected or privileged group. Never privileged or
// widening through the Portcullis MCP.
func (h *Hub) SaveGrant(ctx context.Context, c *directory.Caller, g state.SSHGrant, typedGroup string, p *freshauth.Proof) (out *state.SSHGrant, err error) {
	if c == nil {
		return nil, statusErr(http.StatusForbidden, "not allowed")
	}
	actor := c.Actor()
	g.Group, g.HostGroup = strings.TrimSpace(g.Group), strings.TrimSpace(g.HostGroup)
	if g.Sudo == "" {
		g.Sudo = state.SudoNone
	}
	newGrant := g.ID == ""
	var before *state.SSHGrant
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	for _, x := range st.Grants {
		if x.ID == g.ID {
			x := x
			before = &x
		}
	}
	action := "ssh.grant.update"
	if before == nil {
		action = "ssh.grant.create"
	}
	if !newGrant && before == nil {
		return nil, statusErr(http.StatusNotFound, "no grant %s", g.ID)
	}
	priv, why := sshaccess.Privileged(g)
	// M5: a new grant for a group and host group that already have grants
	// is judged against their merged access, so a second grant can't widen
	// what an edit of the first one couldn't.
	compare := before
	if before == nil {
		compare = mergedGrants(st.Grants, g.Group, g.HostGroup)
	}
	widen := sshaccess.WideningReasons(compare, g, st.Settings)
	defer func() {
		d := grantDetail(before) + " → " + grantDetail(&g)
		if priv {
			d += " privileged=true (" + why + ")"
		}
		if !c.Admin {
			d += " as ssh_access"
		}
		target := g.ID
		if target == "" {
			target = "(new)"
		}
		h.auditOp(actor, action, target, d, err)
	}()
	// The directory's checks on a fresh snapshot (also gives the group id).
	h.sshrt.mu.Lock()
	dir := h.sshrt.dir
	h.sshrt.mu.Unlock()
	if dir == nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the directory isn't connected")
	}
	gid, err := dir.CheckSSHGrantGroup(ctx, c, g.Group)
	if err != nil {
		return nil, err
	}
	if before != nil && before.Group == g.Group && before.GroupID != 0 && before.GroupID != gid {
		// The group was deleted and re-created: the grant keeps the old id
		// (it grants nothing) until an administrator saves it again.
		if !c.Admin {
			return nil, statusErr(http.StatusForbidden, "the group was re-created: an administrator must save this grant again")
		}
	}
	g.GroupID = gid
	if before != nil && before.GroupID != gid {
		widen = sshaccess.WideningReasons(before, g, st.Settings)
	} else if before == nil && compare != nil {
		compare.GroupID = gid
		widen = sshaccess.WideningReasons(compare, g, st.Settings)
	}
	hg, ok := st.HostGroups[g.HostGroup]
	if !ok {
		return nil, statusErr(http.StatusBadRequest, "no host group %s", g.HostGroup)
	}
	switch {
	case c.Via == directory.ViaAI && (priv || len(widen) > 0 || g.PortForwarding):
		return nil, statusErr(http.StatusForbidden, "privileged grants, port forwarding and widening edits can't be made through an AI assistant")
	case !c.Admin:
		if !c.Perms[directory.PermSSHAccess] {
			return nil, statusErr(http.StatusForbidden, "not allowed: needs ssh_access")
		}
		if priv {
			return nil, statusErr(http.StatusForbidden, TextOnlyAdminsPrivileged)
		}
		if !hg.Delegable {
			return nil, statusErr(http.StatusForbidden, "host group %s isn't delegable (admins only)", g.HostGroup)
		}
		if before != nil {
			if bp, _ := sshaccess.Privileged(*before); bp || !st.HostGroups[before.HostGroup].Delegable {
				return nil, statusErr(http.StatusForbidden, TextOnlyAdminsPrivileged)
			}
		}
		if len(widen) > 0 {
			return nil, statusErr(http.StatusForbidden, TextOnlyAdminsWiden)
		}
	default: // an administrator
		if priv && (before == nil || len(widen) > 0 || !privSame(before, g)) {
			if typedGroup != g.Group {
				return nil, statusErr(http.StatusBadRequest, "type the group's name (%s) to confirm a privileged grant", g.Group)
			}
		}
		if (priv && (before == nil || len(widen) > 0)) || len(widen) > 0 {
			if p == nil {
				return nil, statusErr(http.StatusForbidden, freshauth.Message)
			}
			if err := h.checkAdminFresh(ctx, actor, *p); err != nil {
				return nil, err
			}
		}
	}
	// Shape, then the shared account against the directory's usernames.
	if m, merr := h.sshMembers(ctx); merr != nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the directory can't be read")
	} else if err := sshaccess.CheckSharedAgainstUsers(g, m); err != nil {
		return nil, statusErr(http.StatusConflict, "%v", err)
	}
	if newGrant {
		g.ID = newGrantID()
	}
	h.mu.Lock()
	next := h.st.SSH.Clone()
	replaced := false
	for i := range next.Grants {
		if next.Grants[i].ID == g.ID {
			next.Grants[i] = g
			replaced = true
		}
	}
	if !replaced {
		next.Grants = append(next.Grants, g)
	}
	if err := sshaccess.Validate(next); err != nil {
		h.mu.Unlock()
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	h.st.SSH.Grants = next.Grants
	h.saveLocked()
	h.mu.Unlock()
	h.TriggerSSHCompile()
	out = &g
	return out, nil
}

// privSame: an edit of a privileged grant that keeps its privilege
// exactly (narrowing): no typed name needed.
func privSame(before *state.SSHGrant, after state.SSHGrant) bool {
	_, wb := sshaccess.Privileged(*before)
	_, wa := sshaccess.Privileged(after)
	return wb == wa && before.Group == after.Group && before.HostGroup == after.HostGroup
}

// sshMembers is the directory's usernames (a fresh snapshot).
func (h *Hub) sshMembers(ctx context.Context) (map[string]bool, error) {
	h.mu.RLock()
	people := h.people
	h.mu.RUnlock()
	if people == nil {
		return nil, fmt.Errorf("no directory")
	}
	m, err := people.Membership(ctx, h.sshrt.clock())
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for u := range m.Users {
		out[u] = true
	}
	return out, nil
}

// DeleteGrant deletes a grant (administrators; ssh_access holders only
// non-privileged grants on delegable host groups).
func (h *Hub) DeleteGrant(ctx context.Context, c *directory.Caller, id string) (err error) {
	if c == nil {
		return statusErr(http.StatusForbidden, "not allowed")
	}
	h.mu.RLock()
	var g *state.SSHGrant
	for _, x := range h.st.SSH.Grants {
		if x.ID == id {
			x := x
			g = &x
		}
	}
	delegable := g != nil && h.st.SSH.HostGroups[g.HostGroup].Delegable
	h.mu.RUnlock()
	defer func() {
		d := grantDetail(g) + " → -"
		if !c.Admin {
			d += " as ssh_access"
		}
		h.auditOp(c.Actor(), "ssh.grant.delete", id, d, err)
	}()
	if g == nil {
		return statusErr(http.StatusNotFound, "no grant %s", id)
	}
	if !c.Admin {
		if p, _ := sshaccess.Privileged(*g); p || !delegable || !c.Perms[directory.PermSSHAccess] {
			return statusErr(http.StatusForbidden, TextOnlyAdminsPrivileged)
		}
		h.sshrt.mu.Lock()
		dir := h.sshrt.dir
		h.sshrt.mu.Unlock()
		if dir == nil {
			return statusErr(http.StatusServiceUnavailable, "the directory isn't connected")
		}
		if _, err := dir.CheckSSHGrantGroup(ctx, c, g.Group); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.st.SSH.Grants = slices.DeleteFunc(h.st.SSH.Grants, func(x state.SSHGrant) bool { return x.ID == id })
	h.saveLocked()
	h.mu.Unlock()
	h.TriggerSSHCompile()
	return nil
}

// PreviewGrant is the hypothetical preview of an unsaved grant: the host
// group's access as it would be.
func (h *Hub) PreviewGrant(ctx context.Context, c *directory.Caller, g state.SSHGrant) ([]sshaccess.PreviewRow, error) {
	if c == nil || (!c.Admin && !c.Perms[directory.PermSSHAccess]) {
		return nil, statusErr(http.StatusForbidden, "not allowed")
	}
	if g.ID == "" {
		g.ID = "preview"
	}
	if g.Sudo == "" {
		g.Sudo = state.SudoNone
	}
	h.mu.RLock()
	st := h.st.SSH.Clone()
	people := h.people
	h.mu.RUnlock()
	if !c.Admin && !st.HostGroups[g.HostGroup].Delegable {
		return nil, statusErr(http.StatusForbidden, "host group %s isn't delegable (admins only)", g.HostGroup)
	}
	if !c.Admin {
		// L-C4: a delegate previews only a group they could grant to (the
		// preview lists its members).
		h.sshrt.mu.Lock()
		dir := h.sshrt.dir
		h.sshrt.mu.Unlock()
		if dir == nil {
			return nil, statusErr(http.StatusServiceUnavailable, "the directory isn't connected")
		}
		if _, err := dir.CheckSSHGrantGroup(ctx, c, g.Group); err != nil {
			return nil, err
		}
	}
	if people == nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the directory isn't connected")
	}
	now := h.sshrt.clock()
	m, err := people.Membership(ctx, now)
	if err != nil {
		return nil, statusErr(http.StatusServiceUnavailable, "the directory can't be read")
	}
	if mg, ok := m.Groups[g.Group]; ok {
		g.GroupID = mg.ID
	}
	comp, err := sshaccess.Hypothetical(h.sshInput(st, m, now), g)
	if err != nil {
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	}
	return comp.PreviewHostGroup(g.HostGroup, false), nil
}

// revokeOnLeave (plan C35): every issued, unexpired certificate whose
// host group no longer gives that person one of its principals has its
// key revoked (actor -, reason "left <group>"). Runs after each compile.
func (h *Hub) revokeOnLeave(ctx context.Context, c *sshaccess.Compiled) {
	now := h.sshrt.clock()
	revoked, err := h.sshRevokedList()
	if err != nil {
		return
	}
	done := map[string]bool{}
	for _, r := range revoked {
		done[r.FP] = true
	}
	h.mu.RLock()
	grants := slices.Clone(h.st.SSH.Grants)
	h.mu.RUnlock()
	for _, rec := range h.IssuedFor("") {
		if !rec.ValidBefore.After(now) || done[rec.KeyFP] {
			continue
		}
		// FR-H2: revoked when ANY principal of the certificate is no
		// longer the person's (a shared s: principal is the same for every
		// holder, so the host can't fence one person out of it; key-level:
		// the person signs in again for what they still hold).
		have := c.People[rec.User].HostGroups[rec.HostGroup].Principals
		lost := false
		for _, p := range rec.Principals {
			if !slices.Contains(have, p) {
				lost = true
				break
			}
		}
		if !lost {
			continue
		}
		reason := "left " + leftGroup(grants, rec)
		if _, err := h.RevokeFingerprints("-", reason, []string{rec.KeyFP}, rec.User); err != nil {
			log.Printf("ssh: revoking on leave: %v", err)
			continue
		}
		done[rec.KeyFP] = true
	}
	_ = ctx
}

// leftGroup names the groups of the grants on the record's host group
// that gave its principals ({username} for u: principals, the account
// for s: ones).
func leftGroup(grants []state.SSHGrant, rec IssuedRecord) string {
	var gs []string
	for _, g := range grants {
		if g.HostGroup != rec.HostGroup {
			continue
		}
		for _, p := range rec.Principals {
			kind, acct, _, ok := cliapi.ParsePrincipal(p)
			if !ok {
				continue
			}
			if (kind == cliapi.PrincipalPersonal && slices.Contains(g.Accounts, cliapi.UsernamePlaceholder) && acct == rec.User) ||
				(kind == cliapi.PrincipalShared && slices.Contains(g.Accounts, acct)) {
				gs = append(gs, g.Group)
			}
		}
	}
	if len(gs) == 0 {
		return "the grants of " + rec.HostGroup
	}
	return strings.Join(dedupStrings(gs), ",")
}
