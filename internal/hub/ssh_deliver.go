package hub

// The SSH compile loop (contract §18.12 "Delivery", plan C22, C23):
// directory snapshot → sshaccess.Compile → Vault roles through enroll,
// stale roles deleted, host certificates renewed, bundle serials bumped.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/sshaccess"
	"github.com/portcullis/hub/internal/state"
)

// sshCompileTimeout bounds one compile (every enroll call has its own 15 s).
const sshCompileTimeout = 2 * time.Minute

// hostCertTTL is a host certificate's life (90 days).
const hostCertTTL = 90 * 24 * time.Hour

// TriggerSSHCompile asks for a compile, coalesced like TriggerVPNPublish:
// any number of triggers while one is queued make one more run.
func (h *Hub) TriggerSSHCompile() {
	if !h.sshrt.pending.CompareAndSwap(false, true) {
		return
	}
	h.goBackground(func() {
		h.sshrt.runMu.Lock()
		defer h.sshrt.runMu.Unlock()
		h.sshrt.pending.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), sshCompileTimeout)
		defer cancel()
		if err := h.compileSSH(ctx); err != nil {
			log.Printf("ssh: compile: %v", err)
		}
	})
}

// compileSSH runs one compile. Callers hold runMu (TriggerSSHCompile) or
// are tests.
func (h *Hub) compileSSH(ctx context.Context) error {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	people := h.people
	h.mu.RUnlock()
	acts := h.sshActions()
	off := !st.Settings.Enabled
	if off {
		// M6: switching SSH access off ends access, it doesn't freeze it:
		// while managed hosts or unexpired certificates exist, compile with
		// no grants — every host's bundle locks every Portcullis account
		// and every certificate is revoked on leave. No role is written
		// while off (plan C29); signing is refused anyway.
		if len(st.Hosts) == 0 && !h.anyValidIssued() {
			h.sshrt.mu.Lock()
			h.sshrt.compiled, h.sshrt.compileErr = nil, ""
			h.sshrt.mu.Unlock()
			return nil
		}
		st.Grants = nil
	}
	if acts == nil || people == nil {
		return h.sshCompileFailed(errors.New("enroll or the directory isn't connected"))
	}
	now := h.sshrt.clock()
	m, err := people.Membership(ctx, now)
	if err != nil {
		h.sshrt.mu.Lock()
		h.sshrt.dirErr = "the directory can't be read"
		h.sshrt.mu.Unlock()
		return fmt.Errorf("the directory can't be read: the last compilation stays: %w", err)
	}
	h.sshrt.mu.Lock()
	h.sshrt.dirErr = ""
	h.sshrt.mu.Unlock()
	if h.retireReusedUIDs(m.UUIDs) {
		h.mu.RLock()
		cur := h.st.SSH.Clone()
		h.mu.RUnlock()
		st.UIDs, st.UIDOwners, st.UIDsUsed, st.Hosts = cur.UIDs, cur.UIDOwners, cur.UIDsUsed, cur.Hosts
	}
	if err := h.refreshSSHCA(ctx, acts); err != nil {
		return h.sshCompileFailed(err)
	}
	if !off {
		if err := h.renewHostCerts(ctx, acts, &st, now); err != nil {
			log.Printf("ssh: host certificates: %v", err)
		}
	}
	revoked, err := h.sshRevokedList()
	if err != nil {
		return h.sshCompileFailed(err)
	}
	// Only parseable public keys (FR-H1): a fingerprint-only revocation
	// (the key was never recorded, C21-b) stays in revoked.json and the
	// doctor's "revocation incomplete"; the person's account lock carries it.
	keys := make([]string, 0, len(revoked))
	for _, r := range revoked {
		if _, _, err := cliapi.ParseAuthorizedKey(r.Key); err == nil {
			keys = append(keys, r.Key)
		}
	}
	slices.Sort(keys)
	h.sshrt.mu.Lock()
	userCAs := slices.Clone(h.sshrt.userCAs)
	h.sshrt.mu.Unlock()
	in := sshaccess.Input{State: st, Members: m.Users, Pending: m.Pending, Expired: m.Expired, Now: now,
		VPNRanges: h.vpnAllowRanges, UserCAs: userCAs, RevokedKeys: keys}
	c, err := sshaccess.Compile(in)
	if err != nil {
		return h.sshCompileFailed(err)
	}
	if len(c.NeedUIDs) > 0 {
		h.mu.Lock()
		for _, u := range c.NeedUIDs {
			if _, err := sshaccess.AllocUID(&h.st.SSH, u); err != nil {
				log.Printf("ssh: %s: %v", u, err)
			} else if id := m.UUIDs[u]; id != "" {
				if h.st.SSH.UIDOwners == nil {
					h.st.SSH.UIDOwners = map[string]string{}
				}
				h.st.SSH.UIDOwners[u] = id
			}
		}
		h.saveLocked()
		in.State.UIDs, in.State.UIDsUsed, in.State.UIDOwners = clone(h.st.SSH.UIDs), slices.Clone(h.st.SSH.UIDsUsed), clone(h.st.SSH.UIDOwners)
		h.mu.Unlock()
		if c, err = sshaccess.Compile(in); err != nil {
			return h.sshCompileFailed(err)
		}
	}
	if !off {
		h.deliverRoles(ctx, acts, c)
	}
	changed := h.bumpSerials(c, now)
	h.sshrt.mu.Lock()
	h.sshrt.compiled, h.sshrt.compileErr = c, ""
	h.sshrt.mu.Unlock()
	h.sshAfterCompile(ctx, c)
	if changed {
		h.sshBroadcast()
	}
	return nil
}

// retireReusedUIDs (final review M11): a username whose LLDAP uuid isn't
// the one its uid was given to belongs to someone new. Their
// predecessor's uid is retired (UIDsUsed keeps it, it's never given
// again) and every managed host is asked to move the old account aside
// (Remove account: locked, home kept under the removed homes, userdel);
// the bundle names no account of that name until the host reported it
// removed, then the new person gets a fresh uid and a fresh account.
// A name with no uuid now (the person is gone) keeps its uid: the account
// stays locked. Reports whether anything changed (saved).
func (h *Hub) retireReusedUIDs(uuids map[string]string) bool {
	h.mu.Lock()
	s := &h.st.SSH
	changed := false
	var retired []string
	for _, name := range slices.Sorted(maps.Keys(s.UIDs)) {
		now, was := uuids[name], s.UIDOwners[name]
		switch {
		case now == "":
			continue
		case was == "":
			if s.UIDOwners == nil {
				s.UIDOwners = map[string]string{}
			}
			s.UIDOwners[name] = now
			changed = true
			continue
		case now == was:
			continue
		}
		delete(s.UIDs, name)
		delete(s.UIDOwners, name)
		for id, hst := range s.Hosts {
			if !slices.Contains(hst.RemoveAccounts, name) {
				hst.RemoveAccounts = append(hst.RemoveAccounts, name)
				s.Hosts[id] = hst
			}
		}
		retired = append(retired, name)
		changed = true
	}
	if changed {
		h.saveLocked()
	}
	h.mu.Unlock()
	for _, name := range retired {
		h.auditSSH("-", "ssh.uid.retire", name, "the name belongs to a new person: the old uid is retired, its host accounts are moved aside", nil)
	}
	return changed
}

// anyValidIssued: some issued certificate hasn't expired yet.
func (h *Hub) anyValidIssued() bool {
	now := h.sshrt.clock()
	for _, r := range h.IssuedFor("") {
		if r.ValidBefore.After(now) {
			return true
		}
	}
	return false
}

// sshAfterCompile runs the compile's follow-ups: revocation on leave.
func (h *Hub) sshAfterCompile(ctx context.Context, c *sshaccess.Compiled) {
	h.revokeOnLeave(ctx, c)
}

func clone[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (h *Hub) sshCompileFailed(err error) error {
	h.sshrt.mu.Lock()
	h.sshrt.compileErr = err.Error()
	h.sshrt.mu.Unlock()
	return err
}

// refreshSSHCA reads the CA keys and enroll's problems.
func (h *Hub) refreshSSHCA(ctx context.Context, acts SSHActions) error {
	ca, err := acts.SSHCA(ctx)
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	if err != nil {
		h.sshrt.caProblems = []string{"enroll's SSH CA can't be read"}
		if len(h.sshrt.userCAs) == 0 {
			return errors.New("no user CA key known yet")
		}
		return nil // the last known keys stay
	}
	if len(ca.UserCAs) == 0 {
		h.sshrt.caProblems = append([]string{"no user CA"}, ca.Problems...)
		return errors.New("enroll reports no user CA")
	}
	for _, k := range append(slices.Clone(ca.UserCAs), ca.HostCAs...) {
		if _, _, err := cliapi.ParseAuthorizedKey(k); err != nil {
			h.sshrt.caProblems = []string{"enroll answered a CA key that isn't a public key"}
			return errors.New("enroll answered a malformed CA key")
		}
	}
	h.sshrt.userCAs, h.sshrt.hostCAs = slices.Clone(ca.UserCAs), slices.Clone(ca.HostCAs)
	h.sshrt.caProblems = slices.Clone(ca.Problems)
	return nil
}

// deliverRoles puts every changed role and deletes stale hg-* roles.
func (h *Hub) deliverRoles(ctx context.Context, acts SSHActions, c *sshaccess.Compiled) {
	for _, hg := range sshKeys(c.Roles) {
		if err := h.putRole(ctx, acts, hg, c.Roles[hg]); err != nil {
			log.Printf("ssh: role hg-%s: %v", hg, err)
		}
	}
	have, err := acts.ListSSHRoles(ctx)
	if err != nil {
		log.Printf("ssh: listing roles: %v", err)
		return
	}
	for _, hg := range have {
		if _, ok := c.Roles[hg]; ok {
			continue
		}
		if err := acts.DeleteSSHRole(ctx, hg); err != nil {
			log.Printf("ssh: deleting role hg-%s: %v", hg, err)
			continue
		}
		h.sshrt.mu.Lock()
		delete(h.sshrt.roles, hg)
		delete(h.sshrt.roleErr, hg)
		h.sshrt.mu.Unlock()
	}
}

// putRole writes hg's role unless the last read-back already equals it.
// A read-back that differs is an error (and recorded).
func (h *Hub) putRole(ctx context.Context, acts SSHActions, hg string, spec cliapi.RoleSpec) error {
	h.sshrt.mu.Lock()
	last, ok := h.sshrt.roles[hg]
	h.sshrt.mu.Unlock()
	if ok && last.Equal(spec) {
		return nil
	}
	back, err := acts.PutSSHRole(ctx, hg, spec)
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	if h.sshrt.roles == nil {
		h.sshrt.roles, h.sshrt.roleErr = map[string]cliapi.RoleSpec{}, map[string]string{}
	}
	if err != nil {
		delete(h.sshrt.roles, hg)
		h.sshrt.roleErr[hg] = "the role couldn't be written"
		return err
	}
	if !back.Equal(spec) {
		delete(h.sshrt.roles, hg)
		h.sshrt.roleErr[hg] = "Vault's read-back of the role differs from the compiled one"
		return errors.New("read-back differs from the compiled role")
	}
	h.sshrt.roles[hg] = *back
	delete(h.sshrt.roleErr, hg)
	return nil
}

// ensureRoleCurrent makes sure hg's Vault role is the compiled one before
// a signing (fail closed: any doubt is an error).
func (h *Hub) ensureRoleCurrent(ctx context.Context, hg string) error {
	c := h.sshCompiled()
	acts := h.sshActions()
	if c == nil || acts == nil {
		return errors.New("SSH access isn't compiled yet")
	}
	spec, ok := c.Roles[hg]
	if !ok {
		return fmt.Errorf("host group %s has no role", hg)
	}
	return h.putRole(ctx, acts, hg, spec)
}

// renewHostCerts gives every managed, enrolled host whose groups want
// host certificates a new one when it has none or ≤ ⅓ of its life left
// (plan C23). st is updated with what was saved.
func (h *Hub) renewHostCerts(ctx context.Context, acts SSHActions, st *state.SSHState, now time.Time) error {
	var errs []string
	for _, id := range sshKeys(st.Hosts) {
		hst := st.Hosts[id]
		if !hst.Managed || hst.Removed || hst.HostKey == "" || !wantsHostCert(*st, hst) {
			continue
		}
		if hst.HostCert != "" {
			life := hst.HostCertUntil.Sub(hst.HostCertFrom)
			if life > 0 && hst.HostCertUntil.Sub(now) > life/3 {
				continue
			}
		}
		hg := cliapi.BuiltinAllHostGroup
		if len(hst.HostGroups) > 0 {
			hg = hst.HostGroups[0]
		}
		signed, err := acts.SignSSHHost(ctx, invite.SSHHostSign{PublicKey: hst.HostKey, Principals: append(slices.Clone(hst.Names), hst.Addrs...), HostGroup: hg, HostID: id})
		if err != nil {
			errs = append(errs, id)
			continue
		}
		h.mu.Lock()
		cur, ok := h.st.SSH.Hosts[id]
		if ok && cur.HostKey == hst.HostKey && !cur.Removed {
			cur.HostCert, cur.HostCertFrom, cur.HostCertUntil = signed.Certificate, now, signed.ValidBefore
			h.st.SSH.Hosts[id] = cur
			h.saveLocked()
			hst = cur
		}
		h.mu.Unlock()
		st.Hosts[id] = hst
		h.auditSSH("-", "ssh.host_certificate.issue", id, "serial "+signed.Serial+" until "+signed.ValidBefore.UTC().Format(time.RFC3339), nil)
	}
	if len(errs) > 0 {
		return fmt.Errorf("couldn't renew the host certificates of %s", strings.Join(errs, ", "))
	}
	return nil
}

func wantsHostCert(st state.SSHState, hst state.SSHHost) bool {
	for _, g := range hst.HostGroups {
		if st.HostGroups[g].HostCerts() {
			return true
		}
	}
	return len(hst.HostGroups) == 0 && st.HostGroups[cliapi.BuiltinAllHostGroup].HostCerts()
}

// bumpSerials gives each host whose bundle content changed the next
// Hub-wide serial (plan C22) and reports whether any moved.
func (h *Hub) bumpSerials(c *sshaccess.Compiled, now time.Time) bool {
	h.sshhosts.mu.Lock()
	syncs := clone(h.sshhosts.lastSync)
	h.sshhosts.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	changed, dirty := false, false
	for id, t := range syncs {
		if hst, ok := h.st.SSH.Hosts[id]; ok && t.Sub(hst.LastSync) > time.Minute {
			hst.LastSync = t.UTC()
			h.st.SSH.Hosts[id] = hst
			dirty = true
		}
	}
	for _, id := range sshKeys(c.Bundles) {
		b := c.Bundles[id]
		hash := sshaccess.BundleHash(b)
		hst, ok := h.st.SSH.Hosts[id]
		if !ok {
			continue
		}
		if hst.BundleHash != hash || hst.Serial == 0 {
			h.st.SSH.Serial++
			hst.Serial, hst.BundleHash = h.st.SSH.Serial, hash
			h.st.SSH.Hosts[id] = hst
			changed = true
		}
		b.Serial, b.Generated = hst.Serial, now.UTC()
	}
	if changed || dirty {
		h.saveLocked()
	}
	return changed
}

// auditSSH appends an SSH audit entry with actor (a username or "-").
// A refusal is audited with its reason (never its input) and result
// refused (status < 500) or error.
func (h *Hub) auditSSH(actor, action, target, detail string, err error) {
	var r *sshRefusal
	if errors.As(err, &r) {
		err = &StatusError{Status: r.status, Err: errors.New(r.reason)}
	}
	h.auditOp(directory.Actor{User: actor}, action, target, detail, err)
}

// sshKeys are m's keys, sorted.
func sshKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// RunSSH triggers a compile every tick (temporary memberships ending,
// host certificates to renew) until ctx ends; the first one at once.
func (h *Hub) RunSSH(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	h.TriggerSSHCompile()
	var pruned time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if now := h.sshrt.clock(); now.Sub(pruned) > 24*time.Hour {
				h.pruneRevoked(now)
				h.pruneKeys(now)
				pruned = now
			}
			h.TriggerSSHCompile()
		}
	}
}
