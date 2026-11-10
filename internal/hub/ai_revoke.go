package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Credential revocation and its reconcile (contract §15.5 "Revoke on
// leave", "revoke_all", "Template updates", "No AI resource left"; §8
// "Disconnecting"; plan 4 Task 13b; G33, G35).
//
// ReconcileAICredentials is one pass, run after every policy write of the
// directory sync loop and every drift reconcile (TriggerAIReconcile; its
// own loop, so a slow hook never delays a policy write), serialised by
// aiReconMu:
//
//  1. an instance whose sign-in template is now certificate-only (a
//     restore, a template update) gets AI support switched off
//     (ai.disable, "sign-in needs a client certificate");
//  2. companions a template update switched off (Pruned) get their owed
//     revoke_all, with the hook they were switched on with;
//  3. app_token entries of people no longer in their companion's
//     population (the gate's own population: the same building blocks as
//     gateFile, so mint and revoke agree), of a disabled instance or of a
//     companion that is off are marked revoking, then revoked ({"action":
//     "revoke","user","ids":[id]}); revoking entries are retried; success
//     removes them; a failure keeps them revoking (the gate ignores them)
//     with the companion's LastError — never reported as done;
//  4. credentials a mint couldn't store (orphans.json: ids only) are
//     revoked;
//  5. app_oauth companions: who was in the population while AI was on is
//     recorded in <data>/ai/oauth-seen.json; a person who left (or
//     everyone recorded, once the companion is off) gets {"action":
//     "revoke","user","ids":[]};
//  6. a person who can use no AI resource any more (deleted, or in no
//     population) gets their consents and offline sessions deleted for
//     every AI client (connections-seen.json records who could).
//
// Locks (G35): the per-instance AI lock only (aiTryLock, bounded), never
// lockApp; never Hub.mu across a hook, Keycloak or directory call. With
// the directory unreadable or the master switch off nobody is judged a
// leaver (revoking entries are still retried).

// aiRevokeLockWait bounds a revoke's wait for the instance's AI lock (a
// mint or a lifecycle operation holds it); the next pass retries.
var aiRevokeLockWait = 10 * time.Second

// aiReconcileTimeout bounds one reconcile pass.
const aiReconcileTimeout = 5 * time.Minute

// aiHubActor attributes the Hub's own revocations.
var aiHubActor = directory.Human(purgeActor)

// TriggerAIReconcile asks the AI reconcile loop for a pass soon
// (non-blocking, coalesced).
func (h *Hub) TriggerAIReconcile() {
	select {
	case h.aiReconKick <- struct{}{}:
	default:
	}
}

// runAIReconcile runs ReconcileAICredentials on each kick until ctx is
// done (started by RunReconciler).
func (h *Hub) runAIReconcile(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.aiReconKick:
		}
		pctx, cancel := context.WithTimeout(ctx, aiReconcileTimeout)
		h.ReconcileAICredentials(pctx)
		cancel()
	}
}

// ReconcileAICredentials is one reconcile pass (see the file comment).
func (h *Hub) ReconcileAICredentials(ctx context.Context) {
	h.aiReconMu.Lock()
	defer h.aiReconMu.Unlock()
	h.aiOffForCertOnly(ctx)
	h.revokePruned(ctx)
	mctx, cancel := context.WithTimeout(ctx, directoryStateTimeout)
	m, err := h.membership(mctx)
	cancel()
	if err != nil {
		m = nil
	}
	h.reconcileTokenCredentials(ctx, m)
	h.retryOrphans(ctx)
	h.reconcileOAuthSeen(ctx, m)
	h.reconcileConnections(ctx, m)
}

// ── who may hold a credential ─────────────────────────────

// aiHoldersLocked: the people who may hold c's app-side credentials now
// (known false: can't tell — the directory is unreadable, the master
// switch is off, or a revoke_all is owed anyway). An instance that is
// disabled, a companion that is off, a certificate-only sign-in
// template or a population
// emptied by state (sign_in native, …) = nobody. Members whose expiry has
// passed are left out (the gate's expiring rule). Caller holds mu.
func (h *Hub) aiHoldersLocked(t *templates.Template, c *templates.Companion, s state.AICompanion, m *directory.Membership, now time.Time) (map[string]bool, bool) {
	if !h.st.AI.Enabled || s.RevokePending || s.Pruned {
		return nil, false
	}
	nobody := map[string]bool{}
	if !t.Enabled || !s.Enabled || !slices.Contains(c.Modes, s.Mode) {
		return nobody, true
	}
	if h.certOnlyLocked(t) {
		return nobody, true
	}
	if h.populationWhyLocked(t) != "" {
		return nobody, true
	}
	if m == nil {
		return nil, false
	}
	pop := h.populationLocked(t, m)
	users := make([]string, 0, len(pop.People))
	for _, p := range pop.People {
		users = append(users, p.User)
	}
	users = validUsers(users)
	group := accessGroupOf(t)
	out := map[string]bool{}
	for _, u := range users {
		if at, ok := m.Pending[u][group]; group != "" && ok && !now.Before(at) {
			continue
		}
		out[u] = true
	}
	return out, true
}

// revokeHookOf is the hook that revokes companion name's credentials:
// the template's own while it declares the companion, else the one it
// was switched on with (state) while the template still has it ("": none
// left — the entries stay revoking, AIRevokeProblems). A Pruned
// companion's credentials are only ever revoked with the stored hook
// (never the new definition's).
func revokeHookOf(t *templates.Template, name string, s state.AICompanion) string {
	if s.Pruned {
		if s.RevokeHook != "" && aiHookExists(t, s.RevokeHook) {
			return s.RevokeHook
		}
		return ""
	}
	if c := companionOf(t, name); c != nil && (s.IdentityMode == "" || c.Identity.Mode == s.IdentityMode) {
		return c.Identity.Revoke
	}
	if s.RevokeHook != "" && aiHookExists(t, s.RevokeHook) {
		return s.RevokeHook
	}
	return ""
}

// aiHookExists: t declares an ai hook named name.
func aiHookExists(t *templates.Template, name string) bool {
	for i := range t.Manifest.Hooks {
		if t.Manifest.Hooks[i].Name == name && t.Manifest.Hooks[i].IsAI() {
			return true
		}
	}
	return false
}

// ── hook runs ─────────────────────────────────────────────

// runRevoke runs an app_token companion's hook with
// {"action":"revoke","user","ids"} (app_oauth: runRevokeOAuth). Caller
// holds the instance's AI lock. The error is the redacted, clipped hook
// error.
func (h *Hub) runRevoke(ctx context.Context, t *templates.Template, hook, user string, ids []string) error {
	if ids == nil {
		ids = []string{}
	}
	stdin, _ := json.Marshal(aiRevokeIn{Action: "revoke", User: user, IDs: ids})
	out, u := h.runAIHook(ctx, t, hook, stdin)
	clear(out)
	if !u.OK {
		return errors.New(u.Error)
	}
	return nil
}

// runRevokeOAuthSub runs an app_oauth hook's revoke for user with sub
// (never empty).
func (h *Hub) runRevokeOAuthSub(ctx context.Context, t *templates.Template, hook, user, sub string) error {
	if sub == "" {
		return errors.New("no Keycloak id: not sent")
	}
	stdin, _ := json.Marshal(aiRevokeIn{Action: "revoke", User: user, Sub: sub, IDs: []string{}})
	out, u := h.runAIHook(ctx, t, hook, stdin)
	clear(out)
	if !u.OK {
		return errors.New(u.Error)
	}
	return nil
}

// errNoRevokeHook: the template no longer has the hook that revokes a
// companion's credentials.
func errNoRevokeHook(companion string) error {
	return fmt.Errorf("companion %s: its credentials can't be revoked: the template no longer has its revoke hook (they stay revoking; the gate never uses them)", companion)
}

// revokeAudit audits a revocation: every success; a failure only when its
// text differs from the last one for that key (a hook failing at every
// reconcile isn't audited every pass; LastError and the log show it).
func (h *Hub) revokeAudit(actor directory.Actor, key, target, detail string, err error) {
	h.aiErrMu.Lock()
	if h.aiRevokeErrs == nil {
		h.aiRevokeErrs = map[string]string{}
	}
	repeat := false
	if err == nil {
		delete(h.aiRevokeErrs, key)
	} else {
		repeat = h.aiRevokeErrs[key] == err.Error()
		h.aiRevokeErrs[key] = err.Error()
	}
	h.aiErrMu.Unlock()
	if repeat {
		return
	}
	if err != nil {
		log.Printf("ai: revoking %s (%s) failed (kept, retried at every reconcile): %v", target, detail, err)
	}
	h.auditAI(actor, "ai.credential.revoke", target, detail, err)
}

// revokeTokenEntry revokes one app_token entry: marked revoking first (the
// gate stops using it at its next reload), then the revoke hook with its
// id; success removes it. Caller holds the instance's AI lock.
func (h *Hub) revokeTokenEntry(ctx context.Context, t *templates.Template, hook string, e aigate.Credential, actor directory.Actor) error {
	target := e.Instance + "/" + e.Companion + "/" + e.User
	detail := "id " + e.ID
	key := "entry:" + target + ":" + e.ID
	if e.State != aigate.StateRevoking {
		if err := h.creds().MarkRevoking(e.Instance, e.Companion, e.User); err != nil {
			err = fmt.Errorf("companion %s: marking the credential revoking: %v", e.Companion, err)
			h.revokeAudit(actor, key, target, detail, err)
			return err
		}
	}
	if hook == "" {
		err := errNoRevokeHook(e.Companion)
		h.revokeAudit(actor, key, target, detail, err)
		return err
	}
	if err := h.runRevoke(ctx, t, hook, e.User, []string{e.ID}); err != nil {
		h.revokeAudit(actor, key, target, detail, err)
		return err
	}
	if err := h.removeCred(e.Instance, e.Companion, e.User); err != nil {
		err = fmt.Errorf("companion %s: removing the revoked credential %s: %v", e.Companion, e.ID, err)
		h.revokeAudit(actor, key, target, detail, err)
		return err
	}
	h.revokeAudit(actor, key, target, detail, nil)
	return nil
}

// revokeFailed records a revoke failure as the companion's last error
// (the AI tab: status failed) unless it already holds a lifecycle error.
func (h *Hub) revokeFailed(id, companion string, err error) {
	h.setAIError(id, companion, err.Error())
}

// revokeDone clears a revoke failure (or a mint's) from the companion's
// last error.
func (h *Hub) revokeDone(t *templates.Template, name string) {
	if c := companionOf(t, name); c != nil {
		h.clearMintError(t.ID, c)
	}
}

// ── RevokeAICredentials ───────────────────────────────────

// RevokeAICredentials revokes user's AI credentials for instance's
// companion now (POST /api/instances/{id}/ai/revoke): user "" = everyone
// (revoke_all, entries marked revoking first, removed after success);
// else the person's entry (revoke with its id; app_oauth: ids []).
// Audited ai.credential.revoke. A failure keeps the entries revoking
// (502 with the redacted stderr). Takes the instance's AI lock only
// (G35): 503 while it stays busy.
func (h *Hub) RevokeAICredentials(ctx context.Context, instance, companion, user string, actor directory.Actor) error {
	if err := checkAIActor(actor); err != nil {
		return err
	}
	t := h.Template(instance)
	if t == nil {
		return ErrNotFound
	}
	c := companionOf(t, companion)
	if c == nil {
		return &StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("%s has no companion %s", instance, clipQuoted(companion))}
	}
	if user != "" && !aigate.ValidUsername(user) {
		return statusErr(http.StatusBadRequest, "user: not a username")
	}
	target := instance + "/" + companion
	if user != "" {
		target += "/" + user
	}
	h.mu.RLock()
	s := h.st.AIInstances[instance].Companions[companion]
	h.mu.RUnlock()
	// A companion a template update switched off is revoked with the hook
	// it was switched on with, as the identity mode it had (fix round 1).
	hook, mode := revokeHookOf(t, companion, s), c.Identity.Mode
	if s.Pruned && s.IdentityMode != "" {
		mode = s.IdentityMode
	}
	if hook == "" {
		var err error
		if s.Pruned {
			err = statusErr(http.StatusConflict, "companion %s: its credentials can't be revoked: the template no longer has the hook it was switched on with", companion)
		} else {
			err = statusErr(http.StatusConflict, "companion %s holds no app-side credentials (identity mode %s)", companion, c.Identity.Mode)
		}
		h.auditAI(actor, "ai.credential.revoke", target, "", err)
		return err
	}
	unlock, ok := h.aiTryLock(instance, aiRevokeLockWait)
	if !ok {
		err := statusErr(http.StatusServiceUnavailable, "companion %s: the instance is busy; try again", companion)
		h.auditAI(actor, "ai.credential.revoke", target, "", err)
		return err
	}
	defer unlock()
	oauth := mode == templates.IdentityAppOAuth
	if user == "" {
		err := h.revokeAllWith(ctx, t, companion, hook)
		h.auditAI(actor, "ai.credential.revoke", target, "revoke_all", err)
		if err != nil {
			h.revokeFailed(instance, companion, err)
			return err
		}
		if s.Pruned {
			h.setPrunedProblem(target, "")
			h.clearPruned(instance, companion)
		}
		h.revokeDone(t, companion)
		return nil
	}
	if oauth {
		ref := instance + "/" + companion
		f, err := h.oauthSeenRead()
		if err == nil && !slices.Contains(f.Companions[ref], user) {
			err = &StatusError{Status: http.StatusConflict, Err: fmt.Errorf("%s has no recorded %s account", user, appNameOf(t))}
		} else if err == nil && !f.verified(ref, user) {
			err = &StatusError{Status: http.StatusConflict, Err: fmt.Errorf("%s's %s account can't be matched (no Keycloak id or LLDAP uuid recorded): revoke everyone instead", user, appNameOf(t))}
		}
		var se *StatusError
		if errors.As(err, &se) {
			h.auditAI(actor, "ai.credential.revoke", target, "ids []", err)
			return err
		}
		if err == nil {
			for _, sub := range f.Subs[ref][user] {
				if err = h.runRevokeOAuthSub(ctx, t, hook, user, sub); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = h.oauthSeenMarkRevoked(ref, map[string][]string{user: f.Subs[ref][user]})
		}
		h.auditAI(actor, "ai.credential.revoke", target, "ids []", err)
		if err != nil {
			h.revokeFailed(instance, companion, err)
			return &StatusError{Status: http.StatusBadGateway, Err: err}
		}
		h.revokeDone(t, companion)
		return nil
	}
	var entry *aigate.Credential
	for _, e := range h.creds().Entries() {
		if e.Instance == instance && e.Companion == companion && e.User == user {
			entry = &e
		}
	}
	if entry == nil {
		h.auditAI(actor, "ai.credential.revoke", target, "nothing to revoke", nil)
		return nil
	}
	if err := h.revokeTokenEntry(ctx, t, hook, *entry, actor); err != nil {
		h.revokeFailed(instance, companion, err)
		return &StatusError{Status: http.StatusBadGateway, Err: err}
	}
	h.revokeDone(t, companion)
	return nil
}

// ── 1. certificate-only (12b carry) ───────────────────────

// aiOffForCertOnly switches AI support off on every instance whose
// sign-in template is certificate-only while a companion is on (a restore
// or a template update landed it there; settings saves and sign-in
// changes do it themselves), audited ai.disable "sign-in needs a client
// certificate". A busy instance is retried next pass.
func (h *Hub) aiOffForCertOnly(ctx context.Context) {
	h.mu.RLock()
	off := map[string][]string{}
	for i := range h.instances {
		t := &h.instances[i]
		if h.instanceBusyLocked(t.ID) || !t.HasAIMCP() || !h.certOnlyLocked(t) {
			continue
		}
		var on []string
		for _, name := range h.enabledCompanionsLocked(t.ID) {
			if companionOf(t, name) != nil {
				on = append(on, name)
			}
		}
		if len(on) > 0 {
			off[t.ID] = on
		}
	}
	h.mu.RUnlock()
	for _, id := range slices.Sorted(maps.Keys(off)) {
		if err := h.switchAIOff(ctx, id, off[id], aiHubActor, aiCertOffDetail); err != nil {
			log.Printf("ai: %s: switching AI support off (its sign-in needs a client certificate) failed (retried at the next reconcile): %v", id, err)
		}
	}
}

// ── 2. template updates (G33) ─────────────────────────────

// pruneAI is run after the final Discover of a source sync and at Init
// (G33): a switched-on companion that disappeared from its template, or
// whose identity mode changed, is switched off (audited ai.disable,
// "template changed") and marked Pruned (the revoke_all it owes, with
// the hook it was switched on with); its entries are marked revoking; a
// mode-changed one owes its on_change (enabled false). The owed
// revoke_all runs in the AI reconcile (kicked here); an enabled instance
// is re-rendered: restartNow queues the restart, else (Init) it is only
// recorded as owed (requeueOwed starts it) and the gate file waits for
// Init's first policy write. A companion off with nothing
// owed whose template dropped it loses its state entry.
func (h *Hub) pruneAI(restartNow bool) {
	type pruned struct{ id, name string }
	entries := h.creds().Entries()
	seen, _ := h.oauthSeen()
	hasEntries := func(id, name string) bool {
		return slices.ContainsFunc(entries, func(e aigate.Credential) bool { return e.Instance == id && e.Companion == name })
	}
	var marks []pruned
	var audits []func()
	var restart []string
	var scopes []aiChange
	h.mu.Lock()
	prev := maps.Clone(h.st.AIInstances)
	changed := false
	for _, id := range slices.Sorted(maps.Keys(h.st.AIInstances)) {
		t := h.findLocked(id)
		if t == nil {
			// No view (template missing): nothing of it is rendered or
			// listed; judged when the template is back.
			continue
		}
		a := h.st.AIInstances[id]
		next := maps.Clone(a.Companions)
		dirty, rendered := false, false
		for _, name := range slices.Sorted(maps.Keys(a.Companions)) {
			s := a.Companions[name]
			c := companionOf(t, name)
			gone := c == nil
			modeChanged := c != nil && s.IdentityMode != "" && s.IdentityMode != c.Identity.Mode
			if (!gone && !modeChanged) || s.Pruned {
				continue
			}
			owes := s.RevokePending || hasEntries(id, name) || len(seen[id+"/"+name]) > 0
			if !s.Enabled && !owes {
				if gone {
					delete(next, name)
					dirty = true
				}
				continue
			}
			wasOn := s.Enabled
			s.Enabled = false
			// The owed revoke_all is the old hook's (RevokeHook), never the
			// new definition's.
			s.RevokePending = false
			s.Pruned = s.RevokeHook != "" || owes
			if modeChanged && t.Manifest.AI.OnChange != "" && wasOn {
				s.OnChangePending = true
			}
			next[name] = s
			dirty = true
			marks = append(marks, pruned{id, name})
			if wasOn {
				target := id + "/" + name
				audits = append(audits, func() { h.auditOp(aiHubActor, "ai.disable", target, "template changed", nil) })
				if t.Enabled {
					rendered = true
				}
				if s.IdentityMode != templates.IdentityAppOAuth {
					scopes = append(scopes, aiChange{c: &templates.Companion{Name: name, Identity: templates.Identity{Mode: s.IdentityMode}},
						after: s, scope: aigate.CompanionScope(id, name)})
				}
			}
			log.Printf("ai: %s/%s switched off: the template no longer declares it as it was switched on (template changed)", id, name)
		}
		if dirty {
			a.Companions = next
			h.st.AIInstances[id] = a
			changed = true
			if rendered {
				restart = append(restart, id)
			}
		}
	}
	if changed {
		if err := h.saveStateLocked(); err != nil {
			h.st.AIInstances = prev
			h.mu.Unlock()
			log.Printf("ai: switching off companions a template update dropped failed (state not saved; retried at the next sync or start): %v", err)
			return
		}
	}
	h.mu.Unlock()
	if !changed {
		return
	}
	for _, p := range marks {
		for _, e := range entries {
			if e.Instance == p.id && e.Companion == p.name && e.State == aigate.StateActive {
				if err := h.creds().MarkRevoking(e.Instance, e.Companion, e.User); err != nil {
					log.Printf("ai: %s/%s: marking %s's credential revoking failed: %v", p.id, p.name, e.User, err)
				}
			}
		}
	}
	for _, a := range audits {
		a()
	}
	if restartNow {
		// At Init the first policy write follows (with the header seed).
		h.writePolicyLogged()
	}
	if len(scopes) > 0 {
		h.goBackground(func() {
			if err := h.applyAIScopes(context.Background(), scopes); err != nil {
				log.Printf("ai: the scopes of companions a template update switched off: %v", err)
			}
		})
	}
	if len(restart) > 0 {
		h.oweMasterRestarts(restart)
		if restartNow {
			h.restartForMaster(restart)
		}
	}
	h.TriggerAIReconcile()
}

// revokePruned runs the revoke_all every Pruned companion owes, with the
// hook it was switched on with (still declared by the template): success
// removes its entries, its oauth-seen record and the flag (and the state
// entry of a companion the template dropped); a failure or a missing
// hook leaves everything revoking (AIRevokeProblems).
func (h *Hub) revokePruned(ctx context.Context) {
	type owed struct {
		id, name string
		s        state.AICompanion
	}
	var todo []owed
	h.mu.RLock()
	for id, a := range h.st.AIInstances {
		if h.instanceBusyLocked(id) {
			continue
		}
		for name, s := range a.Companions {
			if s.Pruned {
				todo = append(todo, owed{id, name, s})
			}
		}
	}
	h.mu.RUnlock()
	sort.Slice(todo, func(i, j int) bool { return todo[i].id+"/"+todo[i].name < todo[j].id+"/"+todo[j].name })
	for _, o := range todo {
		t := h.Template(o.id)
		if t == nil {
			continue
		}
		target := o.id + "/" + o.name
		key := "pruned:" + target
		hook := ""
		if o.s.RevokeHook != "" && aiHookExists(t, o.s.RevokeHook) {
			hook = o.s.RevokeHook
		}
		if hook == "" && o.s.RevokeHook == "" && !h.hasCredsOf(o.id, o.name) {
			// A revoke_all was owed but no hook was ever recorded for it:
			// nothing can run it. Never silently done (fix round 1): logged
			// and audited as an error, then cleared (oauth-seen leftovers
			// stay listed in AIRevokeProblems).
			err := errors.New("owed revoke_all dropped: no hook recorded")
			log.Printf("ai: %s: %v", target, err)
			h.auditAI(aiHubActor, "ai.credential.revoke", target, "owed revoke_all dropped: no hook recorded", err)
			h.setPrunedProblem(target, "")
			h.clearPruned(o.id, o.name)
			continue
		}
		if hook == "" {
			err := errNoRevokeHook(o.name)
			h.setPrunedProblem(target, err.Error())
			h.revokeAudit(aiHubActor, key, target, "revoke_all (template changed)", err)
			continue
		}
		unlock, ok := h.aiTryLock(o.id, aiRevokeLockWait)
		if !ok {
			h.setPrunedProblem(target, "the instance's AI lock stayed busy; retried at the next reconcile")
			continue
		}
		err := h.revokeAllWith(ctx, t, o.name, hook)
		if err == nil {
			// The template dropped (or changed) the companion: its record goes.
			err = h.oauthSeenDrop(target)
		}
		unlock()
		h.revokeAudit(aiHubActor, key, target, "revoke_all (template changed)", err)
		if err != nil {
			h.setPrunedProblem(target, err.Error())
			if companionOf(t, o.name) != nil {
				h.revokeFailed(o.id, o.name, err)
			}
			continue
		}
		h.setPrunedProblem(target, "")
		h.revokeDone(t, o.name)
		h.clearPruned(o.id, o.name)
	}
}

func (h *Hub) hasCredsOf(id, name string) bool {
	return slices.ContainsFunc(h.creds().Entries(), func(e aigate.Credential) bool { return e.Instance == id && e.Companion == name })
}

// clearPruned clears a companion's Pruned flag (and drops the state entry
// of one its template no longer declares, if it owes nothing else).
func (h *Hub) clearPruned(id, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.st.AIInstances[id]
	if !ok {
		return
	}
	s, ok := a.Companions[name]
	if !ok || !s.Pruned {
		return
	}
	before := a
	a.Companions = maps.Clone(a.Companions)
	s.Pruned = false
	if t := h.findLocked(id); t != nil && companionOf(t, name) == nil {
		delete(a.Companions, name)
	} else {
		a.Companions[name] = s
	}
	h.st.AIInstances[id] = a
	if err := h.saveStateLocked(); err != nil {
		h.st.AIInstances[id] = before
		log.Printf("ai: %s/%s: clearing the owed revoke_all failed (it runs again): %v", id, name, err)
	}
}

func (h *Hub) setPrunedProblem(target, msg string) {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	if msg == "" {
		delete(h.aiPrunedErrs, target)
		return
	}
	if h.aiPrunedErrs == nil {
		h.aiPrunedErrs = map[string]string{}
	}
	h.aiPrunedErrs[target] = clipRunes(msg, unitErrorMax)
}

// revokeAllWith runs revoke_all with hook for companion name of t: its
// entries marked revoking first, removed after success (an app_oauth
// companion's oauth-seen record is kept). Caller holds the AI lock.
func (h *Hub) revokeAllWith(ctx context.Context, t *templates.Template, name, hook string) error {
	return h.revokeAllRun(ctx, t, name, hook, false)
}

// revokeAllRun is revokeAllWith; afterUp: the hook runs right after a
// compose up recreated or started the app (runAIHookAfterUp).
func (h *Hub) revokeAllRun(ctx context.Context, t *templates.Template, name, hook string, afterUp bool) error {
	var mine []aigate.Credential
	for _, e := range h.creds().Entries() {
		if e.Instance == t.ID && e.Companion == name {
			mine = append(mine, e)
		}
	}
	for _, e := range mine {
		if err := h.creds().MarkRevoking(e.Instance, e.Companion, e.User); err != nil {
			return statusErr(http.StatusInternalServerError, "companion %s: marking its credentials revoking: %v", name, err)
		}
	}
	stdin, _ := json.Marshal(aiRevokeAllIn{Action: "revoke_all", Prefix: templates.AIClientPrefix})
	run := h.runAIHook
	if afterUp {
		run = h.runAIHookAfterUp
	}
	out, u := run(ctx, t, hook, stdin)
	clear(out)
	if !u.OK {
		return &StatusError{Status: http.StatusBadGateway, Err: fmt.Errorf("companion %s: revoke_all failed: %s", name, u.Error)}
	}
	for _, e := range mine {
		if err := h.removeCred(e.Instance, e.Companion, e.User); err != nil {
			return statusErr(http.StatusInternalServerError, "companion %s: removing its revoked credentials: %v", name, err)
		}
	}
	// app_oauth: oauth-seen.json is kept (T27): revoke_all ends only AI
	// clients' tokens, so a recorded person who leaves later still gets
	// their own revoke (revokePruned drops a pruned companion's record).
	return nil
}

// AIRevokeProblem is a companion whose app-side credentials are owed a
// revocation that hasn't succeeded (the doctor's ai_credentials_revoking,
// Task 20).
type AIRevokeProblem struct {
	Instance  string `json:"instance"`
	Companion string `json:"companion"`
	// Revoking: entries kept revoking (the gate never uses them).
	Revoking int `json:"revoking"`
	// Pruned: switched off by a template update, its revoke_all owed.
	Pruned bool `json:"pruned"`
	// Recorded: app_oauth people recorded in oauth-seen.json who are owed
	// a revoke the template no longer has the hook for (fix round 1).
	Recorded int `json:"recorded"`
	// NoHook: the template no longer has the hook to revoke them.
	NoHook bool `json:"no_hook"`
	// Unmatched: app_oauth people who left before their app account could
	// be matched: the revoke_all ended only AI clients' tokens; listed
	// until an administrator dismisses them (AIRevokeDismiss; T27).
	Unmatched []string `json:"unmatched,omitempty"`
	// Unverifiable: app_oauth people recorded without an LLDAP uuid, or
	// whose Keycloak id lookup failed 3 passes running.
	Unverifiable []string `json:"unverifiable,omitempty"`
	Reason       string   `json:"reason"`
}

// AIRevokeProblems lists every companion with revoking entries or an owed
// template-update revoke_all, sorted (Task 20 reads it).
func (h *Hub) AIRevokeProblems() []AIRevokeProblem {
	entries, credsErr := h.creds().EntriesErr()
	aiStoreMu.Lock()
	seenFile, seenErr := h.oauthSeenFileLocked()
	aiStoreMu.Unlock()
	seen := seenFile.Companions
	// Unverifiable: no uuid (for good), or a uuid whose id lookups failed
	// three passes running.
	unverifiable := map[string][]string{}
	h.aiErrMu.Lock()
	for ref, users := range seenFile.Companions {
		for _, u := range users {
			if seenFile.UUIDs[ref][u] == "" || (len(seenFile.Subs[ref][u]) == 0 && h.aiPendingPasses[ref][u] >= 3) {
				unverifiable[ref] = append(unverifiable[ref], u)
			}
		}
	}
	seenWriteErr := h.aiSeenWriteError
	unwritten := maps.Clone(h.aiSeenUnwritten)
	h.aiErrMu.Unlock()
	byKey := map[string]*AIRevokeProblem{}
	get := func(id, name string) *AIRevokeProblem {
		k := id + "/" + name
		if p := byKey[k]; p != nil {
			return p
		}
		p := &AIRevokeProblem{Instance: id, Companion: name}
		byKey[k] = p
		return p
	}
	for _, e := range entries {
		if e.State == aigate.StateRevoking {
			get(e.Instance, e.Companion).Revoking++
		}
	}
	h.mu.RLock()
	for id, a := range h.st.AIInstances {
		for name, s := range a.Companions {
			if s.Pruned {
				get(id, name).Pruned = true
			}
		}
	}
	// app_oauth records nothing can revoke any more: the template dropped
	// the companion (or its app_oauth mode) and the hook it had.
	for ref, users := range seen {
		id, name, _ := strings.Cut(ref, "/")
		t := h.findLocked(id)
		if t == nil || len(users) == 0 {
			continue
		}
		s := h.st.AIInstances[id].Companions[name]
		if c := companionOf(t, name); c != nil && c.Identity.Mode == templates.IdentityAppOAuth && !s.Pruned {
			continue // still its companion: reconcileOAuthSeen handles it
		}
		if revokeHookOf(t, name, s) == "" {
			get(id, name).Recorded = len(users)
		}
	}
	notes := map[string][]string{}
	note := func(ref, text string) {
		id, name, _ := strings.Cut(ref, "/")
		if h.findLocked(id) != nil {
			get(id, name)
			notes[ref] = append(notes[ref], text)
		}
	}
	for ref, users := range seenFile.Unmatched {
		id, name, _ := strings.Cut(ref, "/")
		if h.findLocked(id) != nil {
			get(id, name).Unmatched = slices.Clone(users)
			for _, u := range users {
				note(ref, unmatchedText(u, id, appNameOf(h.findLocked(id))))
			}
		}
	}
	h.aiErrMu.Lock()
	for ref, users := range h.aiOwedRevokeAll {
		id, _, _ := strings.Cut(ref, "/")
		note(ref, fmt.Sprintf("revoke_all owed for %s (they left %s before their %s account could be matched); it failed and is retried at every reconcile: %s", strings.Join(users, ", "), id, appNameOf(h.findLocked(id)), h.aiErrs[ref]))
	}
	h.aiErrMu.Unlock()
	for ref, users := range unwritten {
		note(ref, fmt.Sprintf("recording %s failed (%s): %s will be recorded unverifiable once a write succeeds", oauthSeenName, seenWriteErr, strings.Join(users, ", ")))
	}
	for ref, users := range unverifiable {
		id, name, _ := strings.Cut(ref, "/")
		if h.findLocked(id) != nil {
			get(id, name).Unverifiable = sortedSet(users)
			note(ref, fmt.Sprintf("%d recorded people can't be verified (no LLDAP uuid recorded, or their Keycloak id lookup keeps failing): if one leaves, everyone's AI grants for %s end (revoke_all) and they must be handled in %s", len(users), id, appNameOf(h.findLocked(id))))
		}
	}
	// No way to look Keycloak ids up while an app_oauth companion is on:
	// every person stays pending and any leaver costs a revoke_all.
	if _, ok := h.aiKC.(AIUserIDs); !ok {
		for i := range h.instances {
			t := &h.instances[i]
			for _, name := range h.enabledCompanionsLocked(t.ID) {
				if c := companionOf(t, name); c != nil && c.Identity.Mode == templates.IdentityAppOAuth {
					get(t.ID, name).Reason = errNoUserIDs.Error()
				}
			}
		}
	}
	for _, p := range byKey {
		var s state.AICompanion
		if a, ok := h.st.AIInstances[p.Instance]; ok {
			s = a.Companions[p.Companion]
		}
		if t := h.findLocked(p.Instance); t != nil {
			p.NoHook = revokeHookOf(t, p.Companion, s) == "" && !(p.Pruned && s.RevokeHook != "" && aiHookExists(t, s.RevokeHook))
		}
	}
	h.mu.RUnlock()
	if seenErr != nil {
		get("", oauthSeenName).Reason = seenErr.Error()
	}
	if credsErr != nil {
		// Owed app-side revocations can't be judged (final review M3).
		get("", aigate.CredsFileName).Reason = credsErr.Error() + ": owed revocations are on hold until it is fixed or removed"
	}
	h.aiErrMu.Lock()
	for k, p := range byKey {
		if p.Reason != "" {
			continue
		}
		if n := notes[k]; len(n) > 0 {
			p.Reason = strings.Join(n, "\n")
			continue
		}
		if msg := h.aiPrunedErrs[k]; msg != "" {
			p.Reason = msg
		} else if msg := h.aiErrs[k]; msg != "" {
			p.Reason = msg
		} else if p.NoHook {
			p.Reason = errNoRevokeHook(p.Companion).Error()
		} else {
			p.Reason = "revocation pending (retried at every reconcile)"
		}
	}
	h.aiErrMu.Unlock()
	out := make([]AIRevokeProblem, 0, len(byKey))
	for _, k := range slices.Sorted(maps.Keys(byKey)) {
		out = append(out, *byKey[k])
	}
	return out
}

// ── 3. app_token leavers and revoking retries ─────────────

// reconcileTokenCredentials: per instance, the leavers' active entries
// and every revoking entry are revoked under the instance's AI lock, the
// leavers judged again from a fresh directory snapshot after the lock is
// held (a mint may have waited for it).
func (h *Hub) reconcileTokenCredentials(ctx context.Context, m *directory.Membership) {
	work := h.tokenWork(h.creds().Entries(), m)
	for _, id := range slices.Sorted(maps.Keys(work)) {
		t := h.Template(id)
		if t == nil {
			continue
		}
		unlock, ok := h.aiTryLock(id, aiRevokeLockWait)
		if !ok {
			log.Printf("ai: %s: revocations left for the next reconcile: the AI lock stayed busy", id)
			continue
		}
		var fresh *directory.Membership
		if m != nil {
			mctx, cancel := context.WithTimeout(ctx, directoryStateTimeout)
			fm, err := h.membership(mctx)
			cancel()
			if err == nil {
				fresh = fm
			}
		}
		again := h.tokenWork(h.creds().Entries(), fresh)[id]
		for _, w := range again {
			if err := h.revokeTokenEntry(ctx, t, w.hook, w.e, aiHubActor); err != nil {
				if companionOf(t, w.e.Companion) != nil {
					h.revokeFailed(id, w.e.Companion, err)
				}
				continue
			}
			h.revokeDone(t, w.e.Companion)
		}
		unlock()
	}
}

// markLeavers marks the active app_token entries of people m no longer
// lets hold them revoking (the gate stops using them at its next reload)
// and kicks the reconcile loop, which runs the revoke hooks. It runs in
// every policy write, right after the gate file (fix round 1 ruling):
// never a hook, never a wait — an instance whose AI lock is held (a mint
// or a lifecycle operation) is left to the loop, which judges again under
// the lock.
func (h *Hub) markLeavers(m *directory.Membership) {
	work := h.tokenWork(h.creds().Entries(), m)
	if len(work) == 0 {
		return
	}
	for _, id := range slices.Sorted(maps.Keys(work)) {
		unlock, ok := h.aiTryLock(id, 0)
		if !ok {
			continue
		}
		// Judged again under the lock: a mint may have just finished.
		for _, w := range h.tokenWork(h.creds().Entries(), m)[id] {
			if w.e.State != aigate.StateActive {
				continue
			}
			if err := h.creds().MarkRevoking(w.e.Instance, w.e.Companion, w.e.User); err != nil {
				log.Printf("ai: %s/%s/%s: marking the leaver's credential revoking failed (the reconcile retries): %v", w.e.Instance, w.e.Companion, w.e.User, err)
			}
		}
		unlock()
	}
	h.TriggerAIReconcile()
}

type tokenWork struct {
	e    aigate.Credential
	hook string
}

// tokenWork: per instance, the entries to revoke now — every revoking
// one, and every active one whose person can't hold it any more (m nil:
// none judged). Instances being deleted or restored, Pruned companions
// (revokePruned) and instances without a view are left alone.
func (h *Hub) tokenWork(entries []aigate.Credential, m *directory.Membership) map[string][]tokenWork {
	now := time.Now()
	out := map[string][]tokenWork{}
	// The account each entry was minted for (N1): read before mu; an
	// unreadable record leaves every entry unverifiable.
	rec, recErr := h.credUUIDs()
	h.mu.RLock()
	defer h.mu.RUnlock()
	type key struct{ id, name string }
	holders := map[key]map[string]bool{}
	known := map[key]bool{}
	for _, e := range entries {
		k := key{e.Instance, e.Companion}
		t := h.findLocked(e.Instance)
		if t == nil || h.instanceBusyLocked(e.Instance) {
			continue
		}
		s := h.st.AIInstances[e.Instance].Companions[e.Companion]
		if s.Pruned {
			continue
		}
		hook := revokeHookOf(t, e.Companion, s)
		if e.State == aigate.StateRevoking {
			out[e.Instance] = append(out[e.Instance], tokenWork{e, hook})
			continue
		}
		if _, done := known[k]; !done {
			if c := companionOf(t, e.Companion); c != nil && c.Identity.Mode == templates.IdentityAppToken {
				holders[k], known[k] = h.aiHoldersLocked(t, c, s, m, now)
			} else {
				// The template no longer has it as an app_token companion
				// (pruneAI switches it off): nobody may hold one.
				holders[k], known[k] = map[string]bool{}, h.st.AI.Enabled
			}
		}
		if known[k] && !holders[k][e.User] {
			out[e.Instance] = append(out[e.Instance], tokenWork{e, hook})
			continue
		}
		// A holder by name whose LLDAP account isn't the one the entry was
		// minted for (deleted and re-created, or never recorded): the
		// former person's credential, a leaver's. A current account LLDAP
		// gives no uuid for proves nothing either way.
		if known[k] && m != nil {
			if cur := m.UUIDs[e.User]; cur != "" && (recErr != nil || !credMintedFor(rec, e, cur)) {
				out[e.Instance] = append(out[e.Instance], tokenWork{e, hook})
			}
		}
	}
	return out
}

// ── small JSON stores under <data>/ai ─────────────────────

// aiStoreMu serialises the reconcile's own files (oauth-seen.json,
// orphans.json, connections-seen.json).
var aiStoreMu sync.Mutex

// readAIStore decodes <data>/ai/<name> strictly into v (missing = left as
// it is). A file that doesn't decode is an error and is never replaced:
// it may hold owed revocations.
func (h *Hub) readAIStore(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(h.cfg.DataDir, "ai", name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s doesn't decode (%v): fix or remove it", name, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: trailing data: fix or remove it", name)
	}
	return nil
}

// writeAIStore writes v as <data>/ai/<name> (0600, atomic; the directory
// 0700, ensurePrivateDir).
func (h *Hub) writeAIStore(name string, v any) error {
	dir := filepath.Join(h.cfg.DataDir, "ai")
	if err := ensurePrivateDir(dir); err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, name), append(b, '\n'), 0o600)
}

// oauthSeenFile is <data>/ai/oauth-seen.json: per app_oauth companion
// ("<instance>/<companion>") everyone who was a holder of its instance's
// population while the companion was on (who may hold app-side tokens),
// sorted, with the LLDAP uuid they had when first recorded (UUIDs, absent
// when LLDAP gave none) and every Keycloak user id seen for them while
// they held (Subs: the app_oauth revoke's "sub", contract §15.5; only ids
// of Keycloak copies whose LDAP_ID is that uuid; a list because a
// person's Keycloak id changes whenever Keycloak removes and re-imports
// their copy, and changed once when core switched the link to entryUUID;
// a re-created name is a new person with a new uuid). A record is
// verified when it has a uuid and at least one id, else unverifiable
// (T27): a uuid is never filled in later; ids are added only while the
// live account's uuid equals the stored one. Unmatched: people who left before their
// account could be matched, listed until an administrator dismisses them
// (AIRevokeDismiss). Revoked: leavers whose targeted revoke succeeded,
// with their ids, kept so a same-instance restore (which brings their
// tokens back) replays it (Replay: owed after the restore's revoke_all).
// Copied: a restore into a new id's people from the source instance's
// record, judged at the next pass (outside the population = unmatched).
// Everything is on disk.
type oauthSeenFile struct {
	Version    int                            `json:"version"`
	Companions map[string][]string            `json:"companions"`
	UUIDs      map[string]map[string]string   `json:"uuids,omitempty"`
	Subs       map[string]map[string][]string `json:"subs,omitempty"`
	Unmatched  map[string][]string            `json:"unmatched,omitempty"`
	Revoked    map[string]map[string][]string `json:"revoked,omitempty"`
	Replay     map[string]bool                `json:"replay,omitempty"`
	Copied     map[string][]string            `json:"copied,omitempty"`
}

const oauthSeenName = "oauth-seen.json"

func (f oauthSeenFile) verified(ref, user string) bool {
	return f.UUIDs[ref][user] != "" && len(f.Subs[ref][user]) > 0
}

func (h *Hub) oauthSeen() (map[string][]string, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f, err := h.oauthSeenFileLocked()
	return f.Companions, err
}

func (h *Hub) oauthSeenRead() (oauthSeenFile, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	return h.oauthSeenFileLocked()
}

func (h *Hub) oauthSeenFileLocked() (oauthSeenFile, error) {
	f := oauthSeenFile{Version: 1}
	if err := h.readAIStore(oauthSeenName, &f); err != nil {
		return oauthSeenFile{}, err
	}
	if f.Companions == nil {
		f.Companions = map[string][]string{}
	}
	if f.UUIDs == nil {
		f.UUIDs = map[string]map[string]string{}
	}
	if f.Subs == nil {
		f.Subs = map[string]map[string][]string{}
	}
	if f.Unmatched == nil {
		f.Unmatched = map[string][]string{}
	}
	if f.Revoked == nil {
		f.Revoked = map[string]map[string][]string{}
	}
	if f.Replay == nil {
		f.Replay = map[string]bool{}
	}
	if f.Copied == nil {
		f.Copied = map[string][]string{}
	}
	return f, nil
}

// oauthSeenUpdate applies fn to the record and writes it when fn reports
// a change. The uuids and ids of people no longer recorded go with them.
func (h *Hub) oauthSeenUpdate(fn func(map[string][]string) bool) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool { return fn(f.Companions) })
}

func (h *Hub) oauthSeenUpdateFile(fn func(*oauthSeenFile) bool) error {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f, err := h.oauthSeenFileLocked()
	if err != nil {
		return err
	}
	if !fn(&f) {
		return nil
	}
	for _, lists := range []map[string][]string{f.Companions, f.Unmatched, f.Copied} {
		for k, v := range lists {
			if len(v) == 0 {
				delete(lists, k)
			} else {
				lists[k] = sortedSet(v)
			}
		}
	}
	for ref, vals := range f.UUIDs {
		for u, v := range vals {
			if v == "" || !slices.Contains(f.Companions[ref], u) {
				delete(vals, u)
			}
		}
		if len(vals) == 0 {
			delete(f.UUIDs, ref)
		}
	}
	for ref, vals := range f.Subs {
		for u, v := range vals {
			if len(v) == 0 || !slices.Contains(f.Companions[ref], u) {
				delete(vals, u)
			} else {
				vals[u] = sortedSet(v)
			}
		}
		if len(vals) == 0 {
			delete(f.Subs, ref)
		}
	}
	for ref, vals := range f.Revoked {
		for u, v := range vals {
			vals[u] = sortedSet(v)
		}
		if len(vals) == 0 {
			delete(f.Revoked, ref)
		}
	}
	for ref, on := range f.Replay {
		if !on {
			delete(f.Replay, ref)
		}
	}
	out := oauthSeenFile{Version: 1, Companions: f.Companions}
	if len(f.Revoked) > 0 {
		out.Revoked = f.Revoked
	}
	if len(f.Replay) > 0 {
		out.Replay = f.Replay
	}
	if len(f.Copied) > 0 {
		out.Copied = f.Copied
	}
	if len(f.UUIDs) > 0 {
		out.UUIDs = f.UUIDs
	}
	if len(f.Subs) > 0 {
		out.Subs = f.Subs
	}
	if len(f.Unmatched) > 0 {
		out.Unmatched = f.Unmatched
	}
	return h.writeAIStore(oauthSeenName, out)
}

// oauthSeenAdd records people of ref (user → LLDAP uuid; "" when LLDAP
// gave none, or when they must be unverifiable: never filled in later)
// and adds the Keycloak ids found (user → id) to recorded people whose
// stored uuid is non-empty.
func (h *Hub) oauthSeenAdd(ref string, add, subs map[string]string) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		changed := false
		for u, uuid := range add {
			if slices.Contains(f.Companions[ref], u) {
				continue
			}
			f.Companions[ref] = append(f.Companions[ref], u)
			if uuid != "" {
				if f.UUIDs[ref] == nil {
					f.UUIDs[ref] = map[string]string{}
				}
				f.UUIDs[ref][u] = uuid
			}
			changed = true
		}
		for u, sub := range subs {
			if sub == "" || !slices.Contains(f.Companions[ref], u) || f.UUIDs[ref][u] == "" || slices.Contains(f.Subs[ref][u], sub) {
				continue
			}
			if f.Subs[ref] == nil {
				f.Subs[ref] = map[string][]string{}
			}
			f.Subs[ref][u] = append(f.Subs[ref][u], sub)
			changed = true
		}
		return changed
	})
}

// oauthSeenEntry is one person's record (rebuild input).
type oauthSeenEntry struct {
	uuid string
	subs []string
}

// oauthSeenRebuild replaces ref's record with keep, marks revoked
// (user → ids) revoked and adds unmatched to ref's Unmatched list, in one
// update: the record after a revoke_all. People recorded since the pass
// read the file (start: its record then) are kept as they are.
func (h *Hub) oauthSeenRebuild(ref string, start []string, keep map[string]oauthSeenEntry, revoked map[string][]string, unmatched []string) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		for _, u := range f.Companions[ref] {
			if _, ok := keep[u]; !ok && !slices.Contains(start, u) && revoked[u] == nil {
				keep[u] = oauthSeenEntry{uuid: f.UUIDs[ref][u], subs: f.Subs[ref][u]}
			}
		}
		markRevoked(f, ref, revoked)
		f.Companions[ref] = slices.Sorted(maps.Keys(keep))
		delete(f.UUIDs, ref)
		delete(f.Subs, ref)
		for u, e := range keep {
			if e.uuid == "" {
				continue
			}
			if f.UUIDs[ref] == nil {
				f.UUIDs[ref] = map[string]string{}
			}
			f.UUIDs[ref][u] = e.uuid
			if len(e.subs) > 0 {
				if f.Subs[ref] == nil {
					f.Subs[ref] = map[string][]string{}
				}
				f.Subs[ref][u] = slices.Clone(e.subs)
			}
		}
		f.Unmatched[ref] = append(f.Unmatched[ref], unmatched...)
		return true
	})
}

// markRevoked moves people (user → ids) from ref's record to its revoked
// marks (ids merged).
func markRevoked(f *oauthSeenFile, ref string, revoked map[string][]string) {
	for u, subs := range revoked {
		f.Companions[ref] = slices.DeleteFunc(f.Companions[ref], func(x string) bool { return x == u })
		if f.Revoked[ref] == nil {
			f.Revoked[ref] = map[string][]string{}
		}
		f.Revoked[ref][u] = append(f.Revoked[ref][u], subs...)
	}
}

// oauthSeenMarkRevoked records that people (user → ids) were revoked.
func (h *Hub) oauthSeenMarkRevoked(ref string, revoked map[string][]string) error {
	if len(revoked) == 0 {
		return nil
	}
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		markRevoked(f, ref, revoked)
		return true
	})
}

// oauthSeenSetReplay marks ref's revoked people owed their revoke again
// (after a restore's revoke_all).
func (h *Hub) oauthSeenSetReplay(ref string) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		if len(f.Revoked[ref]) == 0 || f.Replay[ref] {
			return false
		}
		f.Replay[ref] = true
		return true
	})
}

// oauthCopyForRestoreAs records, for each app_oauth companion of t (the
// new instance newID), the people the source instance's record knows
// (holders, revoked and unmatched) as copied: the archive's app data
// holds their accounts. A warning names how many.
func (h *Hub) oauthCopyForRestoreAs(t *templates.Template, src, newID string) string {
	n := 0
	err := h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		changed := false
		for i := range t.Manifest.AI.MCP {
			c := &t.Manifest.AI.MCP[i]
			if c.Identity.Mode != templates.IdentityAppOAuth {
				continue
			}
			from, to := src+"/"+c.Name, newID+"/"+c.Name
			people := slices.Clone(f.Companions[from])
			people = append(people, slices.Collect(maps.Keys(f.Revoked[from]))...)
			people = append(people, f.Unmatched[from]...)
			if len(people) == 0 {
				continue
			}
			f.Copied[to] = sortedSet(append(f.Copied[to], people...))
			n += len(sortedSet(people))
			changed = true
		}
		return changed
	})
	if err != nil {
		return fmt.Sprintf("AI: recording the people of %s's app data for %s failed (%v): anyone outside %s's population keeps their app-side tokens in the copy and isn't listed", src, newID, err, newID)
	}
	if n > 0 {
		return fmt.Sprintf("AI: the copy holds the app accounts of %d people %s knew; those outside %s's population are listed as unmatched until an administrator deals with them in the app", n, src, newID)
	}
	return ""
}

func (h *Hub) oauthSeenRemoveUsers(ref string, users []string) error {
	return h.oauthSeenUpdate(func(seen map[string][]string) bool {
		n := len(seen[ref])
		seen[ref] = slices.DeleteFunc(seen[ref], func(u string) bool { return slices.Contains(users, u) })
		return len(seen[ref]) != n
	})
}

// oauthSeenDrop removes ref's whole record, revoked marks, replay and
// copied people (its Unmatched list stays).
func (h *Hub) oauthSeenDrop(ref string) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		delete(f.Companions, ref)
		delete(f.Revoked, ref)
		delete(f.Replay, ref)
		delete(f.Copied, ref)
		return true
	})
}

// AIUserIDs looks a person's Keycloak user id and LDAP link (LDAP_ID:
// the LLDAP uuid of the account the copy belongs to) up by exact
// username (keycloak.Client.ImportUserLink). The AIKeycloak wired with
// SetAIKeycloak provides it when it implements it (main's does); else
// every app_oauth record stays unverifiable and AIRevokeProblems lists it.
type AIUserIDs interface {
	ImportUserLink(ctx context.Context, username string) (id, ldapID string, err error)
}

// errNoUserIDs: no Keycloak lookup is wired (AIRevokeProblems, log).
var errNoUserIDs = errors.New("Keycloak is not configured: app_oauth people's Keycloak ids can't be recorded, so every leaver ends everyone's AI grants for the app (revoke_all) and can't be matched")

// lookupSub is user's Keycloak user id, now: only ever called for a
// current holder whose live LLDAP uuid is the one recorded (or being
// recorded), never to revoke. The Keycloak copy must be linked to that
// account (its LDAP_ID is uuid, the recorded LLDAP uuid): a copy of
// another account under the name (re-created between the directory read
// and the lookup) or without a link gives an error, so no id is stored.
func (h *Hub) lookupSub(ctx context.Context, user, uuid string) (string, error) {
	kc, _ := h.aiKeycloak().(AIUserIDs)
	if kc == nil {
		log.Printf("ai: ERROR: %v", errNoUserIDs)
		return "", errNoUserIDs
	}
	if uuid == "" {
		return "", errors.New("no LLDAP uuid recorded")
	}
	sub, ldapID, err := kc.ImportUserLink(ctx, user)
	if err != nil {
		return "", err
	}
	if !keycloak.ValidUserID(sub) {
		return "", errors.New("Keycloak answered an invalid user id")
	}
	if !strings.EqualFold(ldapID, uuid) {
		return "", fmt.Errorf("Keycloak's copy of %s is linked to LLDAP account %s, not the recorded %s", user, clipQuoted(ldapID), uuid)
	}
	return sub, nil
}

// unmatchedText is the AIRevokeProblems line for a person who left before
// their account in app (the template's name) could be matched.
func unmatchedText(user, instance, app string) string {
	return fmt.Sprintf("%s left %s before their %s account could be matched: their other sessions and tokens in it remain; deactivate or delete %s in %s, then dismiss", user, instance, app, user, app)
}

// appNameOf is the app's name for guidance text (never a template id
// in Hub code, §15: the name is the template's); nil = "the app".
func appNameOf(t *templates.Template) string {
	if t == nil || t.Manifest.Name == "" {
		return "the app"
	}
	return t.Manifest.Name
}

// AIRevokeDismiss clears user from the unmatched leavers of instance's
// companion ("" = every companion of it) once an administrator has dealt
// with their remaining app-side tokens (POST /api/instances/{id}/ai/dismiss,
// the MCP's dismiss_ai_revoke_problem; the AI tab and the doctor). Audited
// ai.credential.revoke detail "dismissed"; 404 when not listed.
func (h *Hub) AIRevokeDismiss(instance, companion, user string, actor directory.Actor) error {
	target := instance + "/" + companion + "/" + user
	if companion == "" {
		target = instance + "/" + user
	}
	if !aigate.ValidUsername(user) {
		err := statusErr(http.StatusBadRequest, "user: not a username")
		h.auditAI(actor, "ai.credential.revoke", target, "dismissed", err)
		return err
	}
	if h.Template(instance) == nil {
		return ErrNotFound
	}
	found := false
	err := h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		for ref, users := range f.Unmatched {
			id, name, _ := strings.Cut(ref, "/")
			if id != instance || (companion != "" && name != companion) {
				continue
			}
			n := len(users)
			f.Unmatched[ref] = slices.DeleteFunc(users, func(u string) bool { return u == user })
			found = found || len(f.Unmatched[ref]) != n
		}
		return found
	})
	if err == nil && !found {
		err = &StatusError{Status: http.StatusNotFound, Err: fmt.Errorf("%s is not listed as unmatched on %s", user, instance)}
	}
	h.auditAI(actor, "ai.credential.revoke", target, "dismissed: an administrator handled the remaining app-side tokens", err)
	return err
}

// orphansFile is <data>/ai/orphans.json: credentials a mint hook created
// that the Hub couldn't store (ids only, never a credential), revoked by
// the reconcile.
type orphansFile struct {
	Version int          `json:"version"`
	Orphans []aiOrphanID `json:"orphans"`
}

type aiOrphanID struct {
	Instance  string `json:"instance"`
	Companion string `json:"companion"`
	User      string `json:"user"`
	ID        string `json:"id"`
}

const orphansName = "orphans.json"

func (h *Hub) orphansUpdate(fn func([]aiOrphanID) ([]aiOrphanID, bool)) ([]aiOrphanID, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f := orphansFile{Version: 1, Orphans: []aiOrphanID{}}
	if err := h.readAIStore(orphansName, &f); err != nil {
		return nil, err
	}
	next, changed := fn(slices.Clone(f.Orphans))
	if !changed {
		return f.Orphans, nil
	}
	if next == nil {
		next = []aiOrphanID{}
	}
	return next, h.writeAIStore(orphansName, orphansFile{Version: 1, Orphans: next})
}

// recordOrphan keeps a just-minted id the Hub couldn't store, so the
// reconcile revokes it (a failure here is logged: nothing else holds it).
func (h *Hub) recordOrphan(o aiOrphanID) {
	if _, err := h.orphansUpdate(func(l []aiOrphanID) ([]aiOrphanID, bool) {
		if slices.Contains(l, o) {
			return l, false
		}
		return append(l, o), true
	}); err != nil {
		log.Printf("ai: %s/%s: the unstored credential %s of %s couldn't be recorded for revocation: %v — revoke it in the app", o.Instance, o.Companion, o.ID, o.User, err)
	}
}

func (h *Hub) dropOrphan(o aiOrphanID) error {
	_, err := h.orphansUpdate(func(l []aiOrphanID) ([]aiOrphanID, bool) {
		n := len(l)
		l = slices.DeleteFunc(l, func(x aiOrphanID) bool { return x == o })
		return l, len(l) != n
	})
	return err
}

// ── 4. orphans (13a carry) ────────────────────────────────

// retryOrphans revokes every recorded unstored credential.
func (h *Hub) retryOrphans(ctx context.Context) {
	list, err := h.orphansUpdate(func(l []aiOrphanID) ([]aiOrphanID, bool) { return l, false })
	if err != nil {
		log.Printf("ai: %v", err)
		return
	}
	for _, o := range list {
		t := h.Template(o.Instance)
		if t == nil {
			continue
		}
		h.mu.RLock()
		s := h.st.AIInstances[o.Instance].Companions[o.Companion]
		busy := h.instanceBusyLocked(o.Instance)
		h.mu.RUnlock()
		if busy {
			continue
		}
		target := o.Instance + "/" + o.Companion + "/" + o.User
		key := "orphan:" + target + ":" + o.ID
		hook := revokeHookOf(t, o.Companion, s)
		if hook == "" {
			h.revokeAudit(aiHubActor, key, target, "id "+o.ID+" (unstored)", errNoRevokeHook(o.Companion))
			continue
		}
		unlock, ok := h.aiTryLock(o.Instance, aiRevokeLockWait)
		if !ok {
			continue
		}
		err := h.runRevoke(ctx, t, hook, o.User, []string{o.ID})
		unlock()
		if err == nil {
			err = h.dropOrphan(o)
		}
		h.revokeAudit(aiHubActor, key, target, "id "+o.ID+" (unstored)", err)
	}
}

// ── 5. app_oauth leavers ──────────────────────────────────

// reconcileOAuthSeen keeps oauth-seen.json for each app_oauth companion
// and revokes what its leavers may hold (T27). A record is verified (LLDAP
// uuid and at least one Keycloak id) or unverifiable.
//   - The holders are the instance's population, whatever the companion,
//     policy or LoA (a policy change is no leaving); not known (nobody
//     judged, records kept) while the instance is disabled or its
//     population is empty by state (native sign-in, …). New holders are
//     recorded only while the companion is on (also by the policy pass,
//     recordOAuthHolders), with their live uuid ("" = unverifiable for
//     good). Ids are looked up every pass for current holders whose live
//     uuid is the stored one, and dropped when a fresh directory read
//     after the lookups shows another uuid.
//   - A verified leaver gets {"action":"revoke","user","sub","ids":[]}
//     for every stored id; once all succeed they are marked revoked (kept
//     for a restore's replay).
//   - An unverifiable leaver, a recorded name whose live uuid differs, or
//     a holder a failed write left unrecorded who leaves makes the
//     companion's revoke_all run (AI clients' tokens only), then the
//     record is rebuilt (this pass's holders, verified leavers whose
//     revoke failed, people recorded meanwhile) and they are listed
//     unmatched until dismissed. A failure is retried every pass.
//   - After a restore's owed revoke_all (Replay), every revoked person
//     who isn't a holder gets their targeted revoke again.
//   - A restore into a new id's copied people outside its population are
//     listed unmatched.
//
// Each companion is handled under its instance's AI lock (revoke_all and
// rebuild included), re-checked there. The membership is read here.
func (h *Hub) reconcileOAuthSeen(ctx context.Context, _ *directory.Membership) {
	file, err := h.oauthSeenRead()
	if err != nil {
		log.Printf("ai: app_oauth revocations skipped: %v", err)
		return
	}
	mctx, cancel := context.WithTimeout(ctx, directoryStateTimeout)
	m, err := h.membership(mctx)
	cancel()
	if err != nil {
		m = nil
	}
	now := time.Now()
	var passes []oauthPass
	h.mu.RLock()
	refs := map[string]bool{}
	for _, by := range []map[string][]string{file.Companions, file.Copied} {
		for ref := range by {
			refs[ref] = true
		}
	}
	for ref := range file.Revoked {
		refs[ref] = true
	}
	for i := range h.instances {
		t := &h.instances[i]
		for j := range t.Manifest.AI.MCP {
			if c := &t.Manifest.AI.MCP[j]; c.Identity.Mode == templates.IdentityAppOAuth {
				refs[t.ID+"/"+c.Name] = true
			}
		}
	}
	for ref := range refs {
		if p, ok := h.oauthPassLocked(ref, m, now); ok {
			passes = append(passes, p)
		}
	}
	h.mu.RUnlock()
	sort.Slice(passes, func(i, j int) bool { return passes[i].ref < passes[j].ref })
	for _, p := range passes {
		h.reconcileOAuthRef(ctx, p)
	}
}

// oauthPassLocked: ref's holders this pass (false: not judged). Caller
// holds mu.
func (h *Hub) oauthPassLocked(ref string, m *directory.Membership, now time.Time) (oauthPass, bool) {
	id, name, _ := strings.Cut(ref, "/")
	t := h.findLocked(id)
	if t == nil || h.instanceBusyLocked(id) {
		return oauthPass{}, false
	}
	s := h.st.AIInstances[id].Companions[name]
	if s.Pruned {
		return oauthPass{}, false // revokePruned's revoke_all
	}
	p := oauthPass{ref: ref, name: name, hook: revokeHookOf(t, name, s), holders: map[string]string{}}
	c := companionOf(t, name)
	if c != nil && c.Identity.Mode == templates.IdentityAppOAuth {
		hold, known := h.aiOAuthHoldersLocked(t, s, m, now)
		if !known {
			return oauthPass{}, false
		}
		for u := range hold {
			p.holders[u] = m.UUIDs[u]
		}
		p.recordNew = s.Enabled && slices.Contains(c.Modes, s.Mode)
	}
	return p, true
}

// aiOAuthHoldersLocked: an app_oauth companion's holders are its
// instance's population, whatever the companion switch, the policy or its
// LoA (none of which is leaving). Not known (false): the master switch is
// off, a revoke_all is owed, the instance is disabled, its population is
// empty by state (populationWhyLocked: native sign-in, …), or there is no
// directory snapshot.
func (h *Hub) aiOAuthHoldersLocked(t *templates.Template, s state.AICompanion, m *directory.Membership, now time.Time) (map[string]bool, bool) {
	if !h.st.AI.Enabled || s.RevokePending || s.Pruned || !t.Enabled || h.populationWhyLocked(t) != "" || m == nil {
		return nil, false
	}
	pop := h.populationLocked(t, m)
	users := make([]string, 0, len(pop.People))
	for _, p := range pop.People {
		users = append(users, p.User)
	}
	group := accessGroupOf(t)
	out := map[string]bool{}
	for _, u := range validUsers(users) {
		if at, ok := m.Pending[u][group]; group != "" && ok && !now.Before(at) {
			continue
		}
		out[u] = true
	}
	return out, true
}

// oauthPass is one app_oauth companion's holders this pass (user → live
// LLDAP uuid, "" = none); recordNew: the companion is on (new holders are
// recorded).
type oauthPass struct {
	ref, name, hook string
	holders         map[string]string
	recordNew       bool
}

func (h *Hub) reconcileOAuthRef(ctx context.Context, p oauthPass) {
	id, _, _ := strings.Cut(p.ref, "/")
	unlock, ok := h.aiTryLock(id, aiRevokeLockWait)
	if !ok {
		return // retried at the next pass
	}
	defer unlock()
	// Re-checked under the AI lock: the instance is still there and idle.
	h.mu.RLock()
	gone := h.findLocked(id) == nil || h.instanceBusyLocked(id)
	h.mu.RUnlock()
	t := h.Template(id)
	if gone || t == nil {
		return
	}
	f, err := h.oauthSeenRead()
	if err != nil {
		return
	}
	recorded := f.Companions[p.ref]
	h.aiErrMu.Lock()
	unwritten := slices.Clone(h.aiSeenUnwritten[p.ref])
	h.aiErrMu.Unlock()
	var owe, leaving []string // unverifiable leavers or replaced names; verified leavers
	for _, u := range recorded {
		stored := f.UUIDs[p.ref][u]
		live, holds := p.holders[u]
		switch {
		case holds && stored != "" && live != "" && stored != live, !holds && !f.verified(p.ref, u):
			owe = append(owe, u)
		case !holds:
			leaving = append(leaving, u)
		}
	}
	for _, u := range unwritten {
		if _, holds := p.holders[u]; !holds && !slices.Contains(recorded, u) {
			owe = append(owe, u) // left before a write could record them
		}
	}
	// A restore into a new id's copied people: outside the population =
	// unmatched; the others are holders like anyone.
	var copiedOut []string
	for _, u := range f.Copied[p.ref] {
		if _, holds := p.holders[u]; !holds {
			copiedOut = append(copiedOut, u)
		}
	}
	if len(f.Copied[p.ref]) > 0 {
		if err := h.oauthSeenUpdateFile(func(g *oauthSeenFile) bool {
			delete(g.Copied, p.ref)
			g.Unmatched[p.ref] = append(g.Unmatched[p.ref], copiedOut...)
			return true
		}); err != nil {
			h.seenWriteFailed(p.ref, nil, err)
		}
		for _, u := range copiedOut {
			target := p.ref + "/" + u
			h.revokeAudit(aiHubActor, "oauth:"+target, target, "unmatched: "+u+"'s app account came with a restore from another instance and they aren't in this one's population; their tokens in the copy remain", nil)
		}
	}
	// 1. Every verified leaver gets their own revoke.
	revoked := map[string][]string{}
	failed := map[string]bool{}
	for _, u := range sortedSet(leaving) {
		if h.revokeVerified(ctx, t, p, u, f.Subs[p.ref][u], "ids []") {
			revoked[u] = f.Subs[p.ref][u]
		} else {
			failed[u] = true
		}
	}
	// 2. A restore's replay: revoked people who aren't holders again.
	if f.Replay[p.ref] {
		done := true
		for _, u := range slices.Sorted(maps.Keys(f.Revoked[p.ref])) {
			if _, holds := p.holders[u]; holds {
				continue
			}
			if !h.revokeVerified(ctx, t, p, u, f.Revoked[p.ref][u], "ids [] (again after a restore)") {
				done = false
			}
		}
		if done {
			if err := h.oauthSeenUpdateFile(func(g *oauthSeenFile) bool { delete(g.Replay, p.ref); return true }); err != nil {
				h.seenWriteFailed(p.ref, nil, err)
			}
		}
	}
	// 3. Keycloak ids of current holders whose live account is the
	// recorded one (or who are being recorded now with a uuid).
	add := map[string]string{}
	want := map[string]string{} // holder → the uuid their record has or gets
	for u, live := range p.holders {
		inRec := slices.Contains(recorded, u)
		switch {
		case slices.Contains(unwritten, u) && !inRec:
			add[u] = "" // unverifiable: unrecorded while the write failed
		case !inRec && p.recordNew:
			add[u] = live
			if live != "" {
				want[u] = live
			}
		case inRec && live != "" && f.UUIDs[p.ref][u] == live:
			want[u] = f.UUIDs[p.ref][u]
		}
	}
	subs := h.lookupHolders(ctx, p.ref, want)
	if len(owe) > 0 {
		h.revokeAllForUnverifiable(ctx, t, p, f, sortedSet(owe), failed, revoked, subs, unwritten)
		return
	}
	if len(revoked) > 0 {
		if err := h.oauthSeenMarkRevoked(p.ref, revoked); err != nil {
			h.seenWriteFailed(p.ref, nil, err)
		}
	}
	if len(add) > 0 || len(subs) > 0 {
		if err := h.oauthSeenAdd(p.ref, add, subs); err != nil {
			h.seenWriteFailed(p.ref, slices.Collect(maps.Keys(add)), err)
			return
		}
	}
	h.seenWriteDone(p.ref, slices.Collect(maps.Keys(add)))
}

// revokeVerified runs the targeted revoke for every id of user (audited
// with detail); true once all succeeded. Caller holds the AI lock.
func (h *Hub) revokeVerified(ctx context.Context, t *templates.Template, p oauthPass, user string, subs []string, detail string) bool {
	target := p.ref + "/" + user
	key := "oauth:" + target
	if p.hook == "" {
		h.revokeAudit(aiHubActor, key, target, detail, errNoRevokeHook(p.name))
		return false
	}
	var err error
	for _, sub := range subs {
		if err = h.runRevokeOAuthSub(ctx, t, p.hook, user, sub); err != nil {
			break
		}
	}
	h.revokeAudit(aiHubActor, key, target, detail, err)
	if err != nil {
		if companionOf(t, p.name) != nil {
			h.revokeFailed(t.ID, p.name, err)
		}
		return false
	}
	h.revokeDone(t, p.name)
	return true
}

// lookupHolders looks the Keycloak ids of want's people (current
// holders → the LLDAP uuid their record has or gets) up; the Keycloak
// copy must be linked to that uuid (lookupSub). A failure counts a
// pending pass (AIRevokeProblems after 3). The directory is read before
// and again afterwards: ids of people whose live LLDAP uuid isn't
// want's (or all, if it can't be read) are dropped.
func (h *Hub) lookupHolders(ctx context.Context, ref string, want map[string]string) map[string]string {
	out := map[string]string{}
	if len(want) == 0 {
		return out
	}
	users := slices.Sorted(maps.Keys(want))
	mctx, cancel := context.WithTimeout(ctx, directoryStateTimeout)
	before, err := h.membership(mctx)
	cancel()
	if err != nil {
		return out
	}
	h.aiErrMu.Lock()
	if h.aiPendingPasses == nil {
		h.aiPendingPasses = map[string]map[string]int{}
	}
	if h.aiPendingPasses[ref] == nil {
		h.aiPendingPasses[ref] = map[string]int{}
	}
	h.aiErrMu.Unlock()
	for _, u := range users {
		sub, err := h.lookupSub(ctx, u, want[u])
		h.aiErrMu.Lock()
		if err != nil {
			h.aiPendingPasses[ref][u]++
		} else {
			delete(h.aiPendingPasses[ref], u)
			out[u] = sub
		}
		h.aiErrMu.Unlock()
		if err != nil {
			log.Printf("ai: %s: looking up the Keycloak id of %s failed (retried at the next reconcile): %v", ref, u, err)
		}
	}
	mctx, cancel = context.WithTimeout(ctx, directoryStateTimeout)
	after, err := h.membership(mctx)
	cancel()
	if err != nil {
		return map[string]string{}
	}
	for u := range out {
		if b, a := before.UUIDs[u], after.UUIDs[u]; b == "" || a != b || b != want[u] {
			delete(out, u)
		}
	}
	return out
}

// seenWriteFailed keeps users (holders a failed write left unrecorded;
// recorded unverifiable by the next successful write) and the error for
// AIRevokeProblems.
func (h *Hub) seenWriteFailed(ref string, users []string, err error) {
	log.Printf("ai: ERROR: writing %s for %s failed: %v", oauthSeenName, ref, err)
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	if h.aiSeenUnwritten == nil {
		h.aiSeenUnwritten = map[string][]string{}
	}
	h.aiSeenUnwritten[ref] = sortedSet(append(h.aiSeenUnwritten[ref], users...))
	h.aiSeenWriteError = err.Error()
}

// seenWriteDone forgets the users a successful write recorded (written)
// from ref's unwritten holders.
func (h *Hub) seenWriteDone(ref string, written []string) {
	h.aiErrMu.Lock()
	defer h.aiErrMu.Unlock()
	if left := slices.DeleteFunc(h.aiSeenUnwritten[ref], func(u string) bool { return slices.Contains(written, u) }); len(left) > 0 {
		h.aiSeenUnwritten[ref] = left
	} else {
		delete(h.aiSeenUnwritten, ref)
	}
	if len(h.aiSeenUnwritten) == 0 {
		h.aiSeenWriteError = ""
	}
}

// revokeAllForUnverifiable runs p's revoke_all because owe (unverifiable
// leavers, re-used names) can't be matched. It ends AI clients' tokens
// only: each is then listed unmatched until an administrator dismisses
// them. On success the record is rebuilt in one update from this pass's
// holders (fresh: live uuid + the ids just found, earlier ids kept while
// the uuid matches), holders a failed write left unrecorded
// (unverifiable), the verified leavers whose own revoke failed, and people
// recorded since the pass read the file; revoked verified leavers are
// marked revoked. Audited per person; a failure is retried every pass.
// Caller holds the AI lock.
func (h *Hub) revokeAllForUnverifiable(ctx context.Context, t *templates.Template, p oauthPass, f oauthSeenFile, owe []string, failed map[string]bool, revoked map[string][]string, subs map[string]string, unwritten []string) {
	var err error
	if p.hook == "" {
		err = errNoRevokeHook(p.name)
	} else {
		err = h.revokeAllWith(ctx, t, p.name, p.hook)
	}
	if err == nil {
		// The rebuilt record is a fresh recording: ids for every holder
		// with a live uuid (found ones kept).
		more := map[string]string{} // rebuilt with their live uuid
		for u, live := range p.holders {
			if live != "" && subs[u] == "" && (p.recordNew || slices.Contains(f.Companions[p.ref], u)) {
				more[u] = live
			}
		}
		maps.Copy(subs, h.lookupHolders(ctx, p.ref, more))
		keep := map[string]oauthSeenEntry{}
		for u, live := range p.holders {
			if slices.Contains(unwritten, u) && !slices.Contains(f.Companions[p.ref], u) {
				keep[u] = oauthSeenEntry{} // unverifiable for good
				continue
			}
			if !p.recordNew && !slices.Contains(f.Companions[p.ref], u) {
				continue
			}
			e := oauthSeenEntry{uuid: live}
			if live != "" && f.UUIDs[p.ref][u] == live {
				e.subs = slices.Clone(f.Subs[p.ref][u])
			}
			if live != "" && subs[u] != "" && !slices.Contains(e.subs, subs[u]) {
				e.subs = append(e.subs, subs[u])
			}
			keep[u] = e
		}
		for u := range failed {
			keep[u] = oauthSeenEntry{uuid: f.UUIDs[p.ref][u], subs: f.Subs[p.ref][u]}
		}
		if err = h.oauthSeenRebuild(p.ref, f.Companions[p.ref], keep, revoked, owe); err != nil {
			h.seenWriteFailed(p.ref, nil, err)
		} else {
			h.seenWriteDone(p.ref, append(slices.Collect(maps.Keys(keep)), owe...))
		}
	} else if len(revoked) > 0 {
		if merr := h.oauthSeenMarkRevoked(p.ref, revoked); merr != nil {
			h.seenWriteFailed(p.ref, nil, merr)
		}
	}
	for _, u := range owe {
		target := p.ref + "/" + u
		h.revokeAudit(aiHubActor, "oauth:"+target, target,
			"revoke_all (AI clients' tokens only): "+u+" left before their "+appNameOf(t)+" account could be matched; their other sessions and tokens in it remain", err)
	}
	h.aiErrMu.Lock()
	if h.aiOwedRevokeAll == nil {
		h.aiOwedRevokeAll = map[string][]string{}
	}
	if err != nil {
		h.aiOwedRevokeAll[p.ref] = owe
	} else {
		delete(h.aiOwedRevokeAll, p.ref)
	}
	h.aiErrMu.Unlock()
	if err != nil {
		if companionOf(t, p.name) != nil {
			h.revokeFailed(t.ID, p.name, err)
		}
		return
	}
	h.revokeDone(t, p.name)
}

// recordOAuthHolders is the policy pass's part (T27): every holder of a
// switched-on app_oauth companion in m is recorded at once, with their
// LLDAP uuid and no Keycloak id yet (the reconcile backfills), so nobody
// in a published population can leave unrecorded. No Keycloak call; each
// companion under its instance's AI lock (busy: the next reconcile
// records them).
func (h *Hub) recordOAuthHolders(m *directory.Membership) {
	if m == nil {
		return
	}
	now := time.Now()
	var passes []oauthPass
	h.mu.RLock()
	for i := range h.instances {
		t := &h.instances[i]
		for j := range t.Manifest.AI.MCP {
			if c := &t.Manifest.AI.MCP[j]; c.Identity.Mode == templates.IdentityAppOAuth {
				if p, ok := h.oauthPassLocked(t.ID+"/"+c.Name, m, now); ok && p.recordNew {
					passes = append(passes, p)
				}
			}
		}
	}
	h.mu.RUnlock()
	for _, p := range passes {
		id, _, _ := strings.Cut(p.ref, "/")
		unlock, ok := h.aiTryLock(id, 0)
		if !ok {
			h.TriggerAIReconcile()
			continue
		}
		f, err := h.oauthSeenRead()
		if err == nil {
			add := map[string]string{}
			for u, live := range p.holders {
				if !slices.Contains(f.Companions[p.ref], u) {
					add[u] = live
				}
			}
			if len(add) > 0 {
				if err := h.oauthSeenAdd(p.ref, add, nil); err != nil {
					h.seenWriteFailed(p.ref, slices.Collect(maps.Keys(add)), err)
				}
			}
		}
		unlock()
	}
}

// ── 6. connections of people with no AI resource (§8) ─────

// connSeenFile is <data>/ai/connections-seen.json: the people who could
// use an AI resource at the last pass (so a person who no longer can —
// deleted, or in no population — gets their AI connections removed once).
type connSeenFile struct {
	Version int      `json:"version"`
	People  []string `json:"people"`
}

const connSeenName = "connections-seen.json"

// aiEligibleLocked: the people who can use some AI resource now — a
// switched-on companion's population (any identity mode), everyone while
// the people MCP is on, lldap_admin members while the admin MCP is on.
// Caller holds mu; m non-nil, master on.
func (h *Hub) aiEligibleLocked(m *directory.Membership) map[string]bool {
	out := map[string]bool{}
	if h.st.AI.PortcullisPeople {
		for _, u := range validUsers(slices.Collect(maps.Keys(m.Users))) {
			out[u] = true
		}
	}
	if h.st.AI.PortcullisAdmin {
		for _, u := range groupMembers(m, lldap.AdminGroup) {
			out[u] = true
		}
	}
	now := time.Now()
	for i := range h.instances {
		t := &h.instances[i]
		for name, s := range h.st.AIInstances[t.ID].Companions {
			c := companionOf(t, name)
			if c == nil {
				continue
			}
			s.RevokePending = false // a revoke_all owed doesn't take the person's resource away
			if hold, known := h.aiHoldersLocked(t, c, s, m, now); known {
				for u := range hold {
					out[u] = true
				}
			}
		}
	}
	return out
}

// aiClientIDs are the Hub's AI client ids: its three and every ai_client
// of an ai.chat instance (Task 23's), sorted.
func (h *Hub) aiClientIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.aiClientIDsLocked()
}

func (h *Hub) aiClientIDsLocked() []string {
	var out []string
	for _, c := range hubAIClients(h.st.AI) {
		out = append(out, c.id)
	}
	for i := range h.instances {
		t := &h.instances[i]
		// An instance view's client ids are already the instance's.
		if c := instanceAIClient(t); c != nil {
			out = append(out, c.ClientID)
		}
	}
	return sortedSet(out)
}

// reconcileConnections removes the AI connections (consents and offline
// sessions, every AI client) of each person recorded as able to use an AI
// resource who no longer can; success drops them from the record.
func (h *Hub) reconcileConnections(ctx context.Context, m *directory.Membership) {
	kc := h.aiConnector()
	if m == nil || kc == nil {
		return
	}
	h.mu.RLock()
	if !h.st.AI.Enabled {
		// Master off: connections are kept (§15.11).
		h.mu.RUnlock()
		return
	}
	eligible := h.aiEligibleLocked(m)
	// An instance being deleted or restored: the people of its population
	// aren't judged mid-operation (fix round 1: only them).
	for i := range h.instances {
		t := &h.instances[i]
		if !h.instanceBusyLocked(t.ID) || len(h.st.AIInstances[t.ID].Companions) == 0 {
			continue
		}
		for _, p := range h.populationLocked(t, m).People {
			eligible[p.User] = true
		}
	}
	clients := h.aiClientIDsLocked()
	h.mu.RUnlock()
	aiStoreMu.Lock()
	f := connSeenFile{Version: 1, People: []string{}}
	err := h.readAIStore(connSeenName, &f)
	aiStoreMu.Unlock()
	if err != nil {
		log.Printf("ai: connection cleanup skipped: %v", err)
		return
	}
	var gone []string
	for _, u := range f.People {
		if !eligible[u] {
			gone = append(gone, u)
		}
	}
	keep := map[string]bool{}
	for u := range eligible {
		keep[u] = true
	}
	for _, u := range gone {
		var errs []error
		for _, cl := range clients {
			if err := revokeConnection(ctx, kc, u, cl); err != nil {
				errs = append(errs, err)
			}
		}
		err := errors.Join(errs...)
		key := "conn:" + u
		h.aiErrMu.Lock()
		if h.aiRevokeErrs == nil {
			h.aiRevokeErrs = map[string]string{}
		}
		repeat := err != nil && h.aiRevokeErrs[key] == err.Error()
		if err != nil {
			h.aiRevokeErrs[key] = err.Error()
		} else {
			delete(h.aiRevokeErrs, key)
		}
		h.aiErrMu.Unlock()
		if err != nil {
			keep[u] = true
			if !repeat {
				log.Printf("ai: removing %s's AI connections failed (retried at every reconcile): %v", u, err)
				h.auditAI(aiHubActor, "ai.connection.revoke", u, "no AI resource left", err)
			}
			continue
		}
		h.auditAI(aiHubActor, "ai.connection.revoke", u, "no AI resource left", nil)
	}
	next := sortedSet(slices.Collect(maps.Keys(keep)))
	if slices.Equal(next, sortedSet(f.People)) {
		return
	}
	aiStoreMu.Lock()
	err = h.writeAIStore(connSeenName, connSeenFile{Version: 1, People: next})
	aiStoreMu.Unlock()
	if err != nil {
		log.Printf("ai: %s: %v", connSeenName, err)
	}
}

// ── restore (§15.4, ruling: RevokePending) ────────────────

// oweAIRevokeLocked marks every switched-on companion of a restored
// instance that has a revoke hook RevokePending: its app data was just
// replaced (and may hold old portcullis-ai-* tokens), so it is neither
// rendered nor listed in mcp-gate.json until the revoke_all its next
// start runs (pendingAIAfterStart, under the restore's AI lock) has
// succeeded. Caller holds mu and saves.
func (h *Hub) oweAIRevokeLocked(id string) {
	t := h.findLocked(id)
	a, ok := h.st.AIInstances[id]
	if t == nil || !ok {
		return
	}
	next := maps.Clone(a.Companions)
	for name, s := range a.Companions {
		c := companionOf(t, name)
		if !s.Enabled || c == nil || c.Identity.Revoke == "" {
			continue
		}
		s.RevokePending = true
		next[name] = s
	}
	a.Companions = next
	h.st.AIInstances[id] = a
}

// oweAIRestoredOffLocked: a same-instance restore brought the app's data
// back, so the people revoked since the backup hold working tokens again
// whatever the companion's switch. Every app_oauth companion of the
// template is returned (its replay is marked by markOAuthReplay, outside
// mu: reconcileOAuthRef replays regardless of the switch), and one the
// archive had on but that was restored off owes a revoke_all
// (RevokePending; runPendingAI runs it for an off companion too). Caller
// holds mu and saves.
func (h *Hub) oweAIRestoredOffLocked(id string, archived *aiArchive) []string {
	t := h.findLocked(id)
	if t == nil {
		return nil
	}
	a := h.st.AIInstances[id]
	var refs []string
	next := maps.Clone(a.Companions)
	changed := false
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		if c.Identity.Mode != templates.IdentityAppOAuth {
			continue
		}
		refs = append(refs, id+"/"+c.Name)
		s, ok := a.Companions[c.Name]
		// An archive whose AI state can't be read (or has none) may have
		// had it on: owed too (fail closed).
		hadOn := archived == nil || archived.Companions[c.Name].Enabled
		if c.Identity.Revoke == "" || !hadOn || (ok && (s.Enabled || s.Pruned)) {
			continue
		}
		if s.Mode == "" {
			s.Mode = defaultMode(c)
		}
		s.RevokePending = true
		if next == nil {
			next = map[string]state.AICompanion{}
		}
		next[c.Name] = s
		changed = true
	}
	if changed {
		a.Companions = next
		if h.st.AIInstances == nil {
			h.st.AIInstances = map[string]state.AIInstance{}
		}
		h.st.AIInstances[id] = a
	}
	return refs
}

// markOAuthReplay marks each app_oauth companion's revoked leavers owed
// again (a restore) and kicks the reconcile.
func (h *Hub) markOAuthReplay(refs []string) {
	for _, ref := range refs {
		if err := h.oauthSeenSetReplay(ref); err != nil {
			log.Printf("ai: %s: marking the revoked leavers owed again after a restore failed: %v", ref, err)
		}
	}
	if len(refs) > 0 {
		h.TriggerAIReconcile()
	}
}

// ForgetDeletedPerson is the AI part of a person's deletion through the
// Hub (the directory's UserDeleted, after the LLDAP delete): a person
// recorded in connections-seen.json has every AI client's consent and
// offline sessions removed (none are left when Keycloak's copy went with
// the account), then is dropped from the record (task 32 concern 2: with
// the master switch off the reconcile keeps the record, so a deleted
// person stayed listed). A failure keeps them recorded — the reconcile
// retries while AI is on — and is returned as a warning. Their credential
// entries are revoked by the reconcile (a leaver), which drops their
// records (removeCred). Never holds mu or aiStoreMu across a Keycloak call.
func (h *Hub) ForgetDeletedPerson(ctx context.Context, actor directory.Actor, user string) []string {
	user = strings.ToLower(user)
	aiStoreMu.Lock()
	f := connSeenFile{Version: 1, People: []string{}}
	err := h.readAIStore(connSeenName, &f)
	aiStoreMu.Unlock()
	if err != nil {
		log.Printf("ai: %s: %v", connSeenName, err)
		return []string{fmt.Sprintf("checking %s's AI connections: %s: %v", user, connSeenName, err)}
	}
	if !slices.Contains(f.People, user) {
		return nil
	}
	kc := h.aiConnector()
	if kc == nil {
		return []string{fmt.Sprintf("%s's AI connections were not checked (Keycloak's AI calls are not configured): they stay recorded", user)}
	}
	var errs []error
	for _, cl := range h.aiClientIDs() {
		if err := revokeConnection(ctx, kc, user, cl); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		h.auditAI(actor, "ai.connection.revoke", user, "person deleted", err)
		return []string{fmt.Sprintf("removing %s's AI connections failed (retried by the AI reconcile while AI is on): %v", user, err)}
	}
	h.auditAI(actor, "ai.connection.revoke", user, "person deleted", nil)
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f = connSeenFile{Version: 1, People: []string{}}
	if err := h.readAIStore(connSeenName, &f); err != nil {
		return []string{fmt.Sprintf("dropping %s from %s: %v", user, connSeenName, err)}
	}
	next := slices.DeleteFunc(slices.Clone(f.People), func(u string) bool { return u == user })
	if len(next) == len(f.People) {
		return nil
	}
	if err := h.writeAIStore(connSeenName, connSeenFile{Version: 1, People: next}); err != nil {
		return []string{fmt.Sprintf("dropping %s from %s: %v", user, connSeenName, err)}
	}
	return nil
}

// PersonDeleted is the directory's UserDeleted: the person's entered
// values (PurgePersonValues), then their AI records (ForgetDeletedPerson).
func (h *Hub) PersonDeleted(ctx context.Context, actor directory.Actor, user string) []string {
	return append(append(h.PurgePersonValues(ctx, actor, user), h.ForgetDeletedPerson(ctx, actor, user)...), h.forgetPassword(user)...)
}
