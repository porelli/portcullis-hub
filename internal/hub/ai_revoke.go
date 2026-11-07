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
	"github.com/portcullis/hub/internal/policy"
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
//  1. an instance whose effective policy now reaches LoA 3 (a restore, a
//     template update) gets AI support switched off (ai.disable, "policy
//     needs mTLS");
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
	h.aiOffForLoA3(ctx)
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
// disabled, a companion that is off, a policy at LoA 3 or a population
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
	if loa := policy.LoA(h.effectivePolicyLocked(t)); loa < 0 || loa > 2 {
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

// runRevokeOAuth runs an app_oauth companion's hook with
// {"action":"revoke","user","sub","ids":[]} for the person recorded in
// ref (contract §15.5): sub is their stored Keycloak user id (oauthSub);
// without one it fails with errNoSub, nothing runs.
func (h *Hub) runRevokeOAuth(ctx context.Context, t *templates.Template, ref, hook, user string) error {
	sub, err := h.oauthSub(ref, user)
	if err != nil {
		return err
	}
	return h.runRevokeOAuthSub(ctx, t, hook, user, sub)
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
	if err := h.creds().Remove(e.Instance, e.Companion, e.User); err != nil {
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
		err := h.revokeAllWith(ctx, t, companion, hook, oauth)
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
		err := h.runRevokeOAuth(ctx, t, instance+"/"+companion, hook, user)
		var noSub errNoSub
		if errors.As(err, &noSub) {
			h.auditAI(actor, "ai.credential.revoke", target, "ids [] (no Keycloak id recorded)", err)
			return &StatusError{Status: http.StatusConflict, Err: err}
		}
		if err == nil {
			err = h.oauthSeenRemove(instance+"/"+companion, user)
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

// ── 1. LoA 3 (12b carry) ──────────────────────────────────

// aiOffForLoA3 switches AI support off on every instance whose effective
// policy reaches LoA 3 while a companion is on (a restore or a template
// update landed it there; policy saves do it themselves), audited
// ai.disable "policy needs mTLS". A busy instance is retried next pass.
func (h *Hub) aiOffForLoA3(ctx context.Context) {
	h.mu.RLock()
	off := map[string][]string{}
	for i := range h.instances {
		t := &h.instances[i]
		if h.instanceBusyLocked(t.ID) || !t.HasAIMCP() || policy.LoA(h.effectivePolicyLocked(t)) != 3 {
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
		if err := h.switchAIOff(ctx, id, off[id], aiHubActor, aiPolicyOffDetail); err != nil {
			log.Printf("ai: %s: switching AI support off (its policy needs mTLS) failed (retried at the next reconcile): %v", id, err)
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
		err := h.revokeAllWith(ctx, t, o.name, hook, true)
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
// entries marked revoking first, removed after success, its oauth-seen
// record dropped (oauth: the companion is app_oauth). Caller holds the AI
// lock.
func (h *Hub) revokeAllWith(ctx context.Context, t *templates.Template, name, hook string, oauth bool) error {
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
	out, u := h.runAIHook(ctx, t, hook, stdin)
	clear(out)
	if !u.OK {
		return &StatusError{Status: http.StatusBadGateway, Err: fmt.Errorf("companion %s: revoke_all failed: %s", name, u.Error)}
	}
	for _, e := range mine {
		if err := h.creds().Remove(e.Instance, e.Companion, e.User); err != nil {
			return statusErr(http.StatusInternalServerError, "companion %s: removing its revoked credentials: %v", name, err)
		}
	}
	if oauth {
		// Everyone's MCP tokens are gone: nobody recorded owes a revoke.
		if err := h.oauthSeenDrop(t.ID + "/" + name); err != nil {
			return statusErr(http.StatusInternalServerError, "companion %s: %v", name, err)
		}
		h.aiErrMu.Lock()
		delete(h.aiOAuthUnrecorded, t.ID+"/"+name)
		delete(h.aiPendingLeavers, t.ID+"/"+name)
		h.aiErrMu.Unlock()
	}
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
	// Unmatched: app_oauth people who left while their Keycloak id was
	// pending, whose revoke_all failed (retried; T27).
	Unmatched []string `json:"unmatched,omitempty"`
	Reason    string   `json:"reason"`
}

// AIRevokeProblems lists every companion with revoking entries or an owed
// template-update revoke_all, sorted (Task 20 reads it).
func (h *Hub) AIRevokeProblems() []AIRevokeProblem {
	entries := h.creds().Entries()
	seen, seenErr := h.oauthSeen()
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
	h.aiErrMu.Lock()
	for ref, users := range h.aiPendingLeavers {
		id, name, _ := strings.Cut(ref, "/")
		if h.findLocked(id) != nil {
			get(id, name).Unmatched = slices.Clone(users)
		}
	}
	h.aiErrMu.Unlock()
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
	h.aiErrMu.Lock()
	for k, p := range byKey {
		if p.Reason != "" {
			continue
		}
		if len(p.Unmatched) > 0 {
			var texts []string
			for _, u := range p.Unmatched {
				texts = append(texts, errNoSub{user: u, instance: p.Instance}.Error())
			}
			if msg := h.aiErrs[k]; msg != "" {
				texts = append(texts, "the revoke_all failed (retried at every reconcile): "+msg)
			}
			p.Reason = strings.Join(texts, "\n")
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
// ("<instance>/<companion>") the people who were in its population while
// AI was on (who may hold app-side MCP tokens), sorted; Subs keeps each
// recorded person's Keycloak user id (ref → user → id): the app_oauth
// revoke's "sub" (contract §15.5), which the app matches its accounts by,
// still known once the person is gone from LLDAP and Keycloak. A person
// is recorded at once; their id is looked up (and backfilled) only while
// they are a current holder, so the username is that live account's. No
// id yet = pending: if they leave pending, the companion's revoke_all
// runs instead (fails closed). A person is recorded only with their LLDAP
// uuid, and an id is backfilled only while the live account's uuid is the
// recorded one.
type oauthSeenFile struct {
	Version    int                          `json:"version"`
	Companions map[string][]string          `json:"companions"`
	Subs       map[string]map[string]string `json:"subs,omitempty"`
	// UUIDs: ref → user → the LLDAP account uuid they were recorded with
	// (Membership.UUIDs): a name re-used by a new account is not theirs.
	UUIDs map[string]map[string]string `json:"uuids,omitempty"`
}

const oauthSeenName = "oauth-seen.json"

func (h *Hub) oauthSeen() (map[string][]string, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f, err := h.oauthSeenFileLocked()
	return f.Companions, err
}

func (h *Hub) oauthSeenFileLocked() (oauthSeenFile, error) {
	f := oauthSeenFile{Version: 1, Companions: map[string][]string{}}
	if err := h.readAIStore(oauthSeenName, &f); err != nil {
		return oauthSeenFile{}, err
	}
	if f.Companions == nil {
		f.Companions = map[string][]string{}
	}
	if f.Subs == nil {
		f.Subs = map[string]map[string]string{}
	}
	if f.UUIDs == nil {
		f.UUIDs = map[string]map[string]string{}
	}
	return f, nil
}

// oauthSeenUpdate applies fn to the record and writes it when fn reports
// a change. The Keycloak ids of people no longer recorded go with them.
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
	seen := f.Companions
	for k, v := range seen {
		if len(v) == 0 {
			delete(seen, k)
		} else {
			seen[k] = sortedSet(v)
		}
	}
	for _, perRef := range []map[string]map[string]string{f.Subs, f.UUIDs} {
		for ref, vals := range perRef {
			for u := range vals {
				if !slices.Contains(seen[ref], u) {
					delete(vals, u)
				}
			}
			if len(vals) == 0 {
				delete(perRef, ref)
			}
		}
	}
	out := oauthSeenFile{Version: 1, Companions: seen}
	if len(f.Subs) > 0 {
		out.Subs = f.Subs
	}
	if len(f.UUIDs) > 0 {
		out.UUIDs = f.UUIDs
	}
	return h.writeAIStore(oauthSeenName, out)
}

// oauthSeenAdd records people (ref → user → LLDAP uuid, never empty)
// with their uuid, and stores the Keycloak ids found (ref → user → id)
// for recorded people that have none; a stored id or uuid is never
// replaced (a re-created account with the same name is another person).
func (h *Hub) oauthSeenAdd(add, subs map[string]map[string]string) error {
	return h.oauthSeenUpdateFile(func(f *oauthSeenFile) bool {
		changed := false
		for ref, people := range add {
			for u, uuid := range people {
				if uuid == "" || slices.Contains(f.Companions[ref], u) {
					continue
				}
				f.Companions[ref] = append(f.Companions[ref], u)
				if f.UUIDs[ref] == nil {
					f.UUIDs[ref] = map[string]string{}
				}
				f.UUIDs[ref][u] = uuid
				changed = true
			}
		}
		for ref, people := range subs {
			for u, sub := range people {
				if sub == "" || !slices.Contains(f.Companions[ref], u) || f.Subs[ref][u] != "" {
					continue
				}
				if f.Subs[ref] == nil {
					f.Subs[ref] = map[string]string{}
				}
				f.Subs[ref][u] = sub
				changed = true
			}
		}
		return changed
	})
}

// oauthSeenRemoveUsers removes users from ref's record in one update.
func (h *Hub) oauthSeenRemoveUsers(ref string, users []string) error {
	return h.oauthSeenUpdate(func(seen map[string][]string) bool {
		n := len(seen[ref])
		seen[ref] = slices.DeleteFunc(seen[ref], func(u string) bool { return slices.Contains(users, u) })
		return len(seen[ref]) != n
	})
}

func (h *Hub) oauthSeenSub(ref, user string) (string, error) {
	aiStoreMu.Lock()
	defer aiStoreMu.Unlock()
	f, err := h.oauthSeenFileLocked()
	if err != nil {
		return "", err
	}
	return f.Subs[ref][user], nil
}

func (h *Hub) oauthSeenRemove(ref, user string) error {
	return h.oauthSeenUpdate(func(seen map[string][]string) bool {
		n := len(seen[ref])
		seen[ref] = slices.DeleteFunc(seen[ref], func(u string) bool { return u == user })
		return len(seen[ref]) != n
	})
}

func (h *Hub) oauthSeenDrop(ref string) error {
	return h.oauthSeenUpdate(func(seen map[string][]string) bool {
		if _, ok := seen[ref]; !ok {
			return false
		}
		delete(seen, ref)
		return true
	})
}

// AIUserIDs looks a person's Keycloak user id up by exact username
// (keycloak.Client.ImportUser). The AIKeycloak wired with SetAIKeycloak
// provides it when it implements it (main's does); else every app_oauth
// person stays pending, a leaver costs a revoke_all, and AIRevokeProblems
// lists it.
type AIUserIDs interface {
	ImportUser(ctx context.Context, username string) (string, error)
}

// errNoUserIDs: no Keycloak lookup is wired (AIRevokeProblems, log).
var errNoUserIDs = errors.New("Keycloak is not configured: app_oauth people's Keycloak ids can't be recorded, so every leaver ends everyone's AI grants for the app (revoke_all)")

// lookupSub is user's Keycloak user id, now: only ever called for a
// current holder (in the population this pass), never to revoke.
func (h *Hub) lookupSub(ctx context.Context, user string) (string, error) {
	kc, _ := h.aiKeycloak().(AIUserIDs)
	if kc == nil {
		log.Printf("ai: ERROR: %v", errNoUserIDs)
		return "", errNoUserIDs
	}
	sub, err := kc.ImportUser(ctx, user)
	if err != nil {
		return "", err
	}
	if !keycloak.ValidUserID(sub) {
		return "", errors.New("Keycloak answered an invalid user id")
	}
	return sub, nil
}

// errNoSub: a recorded app_oauth person whose Keycloak id is still
// pending. Nothing can match their app-side tokens; a person who is no
// longer a holder is never looked up by name (the name may belong to
// someone else by now): the companion's revoke_all covers them.
type errNoSub struct{ user, instance string }

func (e errNoSub) Error() string {
	return fmt.Sprintf("%s on %s: app-side tokens can't be matched (no Keycloak id recorded); revoking everyone's (revoke_all)", e.user, e.instance)
}

// oauthSub is the "sub" of user's app_oauth revoke for ref: the Keycloak
// id stored when they were recorded. None = errNoSub; there is no lookup.
func (h *Hub) oauthSub(ref, user string) (string, error) {
	sub, err := h.oauthSeenSub(ref, user)
	if err != nil {
		return "", err
	}
	if sub == "" {
		id, _, _ := strings.Cut(ref, "/")
		return "", errNoSub{user: user, instance: id}
	}
	return sub, nil
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

// reconcileOAuthSeen records each switched-on app_oauth companion's
// holders (with their LLDAP uuid; their Keycloak id looked up, or
// backfilled later, only while the live account's uuid is the recorded
// one) and revokes everyone who may no longer hold its tokens: a recorded
// person who left the population (everyone once the companion is off or
// its template dropped it), or whose name now belongs to another account.
// A leaver with a stored id gets {"action":"revoke","user","sub","ids":[]};
// one whose id is pending, or a holder seen without a uuid who left
// before being recorded, makes the companion's revoke_all run instead.
// With the directory unreadable or the master switch off nobody new is
// judged.
func (h *Hub) reconcileOAuthSeen(ctx context.Context, m *directory.Membership) {
	aiStoreMu.Lock()
	file, err := h.oauthSeenFileLocked()
	aiStoreMu.Unlock()
	if err != nil {
		log.Printf("ai: app_oauth revocations skipped: %v", err)
		return
	}
	seen := file.Companions
	uuidOf := func(u string) string {
		if m == nil {
			return ""
		}
		return m.UUIDs[u]
	}
	h.aiErrMu.Lock()
	prevUnrec := map[string][]string{}
	for ref, us := range h.aiOAuthUnrecorded {
		prevUnrec[ref] = slices.Sorted(maps.Keys(us))
	}
	h.aiErrMu.Unlock()
	now := time.Now()
	add := map[string]map[string]string{} // ref → user → uuid
	backfill := map[string][]string{}     // current holders whose id is pending
	unrec := map[string][]string{}        // holders without a uuid this pass
	judged := map[string]bool{}
	var leavers []leaver
	h.mu.RLock()
	refs := map[string]bool{}
	for ref := range seen {
		refs[ref] = true
	}
	for ref := range prevUnrec {
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
		id, name, _ := strings.Cut(ref, "/")
		t := h.findLocked(id)
		if t == nil || h.instanceBusyLocked(id) {
			continue
		}
		s := h.st.AIInstances[id].Companions[name]
		if s.Pruned {
			continue // revokePruned's revoke_all
		}
		c := companionOf(t, name)
		var hold map[string]bool
		known := false
		if c != nil && c.Identity.Mode == templates.IdentityAppOAuth {
			hold, known = h.aiHoldersLocked(t, c, s, m, now)
		} else {
			hold, known = map[string]bool{}, true
		}
		if !known {
			continue
		}
		judged[ref] = true
		recorded := seen[ref]
		hook := revokeHookOf(t, name, s)
		for u := range hold {
			live := uuidOf(u)
			if !slices.Contains(recorded, u) {
				if live == "" {
					unrec[ref] = append(unrec[ref], u)
					continue
				}
				if add[ref] == nil {
					add[ref] = map[string]string{}
				}
				add[ref][u] = live
				backfill[ref] = append(backfill[ref], u)
				continue
			}
			if rec := file.UUIDs[ref][u]; file.Subs[ref][u] == "" && rec != "" && live == rec {
				backfill[ref] = append(backfill[ref], u)
			}
		}
		for _, u := range recorded {
			rec, live := file.UUIDs[ref][u], uuidOf(u)
			replaced := hold[u] && rec != "" && live != "" && rec != live
			if !hold[u] || replaced {
				leavers = append(leavers, leaver{ref: ref, name: name, hook: hook, user: u, sub: file.Subs[ref][u], recorded: true})
			}
		}
		for _, u := range prevUnrec[ref] {
			if !hold[u] && !slices.Contains(recorded, u) {
				leavers = append(leavers, leaver{ref: ref, name: name, hook: hook, user: u})
			}
		}
	}
	h.mu.RUnlock()
	// Holders seen without a uuid stay in memory (with the unrecorded
	// leavers still owed a revoke_all) until recorded or revoked.
	h.aiErrMu.Lock()
	if h.aiOAuthUnrecorded == nil {
		h.aiOAuthUnrecorded = map[string]map[string]bool{}
	}
	for ref := range judged {
		next := map[string]bool{}
		for _, u := range unrec[ref] {
			next[u] = true
		}
		for _, l := range leavers {
			if l.ref == ref && !l.recorded {
				next[l.user] = true
			}
		}
		if len(next) == 0 {
			delete(h.aiOAuthUnrecorded, ref)
		} else {
			h.aiOAuthUnrecorded[ref] = next
		}
	}
	h.aiErrMu.Unlock()
	// Ids are looked up only for current holders whose live account is the
	// recorded one.
	subs := map[string]map[string]string{}
	found := map[string]string{} // one lookup per person per pass
	for _, ref := range slices.Sorted(maps.Keys(backfill)) {
		for _, u := range sortedSet(backfill[ref]) {
			sub, ok := found[u]
			if !ok {
				var err error
				if sub, err = h.lookupSub(ctx, u); err != nil {
					log.Printf("ai: %s: the Keycloak id of %s is pending (looked up again at the next reconcile): %v", ref, u, err)
				}
				found[u] = sub
			}
			if sub != "" {
				if subs[ref] == nil {
					subs[ref] = map[string]string{}
				}
				subs[ref][u] = sub
			}
		}
	}
	if len(add) > 0 || len(subs) > 0 {
		if err := h.oauthSeenAdd(add, subs); err != nil {
			log.Printf("ai: recording the app_oauth populations failed: %v", err)
		}
	}
	// A companion with a leaver nobody can match (id pending, or never
	// recorded) gets one revoke_all covering all of its leavers.
	pending := map[string][]leaver{}
	for _, l := range leavers {
		if l.sub == "" {
			pending[l.ref] = nil
		}
	}
	for _, l := range leavers {
		if _, ok := pending[l.ref]; ok {
			pending[l.ref] = append(pending[l.ref], l)
		}
	}
	for _, ref := range slices.Sorted(maps.Keys(pending)) {
		h.revokeAllForPending(ctx, ref, pending[ref])
	}
	leavers = slices.DeleteFunc(leavers, func(l leaver) bool { _, ok := pending[l.ref]; return ok })
	sort.Slice(leavers, func(i, j int) bool { return leavers[i].ref+"/"+leavers[i].user < leavers[j].ref+"/"+leavers[j].user })
	for _, l := range leavers {
		id, _, _ := strings.Cut(l.ref, "/")
		t := h.Template(id)
		if t == nil {
			continue
		}
		target := l.ref + "/" + l.user
		key := "oauth:" + target
		if l.hook == "" {
			h.revokeAudit(aiHubActor, key, target, "ids []", errNoRevokeHook(l.name))
			continue
		}
		unlock, ok := h.aiTryLock(id, aiRevokeLockWait)
		if !ok {
			continue
		}
		err := h.runRevokeOAuthSub(ctx, t, l.hook, l.user, l.sub)
		unlock()
		if err == nil {
			err = h.oauthSeenRemoveUsers(l.ref, []string{l.user})
		}
		h.revokeAudit(aiHubActor, key, target, "ids []", err)
		if err != nil {
			if companionOf(t, l.name) != nil {
				h.revokeFailed(id, l.name, err)
			}
			continue
		}
		h.revokeDone(t, l.name)
	}
}

// leaver is an app_oauth person of ref owed a revoke: recorded and no
// longer a holder (or whose name now belongs to another account), or
// seen without a uuid and gone before being recorded.
type leaver struct {
	ref, name, hook, user string
	sub                   string // the stored Keycloak id; "" = can't be matched
	recorded              bool   // in oauth-seen.json (else only in aiOAuthUnrecorded)
}

// revokeAllForPending runs ref's revoke_all because some of its leavers
// (ls) can't be matched (id pending, or never recorded), keeping the
// record of everyone else: only the leavers are removed (recorded ones
// from oauth-seen.json in one update, unrecorded ones from memory).
// Audited per person with the reason; a failure is kept
// (aiPendingLeavers → AIRevokeProblems) and retried at the next reconcile
// like any failed revoke.
func (h *Hub) revokeAllForPending(ctx context.Context, ref string, ls []leaver) {
	id, name, _ := strings.Cut(ref, "/")
	var users, recorded, unmatched []string
	for _, l := range ls {
		users = append(users, l.user)
		if l.recorded {
			recorded = append(recorded, l.user)
		}
		if l.sub == "" {
			unmatched = append(unmatched, l.user)
		}
	}
	users, unmatched = sortedSet(users), sortedSet(unmatched)
	t := h.Template(id)
	if t == nil {
		return
	}
	hook := ls[0].hook
	var err error
	if hook == "" {
		err = errNoRevokeHook(name)
	} else if unlock, ok := h.aiTryLock(id, aiRevokeLockWait); !ok {
		err = errors.New("the instance's AI lock stayed busy; retried at the next reconcile")
	} else {
		err = h.revokeAllWith(ctx, t, name, hook, false)
		unlock()
	}
	if err == nil && len(recorded) > 0 {
		err = h.oauthSeenRemoveUsers(ref, recorded)
	}
	for _, u := range users {
		target := ref + "/" + u
		detail := "revoke_all: " + u + " left before their Keycloak id was recorded"
		if !slices.Contains(unmatched, u) {
			detail = "revoke_all (another leaver of this app can't be matched)"
		}
		h.revokeAudit(aiHubActor, "oauth:"+target, target, detail, err)
	}
	h.aiErrMu.Lock()
	if h.aiPendingLeavers == nil {
		h.aiPendingLeavers = map[string][]string{}
	}
	if err != nil {
		h.aiPendingLeavers[ref] = unmatched
	} else {
		delete(h.aiPendingLeavers, ref)
		for _, u := range users {
			delete(h.aiOAuthUnrecorded[ref], u)
		}
	}
	h.aiErrMu.Unlock()
	if err != nil {
		if companionOf(t, name) != nil {
			h.revokeFailed(id, name, err)
		}
		return
	}
	h.revokeDone(t, name)
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
