package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The credential service (contract §5.1, §13.16; plan 3 Task 8): a
// person creates, regenerates and revokes their own file-sharing
// password (a person_secret option); admins list and revoke, never
// create. The password exists once, in CreatedCredential.Password (the
// caller zeroes it after writing the one answer); its NT hash lives only
// in <secrets>/<instance>/<key>/<user>.nt (credstore.go), its metadata
// in state.yaml (never a hash).
//
// Every revocation is applied the same way (revokeCredentials,
// independently of the delivery engine): under mu the hash file and the
// metadata go (epoch rotated), then the audit, then per instance:
//
//  1. no running container of the hook's service: done;
//  2. else every hook whose when lists credential_change, with a freshly
//     built HookInput, under the instance's deliverLock (TryLock retried
//     for at most revokeLockWait) and an exec timeout of min(the hook's
//     timeout, revokeHookMax); every one exiting 0: done;
//  3. anything else (zero such hooks, the lock not obtained, a skip, an
//     error, a timeout, a timed-out exec still running): forceDown
//     without waiting for lockApp, op record credentials, and a
//     background Restart (if it fails the instance stays down and
//     enabled).
//
// A normal immediate credential_change delivery follows for the
// bookkeeping.

// Revocation timing (§13.16, F25, F47).
const (
	// revokeLockWaitDefault: how long a revocation tries for the
	// instance's delivery lock (Hub.revokeLockWait; tests shorten it).
	revokeLockWaitDefault = 2 * time.Second
	// revokeHookMax caps a revocation hook's exec timeout.
	revokeHookMax = 8 * time.Second
	// revokeLockPoll: how often the lock is tried.
	revokeLockPoll = 20 * time.Millisecond
	// revokeApplyMax bounds a live apply (membership, lock, hooks),
	// independent of the request's context.
	revokeApplyMax = 30 * time.Second
)

// errRevokeNotLive is the op record of a revocation that stopped the
// instance (§13.16 step 3; the cause is logged).
const errRevokeNotLive = "revocation could not be applied live; the instance was stopped"

// Credential statuses (MyCredential.Status, CredentialRow.Status).
const (
	CredStatusNone        = "none"
	CredStatusActive      = "active"
	CredStatusVoided      = "voided"
	CredStatusUnavailable = "unavailable"
	// CredStatusRevoked: admin rows only — revoked (self, admin, leave,
	// deleted); My apps shows none.
	CredStatusRevoked = "revoked"
)

// CreatedCredential is a create's or regenerate's answer: the password
// (the only place it ever appears; the caller zeroes it with
// credentials.Zero once the answer is written) and the metadata.
type CreatedCredential struct {
	Password   []byte
	Credential state.Credential
}

// CredentialRow is one person on an admin's credentials view.
type CredentialRow struct {
	User   string     `json:"user"`
	Status string     `json:"status"`
	Since  *time.Time `json:"since,omitempty"`
	Reason string     `json:"reason,omitempty"`
	// IDs: the person's person_id values by key.
	IDs map[string]int `json:"ids,omitempty"`
	// Values: their person-scope values, displayed.
	Values map[string]string `json:"values,omitempty"`
}

// CredentialsView is one person_secret option of an instance for admins:
// metadata only, never a password or a hash.
type CredentialsView struct {
	Instance   string          `json:"instance"`
	Key        string          `json:"key"`
	Label      string          `json:"label"`
	Population int             `json:"population"`
	Active     int             `json:"active"`
	Rows       []CredentialRow `json:"rows"`
	// Folders: the last hook report's per-person folders (Task 10 stores
	// the report; [] until then).
	Folders  []settings.HookFolder `json:"folders"`
	LastSync *UnitResult           `json:"last_sync,omitempty"`
}

// errNoCredential is the one answer for an instance that isn't enabled,
// a key that isn't a person_secret option and a person outside its
// population (§5.1: nothing leaks which).
var errNoCredential = &StatusError{Status: http.StatusNotFound, Err: errors.New("not found: no such app or password for this account")}

// hubSetOption: o's per-person values are computed by the Hub
// (person_secret, person_id): no admin value lives anywhere — SaveSettings
// refuses the key, the panel, the seed, the per-person resolution, the
// env and My apps' values skip it, the prune drops a stored one (F5).
func hubSetOption(o *templates.Option) bool {
	return o != nil && (o.Type == templates.TypePersonSecret || o.Type == templates.TypePersonID)
}

// personSecretOption is t's person_secret option key (nil: none).
func personSecretOption(t *templates.Template, key string) *templates.Option {
	for _, o := range personSecretOptions(t) {
		if o.Key == key {
			return o
		}
	}
	return nil
}

func credentialsUnit(key string) string { return "credentials:" + key }

// newCredentialID is a credential's id: 8 random bytes, hex (never 32
// hex characters: nothing in a hook's input looks like a hash).
func newCredentialID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// credentialDetail is the audit detail of a credential event (never a
// secret, a hash or a proof).
func credentialDetail(instance, key, user, actor, reason string) string {
	d := fmt.Sprintf("instance=%s key=%s user=%s actor=%s", instance, key, user, actor)
	if reason != "" {
		d += " reason=" + reason
	}
	return d
}

// triggerCredentialCheck asks for a non-blocking holder re-check (F30:
// a removal that raced a create is revoked at once). Task 9 sets
// credentialCheck (TriggerCredentialCheck); nil: nothing.
func (h *Hub) triggerCredentialCheck() {
	if f := h.credentialCheck; f != nil {
		f()
	}
}

// CreateCredential creates or regenerates user's (any case) password for
// instance's person_secret option key. Refusals in contract order: 404
// (errNoCredential), 409 (the username rule; the proof isn't consumed),
// 503 (LLDAP, the uuid, the secrets volume; before the proof), 403 (the
// fresh-auth proof, errFreshAuth). The whole call counts toward the
// people listener's per-caller refusal limit (F45).
func (h *Hub) CreateCredential(ctx context.Context, instance, key, user string, p freshauth.Proof) (*CreatedCredential, error) {
	user = strings.ToLower(user)
	if !h.entryLimit.reserve(user, h.entryClock()) {
		return nil, errEntryLimited
	}
	cc, err := h.createCredential(ctx, instance, key, user, p)
	h.entryLimit.release(user, h.entryClock(), isRefusal(err))
	return cc, err
}

func (h *Hub) createCredential(ctx context.Context, instance, key, user string, p freshauth.Proof) (*CreatedCredential, error) {
	target := instance + "/" + key + "/" + user
	// 1. The instance enabled, key a person_secret option, the caller in
	// its population: else the one 404.
	h.mu.RLock()
	t := h.findLocked(instance)
	ok := t != nil && h.st.IsEnabled(instance) && personSecretOption(t, key) != nil
	h.mu.RUnlock()
	if !ok {
		h.auditCreateRefused(instance, key, user, refusedNotFound)
		return nil, errNoCredential
	}
	m, err := h.membership(ctx)
	if err != nil {
		h.auditCreateRefused(instance, key, user, refusedDirectory)
		return nil, credentialDirectoryErr(err)
	}
	h.mu.RLock()
	t = h.findLocked(instance)
	var o templates.Option
	if t != nil && h.st.IsEnabled(instance) {
		if po := personSecretOption(t, key); po != nil {
			o = *po
			ok = inPopulation(h.populationLocked(t, m), user)
		} else {
			ok = false
		}
	} else {
		ok = false
	}
	h.mu.RUnlock()
	if !ok {
		h.auditCreateRefused(instance, key, user, refusedNotFound)
		return nil, errNoCredential
	}
	// 2. The username rule, before the proof (not consumed for a
	// refused name).
	if okName, reason := credentials.CheckUsername(o.Username, user); !okName {
		err := statusErr(http.StatusConflict, "%s %s", user, reason)
		h.auditOp(user, "credential.create", target, credentialDetail(instance, key, user, user, reason), err)
		return nil, err
	}
	// 3. The account's uuid and the secrets volume (503, before the proof).
	uuid := m.UUIDs[user]
	if uuid == "" {
		h.auditCreateRefused(instance, key, user, refusedNoAccountID)
		return nil, statusErr(http.StatusServiceUnavailable, "Users & Groups gave no account id for %s: try again later", user)
	}
	if err := h.SecretsUsable(); err != nil {
		h.auditCreateRefused(instance, key, user, refusedSecrets)
		return nil, err
	}
	// 4. The fresh-auth proof (outside mu: network calls). Audited with
	// the verifier's reason only.
	if _, reason, err := h.checkFreshAuth(ctx, p, user); err != nil {
		h.auditOp(user, "credential.create", target, credentialDetail(instance, key, user, user, reason), err)
		return nil, err
	}
	// 5. The password and its hash; under mu the metadata, the hash file
	// and the epoch (writeHashLocked saves state.yaml with them).
	pw, err := credentials.Generate(o.Length)
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, "generating the password failed")
	}
	hash := credentials.NTHash(pw)
	now := time.Now().UTC()
	h.mu.Lock()
	t = h.findLocked(instance)
	if t == nil || !h.st.IsEnabled(instance) || personSecretOption(t, key) == nil {
		h.mu.Unlock()
		credentials.Zero(pw)
		h.auditCreateRefused(instance, key, user, refusedNotFound)
		return nil, errNoCredential
	}
	if h.st.Credentials[instance] == nil {
		h.st.Credentials[instance] = map[string]map[string]state.Credential{}
	}
	users := h.st.Credentials[instance][key]
	if users == nil {
		users = map[string]state.Credential{}
		h.st.Credentials[instance][key] = users
	}
	prev, had := users[user]
	regen := had && prev.Active()
	c := state.Credential{ID: newCredentialID(), Version: 1, UUID: uuid, CreatedAt: now, CreatedBy: user}
	if regen {
		c.Version = prev.Version + 1
	}
	users[user] = c
	if werr := h.writeHashLocked(instance, key, user, hash); werr != nil {
		// The new hash may be on the volume (the epoch or state.yaml failed
		// after it): it must never stay under the old metadata (fix round
		// 1). Written (or unknown): a regenerate is voided and the file
		// removed — the person sees "voided" and creates again —, a first
		// create leaves nothing. Not written: the old state is intact.
		written := h.hashFileMayHoldLocked(instance, key, user, hash)
		voided := false
		switch {
		case written && regen:
			at := time.Now().UTC()
			v := prev
			v.RevokedAt, v.RevokedBy, v.Reason = &at, purgeActor, state.CredentialReasonRestore
			users[user] = v
			voided = true
		case had:
			users[user] = prev
		default:
			delete(users, user)
			if len(users) == 0 {
				delete(h.st.Credentials[instance], key)
			}
			if len(h.st.Credentials[instance]) == 0 {
				delete(h.st.Credentials, instance)
			}
		}
		if written {
			if rerr := h.removeHashLocked(instance, key, user); rerr != nil {
				log.Printf("ERROR: credentials: %s/%s/%s: removing the hash of a failed create: %v (the next reconcile removes it)", instance, key, user, rerr)
			}
		}
		h.mu.Unlock()
		credentials.Zero(pw)
		h.auditOp(user, "credential.create", target, credentialDetail(instance, key, user, user, ""), werr)
		if voided {
			// The old password may still be live in the app.
			h.applyRevocation(ctx, instance)
		}
		return nil, werr
	}
	h.mu.Unlock()
	// 6. The audit; 7. the immediate delivery and the holder re-check.
	action := "credential.create"
	if regen {
		action = "credential.regenerate"
	}
	h.auditOp(user, action, target, credentialDetail(instance, key, user, user, ""), nil)
	h.TriggerDelivery(instance, TriggerCredential, true)
	h.triggerCredentialCheck()
	return &CreatedCredential{Password: pw, Credential: c}, nil
}

// hashFileMayHoldLocked: (instance, key, user)'s hash file may hold hash
// (it does, or the volume can't be read to tell). Caller holds mu.
func (h *Hub) hashFileMayHoldLocked(instance, key, user, hash string) bool {
	rel, err := secretRel(instance, key, user)
	if err != nil {
		return false // never written: the name is refused before any write
	}
	r, err := h.openSecrets()
	if err != nil {
		return true
	}
	defer r.Close()
	b, err := r.ReadFile(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return err != nil || string(b) == hash+"\n"
}

// Fixed reasons of refused creates in the audit (#9; never a proof).
const (
	refusedNotFound    = "not found"
	refusedDirectory   = "users & groups unavailable"
	refusedNoAccountID = "no account id"
	refusedSecrets     = "secrets volume unusable"
)

// auditCreateRefused audits a refused create (404, 503) as refused with
// a fixed reason; the instance and key are the caller's, clipped.
func (h *Hub) auditCreateRefused(instance, key, user, reason string) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	instance, key, user = clip(instance, 64), clip(key, 64), clip(user, 64)
	e := directory.AuditEntry{Actor: user, Action: "credential.create", Target: instance + "/" + key + "/" + user,
		Detail: credentialDetail(instance, key, user, user, reason), Result: "refused", Error: reason}
	if err := a.Append(e); err != nil {
		log.Printf("audit: %v", err)
	}
}

// credentialDirectoryErr: the population can't be checked (503, or the
// directory's own 5xx).
func credentialDirectoryErr(err error) error {
	status := http.StatusServiceUnavailable
	var se *StatusError
	if errors.As(err, &se) && se.Status >= 500 {
		status = se.Status
	}
	return &StatusError{Status: status, Err: errors.New("users & groups is not available: the password can't be created now")}
}

// revocation is one credential to revoke: by whom (RevokedBy) and why.
type revocation struct {
	key, user, by, reason string
}

// RevokeOwnCredential revokes user's own credential (reason self, no
// fresh auth: it only removes access). Nothing active is no error; it
// works outside the population and on a disabled instance too.
func (h *Hub) RevokeOwnCredential(ctx context.Context, instance, key, user string) error {
	user = strings.ToLower(user)
	return h.revokeCredentials(ctx, instance, []revocation{{key: key, user: user, by: user, reason: state.CredentialReasonSelf}})
}

// AdminRevokeCredential revokes user's credential as admin actor (reason
// admin, revoked_by actor). An unknown instance or a key that isn't a
// person_secret option is 404; nothing active is no error.
func (h *Hub) AdminRevokeCredential(ctx context.Context, instance, key, user, actor string) error {
	h.mu.RLock()
	t := h.findLocked(instance)
	ok := t != nil && personSecretOption(t, key) != nil
	h.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	return h.revokeCredentials(ctx, instance, []revocation{{key: key, user: strings.ToLower(user), by: strings.ToLower(actor), reason: state.CredentialReasonAdmin}})
}

// revokeAuditAction is a revocation's audit action (§13.16).
func revokeAuditAction(reason string) string {
	if reason == state.CredentialReasonLeave || reason == state.CredentialReasonDeleted {
		return "credential.revoke_leave"
	}
	return "credential.revoke"
}

// revokeCredentials revokes revs on instance (the shared path, §13.16):
// under mu each active credential's metadata and hash file go (epoch
// rotated, state saved; undone on an error), then the audit, then the
// live apply (applyRevocation) once for the instance. Nothing active:
// nothing done.
func (h *Hub) revokeCredentials(ctx context.Context, instance string, revs []revocation) error {
	now := time.Now().UTC()
	type outcome struct {
		r   revocation
		err error
	}
	var done []outcome
	var err error
	h.mu.Lock()
	for _, r := range revs {
		changed, rerr := h.revokeLocked(instance, r, now)
		if changed {
			done = append(done, outcome{r, rerr})
		}
		if rerr != nil {
			if !changed {
				done = append(done, outcome{r, rerr})
			}
			err = rerr
			break
		}
	}
	h.mu.Unlock()
	applied := false
	for _, o := range done {
		actor := o.r.by
		if o.r.reason == state.CredentialReasonSelf {
			actor = "self"
		}
		h.auditOp(o.r.by, revokeAuditAction(o.r.reason), instance+"/"+o.r.key+"/"+o.r.user, credentialDetail(instance, o.r.key, o.r.user, actor, o.r.reason), o.err)
		applied = true
	}
	if applied {
		// Also after a failed save: the metadata is revoked in memory and
		// the file may be gone — the running app must lose the account.
		h.applyRevocation(ctx, instance)
	}
	return err
}

// revokeLocked revokes one credential: the metadata first (revoked now,
// by, reason), then the hash file and the epoch (removeHashLocked saves
// state.yaml). An error never puts the credential back to active (fix
// round 1): the file may already be gone, and a revocation must reach
// the running app whatever failed after; a leftover file has no active
// metadata and goes at the next reconcile. changed false: nothing was
// active. Caller must hold mu (write).
func (h *Hub) revokeLocked(instance string, r revocation, now time.Time) (bool, error) {
	users := h.st.Credentials[instance][r.key]
	c, ok := users[r.user]
	if !ok || !c.Active() {
		return false, nil
	}
	at := now
	c.RevokedAt, c.RevokedBy, c.Reason = &at, r.by, r.reason
	users[r.user] = c
	if err := h.removeHashLocked(instance, r.key, r.user); err != nil {
		log.Printf("ERROR: credentials: %s/%s/%s: the revocation's commit failed (%v): kept revoked, applied anyway", instance, r.key, r.user, err)
		return true, err
	}
	return true, nil
}

// applyRevocation applies revocations on instance id live (§13.16 steps
// 1–3, see the top of this file), then queues the bookkeeping
// credential_change delivery.
func (h *Hub) applyRevocation(ctx context.Context, id string) {
	defer h.TriggerDelivery(id, TriggerCredential, true)
	// A client hanging up must not turn a live revocation into a kill:
	// the request's cancellation is dropped, the work bounded on its own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeApplyMax)
	defer cancel()
	h.mu.RLock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.RUnlock()
		return
	}
	t := *live
	h.mu.RUnlock()
	if h.engine == nil {
		return // no Docker: nothing runs
	}
	services := map[string]bool{}
	for _, o := range personSecretOptions(&t) {
		services[o.Mount.Service] = true
	}
	for _, hk := range t.Manifest.Hooks {
		if slices.Contains(hk.When, templates.HookCredentialChange) {
			services[hk.Service] = true
		}
	}
	cs, _, err := h.appContainers(ctx, &t)
	if err != nil {
		h.revocationKill(&t, fmt.Errorf("listing the containers: %w", err))
		return
	}
	running := false
	for s := range services {
		running = running || liveContainer(cs, s)
	}
	if !running {
		return // 1. the next start's converge has no account for them
	}
	if err := h.revocationHooks(ctx, &t); err != nil {
		h.revocationKill(&t, err) // 3.
	}
}

// liveContainer: a container of service may still serve its accounts —
// running, paused or restarting (a revocation must not count those as
// stopped: they go to the hook, which can't exec in them, then the kill).
func liveContainer(cs []docker.Container, service string) bool {
	for _, c := range cs {
		if c.Service() == service && (c.State == "running" || c.State == "paused" || c.State == "restarting") {
			return true
		}
	}
	return false
}

// revocationHooks runs every credential_change hook of t for a
// revocation (step 2): nil only when at least one ran and every one
// exited 0.
func (h *Hub) revocationHooks(ctx context.Context, t *templates.Template) error {
	var m *directory.Membership
	if hooksNeedPeople(t) {
		mctx, cancel := context.WithTimeout(ctx, groupSnapshotTimeout)
		var err error
		m, err = h.membership(mctx)
		cancel()
		if err != nil {
			return fmt.Errorf("the directory is unavailable: %w", err)
		}
	}
	l := h.deliverLock(t.ID)
	if !tryLockFor(l, h.revokeLockWait) {
		return fmt.Errorf("another delivery held the delivery lock for more than %s", h.revokeLockWait)
	}
	defer l.Unlock()
	if !h.previousHookDone(ctx, t.ID) {
		return errors.New("hook: " + SkipPrevRunning)
	}
	h.mu.RLock()
	live := h.findLocked(t.ID)
	if live == nil {
		h.mu.RUnlock()
		return errors.New("the instance is gone")
	}
	tmpl := *live
	outs := h.buildHooksLocked(&tmpl, m)
	h.mu.RUnlock()
	n := 0
	for _, o := range outs {
		hk := o.hook
		if !slices.Contains(hk.When, templates.HookCredentialChange) {
			continue
		}
		n++
		switch {
		case o.skip != "":
			return fmt.Errorf("hook %s: %s", hk.Name, o.skip)
		case o.err != nil:
			return fmt.Errorf("hook %s: %w", hk.Name, o.err)
		}
		hk.Timeout = templates.Duration(min(hk.EffectiveTimeout(), revokeHookMax))
		in := o.input
		in.Trigger = templates.HookCredentialChange
		u := h.runHook(ctx, &tmpl, hk, in)
		if !u.OK {
			why := u.Error
			if why == "" {
				why = "hook " + hk.Name + ": " + u.Skipped
			}
			return errors.New(why)
		}
	}
	if n == 0 {
		return errors.New("no hook applies credential changes (none declares credential_change)")
	}
	return nil
}

// tryLockFor takes l, trying for at most d.
func tryLockFor(l interface{ TryLock() bool }, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if l.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(revokeLockPoll)
	}
}

// previousHookDone: instance id has no timed-out hook exec still running
// (one check, never a wait: a revocation can't wait out a stuck exec).
func (h *Hub) previousHookDone(ctx context.Context, id string) bool {
	h.deliveryMu.Lock()
	prev := h.hookExecs[id]
	h.deliveryMu.Unlock()
	if prev.execID == "" {
		return true
	}
	running, err := h.engine.ExecRunning(ctx, prev.execID)
	if (err == nil && !running) || docker.IsNotFound(err) {
		h.deliveryMu.Lock()
		if h.hookExecs[id] == prev {
			delete(h.hookExecs, id)
		}
		delete(h.hookStuck, id)
		h.deliveryMu.Unlock()
		return true
	}
	return false
}

// revocationKill is step 3: the project goes down (compose down, else by
// name, else SIGKILL) without waiting for a lifecycle operation, op
// record credentials, then a background Restart (the start converge has
// no account for the revoked people). A failed restart leaves it down
// and enabled.
func (h *Hub) revocationKill(t *templates.Template, cause error) {
	log.Printf("credentials: %s: a revocation could not be applied live (%s): stopping the instance", t.ID, h.redactUnitError(t.ID, cause))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	derr := h.forceDown(ctx, t)
	cancel()
	rec := errors.New(errRevokeNotLive)
	if derr != nil {
		log.Printf("ERROR: credentials: %s: stopping the instance failed: %v", t.ID, derr)
		rec = fmt.Errorf("revocation could not be applied live and stopping the instance failed: %w", derr)
	}
	h.finishOpGuarded(t.ID, OpCredentials, rec, false, true)
	h.setOwed(t.ID, settings.EffectRestart)
	tmpl := *t
	h.goBackground(func() { h.Restart(tmpl) })
}

// hookCredentialsLocked is t's HookInput.Credentials: per person_secret
// option, the active credentials' ids and versions. Caller holds mu.
func (h *Hub) hookCredentialsLocked(t *templates.Template) map[string]map[string]settings.HookCredential {
	out := map[string]map[string]settings.HookCredential{}
	for _, o := range personSecretOptions(t) {
		m := map[string]settings.HookCredential{}
		for u, c := range h.st.Credentials[t.ID][o.Key] {
			if c.Active() {
				m[u] = settings.HookCredential{ID: c.ID, Version: c.Version}
			}
		}
		out[o.Key] = m
	}
	return out
}

// credentialDigestLocked is the credentials unit's digest of key's
// active metadata (users, ids, versions; never hash bytes, F61) and how
// many are active. Caller holds mu.
func (h *Hub) credentialDigestLocked(id, key string) (string, int) {
	type entry struct {
		User    string `json:"user"`
		ID      string `json:"id"`
		Version int    `json:"version"`
	}
	users := h.st.Credentials[id][key]
	list := []entry{}
	for _, u := range slices.Sorted(maps.Keys(users)) {
		if c := users[u]; c.Active() {
			list = append(list, entry{u, c.ID, c.Version})
		}
	}
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), len(list)
}

// credentialUnits are the credentials:<key> units of a delivery run of
// instance t (§13.9): the secrets reconcile (epoch check; orphan hash
// files deleted, active metadata without a file voided), then per
// person_secret option the digest of its active metadata, recorded in
// delivered. Voids queue a credential_change delivery of every enabled
// instance with person_secret options.
func (h *Hub) credentialUnits(t *templates.Template, delivered *deliveredDoc, now time.Time) []UnitResult {
	opts := personSecretOptions(t)
	if len(opts) == 0 {
		return nil
	}
	rerr := h.secretsBaseErr()
	voided := 0
	if rerr == nil {
		voided, rerr = h.reconcileSecrets("delivery of " + t.ID)
	}
	out := make([]UnitResult, 0, len(opts))
	h.mu.RLock()
	for _, o := range opts {
		u := UnitResult{Unit: credentialsUnit(o.Key), At: now}
		if rerr != nil {
			u.Error = h.redactUnitError(t.ID, rerr)
			out = append(out, u)
			continue
		}
		d, n := h.credentialDigestLocked(t.ID, o.Key)
		u.OK = true
		if delivered.Hashes[u.Unit] == d {
			u.Skipped = SkipUnchanged
		} else {
			u.Message = fmt.Sprintf("%d active", n)
			delivered.Hashes[u.Unit] = d
		}
		out = append(out, u)
	}
	var again []string
	if voided > 0 {
		for _, id := range h.st.Enabled {
			if it := h.findLocked(id); it != nil && len(personSecretOptions(it)) > 0 {
				again = append(again, id)
			}
		}
	}
	h.mu.RUnlock()
	for _, id := range again {
		h.TriggerDelivery(id, TriggerCredential, true)
	}
	return out
}

// credentialHashes are instance id's current NT hashes, upper and lower
// case, for redaction (F44): read from the volume (no mu). nil, nil
// without person_secret options; an error when they exist but the
// volume or a hash file can't be read (callers fail closed, fix round 1).
func (h *Hub) credentialHashes(id string, t *templates.Template) ([]string, error) {
	if t == nil {
		return nil, nil
	}
	opts := personSecretOptions(t)
	if len(opts) == 0 {
		return nil, nil
	}
	if h.secretsErr != nil {
		return nil, fmt.Errorf("the secrets volume is not usable: %v", h.secretsErr)
	}
	r, err := os.OpenRoot(h.cfg.SecretsDir)
	if err != nil {
		return nil, fmt.Errorf("the secrets volume can't be opened: %v", err)
	}
	defer r.Close()
	var out []string
	for _, o := range opts {
		dir, err := secretDirRel(id, o.Key)
		if err != nil {
			return nil, err
		}
		entries, err := fs.ReadDir(r.FS(), dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue // nothing created yet
		}
		if err != nil {
			return nil, fmt.Errorf("the secrets of %s/%s can't be listed: %v", id, o.Key, err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".nt") {
				continue
			}
			b, err := r.ReadFile(dir + "/" + e.Name())
			if err != nil {
				return nil, fmt.Errorf("a hash file of %s/%s can't be read: %v", id, o.Key, err)
			}
			if v := strings.TrimSpace(string(b)); ntHashRe.MatchString(v) {
				out = append(out, v, strings.ToLower(v))
			}
		}
	}
	return out, nil
}

// errHashesUnreadable is the Exec / Logs answer for a person_secret
// instance whose hashes can't be read for redaction (F44, fail closed).
func errHashesUnreadable(id string) error {
	return statusErr(http.StatusServiceUnavailable, "%s's password hashes can't be read to redact this output: it is not shown", id)
}

// redactCredentialHashes blanks instance t's current hashes in s (Exec
// answers, the container logs API: F44); truncated: s was cut, so a
// trailing hex run that begins a hash is blanked too. An unreadable
// hash set is an error (503).
func (h *Hub) redactCredentialHashes(t *templates.Template, s string, truncated bool) (string, error) {
	hs, err := h.credentialHashes(t.ID, t)
	if err != nil {
		log.Printf("credentials: %s: %v", t.ID, err)
		return "", errHashesUnreadable(t.ID)
	}
	if len(hs) == 0 {
		return s, nil
	}
	if truncated {
		s = blankHashPrefixTail(s, hs)
	}
	return redactValues(s, hs), nil
}

// hashPrefixMin: the shortest trailing hash prefix blanked.
const hashPrefixMin = 8

// blankHashPrefixTail replaces the longest trailing run of s (≥
// hashPrefixMin hex characters) that is the start of one of hashes (any
// case) with [redacted]: what an output cap left of a cut hash.
func blankHashPrefixTail(s string, hashes []string) string {
	i := len(s)
	for i > 0 && isHex(s[i-1]) {
		i--
	}
	for j := i; len(s)-j >= hashPrefixMin; j++ {
		tail := strings.ToUpper(s[j:])
		for _, h := range hashes {
			if strings.HasPrefix(strings.ToUpper(h), tail) {
				return s[:j] + "[redacted]"
			}
		}
	}
	return s
}

func isHex(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}

// myCredentialLocked is user's card for person_secret option o of t
// (§5.1): active (since created), unavailable (the username rule's
// reason), voided by a restore (since voided), else none; the info lines
// rendered for user (not for unavailable). Caller holds mu (read).
func (h *Hub) myCredentialLocked(t *templates.Template, o *templates.Option, user string) MyCredential {
	mc := MyCredential{Key: o.Key, Label: o.Label, Status: CredStatusNone}
	c, has := h.st.Credentials[t.ID][o.Key][user]
	okName, reason := credentials.CheckUsername(o.Username, user)
	switch {
	case has && c.Active():
		at := c.CreatedAt
		mc.Status, mc.Since = CredStatusActive, &at
	case !okName:
		mc.Status, mc.Reason = CredStatusUnavailable, reason
		return mc
	case has && c.Reason == state.CredentialReasonRestore && c.RevokedAt != nil:
		at := *c.RevokedAt
		mc.Status, mc.Reason, mc.Since = CredStatusVoided, state.CredentialReasonRestore, &at
	}
	for _, l := range o.Info {
		mc.Info = append(mc.Info, MyInfoLine{Label: l.Label, Value: h.renderInfoLocked(t, l.Value, user)})
	}
	return mc
}

// renderInfoLocked renders an info value for user: {user}, {value:<key>}
// (an instance option's displayed value), {port:<KEY>} (the host port)
// and {port_suffix:<KEY>:<default>} (":<port>" unless it is the default).
// Plain text: the UI escapes it. Caller holds mu (read).
func (h *Hub) renderInfoLocked(t *templates.Template, s, user string) string {
	ports := map[string]int{}
	for _, b := range resolvePortBindings(t, h.st.Settings[t.ID].Ports) {
		if b.Port > 0 {
			ports[b.Key] = b.Port
		}
	}
	portOf := func(k string) int {
		if p, ok := ports[k]; ok {
			return p
		}
		for _, p := range t.Manifest.Ports {
			if p.Key == k {
				return p.Default
			}
		}
		return 0
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		p := s[i+1 : i+j]
		s = s[i+j+1:]
		switch {
		case p == "user":
			b.WriteString(user)
		case strings.HasPrefix(p, "value:"):
			o := optionByKey(t, strings.TrimPrefix(p, "value:"))
			if o == nil || o.EffectiveScope() != templates.ScopeInstance || o.Type == templates.TypeSecret {
				continue
			}
			if v, ok := h.effectiveValue(t, o, h.st.Settings[t.ID]); ok && v != nil {
				b.WriteString(h.kinds.Display(o, v))
			}
		case strings.HasPrefix(p, "port:"):
			if n := portOf(strings.TrimPrefix(p, "port:")); n > 0 {
				b.WriteString(strconv.Itoa(n))
			}
		case strings.HasPrefix(p, "port_suffix:"):
			k, def, _ := strings.Cut(strings.TrimPrefix(p, "port_suffix:"), ":")
			if n := portOf(k); n > 0 && strconv.Itoa(n) != def {
				b.WriteString(":" + strconv.Itoa(n))
			}
		}
	}
	return b.String()
}

// Credentials lists instance's person_secret options for admins:
// metadata only. The directory snapshot is taken before mu; unavailable,
// the rows are the metadata holders only (population 0, no values).
func (h *Hub) Credentials(ctx context.Context, instance string) ([]CredentialsView, error) {
	if h.Template(instance) == nil {
		return nil, ErrNotFound
	}
	m, merr := h.membership(ctx)
	status := h.DeliveryStatus(instance)
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(instance)
	if t == nil {
		return nil, ErrNotFound
	}
	var pop Population
	var resolved map[string]map[string]settings.Resolved
	if merr == nil {
		pop = h.populationLocked(t, m)
		resolved = h.resolvePeopleLocked(t, m)
	}
	out := []CredentialsView{}
	for _, o := range personSecretOptions(t) {
		v := CredentialsView{Instance: instance, Key: o.Key, Label: o.Label, Population: len(pop.People), Rows: []CredentialRow{}, Folders: []settings.HookFolder{}}
		users := map[string]bool{}
		for _, p := range pop.People {
			users[p.User] = true
		}
		for u := range h.st.Credentials[instance][o.Key] {
			users[u] = true
		}
		for _, u := range slices.Sorted(maps.Keys(users)) {
			row := h.credentialRowLocked(t, o, u, resolved[u])
			if row.Status == CredStatusActive {
				v.Active++
			}
			v.Rows = append(v.Rows, row)
		}
		for _, hk := range sortedHooks(t) {
			if hk.Service == o.Mount.Service && slices.Contains(hk.When, templates.HookCredentialChange) {
				if u, ok := status.Units[hookUnit(hk.Name)]; ok {
					v.LastSync = &u
					break
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// credentialRowLocked is user's row for o: the status (revoked with its
// reason for self, admin, leave, deleted), their person_id values and
// displayed person-scope values. Caller holds mu (read).
func (h *Hub) credentialRowLocked(t *templates.Template, o *templates.Option, user string, resolved map[string]settings.Resolved) CredentialRow {
	row := CredentialRow{User: user, Status: CredStatusNone}
	c, has := h.st.Credentials[t.ID][o.Key][user]
	okName, reason := credentials.CheckUsername(o.Username, user)
	switch {
	case has && c.Active():
		at := c.CreatedAt
		row.Status, row.Since = CredStatusActive, &at
	case !okName:
		row.Status, row.Reason = CredStatusUnavailable, reason
	case has && c.RevokedAt != nil:
		at := *c.RevokedAt
		row.Status, row.Reason, row.Since = CredStatusRevoked, c.Reason, &at
		if c.Reason == state.CredentialReasonRestore {
			row.Status = CredStatusVoided
		}
	}
	opts := t.Manifest.Options()
	for i := range opts {
		po := &opts[i]
		switch {
		case po.Type == templates.TypePersonID:
			for _, e := range h.st.PersonIDs[po.Pool].Entries {
				if e.User == user && e.RetiredAt == nil {
					if row.IDs == nil {
						row.IDs = map[string]int{}
					}
					row.IDs[po.Key] = e.ID
				}
			}
		case po.EffectiveScope() == templates.ScopePerson && !hubSetOption(po) && po.Type != templates.TypeSecret:
			if r, ok := resolved[po.Key]; ok && r.Value != nil {
				if row.Values == nil {
					row.Values = map[string]string{}
				}
				row.Values[po.Key] = h.kinds.Display(po, r.Value)
			}
		}
	}
	return row
}
