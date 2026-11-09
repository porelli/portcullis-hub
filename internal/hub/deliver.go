package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The settings delivery engine (contract §13.6–13.9, spec calls 14, 17,
// 25). One run per instance at a time, under deliverLock(id):
//
//  1. outside mu: the directory snapshot (People.Membership) when a unit
//     needs people, after reconcileGroupRows (P8);
//  2. under mu: the generation (a digest of the instance's settings,
//     enabled flag, sign-in mode and the template's settings model) and
//     the desired output of every unit;
//  3. each unit is compared with <data>/settings/<id>/delivered.json and
//     what is on disk; unchanged units are skipped;
//  4. changed units are applied in order — files, claims
//     (deliver_claims.go; a start runs them in the background after the
//     up: deliverClaimsAfterStart), headers (deliver_headers.go: the
//     hosts section of user-attributes.json, published by a policy
//     write; after a start with the claims), hooks (deliver_hooks.go), then the strongest effect: reload or a
//     background Restart (P5: the engine is the only one that reloads or
//     restarts) — each write after re-checking the generation under mu:
//     a newer commit makes the run stop ("superseded") and run again;
//  5. hashes and status are persisted.
//
// The directory unavailable: units that need people are skipped
// ("directory unavailable") and keep what they last delivered (Review
// Focus 2). A disabled instance delivers nothing. While the instance is
// busy (lifecycle lock) or restoring / being deleted, a run is skipped
// ("busy") and re-queued (P20). composeUp writes the data files before
// compose creates the containers (P6, deliverForStart).

// Engine timing.
const (
	// settingsDebounce: membership deliveries per instance (call 17).
	settingsDebounce = 60 * time.Second
	// busyRetry: a run skipped while the instance is busy runs again.
	busyRetry = 15 * time.Second
	// reloadGrace: a reload counts as applied when the app still runs
	// after it (call 25).
	reloadGrace = 10 * time.Second
	// unitErrorMax clips a unit's error (after redaction).
	unitErrorMax = 2000
	// supersededTries bounds a start delivery's re-runs when settings
	// change under it.
	supersededTries = 3
)

// Skip reasons (UnitResult.Skipped).
const (
	SkipUnchanged   = "unchanged"
	SkipNotRunning  = "not running"
	SkipDirectory   = "directory unavailable"
	SkipBusy        = "busy"
	SkipSuperseded  = "superseded"
	SkipUnsupported = "not supported"
)

// Delivery units.
const (
	unitEnv = "env"
	// unitEnvValues: option env values written empty (optionEnvLocked).
	unitEnvValues = "env:values"
	unitReload    = "reload"
	unitRestart   = "restart"
	unitBusy      = "delivery"
)

func fileUnit(name string) string { return "file:" + name }

// DeliveryStatus is an instance's last delivery outcome per unit, for the
// panel; Pending: a run is queued (debounced or re-queued); Trigger: the
// last requested one.
type DeliveryStatus struct {
	Units   map[string]UnitResult `json:"units"`
	Pending bool                  `json:"pending"`
	Trigger Trigger               `json:"trigger,omitempty"`
}

// queuedDelivery is a run waiting for its timer (or, stop nil, about to
// run).
type queuedDelivery struct {
	trig   Trigger
	effect string
	stop   func() bool
	due    time.Time // when the armed timer fires
	// force: hooks the run must run whatever its trigger (skipped start
	// or forced runs re-queued; merged requests union them); real: some
	// merged request is not a stuck-exec re-queue (deliver_hooks.go).
	force map[string]bool
	real  bool
	// whens: the hook triggers of every merged request (a save merged
	// into a higher-ranked credential run keeps its settings_change
	// hooks).
	whens map[string]bool
}

// deletingInstance: instance id is being deleted (state deleting): no
// effect is owed for it.
func (h *Hub) deletingInstance(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.Instances[id].State == state.InstanceDeleting
}

// forceAllHooks in a run's force set re-runs every hook (a retry merged
// into a queued run of another trigger). Never a hook name (hook names
// match the validator's name rule).
const forceAllHooks = "*"

// deliverOpts: effect is a save's effect on the running instance (P5:
// SaveSettings computes it, the engine applies it); lifecycle: the run is
// part of a lifecycle operation that holds the instance's lock (compose
// up): no busy check, no reload or restart, and a failure is an error.
type deliverOpts struct {
	effect    string
	lifecycle bool
	// force: hooks to run whatever the trigger; stuckRetry: only a
	// re-queue after a still-running timed-out hook asked for this run.
	force      map[string]bool
	stuckRetry bool
	// noWait: never wait for the delivery lock (a save's request): a run
	// in progress gets this one queued with its effect, and the report
	// is one busy unit.
	noWait bool
	// whens: hook triggers of requests merged into this run.
	whens map[string]bool
}

func realAfterFunc(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// deliverLock is instance id's delivery lock.
func (h *Hub) deliverLock(id string) *sync.Mutex {
	m, _ := h.deliverLocks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (h *Hub) stage(id, s string) {
	if h.deliverHook != nil {
		h.deliverHook(id, s)
	}
}

// triggerRank orders triggers when queued runs merge: a credential
// change beats a settings change beats a membership change beats a retry
// beats a start (a merged run keeps credential_change: F23).
func triggerRank(t Trigger) int {
	switch t {
	case TriggerCredential:
		return 5
	case TriggerSave:
		return 4
	case TriggerMembership:
		return 3
	case TriggerRetry:
		return 2
	case TriggerStart:
		return 1
	}
	return 0
}

// queueDelivery queues a run of instance id: after delay (an armed timer
// is kept, so repeated requests within the window make one run; a
// shorter delay re-arms it), or at
// once (delay 0; an armed timer is folded in). Effects and triggers of
// merged requests combine. Never runs inline: safe under any lock but
// deliveryMu.
func (h *Hub) queueDelivery(id string, trig Trigger, effect string, delay time.Duration) {
	h.queueDeliveryWith(id, trig, effect, delay, nil, false)
}

// queueDeliveryWith is queueDelivery with hooks to force and whether the
// request is a stuck-exec re-queue (not a new trigger).
func (h *Hub) queueDeliveryWith(id string, trig Trigger, effect string, delay time.Duration, force []string, stuckRetry bool) {
	h.queueDeliveryWhens(id, trig, effect, delay, force, stuckRetry, nil)
}

// queueDeliveryWhens is queueDeliveryWith carrying the hook triggers of
// requests already merged into the run being re-queued.
func (h *Hub) queueDeliveryWhens(id string, trig Trigger, effect string, delay time.Duration, force []string, stuckRetry bool, whens map[string]bool) {
	if !h.deletingInstance(id) {
		h.setOwed(id, effect)
	}
	if trig == TriggerRetry {
		// Merged into a run of another trigger (membership, save ranks
		// higher), a retry still re-runs every hook.
		force = append(slices.Clone(force), forceAllHooks)
	}
	h.deliveryMu.Lock()
	if h.queued == nil {
		h.queued = map[string]*queuedDelivery{}
	}
	if h.lastTrigger == nil {
		h.lastTrigger = map[string]Trigger{}
	}
	h.lastTrigger[id] = trig
	q := h.queued[id]
	if q == nil {
		q = &queuedDelivery{effect: settings.EffectNone}
		h.queued[id] = q
	}
	if triggerRank(trig) > triggerRank(q.trig) {
		q.trig = trig
	}
	q.effect = settings.Strongest(q.effect, effect)
	q.real = q.real || !stuckRetry
	for w := range whens {
		q.addWhen(w)
	}
	q.addWhen(hookWhen(trig))
	for _, n := range force {
		if q.force == nil {
			q.force = map[string]bool{}
		}
		q.force[n] = true
	}
	if delay <= 0 {
		if q.stop != nil {
			q.stop()
		}
		delete(h.queued, id)
		run := *q
		h.deliveryMu.Unlock()
		h.goBackground(func() { h.runQueued(id, run) })
		return
	}
	due := time.Now().Add(delay)
	switch {
	case q.stop == nil:
	case due.Before(q.due) && q.stop():
		// A shorter delay (a busy retry under a membership debounce):
		// re-armed, so it never waits for the longer window.
	default:
		h.deliveryMu.Unlock()
		return
	}
	q.due = due
	q.stop = h.afterFunc(delay, func() { h.fireQueued(id, q) })
	h.deliveryMu.Unlock()
}

func (q *queuedDelivery) addWhen(w string) {
	if w == "" {
		return
	}
	if q.whens == nil {
		q.whens = map[string]bool{}
	}
	q.whens[w] = true
}

// fireQueued runs q when its timer fires (unless it was replaced).
func (h *Hub) fireQueued(id string, q *queuedDelivery) {
	h.deliveryMu.Lock()
	if h.queued[id] != q {
		h.deliveryMu.Unlock()
		return
	}
	delete(h.queued, id)
	run := *q
	h.deliveryMu.Unlock()
	h.goBackground(func() { h.runQueued(id, run) })
}

func (h *Hub) runQueued(id string, q queuedDelivery) {
	if _, err := h.deliver(context.Background(), id, q.trig, deliverOpts{effect: q.effect, force: q.force, stuckRetry: !q.real, whens: q.whens}); err != nil {
		log.Printf("settings: %s: delivery (%s): %v", id, q.trig, err)
	}
}

// TriggerDelivery queues instance id's settings delivery for trig: at
// once (in the background, never inline: safe under any lifecycle lock —
// PurgeGroupSettings runs inside DeleteInstance's), or debounced by
// settingsDebounce.
func (h *Hub) TriggerDelivery(id string, trig Trigger, immediate bool) {
	delay := settingsDebounce
	if immediate {
		delay = 0
	}
	h.queueDelivery(id, trig, settings.EffectNone, delay)
}

// TriggerMembershipDelivery queues a debounced membership delivery of
// every enabled instance with person, group or person-entered options
// (after each directory sync and every accessSyncInterval): only units
// whose output changed are applied.
func (h *Hub) TriggerMembershipDelivery() {
	h.mu.RLock()
	var ids, hdr []string
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && hasPeopleOptions(t) {
			ids = append(ids, id)
			if headersNeedPeople(t) {
				hdr = append(hdr, id)
			}
		}
	}
	h.mu.RUnlock()
	// Someone left a group: the headers (no restart, no reload) follow at
	// once, so a demotion never waits out the debounce.
	if len(hdr) > 0 && h.membershipRemoval() {
		for _, id := range hdr {
			h.goBackground(func() { h.deliverHeadersNow(id) })
		}
	}
	for _, id := range ids {
		h.queueDelivery(id, TriggerMembership, settings.EffectNone, settingsDebounce)
	}
}

// membershipRemoval reads the directory and compares it with the
// previous call's snapshot: whether someone left a group (or the
// directory) since — an expired membership counts as left (false with
// the directory unavailable).
func (h *Hub) membershipRemoval() bool {
	ctx, cancel := context.WithTimeout(context.Background(), groupSnapshotTimeout)
	m, err := h.membership(ctx)
	cancel()
	if err != nil {
		return false
	}
	cur := map[string]map[string]bool{}
	for u, gs := range m.Users {
		cur[u] = map[string]bool{}
		for g := range gs {
			if !m.Expired[u][g] {
				cur[u][g] = true
			}
		}
	}
	h.deliveryMu.Lock()
	prev := h.lastMembers
	h.lastMembers = cur
	h.deliveryMu.Unlock()
	for u, gs := range prev {
		for g := range gs {
			if !cur[u][g] {
				return true
			}
		}
	}
	return false
}

// deliverHeadersNow runs only instance id's headers unit (a removal:
// TriggerMembershipDelivery), under its delivery lock, from a snapshot
// read once the lock is held (outside mu): runs that queued up behind
// one another never publish an older membership last. The debounced
// full run follows as usual; the directory unavailable: nothing.
func (h *Hub) deliverHeadersNow(id string) {
	l := h.deliverLock(id)
	l.Lock()
	defer l.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), groupSnapshotTimeout)
	m, err := h.membership(ctx)
	cancel()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	delivered := h.loadDelivered(id)
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil || !h.st.IsEnabled(id) || h.pendingLocked(id) != nil {
		h.mu.RUnlock()
		return
	}
	tmpl := *t
	gen := h.deliveryGenLocked(&tmpl)
	_, recorded := delivered.Hashes[unitHeaders]
	plan := h.buildHeadersLocked(&tmpl, m, recorded)
	h.mu.RUnlock()
	if !plan.active {
		return
	}
	current := func() bool {
		live := h.findLocked(id)
		return live != nil && h.deliveryGenLocked(live) == gen
	}
	u, stop := h.runHeaders(id, plan, current, &delivered, now)
	if stop {
		return // a newer commit: its own run follows
	}
	recordUnits(id, &delivered, []UnitResult{u})
	h.saveDelivered(id, delivered)
}

// RunSettingsDelivery queues membership deliveries every
// accessSyncInterval (LLDAP changes made outside the Hub, groups deleted
// there) until ctx is done; then it disarms the queued timers.
func (h *Hub) RunSettingsDelivery(ctx context.Context) {
	tick := time.NewTicker(accessSyncInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			h.deliveryMu.Lock()
			for id, q := range h.queued {
				if q.stop != nil {
					q.stop()
				}
				delete(h.queued, id)
			}
			h.deliveryMu.Unlock()
			return
		case <-tick.C:
			h.TriggerMembershipDelivery()
		}
	}
}

// DeliveryStatus is instance id's last outcome per unit and whether a
// run is queued.
func (h *Hub) DeliveryStatus(id string) DeliveryStatus {
	units := h.statusUnits(id)
	h.deliveryMu.Lock()
	defer h.deliveryMu.Unlock()
	return DeliveryStatus{Units: units, Pending: h.queued[id] != nil, Trigger: h.lastTrigger[id]}
}

// statusUnits: the in-memory status, else delivered.json's.
func (h *Hub) statusUnits(id string) map[string]UnitResult {
	h.deliveryMu.Lock()
	st, ok := h.deliveryStatus[id]
	h.deliveryMu.Unlock()
	if !ok {
		st = h.loadDelivered(id).Status
	}
	out := make(map[string]UnitResult, len(st))
	for k, v := range st {
		out[k] = v
	}
	if u, ok := h.envProblemsUnit(id); ok {
		out[u.Unit] = u
	}
	return out
}

// hasPeopleOptions: t has an option whose deliveries depend on the
// directory (person, group or person-entered scope).
func hasPeopleOptions(t *templates.Template) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() != templates.ScopeInstance {
			return true
		}
	}
	return false
}

// deliveredDoc is <data>/settings/<id>/delivered.json: each unit's last
// delivered output hash (never a value) and its last status.
type deliveredDoc struct {
	Hashes map[string]string     `json:"hashes"`
	Status map[string]UnitResult `json:"status"`
	// Claims: per claim unit ("claim:<attr>"), user → "<uuid>:<hash>"
	// of the value last written (or claimPending), never the value.
	Claims map[string]map[string]string `json:"claims,omitempty"`
	// Owed: the strongest effect (reload, restart) a committed change
	// still owes — recorded before the run that applies it is queued or
	// spawned, cleared once it ran (Init re-queues it). Owned by
	// setOwed / clearOwed: saveDelivered writes the in-memory value.
	Owed string `json:"owed,omitempty"`
	// Members (person_secret instances, F28): the population and each
	// group / groups option's expanded members (expandedMembersLocked)
	// the last run whose file and hook units were all OK built its data
	// files from; the holder check compares it with the directory.
	Members map[string][]string `json:"members,omitempty"`
}

func (h *Hub) deliveredPath(id string) string {
	return filepath.Join(h.secretsDir(id), "delivered.json")
}

func (h *Hub) loadDelivered(id string) deliveredDoc {
	d := deliveredDoc{Hashes: map[string]string{}, Status: map[string]UnitResult{}, Claims: map[string]map[string]string{}}
	if !templates.ValidID(id) {
		return d
	}
	b, err := os.ReadFile(h.deliveredPath(id))
	if err != nil {
		return d
	}
	if err := json.Unmarshal(b, &d); err != nil {
		log.Printf("settings: %s: delivered.json unreadable (%v): every unit is delivered again", id, err)
		return deliveredDoc{Hashes: map[string]string{}, Status: map[string]UnitResult{}, Claims: map[string]map[string]string{}}
	}
	if d.Hashes == nil {
		d.Hashes = map[string]string{}
	}
	if d.Status == nil {
		d.Status = map[string]UnitResult{}
	}
	if d.Claims == nil {
		d.Claims = map[string]map[string]string{}
	}
	return d
}

// recordUnits puts units into d's status and logs a failed one when its
// error changed since the last recorded status (T18: a failure shown
// only in the panel cost a CI iteration; a run repeating it logs
// nothing new). u.Error is already redacted, then clipped
// (redactUnitError, storeError or a fixed text), so it is logged as is;
// no lock is taken (callers may hold mu).
func recordUnits(id string, d *deliveredDoc, units []UnitResult) {
	for _, u := range units {
		prev, had := d.Status[u.Unit]
		d.Status[u.Unit] = u
		if !u.OK && u.Skipped == "" && (!had || prev.Error != u.Error) {
			log.Printf("settings: %s: delivery unit %s failed: %s", id, u.Unit, u.Error)
		}
	}
}

func (h *Hub) saveDelivered(id string, d deliveredDoc) {
	h.deliveryMu.Lock()
	if h.deliveryStatus == nil {
		h.deliveryStatus = map[string]map[string]UnitResult{}
	}
	h.deliveryStatus[id] = d.Status
	h.deliveryMu.Unlock()
	h.owedMu.Lock()
	defer h.owedMu.Unlock()
	d.Owed = h.owedLocked(id)
	h.writeDeliveredLocked(id, d)
}

// writeDeliveredLocked writes delivered.json. Caller holds owedMu.
func (h *Hub) writeDeliveredLocked(id string, d deliveredDoc) {
	if err := h.ensureSecretsDir(id); err != nil {
		log.Printf("settings: %s: delivery record not saved: %v", id, err)
		return
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(h.deliveredPath(id), b, 0600)
	}
	if err != nil {
		log.Printf("settings: %s: delivery record not saved: %v", id, err)
	}
}

// owedLocked is instance id's owed effect (the in-memory value once
// loaded, else delivered.json's). Caller holds owedMu.
func (h *Hub) owedLocked(id string) string {
	if v, ok := h.owed[id]; ok {
		return v
	}
	v := h.loadDelivered(id).Owed
	if h.owed == nil {
		h.owed = map[string]string{}
	}
	h.owed[id] = v
	return v
}

// setOwed records that instance id owes effect (reload, restart; none:
// nothing) in delivered.json before the run that applies it is queued
// or spawned; it returns the record's sequence number for clearOwed.
func (h *Hub) setOwed(id, effect string) int64 {
	h.owedMu.Lock()
	defer h.owedMu.Unlock()
	if effect != settings.EffectReload && effect != settings.EffectRestart || !templates.ValidID(id) {
		return h.owedSeq[id]
	}
	cur := h.owedLocked(id)
	next := settings.Strongest(cur, effect)
	if h.owedSeq == nil {
		h.owedSeq = map[string]int64{}
	}
	h.owedSeq[id]++
	if next != cur {
		h.owed[id] = next
		d := h.loadDelivered(id)
		d.Owed = next
		h.writeDeliveredLocked(id, d)
	}
	return h.owedSeq[id]
}

// owedSeqOf is instance id's current owed sequence number.
func (h *Hub) owedSeqOf(id string) int64 {
	h.owedMu.Lock()
	defer h.owedMu.Unlock()
	return h.owedSeq[id]
}

// clearOwed clears instance id's owed effect once a run applied upTo
// (restart covers a reload), unless something was owed again since seq
// (that run applies it).
func (h *Hub) clearOwed(id string, seq int64, upTo string) {
	h.owedMu.Lock()
	defer h.owedMu.Unlock()
	cur := h.owedLocked(id)
	if cur == "" || h.owedSeq[id] != seq || settings.Strongest(cur, upTo) != upTo {
		return
	}
	h.owed[id] = ""
	if !fileExists(h.deliveredPath(id)) {
		return
	}
	d := h.loadDelivered(id)
	d.Owed = ""
	h.writeDeliveredLocked(id, d)
}

// forgetOwed drops instance id's owed effect (disabled, deleted).
func (h *Hub) forgetOwed(id string) {
	h.owedMu.Lock()
	defer h.owedMu.Unlock()
	if h.owedSeq == nil {
		h.owedSeq = map[string]int64{}
	}
	h.owedSeq[id]++
	if h.owedLocked(id) == "" {
		return
	}
	h.owed[id] = ""
	if fileExists(h.deliveredPath(id)) {
		d := h.loadDelivered(id)
		d.Owed = ""
		h.writeDeliveredLocked(id, d)
	}
}

// requeueOwed queues, at Init, a delivery of every enabled instance that
// still owes a reload or restart (the previous run stopped first).
func (h *Hub) requeueOwed() {
	h.mu.RLock()
	ids := append([]string(nil), h.st.Enabled...)
	h.mu.RUnlock()
	for _, id := range ids {
		h.owedMu.Lock()
		owed := h.owedLocked(id)
		h.owedMu.Unlock()
		if owed != "" {
			log.Printf("settings: %s: a %s is still owed: queued again", id, owed)
			h.queueDelivery(id, TriggerRetry, owed, 0)
		}
	}
}

// deliveryGenLocked is instance t's delivery generation: a digest of
// everything a delivery renders from (state and the template's settings
// model). A run whose generation is no longer current never writes.
// Caller holds mu.
func (h *Hub) deliveryGenLocked(t *templates.Template) string {
	// The population's inputs too (group access, the access role, the
	// policy, public mode): a run built before a policy save never
	// writes the old population after it.
	acc := h.accessLocked(t)
	pol, hasPol := h.st.AuthPolicies[t.ID]
	// An AI page's ai-providers.json (Task 23; errors make it differ).
	providers, perr := h.providersFileBytesLocked(t)
	if perr != nil {
		providers = []byte("error: " + perr.Error())
	}
	b, err := json.Marshal(struct {
		Settings    state.InstanceSettings
		Enabled     bool
		SignIn      string
		Files       []templates.DataFile
		Options     []templates.Option
		Reload      *templates.Reload
		Hooks       []templates.Hook
		GroupAccess bool
		Access      any
		Policy      *policy.AuthPolicy
		Public      any
		PublicMode  any
		Auth        templates.Auth
		AIProviders []byte
	}{h.st.Settings[t.ID], h.st.IsEnabled(t.ID), h.st.SignIn[t.ID], t.Manifest.Files, t.Manifest.Options(), t.Manifest.Reload, t.Manifest.Hooks,
		acc.groupAccess(t), acc, policyOrNil(pol, hasPol), t.Public, h.st.PublicMode[t.ID], t.Manifest.Auth, providers})
	if err != nil {
		// Never equal: the run can't prove it is current.
		return "unmarshalable:" + err.Error() + time.Now().String()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// deliveryGensLocked is every enabled instance's delivery generation.
// Caller holds mu.
func (h *Hub) deliveryGensLocked() map[string]string {
	out := map[string]string{}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil {
			out[id] = h.deliveryGenLocked(t)
		}
	}
	return out
}

// redeliverChanged queues a delivery of every enabled instance whose
// generation differs from before (a source sync): its outputs follow the
// new template without waiting for a save or a start.
func (h *Hub) redeliverChanged(before map[string]string) {
	h.mu.RLock()
	now := h.deliveryGensLocked()
	h.mu.RUnlock()
	for _, id := range slices.Sorted(maps.Keys(now)) {
		if before[id] != now[id] {
			h.queueDelivery(id, TriggerRetry, settings.EffectNone, 0)
		}
	}
}

func policyOrNil(p policy.AuthPolicy, ok bool) *policy.AuthPolicy {
	if !ok {
		return nil
	}
	return &p
}

// redactUnitError is err as a unit shows it: redacted, then clipped.
func (h *Hub) redactUnitError(id string, err error) string {
	return clipRunes(h.secretRedactor(id, secretsOf(err))(err.Error()), unitErrorMax)
}

// Deliver runs instance id's settings deliveries for trig now (waiting
// for a run in progress) and reports each unit. Never call it holding mu
// or id's lifecycle lock.
func (h *Hub) Deliver(ctx context.Context, id string, trig Trigger) (*DeliveryReport, error) {
	return h.deliver(ctx, id, trig, deliverOpts{})
}

// deliverForStart writes instance t's data files before compose creates
// its containers (P6; trigger start: never a reload or restart). It runs
// under the instance's lifecycle lock. A data file that needs people and
// was never delivered fails the start with 503 while the directory is
// unavailable (fail closed); a delivered one is kept.
func (h *Hub) deliverForStart(ctx context.Context, id string) error {
	_, err := h.deliver(ctx, id, TriggerStart, deliverOpts{lifecycle: true})
	return err
}

// deliver is one engine run (see the top of this file).
func (h *Hub) deliver(ctx context.Context, id string, trig Trigger, opt deliverOpts) (*DeliveryReport, error) {
	l := h.deliverLock(id)
	if opt.noWait {
		if !l.TryLock() {
			h.queueDeliveryWhens(id, trig, opt.effect, 0, forceList(opt.force), opt.stuckRetry, opt.whens)
			return &DeliveryReport{Instance: id, Units: []UnitResult{{Unit: unitBusy, Skipped: SkipBusy, Message: "a delivery is running: this one follows it", At: time.Now().UTC()}}}, nil
		}
	} else {
		l.Lock()
	}
	rep, err := h.deliverHeld(ctx, id, trig, opt)
	l.Unlock()
	// A4: credentials the run's reconcile voided are applied live (hook
	// ≤ 8 s, else the kill), after the lock is released: the revocation
	// takes it itself. A start's own instance gets a credential delivery
	// (N1).
	if rep != nil {
		for _, v := range rep.revokeAfter {
			if opt.lifecycle && v == id {
				// N1: the start usually converges it, but a start refused
				// later (a restart's folder probe, before the down) leaves
				// the running app with the voided accounts: the
				// credential delivery runs its hooks either way.
				h.TriggerDelivery(id, TriggerCredential, true)
				continue
			}
			log.Printf("credentials: %s: the secrets reconcile voided file-sharing passwords: applying it live", v)
			h.applyRevocation(ctx, v)
		}
	}
	return rep, err
}

// deliverHeld is deliver's body under the instance's delivery lock.
func (h *Hub) deliverHeld(ctx context.Context, id string, trig Trigger, opt deliverOpts) (*DeliveryReport, error) {
	var voided []string
	for try := 1; ; try++ {
		rep, applied, superseded, err := h.deliverOnce(ctx, id, trig, opt)
		if rep != nil {
			for _, v := range rep.revokeAfter {
				if !slices.Contains(voided, v) {
					voided = append(voided, v)
				}
			}
			rep.revokeAfter = voided
		}
		if !superseded || err != nil {
			return rep, err
		}
		if !opt.lifecycle {
			// A newer commit: its own run follows; this one runs again
			// (after the lock is released) with the effects it owed so far
			// — its own and those of what it already wrote (a written
			// file is unchanged for the next run, which would otherwise
			// never apply its on_membership_change) — and the hooks such
			// a file owes (B-I1: forced, so the re-run never records the
			// reduced members without them).
			force := forceList(opt.force)
			for _, n := range rep.forceAgain {
				if !slices.Contains(force, n) {
					force = append(force, n)
				}
			}
			h.queueDeliveryWhens(id, trig, applied, 0, force, opt.stuckRetry, opt.whens)
			return rep, nil
		}
		if try >= supersededTries {
			return rep, statusErr(409, "the settings of %s kept changing while its data files were written: try again", id)
		}
	}
}

// fileOutput is one data file's desired content.
type fileOutput struct {
	file    templates.DataFile
	data    []byte
	secrets []byte // nil: the file has no secret option
	hash    string
	people  bool   // needs the directory
	skip    string // SkipDirectory: not built
	err     error
	// aiProviders: the AI page's ai-providers.json (Task 23): a change
	// restarts the app (it reads its provider configuration at start).
	aiProviders bool
}

// deliverOnce is deliver's body; superseded: a newer commit made the run
// stop before a write, and applied is then the strongest effect the run
// still owes (its own plus those of the units it already wrote).
func (h *Hub) deliverOnce(ctx context.Context, id string, trig Trigger, opt deliverOpts) (rep *DeliveryReport, applied string, superseded bool, err error) {
	rep = &DeliveryReport{Instance: id, Units: []UnitResult{}}
	now := time.Now().UTC()
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.RUnlock()
		return rep, "", false, nil
	}
	tmpl := *t
	enabled := h.st.IsEnabled(id)
	pendErr := h.pendingLocked(id)
	deleting := h.st.Instances[id].State == state.InstanceDeleting
	hasRows := len(h.st.Settings[id].Person)+len(h.st.Settings[id].Groups)+len(h.st.Settings[id].GroupIDs) > 0
	// The person-entered values as stored before the snapshot (only
	// those can be judged against it: purgeStaleEntries).
	enteredBefore := enteredCopy(h.st.Settings[id].Entered)
	h.mu.RUnlock()
	owedSeq := int64(0)
	if !opt.lifecycle {
		if deleting {
			// Going away: nothing delivered, re-queued or owed (its
			// delivery records are being removed).
			rep.Units = append(rep.Units, UnitResult{Unit: unitBusy, Skipped: SkipBusy, Message: h.redactUnitError(id, pendErr), At: now})
			return rep, "", false, nil
		}
		if h.appBusy(id) {
			// P20: never during a lifecycle or async operation (its op
			// record, a restore's files); run again later.
			rep.Units = append(rep.Units, UnitResult{Unit: unitBusy, Skipped: SkipBusy, At: now})
			h.queueDeliveryWhens(id, trig, opt.effect, busyRetry, forceList(opt.force), opt.stuckRetry, opt.whens)
			return rep, "", false, nil
		}
		if pendErr != nil {
			// Stuck deleting or restoring (no operation running): nothing
			// is delivered and nothing re-queued — finishing the delete or
			// restore starts the instance again (its effect stays owed).
			rep.Units = append(rep.Units, UnitResult{Unit: unitBusy, Skipped: SkipBusy, Message: h.redactUnitError(id, pendErr), At: now})
			return rep, "", false, nil
		}
		if !enabled {
			h.forgetOwed(id)
			return rep, "", false, nil
		}
		// The run's own effect is owed until it is applied (after the
		// busy and pending checks: a busy run's re-queue records it).
		owedSeq = h.setOwed(id, opt.effect)
	}

	// Outside mu: stale rows first (P8: purged, audited), then the
	// directory snapshot the units render from.
	needPeople := filesNeedPeople(&tmpl) || hasGroupEnv(&tmpl) || hasEntryEnv(&tmpl) || (!opt.lifecycle && (claimsNeedPeople(&tmpl) || headersNeedPeople(&tmpl) || hooksNeedPeople(&tmpl)))
	if hasRows && !opt.lifecycle {
		for _, w := range h.reconcileGroupRows(ctx, id) {
			log.Printf("settings: %s: %s", id, w)
		}
	}
	var m *directory.Membership
	var merr error
	if needPeople {
		mctx, cancel := context.WithTimeout(ctx, groupSnapshotTimeout)
		m, merr = h.membership(mctx)
		cancel()
		if merr != nil {
			log.Printf("settings: %s: WARNING: directory unavailable (%v): deliveries that need people keep what they last delivered", id, merr)
		}
	}
	// Person-entered values of accounts deleted or re-created outside
	// the Hub: purged (P22: only while LLDAP looks sane; the delivery
	// below filters them either way).
	if !opt.lifecycle {
		h.purgeStaleEntries(ctx, id, m, enteredBefore)
	}
	// Person ids before the render, start runs included (F9: one short
	// write-locked section; a member without a uuid gets none and is left
	// out of the files). The directory unavailable: nothing to allocate
	// for — the units that need people are skipped.
	if m != nil && len(personIDOptions(&tmpl)) > 0 {
		h.mu.RLock()
		var pop Population
		if live := h.findLocked(id); live != nil {
			pop = h.populationLocked(live, m)
		}
		h.mu.RUnlock()
		if err := h.ensurePersonIDs(id, pop.People, m.UUIDs); err != nil {
			log.Printf("settings: %s: WARNING: person ids not allocated (%v): people without one are left out of the data files", id, err)
		}
	}

	delivered := h.loadDelivered(id)
	// The credentials units first (secrets reconcile, metadata digest):
	// the hook inputs below are built from what they leave.
	credUnits, voided := h.credentialUnits(&tmpl, &delivered, now)
	rep.revokeAfter = voided
	if opt.lifecycle {
		// A1: a start never mounts a volume whose reconcile failed (old
		// or orphan hash files may still be on it).
		for _, u := range credUnits {
			if u.Error != "" {
				rep.Units = append(rep.Units, credUnits...)
				h.saveDelivered(id, delivered)
				return rep, "", false, statusErr(503, "%s: per-person passwords: %s: not starting", id, u.Error)
			}
		}
	}
	// Under mu: the generation and every desired output.
	h.mu.RLock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.RUnlock()
		return rep, "", false, nil
	}
	tmpl = *live
	gen := h.deliveryGenLocked(&tmpl)
	outs := h.buildFilesLocked(&tmpl, m)
	var claims claimPlan
	var headers headerPlan
	if !opt.lifecycle {
		claims = h.buildClaimsLocked(&tmpl, m)
		_, recorded := delivered.Hashes[unitHeaders]
		headers = h.buildHeadersLocked(&tmpl, m, recorded)
	}
	var hookOuts []hookOutput
	if !opt.lifecycle {
		hookOuts = h.buildHooksLocked(&tmpl, m)
	}
	// What grants file access, from the same snapshot (F28; recorded
	// once the files and hooks are through: recordMembers).
	var members map[string][]string
	if m != nil && len(personSecretOptions(&tmpl)) > 0 {
		members = h.expandedMembersLocked(&tmpl, m)
	}
	h.mu.RUnlock()
	h.stage(id, "built")
	recordMembers := func() {
		if members != nil && membersRecordable(rep.Units) {
			delivered.Members = members
		}
	}

	rep.Units = append(rep.Units, credUnits...)
	effects := []string{}
	// A credential run may have merged a save or a membership run: their
	// effect is carried.
	if trig == TriggerSave || trig == TriggerMembership || trig == TriggerRetry || trig == TriggerCredential {
		effects = append(effects, opt.effect)
	}
	// current re-checks the generation (under mu: no commit can happen
	// between the check and the write that follows while mu is held).
	current := func() bool {
		live := h.findLocked(id)
		return live != nil && h.deliveryGenLocked(live) == gen
	}
	finish := func() {
		recordUnits(id, &delivered, rep.Units)
		h.saveDelivered(id, delivered)
	}
	stale := func(from int) {
		for _, o := range outs[from:] {
			rep.Units = append(rep.Units, UnitResult{Unit: fileUnit(o.file.Name), Skipped: SkipSuperseded, At: now})
		}
	}

	// Files.
	membershipHooks := false // a file with on_membership_change: hook changed
	defer func() {
		// B-I1: superseded after such a file was written, the re-run sees
		// it unchanged — it must still run the file's hooks.
		if superseded && membershipHooks {
			for _, hk := range tmpl.Manifest.Hooks {
				if slices.Contains(hk.When, templates.HookMembershipChange) {
					rep.forceAgain = append(rep.forceAgain, hk.Name)
				}
			}
		}
	}()
	for i, o := range outs {
		u := UnitResult{Unit: fileUnit(o.file.Name), At: now}
		switch {
		case o.skip != "":
			if opt.lifecycle && o.people && !fileExists(h.dataFilePathOf(id, &o.file)) {
				finish()
				why := h.redactUnitError(id, merr)
				h.mu.RLock()
				if h.people == nil {
					why = "Users & Groups not configured"
				}
				h.mu.RUnlock()
				return rep, "", false, statusErr(503, "data file %s of %s needs the directory and was never delivered: not starting while the directory is unavailable (%s)", o.file.Name, id, why)
			}
			u.Skipped = o.skip
		case o.err != nil:
			u.Error = h.redactUnitError(id, o.err)
			if opt.lifecycle {
				rep.Units = append(rep.Units, u)
				finish()
				return rep, "", false, statusErr(500, "data file %s of %s: %s", o.file.Name, id, u.Error)
			}
		case delivered.Hashes[u.Unit] == o.hash && h.fileOnDisk(id, o):
			u.OK, u.Skipped = true, SkipUnchanged
		default:
			h.mu.RLock()
			if !current() {
				h.mu.RUnlock()
				stale(i)
				finish()
				return rep, settings.Strongest(effects...), true, nil
			}
			werr := h.writeDataFile(id, o)
			h.mu.RUnlock()
			if werr != nil {
				u.Error = h.redactUnitError(id, werr)
				if opt.lifecycle {
					rep.Units = append(rep.Units, u)
					finish()
					return rep, "", false, statusErr(500, "data file %s of %s: %s", o.file.Name, id, u.Error)
				}
				break
			}
			u.OK = true
			delivered.Hashes[u.Unit] = o.hash
			if trig == TriggerMembership || trig == TriggerRetry || trig == TriggerCredential {
				effects = append(effects, membershipEffect(o.file.OnMembershipChange))
			}
			if o.aiProviders {
				// Any trigger (a lifecycle run ignores effects: compose
				// creates the containers after it).
				effects = append(effects, settings.EffectRestart)
			}
			// A changed hook-file runs its hooks in this run, whatever
			// the trigger (a save of a file-only option included): the
			// hooks' own input may not have changed.
			membershipHooks = membershipHooks || o.file.OnMembershipChange == templates.MembershipHook
		}
		rep.Units = append(rep.Units, u)
	}

	h.stage(id, "files")
	if opt.lifecycle {
		// The person-entered env lists before the containers are created
		// (no restart: compose reads the .env at create); the directory
		// down keeps the last list.
		if hasEntryEnv(&tmpl) {
			u := UnitResult{Unit: unitEnv, At: now}
			if m == nil {
				u.Skipped = SkipDirectory
			} else {
				changed, stop, eerr := h.refreshEngineEnv(&tmpl, gen, m)
				switch {
				case stop:
					finish()
					return rep, "", true, nil
				case eerr != nil:
					u.Error = h.redactUnitError(id, eerr)
				case changed:
					u.OK = true
				default:
					u.OK, u.Skipped = true, SkipUnchanged
				}
			}
			rep.Units = append(rep.Units, u)
		}
		// TriggerStart: compose up follows; never a reload or restart.
		// Claims follow in the background (deliverClaimsAfterStart).
		recordMembers()
		finish()
		return rep, "", false, nil
	}

	// Claims (LLDAP attributes and Keycloak mappers).
	cu, stop := h.runClaims(ctx, claimStep{t: &tmpl, plan: claims, current: current, delivered: &delivered, now: now})
	rep.Units = append(rep.Units, cu...)
	if stop {
		finish()
		return rep, settings.Strongest(effects...), true, nil
	}
	h.stage(id, "claims")

	// Headers (user-attributes.json hosts; next_request: no effect).
	if headers.active {
		hu, stop := h.runHeaders(id, headers, current, &delivered, now)
		if stop {
			finish()
			return rep, settings.Strongest(effects...), true, nil
		}
		rep.Units = append(rep.Units, hu)
		h.stage(id, "headers")
	}

	// Group records and person-entered lists in the env, re-rendered
	// against this run's snapshot (a write without one — directory down —
	// delivered no records and kept the last lists).
	if hasGroupEnv(&tmpl) || hasEntryEnv(&tmpl) {
		u := UnitResult{Unit: unitEnv, At: now}
		if m == nil {
			u.Skipped = SkipDirectory
		} else {
			changed, stop, eerr := h.refreshEngineEnv(&tmpl, gen, m)
			switch {
			case stop:
				finish()
				return rep, settings.Strongest(effects...), true, nil
			case eerr != nil:
				u.Error = h.redactUnitError(id, eerr)
			case changed:
				u.OK = true
				effects = append(effects, settings.EffectRestart)
			default:
				u.OK, u.Skipped = true, SkipUnchanged
			}
		}
		rep.Units = append(rep.Units, u)
		h.stage(id, "env")
	}

	// Hooks; the reload hook runs once, folded with them.
	effect := settings.Strongest(effects...)
	var ran map[string]UnitResult
	if len(hookOuts) > 0 {
		step := hookStep{id: id, trig: trig, outs: hookOuts, force: map[string]bool{}, alsoWhen: opt.whens, current: current, delivered: &delivered, now: now}
		for n := range opt.force {
			step.force[n] = true
		}
		if r := tmpl.Manifest.Reload; effect == settings.EffectReload && r != nil && r.Hook != "" {
			step.force[r.Hook] = true
		}
		if membershipHooks {
			step.forceWhen = templates.HookMembershipChange
		}
		hr := h.runHooks(ctx, &tmpl, step)
		rep.Units = append(rep.Units, hr.units...)
		ran = hr.ran
		if hr.superseded {
			finish()
			return rep, effect, true, nil
		}
		// Skipped hooks: again later (forced, with the reload a skipped
		// reload hook still owes).
		again := settings.EffectNone
		if r := tmpl.Manifest.Reload; effect == settings.EffectReload && r != nil && r.Hook != "" && ran[r.Hook].Skipped != "" && !ran[r.Hook].OK {
			again = settings.EffectReload
		}
		h.requeueHooks(id, trig, again, hr, opt.stuckRetry)
		h.stage(id, "hooks")
	}

	// The strongest effect: one reload or one restart per run.
	switch effect {
	case settings.EffectRestart:
		h.mu.RLock()
		ok := current()
		h.mu.RUnlock()
		if !ok {
			finish()
			return rep, effect, true, nil
		}
		restartTmpl := tmpl
		// Owed until the restart's finishOp (Restart clears it).
		h.setOwed(id, settings.EffectRestart)
		h.goBackground(func() { h.Restart(restartTmpl) })
		rep.Units = append(rep.Units, UnitResult{Unit: unitRestart, OK: true, Message: "restart queued", At: now})
	case settings.EffectReload:
		rep.Units = append(rep.Units, h.reloadUnit(ctx, &tmpl, ran))
		h.clearOwed(id, owedSeq, settings.EffectReload)
	}
	recordMembers()
	finish()
	return rep, "", false, nil
}

// membershipEffect is what a data file's on_membership_change does when
// a membership delivery changed it (hook: the hooks declaring
// membership_change run, deliver_hooks.go).
func membershipEffect(on string) string {
	switch on {
	case templates.MembershipRestart:
		return settings.EffectRestart
	case templates.MembershipReload:
		return settings.EffectReload
	}
	return settings.EffectNone
}

// refreshEngineEnv rewrites the env variables the engine owns in
// instance t's .env with snapshot m (fetched outside mu) when the
// generation is still gen: the option env with the group records, and
// the person-entered lists (P12: generateAppEnvLocked leaves those as it
// finds them; written here with setEnvVars, under the delivery lock, in
// the same section as every other .env writer's mu so no update is
// lost). changed: the .env changed (compose reads it at create: a
// restart). stop: superseded.
func (h *Hub) refreshEngineEnv(t *templates.Template, gen string, m *directory.Membership) (changed, stop bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	live := h.findLocked(t.ID)
	if live == nil || h.deliveryGenLocked(live) != gen {
		return false, true, nil
	}
	before, _ := os.ReadFile(h.envPath(t.ID))
	if hasGroupEnv(live) {
		if err := h.writeOptionEnvLocked(live, m); err != nil {
			return false, false, err
		}
	}
	if hasEntryEnv(live) {
		if err := setEnvVars(h.envPath(t.ID), h.entryEnvLocked(live, m), true); err != nil {
			return false, false, err
		}
		// Every .env write re-checks the env overrides (§11.9).
		if err := h.writeEnvOverridesLocked(live); err != nil {
			return false, false, err
		}
	}
	after, _ := os.ReadFile(h.envPath(t.ID))
	return string(before) != string(after), false, nil
}

// sortedFiles are t's data files by name.
func sortedFiles(t *templates.Template) []templates.DataFile {
	fs := slices.Clone(t.Manifest.Files)
	slices.SortFunc(fs, func(a, b templates.DataFile) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return fs
}
