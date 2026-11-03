package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
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
//  4. changed units are applied in order — files, (claims, headers,
//     hooks: later tasks), then the strongest effect: reload or a
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
	unitEnv     = "env"
	unitReload  = "reload"
	unitRestart = "restart"
	unitBusy    = "delivery"
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
}

// deliverOpts: effect is a save's effect on the running instance (P5:
// SaveSettings computes it, the engine applies it); lifecycle: the run is
// part of a lifecycle operation that holds the instance's lock (compose
// up): no busy check, no reload or restart, and a failure is an error.
type deliverOpts struct {
	effect    string
	lifecycle bool
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

// triggerRank orders triggers when queued runs merge: a settings change
// beats a membership change beats a retry beats a start.
func triggerRank(t Trigger) int {
	switch t {
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
// is kept, so repeated requests within the window make one run), or at
// once (delay 0; an armed timer is folded in). Effects and triggers of
// merged requests combine. Never runs inline: safe under any lock but
// deliveryMu.
func (h *Hub) queueDelivery(id string, trig Trigger, effect string, delay time.Duration) {
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
	if q.stop == nil {
		q.stop = h.afterFunc(delay, func() { h.fireQueued(id, q) })
	}
	h.deliveryMu.Unlock()
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
	if _, err := h.deliver(context.Background(), id, q.trig, deliverOpts{effect: q.effect}); err != nil {
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
	var ids []string
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && hasPeopleOptions(t) {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		h.queueDelivery(id, TriggerMembership, settings.EffectNone, settingsDebounce)
	}
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
}

func (h *Hub) deliveredPath(id string) string {
	return filepath.Join(h.secretsDir(id), "delivered.json")
}

func (h *Hub) loadDelivered(id string) deliveredDoc {
	d := deliveredDoc{Hashes: map[string]string{}, Status: map[string]UnitResult{}}
	if !templates.ValidID(id) {
		return d
	}
	b, err := os.ReadFile(h.deliveredPath(id))
	if err != nil {
		return d
	}
	if err := json.Unmarshal(b, &d); err != nil {
		log.Printf("settings: %s: delivered.json unreadable (%v): every unit is delivered again", id, err)
		return deliveredDoc{Hashes: map[string]string{}, Status: map[string]UnitResult{}}
	}
	if d.Hashes == nil {
		d.Hashes = map[string]string{}
	}
	if d.Status == nil {
		d.Status = map[string]UnitResult{}
	}
	return d
}

func (h *Hub) saveDelivered(id string, d deliveredDoc) {
	h.deliveryMu.Lock()
	if h.deliveryStatus == nil {
		h.deliveryStatus = map[string]map[string]UnitResult{}
	}
	h.deliveryStatus[id] = d.Status
	h.deliveryMu.Unlock()
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

// deliveryGenLocked is instance t's delivery generation: a digest of
// everything a delivery renders from (state and the template's settings
// model). A run whose generation is no longer current never writes.
// Caller holds mu.
func (h *Hub) deliveryGenLocked(t *templates.Template) string {
	b, err := json.Marshal(struct {
		Settings state.InstanceSettings
		Enabled  bool
		SignIn   string
		Files    []templates.DataFile
		Options  []templates.Option
		Reload   *templates.Reload
	}{h.st.Settings[t.ID], h.st.IsEnabled(t.ID), h.st.SignIn[t.ID], t.Manifest.Files, t.Manifest.Options(), t.Manifest.Reload})
	if err != nil {
		// Never equal: the run can't prove it is current.
		return "unmarshalable:" + err.Error() + time.Now().String()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	l.Lock()
	defer l.Unlock()
	for try := 1; ; try++ {
		rep, superseded, err := h.deliverOnce(ctx, id, trig, opt)
		if !superseded || err != nil {
			return rep, err
		}
		if !opt.lifecycle {
			// A newer commit: its own run follows; this one runs again
			// (after the lock is released) with its effect.
			h.queueDelivery(id, trig, opt.effect, 0)
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
}

// deliverOnce is deliver's body; superseded: a newer commit made the run
// stop before a write.
func (h *Hub) deliverOnce(ctx context.Context, id string, trig Trigger, opt deliverOpts) (rep *DeliveryReport, superseded bool, err error) {
	rep = &DeliveryReport{Instance: id, Units: []UnitResult{}}
	now := time.Now().UTC()
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.RUnlock()
		return rep, false, nil
	}
	tmpl := *t
	enabled := h.st.IsEnabled(id)
	pendErr := h.pendingLocked(id)
	hasRows := len(h.st.Settings[id].Person)+len(h.st.Settings[id].Groups) > 0
	h.mu.RUnlock()
	if !opt.lifecycle {
		if pendErr != nil || h.appBusy(id) {
			// P20: never during a lifecycle or async operation (its op
			// record, a restore's files); run again later.
			rep.Units = append(rep.Units, UnitResult{Unit: unitBusy, Skipped: SkipBusy, At: now})
			h.queueDelivery(id, trig, opt.effect, busyRetry)
			return rep, false, nil
		}
		if !enabled {
			return rep, false, nil
		}
	}

	// Outside mu: stale rows first (P8: purged, audited), then the
	// directory snapshot the units render from.
	needPeople := filesNeedPeople(&tmpl) || hasGroupEnv(&tmpl)
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

	// Under mu: the generation and every desired output.
	h.mu.RLock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.RUnlock()
		return rep, false, nil
	}
	tmpl = *live
	gen := h.deliveryGenLocked(&tmpl)
	outs := h.buildFilesLocked(&tmpl, m)
	h.mu.RUnlock()
	h.stage(id, "built")

	delivered := h.loadDelivered(id)
	effects := []string{}
	if trig == TriggerSave || trig == TriggerMembership || trig == TriggerRetry {
		effects = append(effects, opt.effect)
	}
	// current re-checks the generation (under mu: no commit can happen
	// between the check and the write that follows while mu is held).
	current := func() bool { return h.deliveryGenLocked(&tmpl) == gen }
	finish := func() {
		for _, u := range rep.Units {
			delivered.Status[u.Unit] = u
		}
		h.saveDelivered(id, delivered)
	}
	stale := func(from int) {
		for _, o := range outs[from:] {
			rep.Units = append(rep.Units, UnitResult{Unit: fileUnit(o.file.Name), Skipped: SkipSuperseded, At: now})
		}
	}

	// Files.
	for i, o := range outs {
		u := UnitResult{Unit: fileUnit(o.file.Name), At: now}
		switch {
		case o.skip != "":
			if opt.lifecycle && o.people && !fileExists(h.dataFilePath(id, o.file.Name)) {
				finish()
				return rep, false, statusErr(503, "data file %s of %s needs the directory and was never delivered: not starting while the directory is unavailable (%s)", o.file.Name, id, h.redactUnitError(id, merr))
			}
			u.Skipped = o.skip
		case o.err != nil:
			u.Error = h.redactUnitError(id, o.err)
			if opt.lifecycle {
				rep.Units = append(rep.Units, u)
				finish()
				return rep, false, statusErr(500, "data file %s of %s: %s", o.file.Name, id, u.Error)
			}
		case delivered.Hashes[u.Unit] == o.hash && h.fileOnDisk(id, o):
			u.OK, u.Skipped = true, SkipUnchanged
		default:
			h.mu.RLock()
			if !current() {
				h.mu.RUnlock()
				stale(i)
				finish()
				return rep, true, nil
			}
			werr := h.writeDataFile(id, o)
			h.mu.RUnlock()
			if werr != nil {
				u.Error = h.redactUnitError(id, werr)
				if opt.lifecycle {
					rep.Units = append(rep.Units, u)
					finish()
					return rep, false, statusErr(500, "data file %s of %s: %s", o.file.Name, id, u.Error)
				}
				break
			}
			u.OK = true
			delivered.Hashes[u.Unit] = o.hash
			if trig == TriggerMembership || trig == TriggerRetry {
				effects = append(effects, membershipEffect(o.file.OnMembershipChange))
			}
		}
		rep.Units = append(rep.Units, u)
	}

	if opt.lifecycle {
		// TriggerStart: compose up follows; never a reload or restart.
		finish()
		return rep, false, nil
	}

	// Group records in the env, re-rendered against this run's snapshot
	// (a write without one — directory down — delivered none).
	if hasGroupEnv(&tmpl) {
		u := UnitResult{Unit: unitEnv, At: now}
		if m == nil {
			u.Skipped = SkipDirectory
		} else {
			changed, stop, eerr := h.refreshGroupEnv(&tmpl, gen, m)
			switch {
			case stop:
				finish()
				return rep, true, nil
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
	}

	// The strongest effect: one reload or one restart per run.
	switch settings.Strongest(effects...) {
	case settings.EffectRestart:
		h.mu.RLock()
		ok := current()
		h.mu.RUnlock()
		if !ok {
			finish()
			return rep, true, nil
		}
		restartTmpl := tmpl
		h.goBackground(func() { h.Restart(restartTmpl) })
		rep.Units = append(rep.Units, UnitResult{Unit: unitRestart, OK: true, Message: "restart queued", At: now})
	case settings.EffectReload:
		rep.Units = append(rep.Units, h.reloadUnit(ctx, &tmpl))
	}
	finish()
	return rep, false, nil
}

// membershipEffect is what a data file's on_membership_change does when
// a membership delivery changed it (hook: Task 10).
func membershipEffect(on string) string {
	switch on {
	case templates.MembershipRestart:
		return settings.EffectRestart
	case templates.MembershipReload:
		return settings.EffectReload
	}
	return settings.EffectNone
}

// refreshGroupEnv rewrites instance t's option env with snapshot m when
// the generation is still gen; changed: the .env changed (compose reads
// it at create: a restart). stop: superseded.
func (h *Hub) refreshGroupEnv(t *templates.Template, gen string, m *directory.Membership) (changed, stop bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	live := h.findLocked(t.ID)
	if live == nil || h.deliveryGenLocked(live) != gen {
		return false, true, nil
	}
	before, _ := os.ReadFile(h.envPath(t.ID))
	if err := h.writeOptionEnvLocked(live, m); err != nil {
		return false, false, err
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
