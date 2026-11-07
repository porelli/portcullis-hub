package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// Step states (contract §11.7 "The op record").
const (
	StepWaiting = "waiting"
	StepRunning = "running"
	StepDone    = "done"
	StepFailed  = "failed"
	StepStopped = "stopped" // cut short by a Stop or by a Hub stop
	StepUndone  = "undone"  // its effect reversed by a Stop's undo
)

// UndoPrefix starts the key of every undo step a Stop appends
// ("undo:down", "undo:volumes", …).
const UndoPrefix = "undo:"

// Kinds of Created entries (Progress.Created).
const (
	CreatedVolumes         = "volumes"
	CreatedKeycloakClients = "keycloak_clients"
	CreatedGroups          = "groups"
)

// progressThrottle: a running step's percent and detail are written at
// most this often (contract §11.7); every other change at once.
const progressThrottle = 500 * time.Millisecond

// detailMax clips a step's detail (one line, redacted first).
const detailMax = 300

// Step is one step of an operation's op record.
type Step struct {
	Key       string     `json:"key"`
	Label     string     `json:"label"`
	State     string     `json:"state"`
	Percent   *int       `json:"percent,omitempty"`
	Detail    string     `json:"detail,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

// Created is what an operation made, written as it happens: a Stop
// undoes exactly these entries (nothing is inferred at Stop time).
type Created struct {
	Volumes         []string `json:"volumes"`
	KeycloakClients []string `json:"keycloak_clients"`
	Groups          []string `json:"groups"`
}

// MarshalJSON writes the three lists always, possibly empty.
func (c Created) MarshalJSON() ([]byte, error) {
	type plain Created
	p := plain(c)
	for _, l := range []*[]string{&p.Volumes, &p.KeycloakClients, &p.Groups} {
		if *l == nil {
			*l = []string{}
		}
	}
	return json.Marshal(p)
}

func (c *Created) clone() *Created {
	if c == nil {
		return nil
	}
	return &Created{Volumes: slices.Clone(c.Volumes), KeycloakClients: slices.Clone(c.KeycloakClients), Groups: slices.Clone(c.Groups)}
}

// Progress reports an operation's steps into its op record (recordOp:
// memory and <data>/ops/<id>.json). A nil *Progress is valid: every
// method is a no-op (progressFrom of a context without one).
//
// Nothing is written before the operation is accepted (startAsync's
// ready): a refusal leaves no record. Details are redacted with the
// instance's secretRedactor when written; so, like finishOp, its methods
// must never be called with h.mu held.
type Progress struct {
	h      *Hub
	id, op string

	mu sync.Mutex
	// rec is the running record, details unredacted (only written
	// copies are redacted).
	rec    OpRecord
	live   bool // accepted: changes are written
	closed bool // ended: nothing is written any more
	// cancel cancels the operation's context (cancelOp).
	cancel context.CancelFunc
	// stopper: the admin whose Stop was accepted (cancelOp; with via /
	// client) — the undo acts as them (an enable's undo:groups).
	stopper directory.Actor
	// The percent throttle.
	lastWrite  time.Time
	dirty      bool
	flushArmed bool
	// extra: the values the errors it was given carry for redaction
	// (secretsOf: a restore's archive secrets), redacted from every
	// detail together with the instance's set.
	extra []string
}

// newProgress is the reporter for op on id with its planned steps (each
// "waiting" unless set). steps nil: an operation that reports no
// progress and can't be stopped.
func (h *Hub) newProgress(id, op string, steps []Step) *Progress {
	p := &Progress{h: h, id: id, op: op}
	p.rec.Op = op
	if steps != nil {
		p.rec.Steps = make([]Step, len(steps))
		copy(p.rec.Steps, steps)
		for i := range p.rec.Steps {
			if p.rec.Steps[i].State == "" {
				p.rec.Steps[i].State = StepWaiting
			}
		}
		p.rec.Created = &Created{}
		p.rec.Stoppable = true
	}
	return p
}

type progressKey struct{}

// withProgress is ctx carrying p.
func withProgress(ctx context.Context, p *Progress) context.Context {
	return context.WithValue(ctx, progressKey{}, p)
}

// progressFrom is the operation's reporter in ctx (nil: none; its
// methods are then no-ops).
func progressFrom(ctx context.Context) *Progress {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(progressKey{}).(*Progress)
	return p
}

func (p *Progress) now() time.Time {
	if p.h != nil && p.h.progressNow != nil {
		return p.h.progressNow().UTC()
	}
	return time.Now().UTC()
}

// stepLocked is key's step; add: append it (label = key) when missing.
func (p *Progress) stepLocked(key string, add bool) *Step {
	for i := range p.rec.Steps {
		if p.rec.Steps[i].Key == key {
			return &p.rec.Steps[i]
		}
	}
	if !add {
		return nil
	}
	p.rec.Steps = append(p.rec.Steps, Step{Key: key, Label: key, State: StepWaiting})
	return &p.rec.Steps[len(p.rec.Steps)-1]
}

// frozen: a step a Stop (or the undo) already settled — the forward
// work still unwinding never changes it again.
func frozen(s *Step) bool { return s.State == StepStopped || s.State == StepUndone }

// AddStep appends a waiting step (an undo step, "undo:<name>") unless
// key is listed.
func (p *Progress) AddStep(key, label string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stepLocked(key, false) != nil {
		return
	}
	s := p.stepLocked(key, true)
	if label != "" {
		s.Label = label
	}
	p.writeLocked()
}

// Start marks key running (appended when not planned).
func (p *Progress) Start(key string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	s := p.stepLocked(key, true)
	if !frozen(s) {
		t := p.now()
		s.State, s.StartedAt, s.EndedAt, s.Percent, s.Detail = StepRunning, &t, nil, nil, ""
		p.writeLocked()
	}
	p.mu.Unlock()
	if p.h != nil && p.h.testHookStepStart != nil {
		p.h.testHookStepStart(p.op, key)
	}
}

// Percent sets a running step's percentage (clamped to 0–100) and its
// one-line detail; written at most every progressThrottle (the last
// value is flushed after it).
func (p *Progress) Percent(key string, pct int, detail string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stepLocked(key, false)
	if s == nil || (s.State != StepRunning && s.State != StepWaiting) {
		return
	}
	pct = min(max(pct, 0), 100)
	s.Percent, s.Detail = &pct, detail
	if s.State == StepWaiting {
		// A change of state is written at once; only the percent and
		// detail of a running step are throttled.
		t := p.now()
		s.State, s.StartedAt = StepRunning, &t
		p.writeLocked()
		return
	}
	p.throttledLocked()
}

// Detail sets a step's one-line detail (no percent), written at once.
func (p *Progress) Detail(key, detail string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.stepLocked(key, false); s != nil && !frozen(s) {
		s.Detail = detail
		p.writeLocked()
	}
}

// planned is p when key is one of its steps, else nil (a nil reporter's
// methods are no-ops): code shared by several operations reports a step
// only into the one that planned it (Start would append it).
func (p *Progress) planned(key string) *Progress {
	if p.Has(key) {
		return p
	}
	return nil
}

// stopActor is the admin whose Stop was accepted.
func (p *Progress) stopActor() directory.Actor {
	if p == nil {
		return directory.Actor{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopper
}

// snapshot is a copy of the running record (steps and created cloned,
// details unredacted).
func (p *Progress) snapshot() OpRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rec
	r.Created = p.rec.Created.clone()
	r.Steps = slices.Clone(p.rec.Steps)
	return r
}

// Done marks key done (a measured step at 100 %).
func (p *Progress) Done(key string) {
	if p == nil {
		return
	}
	p.endLocked(key, StepDone, nil)
}

// Fail marks key failed; err's text is its detail.
func (p *Progress) Fail(key string, err error) {
	if p == nil {
		return
	}
	p.endLocked(key, StepFailed, err)
}

// Undone marks a forward step whose effect an undo step reversed.
func (p *Progress) Undone(key string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.stepLocked(key, false); s != nil {
		s.State = StepUndone
		p.writeLocked()
	}
}

func (p *Progress) endLocked(key, state string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stepLocked(key, true)
	if frozen(s) {
		return
	}
	t := p.now()
	if s.StartedAt == nil {
		s.StartedAt = &t
	}
	s.State, s.EndedAt = state, &t
	if state == StepDone && s.Percent != nil {
		hundred := 100
		s.Percent = &hundred
	}
	if err != nil {
		p.extra = append(p.extra, secretsOf(err)...)
		s.Detail = err.Error()
	}
	p.writeLocked()
}

// Has: key is one of the operation's steps (planned or added).
func (p *Progress) Has(key string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stepLocked(key, false) != nil
}

// Warn adds a warning to the operation's record, written at once and
// kept in its final record after the operation's own warnings (once
// each; redacted like the details).
func (p *Progress) Warn(text string) {
	if p == nil || text == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if slices.Contains(p.rec.Warnings, text) {
		return
	}
	p.rec.Warnings = append(p.rec.Warnings, text)
	p.writeLocked()
}

// Created records something the operation made (kind CreatedVolumes,
// CreatedKeycloakClients or CreatedGroups), persisted at once: a Stop —
// also of an interrupted operation — undoes exactly these.
func (p *Progress) Created(kind, name string) {
	if p == nil || name == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rec.Created == nil {
		p.rec.Created = &Created{}
	}
	var l *[]string
	switch kind {
	case CreatedVolumes:
		l = &p.rec.Created.Volumes
	case CreatedKeycloakClients:
		l = &p.rec.Created.KeycloakClients
	case CreatedGroups:
		l = &p.rec.Created.Groups
	default:
		log.Printf("ops: %s %s: unknown created kind %q (%s)", p.op, p.id, kind, name)
		return
	}
	if slices.Contains(*l, name) {
		return
	}
	*l = append(*l, name)
	p.writeLocked()
}

// NoReturn marks the operation past its point of no return
// (point_of_no_return true, stoppable false). When a Stop was accepted
// first it changes nothing: cancelOp cancels the context under the same
// lock, so a caller checks ctx.Err() right after NoReturn and undoes
// instead of going on.
func (p *Progress) NoReturn() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rec.Stopping {
		return
	}
	p.rec.PointOfNoReturn, p.rec.Stoppable = true, false
	p.writeLocked()
}

// Stopping: a Stop was accepted (the operation runs its undo).
func (p *Progress) Stopping() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rec.Stopping
}

// throttledLocked writes now when the last write is progressThrottle
// old, else once that much has passed.
func (p *Progress) throttledLocked() {
	if !p.live || p.closed {
		return
	}
	wait := progressThrottle - p.now().Sub(p.lastWrite)
	if wait <= 0 {
		p.writeLocked()
		return
	}
	p.dirty = true
	if p.flushArmed {
		return
	}
	p.flushArmed = true
	after := realAfterFunc
	if p.h != nil && p.h.afterFunc != nil {
		after = p.h.afterFunc
	}
	after(wait, p.flush)
}

func (p *Progress) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushArmed = false
	if p.dirty {
		p.writeLocked()
	}
}

// writeLocked stores the record (redacted) once the operation is
// accepted and until it ended.
func (p *Progress) writeLocked() {
	if !p.live || p.closed {
		return
	}
	// Never over another operation's running record (finish).
	p.h.recordOpUnlessOther(p.id, p.recordLocked())
	p.lastWrite, p.dirty = p.now(), false
}

// recordLocked is the record as written: a copy whose step details are
// redacted (secretRedactor, then one line, then clipped).
func (p *Progress) recordLocked() OpRecord {
	r := p.rec
	r.Created = p.rec.Created.clone()
	if p.rec.Steps != nil {
		r.Steps = make([]Step, len(p.rec.Steps))
		copy(r.Steps, p.rec.Steps)
	}
	var redact func(string) string
	if p.rec.Warnings != nil {
		r.Warnings = make([]string, len(p.rec.Warnings))
		redact = p.h.secretRedactor(p.id, p.extra)
		for i, w := range p.rec.Warnings {
			r.Warnings[i] = clipRunes(redact(w), 600)
		}
	}
	for i := range r.Steps {
		s := &r.Steps[i]
		if s.Percent != nil {
			v := *s.Percent
			s.Percent = &v
		}
		if s.Detail == "" {
			continue
		}
		if redact == nil {
			redact = p.h.secretRedactor(p.id, p.extra)
		}
		s.Detail = clipRunes(oneLine(redact(s.Detail)), detailMax)
	}
	return r
}

// oneLine joins s's lines with spaces.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), " ")
}

// begin accepts the operation: running since now, written from here on.
func (p *Progress) begin(opID, actor string, cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rec.OpID, p.rec.Actor, p.rec.At, p.rec.Running = opID, actor, p.now(), true
	p.cancel = cancel
	p.live = true
	// The lock is held: this operation's record replaces whatever is
	// there (a finished one, or one an earlier operation is still
	// writing after its lock release).
	p.h.recordOp(p.id, p.recordLocked())
	p.lastWrite = p.now()
}

// finish merges the operation's progress into its final record r and
// writes it; nothing is written after it. Steps still running end
// stopped (a Stop was accepted) or failed (an error); an operation that
// stopped (contract §11.7 "Stopped") is ok false with no error, one
// whose undo failed keeps the error and stays stoppable.
func (p *Progress) finish(r OpRecord, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.recordLocked()
	stopping := cur.Stopping
	stopped := stopping && isStopErr(err)
	undoFailed := stopping && err != nil && !stopped
	end := p.now()
	for i := range cur.Steps {
		s := &cur.Steps[i]
		if s.State != StepRunning {
			continue
		}
		switch {
		case stopping && !strings.HasPrefix(s.Key, UndoPrefix):
			s.State = StepStopped
		case err != nil && !stopped:
			s.State = StepFailed
		default:
			s.State = StepDone
		}
		s.EndedAt = &end
	}
	r.OpID, r.Steps, r.Created = cur.OpID, cur.Steps, cur.Created
	for _, w := range cur.Warnings {
		if !slices.Contains(r.Warnings, w) {
			r.Warnings = append(r.Warnings, w)
		}
	}
	r.StoppedBy, r.StoppedAt, r.PointOfNoReturn = cur.StoppedBy, cur.StoppedAt, cur.PointOfNoReturn
	r.Running, r.Stopping, r.Stoppable, r.Interrupted = false, false, false, false
	switch {
	case stopped:
		r.OK, r.Error, r.Output, r.Hint, r.Status, r.RolledBack = false, "", "", "", 0, false
	case undoFailed:
		// The undo failed: Stop again retries it.
		r.Stoppable = cur.Steps != nil
	}
	p.closed = true
	// fn released the instance's lock before returning: another
	// operation may already have accepted and written its running
	// record. Never overwrite it (its poller and the busy answer read
	// it); this operation's outcome is then only logged.
	if !p.h.recordOpUnlessOther(p.id, r) {
		log.Printf("ops: %s %s (%s) ended (ok=%v %s) after another operation started; its record is kept", p.op, p.id, r.OpID, r.OK, r.Error)
	}
}

// stopAccepted: a Stop of this operation was accepted.
func (p *Progress) stopAccepted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rec.StoppedAt != nil
}

// isStopErr: the operation ended because its context was cancelled by
// a Stop (its undo done).
func isStopErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, ErrStopped)
}

// ErrStopped is what an operation returns once a Stop's undo finished
// (as context.Canceled does).
var ErrStopped = statusErr(409, "the operation was stopped")

// opRun is a running operation in the stop registry (Hub.opRuns, keyed
// by the record's key — the instance id): its op id and its reporter
// (whose cancel cancels its context; the stopping actor is the record's
// stopped_by).
type opRun struct {
	opID string
	p    *Progress
}

func (h *Hub) registerOp(key string, run *opRun) {
	h.opRunsMu.Lock()
	defer h.opRunsMu.Unlock()
	if h.opRuns == nil {
		h.opRuns = map[string]*opRun{}
	}
	h.opRuns[key] = run
}

func (h *Hub) unregisterOp(key string, run *opRun) {
	h.opRunsMu.Lock()
	defer h.opRunsMu.Unlock()
	if h.opRuns[key] == run {
		delete(h.opRuns, key)
	}
}

// cancelOp accepts a Stop of id's running operation by actor: the
// record gets stopping, stopped_by and stopped_at, its running steps
// become stopped, and the operation's context is cancelled (it then
// runs its undo). 409 when nothing runs, when the operation is past its
// point of no return, when it can't be stopped or is already stopping;
// 401 without an actor. The HTTP route and the audit are StopOp's.
func (h *Hub) cancelOp(id string, actor directory.Actor) error {
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	h.opRunsMu.Lock()
	run := h.opRuns[id]
	h.opRunsMu.Unlock()
	if run == nil {
		return statusErr(409, "no operation is running on %s", id)
	}
	p := run.p
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.live || p.closed || !p.rec.Running:
		return statusErr(409, "no operation is running on %s", id)
	case p.rec.Stopping:
		return statusErr(409, "the %s of %s is already stopping", p.op, id)
	case p.rec.PointOfNoReturn:
		return statusErr(409, "the %s of %s is past the point of no return — finishing", p.op, id)
	case !p.rec.Stoppable:
		return statusErr(409, "the %s of %s can't be stopped", p.op, id)
	}
	t := p.now()
	p.rec.Stopping, p.rec.Stoppable, p.rec.StoppedBy, p.rec.StoppedAt = true, false, actor.User, &t
	p.stopper = actor
	for i := range p.rec.Steps {
		if s := &p.rec.Steps[i]; s.State == StepRunning {
			s.State, s.EndedAt = StepStopped, &t
		}
	}
	p.writeLocked()
	// Under p.mu: a NoReturn after this sees Stopping, one before it was
	// refused above.
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}
