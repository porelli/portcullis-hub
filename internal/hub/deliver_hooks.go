package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Settings hooks (contract §13.8): a declared argv run with Docker exec
// in a running container of the hook's service (this instance's project
// only, replica 1 preferred — runningContainer, shared with Exec), never
// through a shell, with the hook's full desired state (settings.HookInput:
// every value, person, group record and secret the hook receives, never a
// diff) as JSON on stdin. Secrets reach the hook only there: never on
// argv, in env, logs, op records or errors (its output is redacted, then
// clipped). Exit 0 = applied; anything else is a failure, recorded as the
// instance's op record (op hook, never over another operation's running
// record: P20) and retried on the next trigger the hook declares (its
// hash is recorded only after a success); TriggerRetry re-runs every hook.
//
// Runs are serialised per instance: a run holds deliverLock (Deliver, or
// composeUp's start hooks under the lifecycle lock: lockApp →
// deliverLock). Docker exec can't kill a timed-out process: the next run
// waits until that exec reports not running (ExecRunning polled every
// hookPoll, up to the hook's timeout), else it is skipped ("previous run
// still running") and re-queued.
//
// Which hooks run: those whose `when` has the run's trigger and whose
// input changed (or whose last run failed or was skipped); every one on
// TriggerRetry; on start every hook declaring start; on a membership
// change also those declaring membership_change when a data file with
// on_membership_change: hook changed; and the reload hook when the run
// owes a reload (folded: it runs once).

const (
	// hookPoll: how often a timed-out exec is checked.
	hookPoll = time.Second
	// SkipPrevRunning: a timed-out run of the instance still runs.
	SkipPrevRunning = "previous run still running"
)

func hookUnit(name string) string { return "hook:" + name }

// hookWhen is the hooks[].when value of trig ("" for a retry).
func hookWhen(trig Trigger) string {
	switch trig {
	case TriggerStart:
		return templates.HookStart
	case TriggerSave:
		return templates.HookSettingsChange
	case TriggerMembership:
		return templates.HookMembershipChange
	}
	return ""
}

// hookDeliveries are o's deliveries to hook name.
func hookDeliveries(o *templates.Option, name string) []templates.Delivery {
	var out []templates.Delivery
	for _, d := range o.Delivery {
		if d.Hook == name {
			out = append(out, d)
		}
	}
	return out
}

func hookTarget(name string) docTarget {
	return docTarget{
		deliveries: func(o *templates.Option) []templates.Delivery { return hookDeliveries(o, name) },
		field:      func(*templates.Delivery) string { return "" },
	}
}

// hookNeedsPeople: hook name receives per-person, per-group or
// person-entered values.
func hookNeedsPeople(t *templates.Template, name string) bool {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].EffectiveScope() != templates.ScopeInstance && len(hookDeliveries(&opts[i], name)) > 0 {
			return true
		}
	}
	return false
}

// hooksNeedPeople: some hook of t needs the directory.
func hooksNeedPeople(t *templates.Template) bool {
	for _, hk := range t.Manifest.Hooks {
		if hookNeedsPeople(t, hk.Name) {
			return true
		}
	}
	return false
}

// hookOutput is one hook's desired input (Trigger set when it runs).
type hookOutput struct {
	hook  templates.Hook
	input settings.HookInput
	hash  string // of the input without trigger and secret values
	skip  string // SkipDirectory: not built
	err   error
}

// sortedHooks are t's hooks by name.
func sortedHooks(t *templates.Template) []templates.Hook {
	hs := slices.Clone(t.Manifest.Hooks)
	slices.SortFunc(hs, func(a, b templates.Hook) int { return strings.Compare(a.Name, b.Name) })
	return hs
}

// buildHooksLocked renders every hook's input of t from state and
// snapshot m (nil: hooks that need people are skipped). Caller holds mu
// (read).
func (h *Hub) buildHooksLocked(t *templates.Template, m *directory.Membership) []hookOutput {
	var out []hookOutput
	var people map[string]map[string]settings.Resolved
	var secrets map[string]string
	var secretsErr error
	secretsRead := false
	s := h.st.Settings[t.ID]
	for _, hk := range sortedHooks(t) {
		o := hookOutput{hook: hk}
		needPeople := hookNeedsPeople(t, hk.Name)
		if needPeople && m == nil {
			o.skip = SkipDirectory
			out = append(out, o)
			continue
		}
		if needPeople && people == nil {
			people = h.resolvePeopleLocked(t, m)
		}
		if !secretsRead {
			secrets, secretsErr = h.secretValues(t.ID)
			secretsRead = true
		}
		if secretsErr != nil {
			o.err = secretsErr
			out = append(out, o)
			continue
		}
		doc, sec, err := h.renderDocLocked(t, hookTarget(hk.Name), m, people, secrets)
		if err != nil {
			o.err = err
			out = append(out, o)
			continue
		}
		if sec == nil {
			sec = map[string]string{}
		}
		o.input = settings.HookInput{DataFileDoc: doc, Secrets: sec}
		// The hash: the document plus when each sent secret was last set —
		// never a secret value (delivered.json).
		meta := map[string]time.Time{}
		for k := range sec {
			meta[k] = s.Secrets[k].UpdatedAt
		}
		b, err := json.Marshal(struct {
			Doc     settings.DataFileDoc
			Secrets map[string]time.Time
			Hook    templates.Hook
		}{doc, meta, hk})
		if err != nil {
			o.err = errors.New("the hook input could not be encoded")
			out = append(out, o)
			continue
		}
		sum := sha256.Sum256(b)
		o.hash = hex.EncodeToString(sum[:])
		out = append(out, o)
	}
	return out
}

// hookStep is a run's hook deliveries (under deliverLock, never mu).
// force: hooks that run whatever their when and hash (the trigger they
// get: the run's, else the one they last ran for, else their first
// when); forceWhen: also run every hook declaring that trigger. current
// (nil: never superseded) re-checks the run's generation before each
// exec. ran: each run hook's result.
type hookStep struct {
	id        string
	trig      Trigger
	outs      []hookOutput
	force     map[string]bool
	forceWhen string
	current   func() bool
	delivered *deliveredDoc
	now       time.Time
}

// runHooks runs step; superseded: a newer commit came before an exec;
// requeue: a hook was skipped because a timed-out run still runs.
func (h *Hub) runHooks(ctx context.Context, t *templates.Template, step hookStep) (units []UnitResult, ran map[string]UnitResult, superseded, requeue bool) {
	ran = map[string]UnitResult{}
	want := hookWhen(step.trig)
	for _, o := range step.outs {
		hk := o.hook
		unit := hookUnit(hk.Name)
		declared := want != "" && slices.Contains(hk.When, want)
		forced := step.trig == TriggerRetry || step.force[hk.Name] ||
			(step.forceWhen != "" && slices.Contains(hk.When, step.forceWhen)) ||
			(declared && step.trig == TriggerStart)
		pending := o.hash == "" || step.delivered.Hashes[unit] != o.hash
		u := UnitResult{Unit: unit, At: step.now}
		switch {
		case !forced && !(declared && pending):
			if declared {
				u.OK, u.Skipped = true, SkipUnchanged
				units = append(units, u)
			}
			// Not declared for this trigger: its last status stays.
			continue
		case o.skip != "":
			u.Skipped = o.skip
		case o.err != nil:
			u.Error = h.redactUnitError(step.id, o.err)
		default:
			if step.current != nil {
				h.mu.RLock()
				ok := step.current()
				h.mu.RUnlock()
				if !ok {
					return units, ran, true, requeue
				}
			}
			in := o.input
			switch {
			case declared:
				in.Trigger = want
			case step.forceWhen != "" && slices.Contains(hk.When, step.forceWhen):
				in.Trigger = step.forceWhen
			case want != "":
				in.Trigger = want // the reload hook
			case step.delivered.Triggers[unit] != "":
				in.Trigger = step.delivered.Triggers[unit]
			case len(hk.When) > 0:
				in.Trigger = hk.When[0]
			}
			u = h.runHook(ctx, t, hk, in)
			step.delivered.Triggers[unit] = in.Trigger
			switch {
			case u.OK:
				step.delivered.Hashes[unit] = o.hash
			case u.Skipped == SkipPrevRunning:
				requeue = true
			case u.Skipped == "":
				// Failed: retried on the next trigger even when unchanged.
				delete(step.delivered.Hashes, unit)
			}
		}
		ran[hk.Name] = u
		units = append(units, u)
	}
	return units, ran, false, requeue
}

// runHook runs hook hk of instance t once with input in (under
// deliverLock): in a running container of hk.Service, argv as declared,
// in as JSON on stdin. A failure (exit ≠ 0, timeout, Docker error) is
// the unit's error and the op record (op hook), both redacted, then
// clipped.
func (h *Hub) runHook(ctx context.Context, t *templates.Template, hk templates.Hook, in settings.HookInput) UnitResult {
	u := UnitResult{Unit: hookUnit(hk.Name), At: time.Now().UTC()}
	if h.engine == nil {
		u.Skipped = SkipNotRunning
		return u
	}
	sent := make([]string, 0, len(in.Secrets))
	for _, v := range in.Secrets {
		sent = append(sent, v)
	}
	fail := func(err error) UnitResult {
		err = withSecrets(err, sent)
		u.Error = h.redactUnitError(t.ID, err)
		h.finishDeliveryOp(t.ID, OpHook, err)
		return u
	}
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return fail(fmt.Errorf("hook %s: listing the %s containers: %w", hk.Name, hk.Service, err))
	}
	c := runningContainer(cs, hk.Service)
	if c == nil {
		u.Skipped = SkipNotRunning
		return u
	}
	timeout := hk.EffectiveTimeout()
	if !h.waitPreviousHook(ctx, t.ID, timeout) {
		u.Skipped = SkipPrevRunning
		return u
	}
	stdin, err := json.Marshal(in)
	if err != nil {
		return fail(fmt.Errorf("hook %s: the input could not be encoded", hk.Name))
	}
	res, err := h.engine.ExecStdin(ctx, c.ID, docker.ExecInput{Cmd: slices.Clone(hk.Command), User: hk.User, Stdin: append(stdin, '\n'), Timeout: timeout})
	if res != nil && res.TimedOut && res.ExecID != "" {
		h.deliveryMu.Lock()
		if h.hookExecs == nil {
			h.hookExecs = map[string]string{}
		}
		h.hookExecs[t.ID] = res.ExecID
		h.deliveryMu.Unlock()
	}
	output := func() string {
		if res == nil || len(res.Output) == 0 {
			return ""
		}
		s := string(res.Output)
		if res.Truncated {
			s += "\n[output truncated]"
		}
		return ": output: " + s
	}
	switch {
	case err != nil:
		return fail(fmt.Errorf("hook %s: %w%s", hk.Name, err, output()))
	case res.TimedOut:
		return fail(fmt.Errorf("hook %s: timed out after %s (the process may still run)%s", hk.Name, timeout, output()))
	case res.ExitCode != 0:
		return fail(fmt.Errorf("hook %s: exited %d%s", hk.Name, res.ExitCode, output()))
	}
	u.OK, u.Message = true, "applied (exit 0)"
	if last := h.LastOp(t.ID); last != nil && last.Op == OpHook && !last.OK && strings.HasPrefix(last.Error, "hook "+hk.Name+":") {
		// The failure it recorded is over.
		h.finishDeliveryOp(t.ID, OpHook, nil)
	}
	return u
}

// waitPreviousHook: instance id has no timed-out hook exec still running
// — waiting for one up to timeout (ExecRunning every hookPoll).
func (h *Hub) waitPreviousHook(ctx context.Context, id string, timeout time.Duration) bool {
	h.deliveryMu.Lock()
	execID := h.hookExecs[id]
	h.deliveryMu.Unlock()
	if execID == "" {
		return true
	}
	polls := int(timeout / hookPoll)
	for i := 0; ; i++ {
		running, err := h.engine.ExecRunning(ctx, execID)
		if (err == nil && !running) || docker.IsNotFound(err) {
			h.deliveryMu.Lock()
			if h.hookExecs[id] == execID {
				delete(h.hookExecs, id)
			}
			h.deliveryMu.Unlock()
			return true
		}
		if i >= polls {
			log.Printf("settings: %s: the hook run that timed out is still running (exec %s)", id, execID)
			return false
		}
		if h.sleep(ctx, hookPoll) != nil {
			return false
		}
	}
}

// runStartHooks runs instance id's start hooks after a successful compose
// up (composeUp, under the lifecycle lock; lockApp → deliverLock). A
// failure is reported (status) and op-recorded — the up is not rolled
// back, and the lifecycle operation's success keeps that record. A hook
// skipped because a timed-out run still runs is re-queued.
func (h *Hub) runStartHooks(ctx context.Context, id string) {
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil || len(t.Manifest.Hooks) == 0 {
		h.mu.RUnlock()
		return
	}
	tmpl := *t
	h.mu.RUnlock()
	start := false
	for _, hk := range tmpl.Manifest.Hooks {
		start = start || slices.Contains(hk.When, templates.HookStart)
	}
	if !start {
		return
	}
	l := h.deliverLock(id)
	l.Lock()
	defer l.Unlock()
	var m *directory.Membership
	if hooksNeedPeople(&tmpl) {
		mctx, cancel := context.WithTimeout(ctx, groupSnapshotTimeout)
		var err error
		if m, err = h.membership(mctx); err != nil {
			log.Printf("settings: %s: WARNING: directory unavailable (%v): start hooks that need people are skipped", id, err)
		}
		cancel()
	}
	h.mu.RLock()
	if live := h.findLocked(id); live != nil {
		tmpl = *live
	}
	outs := h.buildHooksLocked(&tmpl, m)
	h.mu.RUnlock()
	delivered := h.loadDelivered(id)
	units, _, _, requeue := h.runHooks(ctx, &tmpl, hookStep{id: id, trig: TriggerStart, outs: outs, delivered: &delivered, now: time.Now().UTC()})
	failed := false
	for _, u := range units {
		delivered.Status[u.Unit] = u
		failed = failed || (!u.OK && u.Skipped == "")
	}
	h.saveDelivered(id, delivered)
	if failed {
		h.opsMu.Lock()
		if r, ok := h.ops[id]; ok && r.Op == OpHook && !r.OK && !r.Running {
			if h.startHookFailed == nil {
				h.startHookFailed = map[string]bool{}
			}
			h.startHookFailed[id] = true
		}
		h.opsMu.Unlock()
	}
	if requeue {
		h.queueDelivery(id, TriggerStart, settings.EffectNone, busyRetry)
	}
}
