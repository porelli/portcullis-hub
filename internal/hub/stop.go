package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Enable in the background and Stop (contract §11.7 "Long operations",
// "Stop"). StartEnable answers once the enable is validated, its groups'
// actor resolved and the instance's lock held; the enable then reports
// its steps (groups, keycloak, images, create, start, healthy, settings)
// and keeps its Created ledger (each group, client and volume it made,
// written the moment it exists). StopOp cancels it — a running compose
// is killed — and the enable runs its undo, still holding the lock:
// compose down, then exactly the ledger's volumes, Keycloak clients and
// groups. A record whose undo failed, or one the Hub stopped in the
// middle (interrupted), is undone by StopOp from the persisted record.

// BusyError is the refusal of an operation on an instance whose lock is
// held by a recorded operation: Record is that running op record (the
// 409 body, so the client shows the running operation). It unwraps to
// ErrBusy (errStatus 409; callers matching ErrBusy keep working).
type BusyError struct {
	ID     string
	Record *OpRecord
}

func (e *BusyError) Error() string { return ErrBusy{ID: e.ID}.Error() }
func (e *BusyError) Unwrap() error { return ErrBusy{ID: e.ID} }

// busyErr is err, as a *BusyError when it is ErrBusy and id's record is
// a running operation's (else unchanged: a lock held by work that keeps
// no record, a shared-folder apply, stays the plain busy refusal).
func (h *Hub) busyErr(id string, err error) error {
	var b ErrBusy
	if !errors.As(err, &b) {
		return err
	}
	if r := h.LastOp(id); r != nil && r.Running {
		return &BusyError{ID: id, Record: r}
	}
	return err
}

// Undo step keys of an enable (contract §11.7 "Enable", in order).
const (
	UndoDown     = UndoPrefix + "down"
	UndoVolumes  = UndoPrefix + "volumes"
	UndoKeycloak = UndoPrefix + "keycloak"
	UndoGroups   = UndoPrefix + "groups"
)

// enablePlan is id's enable steps: groups when the instance has any,
// keycloak when Keycloak is wired, then the start's. An instance enabled
// already only checks its groups.
func (h *Hub) enablePlan(id string) []Step {
	h.mu.RLock()
	var groups bool
	if t := h.findLocked(id); t != nil {
		groups = len(instanceGroups(t)) > 0
	}
	enabled := h.st.IsEnabled(id)
	idp := h.idp != nil
	h.mu.RUnlock()
	var steps []Step
	if groups {
		steps = append(steps, Step{Key: StepGroups, Label: "Groups"})
	}
	if enabled {
		return steps
	}
	if idp {
		steps = append(steps, Step{Key: StepKeycloak, Label: "Sign-in client in Keycloak"})
	}
	return append(steps,
		Step{Key: StepImages, Label: "Downloading images"},
		Step{Key: StepCreate, Label: "Creating containers"},
		Step{Key: StepStart, Label: "Starting services"},
		Step{Key: StepHealthy, Label: "Waiting until healthy"},
		Step{Key: StepSettings, Label: "Applying settings"},
	)
}

// StartEnable starts enabling instance id as actor in the background
// (202). Refused at once, nothing recorded: an unknown instance (404), a
// busy one (*BusyError, 409, with the running record), a pending one
// (deleting, restoring, a folder apply), its port and hostname
// collisions (409), and an actor who can't create its missing groups.
// The groups created are the op record's result "groups_created"
// (comma-separated), the warnings its warnings.
func (h *Hub) StartEnable(id string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpEnable, actor, h.enablePlan(id), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		res, err := h.runEnable(ctx, id, actor, ready)
		var result map[string]string
		if len(res.GroupsCreated) > 0 {
			result = map[string]string{"groups_created": strings.Join(res.GroupsCreated, ",")}
		}
		return result, res.Warnings, err
	})
}

// runEnable is the enable StartEnable and EnableAs run: lock, the
// synchronous refusals, ready, the groups, the enable; a Stop accepted
// meanwhile runs the undo (lock still held) and returns ErrStopped, or
// the undo's error. Any other failure is an *OpError (the record:
// compose's output, the hint, rolled_back). res is never nil.
func (h *Hub) runEnable(ctx context.Context, id string, actor directory.Actor, ready func()) (*EnableResult, error) {
	res := &EnableResult{}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, h.busyErr(id, err)
	}
	defer unlock()
	todo, warnings, err := h.enablePrecheck(ctx, id, actor)
	res.Warnings = warnings
	if err != nil {
		return res, err
	}
	ready()
	p := progressFrom(ctx)
	rolledBack, err := h.enableSteps(ctx, p, id, actor, todo, res)
	// An enable that commits closed stopping at its gate (enableInner);
	// one with nothing to commit (enabled already) closes it here: a Stop
	// accepted before is undone, none is accepted after.
	if err == nil && p.CloseStop() {
		return res, nil
	}
	if p.Stopping() {
		if uerr := h.undoEnable(id, p); uerr != nil {
			return res, uerr
		}
		return res, ErrStopped
	}
	var oe *OpError
	if errors.As(err, &oe) {
		return res, err
	}
	return res, &OpError{Record: h.opRecordOf(id, OpEnable, err, rolledBack), Err: err}
}

// enablePrecheck is the enable's refusals before it is accepted: the
// instance known (404), not pending, its ports and hostnames free (409)
// unless it is enabled already, and its groups planned (planGroups: the
// actor resolved when any must be created). Caller holds id's lock.
func (h *Hub) enablePrecheck(ctx context.Context, id string, actor directory.Actor) (todo, warnings []string, err error) {
	h.mu.RLock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.RUnlock()
		return nil, nil, statusErr(404, "app instance not found: %s", id)
	}
	tmpl := *t
	err = h.pendingLocked(id)
	if err == nil && !h.st.IsEnabled(id) {
		if err = h.checkPortCollisionsLocked(&tmpl); err == nil {
			err = h.checkSubdomainCollisionsLocked(&tmpl)
		}
	}
	h.mu.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	if groups := instanceGroups(&tmpl); len(groups) > 0 {
		return h.planGroups(ctx, id, groups, actor)
	}
	return nil, nil, nil
}

// enableSteps is the accepted enable: the groups step, the template's
// starting rows, then enableInner (keycloak and the start's steps).
func (h *Hub) enableSteps(ctx context.Context, p *Progress, id string, actor directory.Actor, todo []string, res *EnableResult) (rolledBack bool, err error) {
	gp := p.planned(StepGroups)
	gp.Start(StepGroups)
	created, w, err := h.createGroups(ctx, p, id, todo, actor)
	res.GroupsCreated, res.Warnings = created, append(res.Warnings, w...)
	if err != nil {
		if !isStopErr(err) {
			gp.Fail(StepGroups, err)
		}
		return false, err
	}
	gp.Detail(StepGroups, groupsDetail(todo, created, h.instanceGroupNames(id)))
	gp.Done(StepGroups)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// The template's starting rows, bound to the groups that now exist
	// (P7: a default instance has no CreateInstance to seed them).
	h.seedSettings(id)
	h.reseedPlaceholderRows(id, res.GroupsCreated)
	res.Warnings = append(res.Warnings, h.bindPlaceholderRows(context.Background(), id)...)
	return h.enableInner(ctx, id, false)
}

func (h *Hub) instanceGroupNames(id string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []string
	if t := h.findLocked(id); t != nil {
		for _, g := range instanceGroups(t) {
			out = append(out, g.Name)
		}
	}
	return out
}

// groupsDetail is the groups step's line: "users_x created; admin_x
// already exists".
func groupsDetail(todo, created, all []string) string {
	var parts []string
	for _, g := range all {
		switch {
		case slices.Contains(created, g):
			parts = append(parts, g+" created")
		case slices.Contains(todo, g):
			parts = append(parts, g+" not created")
		default:
			parts = append(parts, g+" already exists")
		}
	}
	return strings.Join(parts, "; ")
}

// volumeSet is the names of id's project volumes (by the compose
// project label; the Hub's secrets volume never).
func (h *Hub) volumeSet(ctx context.Context, id string) (map[string]bool, error) {
	vs, err := h.engine.ListVolumes(ctx, docker.Filters{"label": {docker.LabelProject + "=" + projectName(id)}})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range vs {
		if v.Labels[docker.LabelProject] == projectName(id) && v.Name != h.cfg.SecretsVolume {
			out[v.Name] = true
		}
	}
	return out, nil
}

// recordExpectedVolumes writes into p's ledger, before compose create,
// every named volume of t's rendered project (loadRendered: not
// external, not the Hub's secrets volume) that isn't in before and
// doesn't exist yet (one that does, without the project's label, is
// someone else's: never in the ledger). A project that doesn't load is
// logged: the after-listing
// (recordCreatedVolumes) still records what the create made.
func (h *Hub) recordExpectedVolumes(ctx context.Context, p *Progress, t *templates.Template, before map[string]bool) {
	proj, err := loadRendered(ctx, h.project(t), h.cfg.ProjectDir)
	if err != nil {
		log.Printf("instance %s: the project's volumes could not be read before the create (%v): only the ones listed after it are recorded", t.ID, clip(h.secretRedactor(t.ID)(err.Error()), 300))
		return
	}
	var names []string
	for key, v := range proj.Volumes {
		if bool(v.External) {
			continue
		}
		name := v.Name
		if name == "" {
			name = proj.Name + "_" + key
		}
		if name != h.cfg.SecretsVolume && !before[name] {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, v := range names {
		// A volume of that name that exists already is no project volume
		// (before lists those): someone else's, never this operation's.
		if _, err := h.engine.InspectVolume(ctx, v); !docker.IsNotFound(err) {
			if err != nil {
				log.Printf("instance %s: volume %s could not be inspected before the create (%v): not recorded unless the create makes it", t.ID, v, err)
			}
			continue
		}
		p.Created(CreatedVolumes, v)
	}
}

// recordCreatedVolumes writes into p's ledger every volume of id's
// project that wasn't in before (the create made it): the
// reconciliation of recordExpectedVolumes (a volume compose makes under
// another name is added; an expected one it didn't make stays — undo
// treats it as removed). Listing them failing is a warning.
func (h *Hub) recordCreatedVolumes(ctx context.Context, p *Progress, id string, before map[string]bool) {
	after, err := h.volumeSet(ctx, id)
	if err != nil {
		log.Printf("instance %s: listing the volumes after the create failed: %v", id, err)
		p.Warn(fmt.Sprintf("the volumes created for %s could not be listed (%v): a Stop leaves them in place", id, err))
		return
	}
	names := make([]string, 0, len(after))
	for v := range after {
		if !before[v] {
			names = append(names, v)
		}
	}
	slices.Sort(names)
	for _, v := range names {
		p.Created(CreatedVolumes, v)
	}
}

// undoStep is one undo step of an operation (undo:<name>).
type undoStep struct {
	key, label string
	// reverses: the forward steps it reverses (undone once it is done,
	// those that ran).
	reverses []string
	run      func() error
}

// undoEnable puts id back as before the enable p reports (contract
// §11.7 "Enable"), from p's record — its steps and Created ledger, never
// inferred: compose down (containers and network; volumes and images
// kept), the ledger's volumes, its Keycloak clients (with their access
// role; only those tagged with id: DeleteClient) and the forward-auth
// callbacks, its groups (as the stopping admin), then the instance not
// enabled (policy and portal rewritten). Each undo step is listed
// before any runs, recorded as it ends, idempotent, and skipped when
// the record shows it done (a retry). The first failure stops it: that
// step failed, the error returned. Caller holds id's lock.
func (h *Hub) undoEnable(id string, p *Progress) error {
	ctx := context.Background()
	rec := p.snapshot()
	stopper := p.stopActor()
	created := rec.Created
	if created == nil {
		created = &Created{}
	}
	ran := func(key string) bool { return stepRan(rec, key) }
	h.mu.RLock()
	var tmpl *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		tmpl = &c
	}
	groupsAPI := h.groups
	h.mu.RUnlock()

	var steps []undoStep
	if ran(StepCreate) || ran(StepStart) || ran(StepHealthy) || ran(StepSettings) {
		steps = append(steps, undoStep{UndoDown, "Removing the containers", []string{StepCreate, StepStart, StepHealthy, StepSettings}, func() error {
			var err error
			if tmpl != nil {
				err = h.rollbackUp(tmpl)
			} else {
				err = h.compose.DownByName(ctx, projectName(id))
			}
			if err != nil {
				return fmt.Errorf("compose down: %w", err)
			}
			return nil
		}})
	}
	if len(created.Volumes) > 0 {
		steps = append(steps, undoStep{UndoVolumes, "Removing the volumes it created", nil, func() error {
			return h.undoVolumes(ctx, p, id, created.Volumes)
		}})
	}
	if len(created.KeycloakClients) > 0 || ran(StepKeycloak) {
		steps = append(steps, undoStep{UndoKeycloak, "Removing the sign-in client", []string{StepKeycloak}, func() error {
			return h.undoKeycloak(ctx, p, id, tmpl, created.KeycloakClients)
		}})
	}
	if len(created.Groups) > 0 {
		steps = append(steps, undoStep{UndoGroups, "Removing the groups it created", []string{StepGroups}, func() error {
			if groupsAPI == nil {
				return statusErr(503, "users & groups is not available: groups %s were not deleted", strings.Join(created.Groups, ", "))
			}
			missing, err := groupsAPI.MissingInstanceGroups(ctx, created.Groups)
			if err != nil {
				return fmt.Errorf("checking groups %s: %w", strings.Join(created.Groups, ", "), err)
			}
			for _, g := range created.Groups {
				if slices.Contains(missing, g) {
					continue // gone already (a retry)
				}
				w, err := groupsAPI.DeleteInstanceGroup(ctx, stopper, g)
				if err != nil {
					return fmt.Errorf("deleting group %s as %s: %w", g, stopper.User, err)
				}
				for _, x := range w {
					// Kept because Users & Groups didn't answer: not
					// done (Stop again retries); kept because it is
					// protected or shared: done, with the warning.
					if directory.KeptUnavailable(x) {
						return statusErr(503, "%s", x)
					}
					p.Warn(x)
				}
			}
			return nil
		}})
	}
	if err := runUndo(p, rec, steps); err != nil {
		return err
	}
	// Not enabled, as before: only an enable that may have committed (its
	// settings step ran, then the Hub stopped) — never an instance that
	// was enabled already (its enable planned no start steps).
	h.mu.Lock()
	wasEnabled := ran(StepSettings) && h.st.IsEnabled(id)
	if wasEnabled {
		h.st.SetEnabled(id, false)
		h.rebuildLocked()
		h.refreshPublishedLocked()
		h.saveLocked()
	}
	h.mu.Unlock()
	if wasEnabled {
		h.writePolicyLogged()
	}
	h.TriggerReconcile()
	return nil
}

// stepState is key's state in rec ("" = not one of its steps).
func stepState(rec OpRecord, key string) string {
	for _, s := range rec.Steps {
		if s.Key == key {
			return s.State
		}
	}
	return ""
}

// stepRan: key is one of rec's steps and it started (any state but
// waiting: a stopped or failed step may have done part of its work).
func stepRan(rec OpRecord, key string) bool {
	st := stepState(rec, key)
	return st != "" && st != StepWaiting
}

// runUndo runs an operation's undo steps into p (rec: the record they
// were planned from): every step listed before any runs, each recorded
// as it ends and skipped when rec shows it done (Stop again), the
// forward steps it reverses that ran then undone. The first failure
// stops it: that step failed, its error returned.
func runUndo(p *Progress, rec OpRecord, steps []undoStep) error {
	for _, u := range steps {
		p.AddStep(u.key, u.label)
	}
	for _, u := range steps {
		if stepState(rec, u.key) == StepDone {
			continue
		}
		p.Start(u.key)
		if err := u.run(); err != nil {
			p.Fail(u.key, err)
			return err
		}
		p.Done(u.key)
		for _, k := range u.reverses {
			if stepRan(rec, k) {
				p.Undone(k)
			}
		}
	}
	return nil
}

// settleOp ends a stoppable operation after its forward work (err its
// outcome): unless a Stop came first, the commit gate is closed
// (CloseStop: a later Stop is refused "finishing") and the operation
// ends as it is — an error as its *OpError; when a Stop was accepted
// its undo runs (the caller still holds the lock) and it returns
// ErrStopped, or the undo's error. Operations whose commit sits inside
// their forward work close the gate there (CloseStop is idempotent).
func (h *Hub) settleOp(id, op string, p *Progress, err error) error {
	if p.CloseStop() {
		var oe *OpError
		if err == nil || errors.As(err, &oe) {
			return err
		}
		return &OpError{Record: h.opRecordOf(id, op, err, false), Err: err}
	}
	if uerr := h.undoerFor(op)(id, p); uerr != nil {
		return uerr
	}
	return ErrStopped
}

// Undo step keys of a disable, a restart and an AI switch (contract
// §11.7 "Stop").
const (
	UndoStart     = UndoPrefix + "start"
	UndoCallbacks = UndoPrefix + "callbacks"
	UndoSwitch    = UndoPrefix + "switch"
)

// undoDisable turns the app back on (contract §11.7 "Disable"), from p's
// record: its extra-domain sign-in callbacks added back when the
// callbacks step ran (what an enable adds), then — the stop step ran —
// the project brought up with its current files while the instance is
// still enabled (a disable stopped before its commit), or the instance
// enabled again exactly like an enable (enableInner: a disable the Hub
// stopped after its commit). Nothing new is created. Caller holds id's
// lock.
func (h *Hub) undoDisable(id string, p *Progress) error {
	ctx := context.Background()
	rec := p.snapshot()
	h.mu.RLock()
	var tmpl *templates.Template
	var callbacks []string
	if t := h.findLocked(id); t != nil {
		c := *t
		tmpl = &c
		callbacks = callbackURIs(h.signInExtraHostsLocked(tmpl))
	}
	idp := h.idp
	h.mu.RUnlock()
	var steps []undoStep
	if stepRan(rec, StepCallbacks) {
		steps = append(steps, undoStep{UndoCallbacks, "Adding the sign-in callbacks back", []string{StepCallbacks}, func() error {
			if len(callbacks) == 0 {
				return nil
			}
			if idp == nil {
				return statusErr(503, "Keycloak is not configured: the %s callbacks of %s were not added back", keycloak.ForwardAuthClient, id)
			}
			if err := idp.UpdateForwardAuthCallbacks(ctx, callbacks, nil); err != nil {
				return &StatusError{Status: 502, Err: fmt.Errorf("Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)}
			}
			return nil
		}})
	}
	if stepRan(rec, StepStop) {
		steps = append(steps, undoStep{UndoStart, "Starting the app again", []string{StepStop}, func() error {
			if tmpl == nil {
				return statusErr(409, "the template of %s is gone: it can't be started again", id)
			}
			if !h.IsEnabled(id) {
				_, err := h.enableInner(ctx, id, false)
				return err
			}
			if err := h.composeUp(ctx, tmpl); err != nil {
				if composeFailed(err) {
					return fmt.Errorf("compose up failed: %w", err)
				}
				return err
			}
			return nil
		}})
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}

// undoRestart puts the app back as it was before the restart (contract
// §11.7 "Restart"), from p's record (Before "running"): running before —
// brought up again with its current files (prepareUp + startUp without a
// reporter: no own pull, compose up --pull never; never anything newer
// than what ran); not running and the restart started it — taken down
// again. Caller holds id's lock.
func (h *Hub) undoRestart(id string, p *Progress) error {
	rec := p.snapshot()
	wasRunning := rec.Before["running"] != "false"
	tmpl := h.Template(id)
	started := stepRan(rec, StepStart) || stepRan(rec, StepHealthy) || stepRan(rec, StepSettings)
	var steps []undoStep
	switch {
	case wasRunning && (stepRan(rec, StepDown) || started):
		// The app back as it ran: the take-down and the cut-short start
		// are both reversed (images never: downloaded images are kept).
		steps = append(steps, undoStep{UndoStart, "Starting the app again", []string{StepDown, StepStart, StepHealthy, StepSettings}, func() error {
			if tmpl == nil {
				return statusErr(409, "the template of %s is gone: it can't be started again", id)
			}
			if !h.IsEnabled(id) {
				return nil // disabled meanwhile: nothing to bring back
			}
			live, err := h.prepareUp(tmpl)
			if err != nil {
				return err
			}
			if err := h.startUp(context.Background(), live); err != nil {
				if composeFailed(err) {
					return fmt.Errorf("compose up failed: %w", err)
				}
				return err
			}
			return nil
		}})
	case !wasRunning && started:
		steps = append(steps, undoStep{UndoDown, "Stopping the app again", []string{StepStart, StepHealthy, StepSettings}, func() error {
			var err error
			if tmpl != nil {
				h.awaitDelivery(id)
				err = h.rollbackUp(tmpl)
			} else {
				h.awaitDelivery(id)
				err = h.compose.DownByName(context.Background(), projectName(id))
			}
			if err != nil {
				return fmt.Errorf("compose down: %w", err)
			}
			return nil
		}})
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}

// aiBeforeKey prefixes an AI switch's Before entries: one per companion
// it changes, "on <mode>" / "off <mode>" (aiBeforeValue).
const aiBeforeKey = "companion:"

func aiBeforeValue(c state.AICompanion) string {
	if c.Enabled {
		return "on " + c.Mode
	}
	return "off " + c.Mode
}

// undoAI puts the companions of a stopped AI switch back to their
// previous {enabled, mode} (contract §11.7 "AI switch", §15.11), from p's
// record (Before), through the same switch path as the stopping admin
// (revoke_all, state, scopes, gate file, compose up, on_change; the owed
// flags as that path keeps them). Credentials the stopped switch revoked
// are not brought back: they are minted again lazily. A switch that
// never saved finds nothing to change. Caller holds id's lock (never the
// AI lock: the switch takes it).
func (h *Hub) undoAI(id string, p *Progress) error {
	rec := p.snapshot()
	stopper := p.stopActor()
	tmpl := h.Template(id)
	u := InstanceAIUpdate{Companions: map[string]CompanionUpdate{}}
	for _, k := range slices.Sorted(maps.Keys(rec.Before)) {
		name, ok := strings.CutPrefix(k, aiBeforeKey)
		if !ok {
			continue
		}
		onOff, mode, _ := strings.Cut(rec.Before[k], " ")
		on := onOff == "on"
		// A template update meanwhile may have dropped the old mode: the
		// companion's default mode instead, with a warning.
		if tmpl != nil {
			if c := companionOf(tmpl, name); c != nil && !slices.Contains(c.Modes, mode) {
				d := defaultMode(c)
				p.Warn(fmt.Sprintf("companion %s: mode %s is no longer one of %s: switched back with mode %s", name, mode, strings.Join(c.Modes, ", "), d))
				mode = d
			}
		}
		u.Companions[name] = CompanionUpdate{Enabled: &on, Mode: &mode}
	}
	var steps []undoStep
	if len(u.Companions) > 0 {
		steps = append(steps, undoStep{UndoSwitch, "Switching AI support back", []string{StepScopes, StepRestart, StepHooks}, func() error {
			_, err := h.aiSwitch(context.Background(), id, u, stopper, "", aiRun{locked: true})
			return err
		}})
	}
	return runUndo(p, rec, steps)
}

// undoVolumes removes the ledger's volumes; one that is gone is done, one
// that no longer carries id's project label (or is the Hub's secrets
// volume) is left, with a warning.
func (h *Hub) undoVolumes(ctx context.Context, p *Progress, id string, names []string) error {
	if h.engine == nil {
		return statusErr(503, "Docker is not available: volumes %s were not removed", strings.Join(names, ", "))
	}
	for _, v := range names {
		info, err := h.engine.InspectVolume(ctx, v)
		switch {
		case docker.IsNotFound(err):
			continue
		case err != nil:
			return fmt.Errorf("inspecting volume %s: %w", v, err)
		case info.Labels[docker.LabelProject] != projectName(id) || v == h.cfg.SecretsVolume:
			p.Warn(fmt.Sprintf("volume %s was kept: it isn't a volume of %s", v, projectName(id)))
			continue
		}
		if err := h.engine.RemoveVolume(ctx, v); err != nil && !docker.IsNotFound(err) {
			return fmt.Errorf("removing volume %s: %w", v, err)
		}
	}
	return nil
}

// undoKeycloak deletes the ledger's clients (their access role and flow
// first; only clients tagged with id — another's is kept, a warning) and
// the instance's extra-domain callbacks the enable added.
func (h *Hub) undoKeycloak(ctx context.Context, p *Progress, id string, t *templates.Template, clients []string) error {
	if h.idp == nil {
		if len(clients) == 0 {
			return nil
		}
		return statusErr(503, "Keycloak is not configured: clients %s were not deleted", strings.Join(clients, ", "))
	}
	var hosts []string
	if t != nil {
		hosts = instanceHosts(t)
	}
	var aiClient string
	if t != nil {
		if c := instanceAIClient(t); c != nil {
			aiClient = c.ClientID
		}
	}
	for _, c := range clients {
		// Its access role and flow first (enable's ensureAccess covers
		// every client of the template, the ai_client too).
		if err := h.idp.RemoveClientAccess(ctx, c, id, hosts); err != nil {
			return fmt.Errorf("Keycloak access role of client %s: %w", c, err)
		}
		if c == aiClient {
			// The AI page's ai_client (G10): through the AI client calls,
			// owner-tagged with the instance only.
			kc := h.aiKeycloak()
			if kc == nil {
				return statusErr(503, "Keycloak's AI client calls are not configured: client %s was not deleted", c)
			}
			h.aiKCMu.Lock()
			err := kc.DeleteAIClient(ctx, c, id)
			h.aiKCMu.Unlock()
			var ce *keycloak.ConflictError
			switch {
			case errors.As(err, &ce):
				p.Warn(fmt.Sprintf("Keycloak client %s was kept: it is not tagged as owned by %s", c, id))
			case err != nil:
				return fmt.Errorf("deleting Keycloak AI client %s: %w", c, err)
			}
			h.forgetAIClientHealth(c)
			continue
		}
		err := h.idp.DeleteClient(ctx, c, id)
		var ce *keycloak.ConflictError
		switch {
		case errors.As(err, &ce):
			p.Warn(fmt.Sprintf("Keycloak client %s was kept: it is not tagged as owned by %s", c, id))
		case err != nil:
			return fmt.Errorf("deleting Keycloak client %s: %w", c, err)
		}
		h.forgetAIClientHealth(c)
	}
	if t != nil && len(t.ExtraHosts) > 0 {
		if err := h.idp.UpdateForwardAuthCallbacks(ctx, nil, callbackURIs(t.ExtraHosts)); err != nil {
			return fmt.Errorf("Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)
		}
	}
	return nil
}

// undoerFor is op's undo, run from its record: by a Stop of the running
// operation (settleOp, runEnable) and of a record that no longer runs
// (interrupted, or its undo failed: resumeStop). nil: op can't be
// stopped.
func (h *Hub) undoerFor(op string) func(id string, p *Progress) error {
	switch op {
	case OpEnable:
		return h.undoEnable
	case OpDisable:
		return h.undoDisable
	case OpRestart:
		return h.undoRestart
	case OpAI:
		return h.undoAI
	}
	return nil
}

// StopOp stops instance id's operation as actor and undoes what it did
// (contract §11.7 "Stop"); admins only (actor resolved through Users &
// Groups when wired). It answers the record: stopping, with stopped_by /
// stopped_at, while the undo runs in the background — the running
// operation's own, or (a record whose undo failed, or interrupted by a
// Hub stop) one StopOp starts from the persisted record under the
// instance's lock. A refusal answers the current record AND a 409
// *StatusError (nothing runs, past the point of no return, already
// stopping, can't be stopped); 404 (no record returned) for an unknown
// instance or one without a record; 401 / 403 for the actor. Every Stop
// is audited <op>.stop: target id, detail the running step's key, actor
// the stopping admin (via / client kept), result ok or refused.
func (h *Hub) StopOp(id string, actor directory.Actor) (*OpRecord, error) {
	var rec *OpRecord
	err := statusErr(404, "app instance not found: %s", id)
	if templates.ValidID(id) && h.Template(id) != nil {
		if rec = h.LastOp(id); rec == nil {
			err = statusErr(404, "no operation recorded for %s", id)
		}
	}
	if rec == nil {
		h.auditOp(actor, "op.stop", id, "", err)
		return nil, err
	}
	detail := stopDetail(*rec)
	out, err := h.stopOp(id, *rec, actor)
	h.auditOp(actor, rec.Op+".stop", id, detail, err)
	return out, err
}

func (h *Hub) stopOp(id string, rec OpRecord, actor directory.Actor) (*OpRecord, error) {
	if strings.TrimSpace(actor.User) == "" {
		return &rec, statusErr(401, "no acting user")
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI != nil {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return &rec, &StatusError{Status: 403, Err: fmt.Errorf("%s can't stop operations: %w", actor.User, err)}
		}
	}
	if rec.Running {
		if err := h.cancelOp(id, actor); err != nil {
			return h.LastOp(id), err
		}
		return h.LastOp(id), nil
	}
	undo := h.undoerFor(rec.Op)
	switch {
	case rec.Stopping:
		return &rec, statusErr(409, "the %s of %s is already stopping", rec.Op, id)
	case rec.PointOfNoReturn:
		return &rec, statusErr(409, "the %s of %s is past the point of no return — finishing", rec.Op, id)
	case !rec.Stoppable:
		return &rec, statusErr(409, "no operation is running on %s", id)
	case undo == nil:
		return &rec, statusErr(409, "the %s of %s can't be stopped", rec.Op, id)
	}
	return h.resumeStop(id, rec, actor, undo)
}

// stopDetail is the key of the record's running step (else the last one
// a Stop or the Hub's stop cut short, else the last failed).
func stopDetail(r OpRecord) string {
	for _, s := range r.Steps {
		if s.State == StepRunning {
			return s.Key
		}
	}
	for _, want := range []string{StepStopped, StepFailed} {
		for i := len(r.Steps) - 1; i >= 0; i-- {
			if r.Steps[i].State == want {
				return r.Steps[i].Key
			}
		}
	}
	return ""
}

// resumeStop runs undo for rec — an operation that no longer runs — in
// the background under id's lock: the record (same op id, actor, steps
// and ledger) running and stopping again from now, undo steps already
// done skipped, then ended as a Stop ends (stopped, or the undo's error
// and stoppable again). Answers the stopping record.
func (h *Hub) resumeStop(id string, rec OpRecord, actor directory.Actor, undo func(string, *Progress) error) (*OpRecord, error) {
	if h.testHookResume != nil {
		h.testHookResume(id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		berr := h.busyErr(id, err)
		var be *BusyError
		if errors.As(berr, &be) {
			return be.Record, berr
		}
		return &rec, berr
	}
	// The record StopOp judged may be stale (another Stop, or another
	// operation, ran in between): only that same record, still ended,
	// stoppable and not stopping, is undone.
	cur := h.LastOp(id)
	if cur == nil || cur.OpID != rec.OpID || cur.Running || !cur.Stoppable || cur.Stopping {
		unlock()
		if cur == nil {
			return nil, statusErr(409, "no operation is running on %s", id)
		}
		if cur.OpID == rec.OpID && !cur.Running && !cur.Stoppable {
			return cur, statusErr(409, "no operation is running on %s", id)
		}
		return cur, statusErr(409, "the operation of %s changed meanwhile: look again", id)
	}
	rec = *cur
	p := h.newProgress(id, rec.Op, nil)
	now := p.now()
	p.mu.Lock()
	r := rec
	r.Steps = slices.Clone(rec.Steps)
	r.Created = rec.Created.clone()
	r.Before = maps.Clone(rec.Before)
	if r.Created == nil {
		r.Created = &Created{}
	}
	r.Running, r.Stopping, r.Stoppable, r.Interrupted = true, true, false, false
	r.StoppedBy, r.StoppedAt, r.At = actor.User, &now, now
	r.OK, r.Error, r.Status, r.Output, r.Hint, r.RolledBack, r.Result = false, "", 0, "", "", false, nil
	p.rec, p.stopper, p.live = r, actor, true
	h.recordOp(id, p.recordLocked())
	p.lastWrite = p.now()
	p.mu.Unlock()
	run := &opRun{opID: rec.OpID, p: p}
	h.registerOp(id, run)
	h.bg.Add(1)
	go func() {
		defer h.bg.Done()
		defer unlock()
		err := undo(id, p)
		if err == nil {
			err = ErrStopped
		}
		h.finishAsync(id, rec.Op, p, nil, nil, err)
		h.unregisterOp(id, run)
	}()
	return h.LastOp(id), nil
}
