package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Moves between servers (contract §17, Task 11; fix round 3). The
// instance is backed up on its source (which stops it), restored into
// the same id on the target, then switched (relays follow, a new relay
// token, link.json republished) and started there. Until the switch has
// committed, any failure or Stop takes the target down and puts the
// routing back on the source, which starts again; when the target can't
// be taken down, the instance is routed to neither ("stuck", doctor
// server_move_stuck) and retried. Two routed copies never exist. The
// source's copy (its volume names pinned at move time) stays for an
// undo within 7 days, until removed. While an instance is "moving" only
// its move and the recovery may start it.

const (
	OpMove     = "move"
	OpMoveUndo = "move_undo"
	// Move phases (the op's steps and Instance.Move.Phase); MoveStuck: a
	// rollback couldn't take the target down.
	MoveCheck   = "check"
	MoveBackup  = "backup"
	MoveRestore = "restore"
	MoveSwitch  = "switch"
	MoveKeep    = "keep"
	MoveStuck   = "stuck"
	// MoveUndoStarting: an undo is starting its copy on the source (the
	// marker recovery uses to take that copy down after a crash, R4-L8).
	MoveUndoStarting = "undo_start"
	// Undo steps.
	MoveUndoStart = StepStart
	MoveUndoStop  = StepStop
	// UndoWindow: a move can be undone this long after it.
	UndoWindow = 7 * 24 * time.Hour
)

func movePlan() []Step {
	return []Step{
		{Key: MoveCheck, Label: "Checking the target server"},
		{Key: MoveBackup, Label: "Backing up on the source"},
		{Key: MoveRestore, Label: "Restoring on the target"},
		{Key: MoveSwitch, Label: "Switching and starting on the target"},
		{Key: MoveKeep, Label: "Keeping the source's data for an undo"},
	}
}

func undoPlan() []Step {
	return []Step{
		{Key: MoveUndoStart, Label: "Starting the copy it returns to"},
		{Key: MoveSwitch, Label: "Switching the routing"},
		{Key: MoveUndoStop, Label: "Stopping the current copy"},
	}
}

func normServer(s string) string {
	if s == servers.PrimaryID {
		return ""
	}
	return s
}

// moveHook runs the test hook at a phase's start (nil: none).
func (h *Hub) moveHook(phase string) error {
	if h.testHookMove != nil {
		return h.testHookMove(phase)
	}
	return nil
}

// ownMove marks id as started by a move, an undo or a recovery (the
// only starts composeUp allows while it is moving); the release.
func (h *Hub) ownMove(id string) func() {
	h.moveOwners.Store(id, true)
	return func() { h.moveOwners.Delete(id) }
}

// publishLink republishes link.json (a relay token changed or went;
// review B2-M5): the op fails when it can't.
func (h *Hub) publishLink() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.publishLinkLocked(); err != nil {
		return statusErr(500, "link.json: %v", err)
	}
	return nil
}

func removeRelayFiles(h *Hub, id string) {
	for _, p := range []string{h.relayComposePath(id), h.relayEnvPath(id)} {
		os.Remove(p)
	}
}

// dropRelays takes instance id's relays down and their files and token
// away, then republishes link.json (its relay is gone).
func (h *Hub) dropRelays(ctx context.Context, id string) error {
	if err := h.relaysDown(ctx, id); err != nil {
		return err
	}
	removeRelayFiles(h, id)
	return h.publishLink()
}

// MoveInstance moves instance id to server to ("" or "primary": the
// primary) as op move; its record when it ended.
func (h *Hub) MoveInstance(ctx context.Context, id, to string, actor directory.Actor) (*OpRecord, error) {
	_, _, err := h.runOpSync(id, OpMove, actor, movePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.moveInstance(ctx, id, normServer(to), actor, ready)
	})
	return h.LastOp(id), err
}

// boundFolderLocked: instance id binds a shared folder (folder contents
// aren't moved). Caller holds mu.
func (h *Hub) boundFolderLocked(id string) bool {
	for _, v := range h.st.Settings[id].Values {
		if s, ok := v.(string); ok && strings.HasPrefix(s, settings.FolderRefPrefix) {
			return true
		}
	}
	return false
}

func (h *Hub) setMove(id string, mv *state.Move, server string, st string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	in := h.st.Instances[id]
	if mv != nil && in.Move != nil && in.Move != mv && in.Move.StartedAt.Equal(mv.StartedAt) {
		mv.Pushed = mv.Pushed || in.Move.Pushed // the same move: a push stays known
	}
	in.Move, in.Server, in.State = mv, server, st
	h.st.Instances[id] = in
	h.noteInstanceServer(id, server)
	h.saveLocked()
}

// volumeNamesOn are instance id's volumes on server's runtime (its
// compose project's).
func (h *Hub) volumeNamesOn(ctx context.Context, server, id string) ([]string, error) {
	names, _, err := h.volumesOn(ctx, server, id)
	return names, err
}

// volumesOn is instance id's project volumes on server: their names
// (sorted) and each name's compose key (its compose volume label, else
// the instance's own key for that name).
func (h *Hub) volumesOn(ctx context.Context, server, id string) ([]string, map[string]string, error) {
	rt, err := h.rtForServer(server)
	if err != nil {
		return nil, nil, err
	}
	vs, err := rt.ListVolumes(ctx, runtime.Filter{Instance: id})
	if err != nil {
		return nil, nil, err
	}
	h.mu.RLock()
	own := map[string]string{} // name → key
	if t := h.findLocked(id); t != nil {
		for k, n := range h.volumeNamesFor(t, id) {
			own[n] = k
		}
	}
	h.mu.RUnlock()
	var out []string
	keys := map[string]string{}
	for _, v := range vs {
		if v.Labels[docker.LabelProject] != projectName(id) {
			continue
		}
		out = append(out, v.Name)
		if k := v.Labels[docker.LabelVolume]; k != "" {
			keys[v.Name] = k
		} else if k := own[v.Name]; k != "" {
			keys[v.Name] = k
		}
	}
	slices.Sort(out)
	return out, keys, nil
}

// templateOfLocked is instance id's template id (its entry's, else the
// id: a default instance). Caller holds mu.
func (h *Hub) templateOfLocked(id string) string {
	if e, ok := h.st.Instances[id]; ok && e.Template != "" {
		return e.Template
	}
	return id
}

// downOn takes instance t down on server's runtime (a worker's relays
// first, through its placed runtime).
func (h *Hub) downOn(ctx context.Context, server string, t *templates.Template) error {
	if server == "" {
		return h.rt.Down(ctx, h.runtimeProject(t))
	}
	rt, err := h.rtForServer(server)
	if err != nil {
		return err
	}
	if err := h.relaysDown(ctx, t.ID); err != nil {
		return err
	}
	return rt.Down(ctx, h.runtimeProject(t))
}

func (h *Hub) moveInstance(ctx context.Context, id, to string, actor directory.Actor, ready func()) (err error) {
	defer func() {
		h.auditOp(actor, "instance.move", id, "to "+serverLabel(to), err)
	}()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	// The policy follows the outcome (the restore inside published it while
	// the instance was disabled: its host denied): republished at the end,
	// moved, failed back or stopped alike.
	defer h.writePolicyLogged()
	defer h.ownMove(id)()
	h.mu.Lock()
	v := h.findLocked(id)
	in, has := h.st.Instances[id]
	if v != nil && !has {
		in = state.Instance{ID: id, Template: v.TemplateID}
		h.st.Instances[id] = in
	}
	from := in.Server
	bound := h.boundFolderLocked(id)
	enabled := h.st.IsEnabled(id)
	h.mu.Unlock()
	switch {
	case v == nil:
		return statusErr(404, "instance not found: %s", id)
	case from == to:
		return statusErr(409, "%s already runs on %s", id, serverLabel(to))
	case in.State != "" && in.State != state.InstanceCreated:
		return statusErr(409, "%s is %s: it can't be moved now", id, in.State)
	case bound:
		return statusErr(409, "unbind folders first; folder contents aren't moved")
	case keptOn(in, to):
		// Any recorded copy there (an undo's, a failed move's, an older
		// one): the restore would meet its volumes (contract §17.6).
		return statusErr(409, "%s still holds a previous copy of %s: use Undo move, or remove the old copy first", serverLabel(to), id)
	}
	view := *v
	if to != "" {
		// An unknown or revoked target: refused before the op is accepted.
		h.mu.RLock()
		ts, known := h.st.Servers[to]
		h.mu.RUnlock()
		if !known || ts.State == ServerRevoked || ts.State == ServerEnrolling {
			return statusErr(404, "no server %s to move %s to", to, id)
		}
	}
	p := progressFrom(ctx)
	ready()

	// check
	p.Start(MoveCheck)
	if err := h.moveHook(MoveCheck); err != nil {
		return err
	}
	if to != "" {
		if err := h.checkPlacement(ctx, &view, to); err != nil {
			return err
		}
		if err := h.checkReservedID(id, to); err != nil {
			return err
		}
		// The rendered images too (env overrides included), before the
		// backup (final review H2): a refusal here leaves nothing anywhere.
		if err := h.placedImages(ctx, &view, to); err != nil {
			return err
		}
	}
	srcVols, srcKeys, err := h.volumesOn(ctx, from, id)
	if err != nil {
		return statusErr(409, "%s: %v", serverLabel(from), err)
	}
	p.Done(MoveCheck)
	mv := &state.Move{From: from, To: to, StartedAt: h.now().UTC(), Phase: MoveBackup}
	h.setMove(id, mv, from, state.InstanceMoving)
	// back: before the switch, everything goes back to the source — once
	// the target is down (else routed to neither: stuck).
	// targetTouched: something may exist on the target. On the primary,
	// from the restore on; on a worker only once a bundle push to it
	// may have landed (Move.Pushed, set by pushBundle; final review H2):
	// every worker volume and container follows a push, and a never-held
	// id's down is the agent's 404 — an untouched target needs none.
	targetTouched := false
	touched := func() bool {
		if to != "" {
			return h.movePushed(id)
		}
		return targetTouched
	}
	back := func(cause error) error {
		if touched() {
			if derr := h.downOn(context.Background(), to, &view); derr != nil {
				mv.Phase = MoveStuck
				h.setMove(id, mv, from, state.InstanceMoving)
				h.relaysDown(context.Background(), id)
				return fmt.Errorf("%w — and taking %s down on %s failed (%v): it runs nowhere until that succeeds (retried; doctor server_move_stuck)", cause, id, serverLabel(to), derr)
			}
			h.recordTargetLeftover(id, to)
		}
		h.setMove(id, nil, from, "")
		if from == "" {
			removeRelayFiles(h, id)
		}
		if perr := h.publishLink(); perr != nil {
			return fmt.Errorf("%w — %v", cause, perr)
		}
		if enabled {
			h.mu.RLock()
			lv := h.findLocked(id)
			h.mu.RUnlock()
			if serr := h.startAgain(lv); serr != nil {
				return fmt.Errorf("%w — and starting %s again on %s failed: %v", cause, id, serverLabel(from), serr)
			}
		}
		return cause
	}
	stopped := func(err error) error {
		if ctx.Err() != nil {
			return back(ErrStopped)
		}
		return back(err)
	}

	// backup (stops the instance on the source)
	p.Start(MoveBackup)
	if err := h.moveHook(MoveBackup); err != nil {
		return stopped(err)
	}
	entry, err := h.backupCtx(ctx, id, BackupMove, true)
	if err != nil {
		return stopped(fmt.Errorf("the backup on %s failed — nothing was moved: %w", serverLabel(from), err))
	}
	p.Detail(MoveBackup, entry.Archive)
	p.Done(MoveBackup)
	if ctx.Err() != nil {
		return stopped(ctx.Err())
	}
	mv.Archive, mv.Phase = entry.Archive, MoveRestore
	// From here on the instance's runtime is the target's (not routed:
	// nothing runs there until the switch).
	h.setMove(id, mv, to, state.InstanceMoving)
	targetTouched = true

	// restore (same id, target runtime, new volumes)
	p.Start(MoveRestore)
	if err := h.moveHook(MoveRestore); err != nil {
		return stopped(err)
	}
	if err := h.restoreForMove(ctx, id, entry.Archive, actor); err != nil {
		return stopped(fmt.Errorf("the restore on %s failed — %s goes back to %s: %w", serverLabel(to), id, serverLabel(from), err))
	}
	p.Done(MoveRestore)
	if ctx.Err() != nil {
		return stopped(ctx.Err())
	}

	// switch: relays follow, a new relay token, link.json, the start.
	mv.Phase = MoveSwitch
	h.setMove(id, mv, to, state.InstanceMoving)
	p.Start(MoveSwitch)
	if err := h.moveHook(MoveSwitch); err != nil {
		return stopped(err)
	}
	if to == "" {
		if err := h.dropRelays(context.Background(), id); err != nil {
			return stopped(err)
		}
	} else {
		if err := h.newRelayToken(id); err != nil {
			return stopped(statusErr(500, "the relay token: %v", err))
		}
		if err := h.publishLink(); err != nil {
			return stopped(err)
		}
	}
	if enabled {
		if err := h.startAgain(&view); err != nil {
			return stopped(fmt.Errorf("starting %s on %s failed — it goes back to %s: %w", id, serverLabel(to), serverLabel(from), err))
		}
	}
	if !p.CloseStop() {
		return back(ErrStopped)
	}
	p.Done(MoveSwitch)

	// keep: the source's copy (volume names pinned) for an undo; its
	// worker bundle (env included) goes (review B2-M4).
	p.Start(MoveKeep)
	h.mu.Lock()
	in = h.st.Instances[id]
	in.Move, in.State = nil, ""
	keepOlder(&in, in.MovedFrom, to)
	in.MovedFrom = &state.MovedFrom{Server: from, At: h.now().UTC(), Volumes: srcVols, Keys: srcKeys, Template: h.templateOfLocked(id)}
	h.st.Instances[id] = in
	h.saveLocked()
	h.mu.Unlock()
	// Committed, running on the target with the bundle just pushed there:
	// a removal still owed on it is moot (revised ruling). Every failure
	// path above left it in place (moveOwners kept the drain off it).
	if to != "" {
		h.settlePushed(to, id)
	}
	if from != "" {
		if err := h.dropBundleOwed(context.Background(), from, id); err != nil {
			p.Warn(fmt.Sprintf("the bundle of %s on %s wasn't removed yet: %v (retried every 30 s)", id, serverLabel(from), err))
		}
	}
	p.Done(MoveKeep)
	log.Printf("instance %s moved from %s to %s (archive %s)", id, serverLabel(from), serverLabel(to), entry.Archive)
	return nil
}

// movePushed: a bundle push to the target of instance id's open move may
// have landed (H2).
func (h *Hub) movePushed(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	m := h.st.Instances[id].Move
	return m != nil && m.Pushed
}

// markMovePush records (write-ahead, saved) that a bundle push of id to
// server is about to happen while a move to server is open; pushed false
// after the agent refused it (4xx: nothing landed) clears it again.
func (h *Hub) markMovePush(id, server string, pushed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	in, ok := h.st.Instances[id]
	if !ok || in.Move == nil || in.Move.To != server || in.Move.Pushed == pushed {
		return
	}
	// In place: the move's own record (setMove stores its pointer) keeps it.
	in.Move.Pushed = pushed
	h.saveLocked()
}

// recordTargetLeftover records the volumes a failed move left on its
// target (review B2-L5).
func (h *Hub) recordTargetLeftover(id, to string) {
	var vols []string
	keys := map[string]string{}
	if to != "" {
		// A worker's agent hides the volumes of a project it holds no
		// bundle of (the failed restore removed the one it pushed): the
		// instance's own volume names, which is what its restore made —
		// one never made is gone already for the removal.
		h.mu.RLock()
		if t := h.findLocked(id); t != nil {
			for k, n := range h.volumeNamesFor(t, id) {
				vols = append(vols, n)
				keys[n] = k
			}
			slices.Sort(vols)
		}
		h.mu.RUnlock()
	} else {
		var err error
		if vols, keys, err = h.volumesOn(context.Background(), to, id); err != nil {
			return
		}
	}
	if len(vols) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	in := h.st.Instances[id]
	keepOlder(&in, in.MoveTargetLeftover, in.Server)
	in.MoveTargetLeftover = &state.MovedFrom{Server: to, At: h.now().UTC(), Volumes: vols, Keys: keys, Template: h.templateOfLocked(id)}
	h.st.Instances[id] = in
	h.saveLocked()
}

// keptCopies are every copy of in the Hub recorded on a server (the last
// move's source, a failed move's target, older ones), with volumes.
func keptCopies(in state.Instance) []state.MovedFrom {
	var out []state.MovedFrom
	for _, c := range []*state.MovedFrom{in.MovedFrom, in.MoveTargetLeftover} {
		if c != nil && len(c.Volumes) > 0 {
			out = append(out, *c)
		}
	}
	for _, c := range in.OlderCopies {
		if len(c.Volumes) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// keptOn: a recorded copy of in is on server.
func keptOn(in state.Instance, server string) bool {
	return slices.ContainsFunc(keptCopies(in), func(c state.MovedFrom) bool { return c.Server == server })
}

// keepOlder moves old (a record about to be replaced) into in.OlderCopies
// so the copy it names is never forgotten, and drops every recorded copy
// on live (the server the instance runs on now: none is kept there).
func keepOlder(in *state.Instance, old *state.MovedFrom, live string) {
	if old != nil && len(old.Volumes) > 0 && old.Server != live {
		in.OlderCopies = append(in.OlderCopies, *old)
	}
	in.OlderCopies = slices.DeleteFunc(in.OlderCopies, func(c state.MovedFrom) bool { return c.Server == live })
}

// removeWorkerBundle removes instance id's bundle from worker server
// (its containers are down): DELETE /v1/projects/{id}.
func (h *Hub) removeWorkerBundle(ctx context.Context, server, id string) error {
	rt, err := h.rtForServer(server)
	if err != nil {
		return err
	}
	b, ok := unwrapRT(rt).(interface {
		RemoveProject(ctx context.Context, id string) error
	})
	if !ok {
		return nil
	}
	// Its 404 is "no such project": already gone (final review B4: a lost
	// answer, an earlier removal, a bundle the agent dropped at load).
	if err := b.RemoveProject(ctx, id); err != nil && !workerNotFound(err) {
		return err
	}
	// A quarantine goes with the project (R3-L4): audited here, as the
	// Hub's removal is what lifted it.
	if inf := h.serverInfo(server); inf != nil && inf.Quarantined[id] != "" {
		h.auditOp(directory.Actor{}, "server.quarantine_removed_with_bundle", id, "on "+serverLabel(server), nil)
	}
	return nil
}

// restoreForMove restores archive into instance id on its (new)
// runtime: new volumes, the archived settings and files; no start, no
// credential voiding (the same instance, moved).
func (h *Hub) restoreForMove(ctx context.Context, id, archive string, actor directory.Actor) error {
	sb, err := h.stageArchiveCtx(ctx, archive, nil)
	if err != nil {
		return err
	}
	defer sb.cleanup()
	h.mu.RLock()
	v := h.findLocked(id)
	h.mu.RUnlock()
	if v == nil {
		return statusErr(409, "instance %s does not resolve", id)
	}
	plan, err := h.restorePlan(id, v, sb)
	if err != nil {
		return err
	}
	for _, pl := range plan {
		if pl.existed {
			return statusErr(409, "volume %s already exists on the target: remove it first (a leftover of an earlier move?)", pl.vol.Name)
		}
	}
	h.mu.RLock()
	enabled := h.st.IsEnabled(id)
	h.mu.RUnlock()
	_, err = h.applyRestore(ctx, id, sb, plan, false, false, actor, nil)
	// applyRestore leaves it disabled: the switch decides the start.
	h.mu.Lock()
	h.st.SetEnabled(id, enabled)
	h.rebuildLocked()
	h.saveLocked()
	h.mu.Unlock()
	return err
}

// UndoMove undoes instance id's last move (within 7 days; confirm is the
// typed id — changes since the move are lost) as op move_undo: start the
// copy it returns to, switch the routing, stop the current copy. A
// failure before the switch changes nothing. Audited instance.move_undo.
func (h *Hub) UndoMove(ctx context.Context, id, confirm string, actor directory.Actor) (err error) {
	_, _, err = h.runOpSync(id, OpMoveUndo, actor, undoPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.undoMove(ctx, id, confirm, actor, ready)
	})
	return err
}

func (h *Hub) undoMove(ctx context.Context, id, confirm string, actor directory.Actor, ready func()) (err error) {
	defer func() { h.auditOp(actor, "instance.move_undo", id, "", err) }()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	if confirm != id {
		return statusErr(400, "type the instance id (%s) to confirm: changes since the move are lost", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	defer h.writePolicyLogged() // the policy follows the outcome (as a move's)
	defer h.ownMove(id)()
	h.mu.RLock()
	in := h.st.Instances[id]
	v := h.findLocked(id)
	enabled := h.st.IsEnabled(id)
	h.mu.RUnlock()
	switch {
	case v == nil:
		return statusErr(404, "instance not found: %s", id)
	case in.State == state.InstanceMoving:
		return statusErr(409, "instance %s is being moved: wait for the move (or its recovery) to end", id)
	case in.MovedFrom == nil:
		return statusErr(409, "%s has no move to undo", id)
	case h.now().Sub(in.MovedFrom.At) > UndoWindow:
		return statusErr(409, "the move of %s is older than 7 days: it can't be undone (remove the source's data instead)", id)
	}
	src, cur := in.MovedFrom.Server, in.Server
	if src == cur {
		return statusErr(409, "the copy %s would return to is the one it runs on (%s): nothing to undo", id, serverLabel(cur))
	}
	origFrom := *in.MovedFrom
	view := *v

	if src != "" {
		if err := h.checkPlacement(ctx, &view, src); err != nil {
			return err
		}
		if err := h.checkReservedID(id, src); err != nil {
			return err
		}
	}
	curVols, curKeys, _ := h.volumesOn(ctx, cur, id)
	p := progressFrom(ctx)
	ready()
	commit := func() {
		h.mu.Lock()
		in := h.st.Instances[id]
		in.Server = src
		in.Move, in.State = nil, "" // the undo marker ends with the commit
		keepOlder(&in, nil, src)    // the copy on src runs again: no longer a kept one
		in.MovedFrom = &state.MovedFrom{Server: cur, At: h.now().UTC(), Volumes: curVols, Keys: curKeys, Template: h.templateOfLocked(id)}
		h.st.Instances[id] = in
		h.noteInstanceServer(id, src)
		h.saveLocked()
		h.mu.Unlock()
	}
	revert := func() {
		h.mu.Lock()
		in := h.st.Instances[id]
		in.Server = cur
		h.st.Instances[id] = in
		h.noteInstanceServer(id, cur)
		h.saveLocked()
		h.mu.Unlock()
	}

	if src != "" {
		// start: the worker copy, unrouted (no relays yet).
		p.Start(MoveUndoStart)
		if enabled {
			rt, err := h.rtForServer(src)
			if err != nil {
				return err
			}
			// A marker first (R4-L8): a crash from here leaves recovery a
			// record to take the src copy down by, the instance kept on cur.
			h.setMove(id, &state.Move{From: cur, To: src, StartedAt: h.now().UTC(), Phase: MoveUndoStarting}, cur, state.InstanceMoving)
			unmark := func() { h.setMove(id, nil, cur, "") }
			// The bundle and render are the source's: the runtime index only,
			// never the stored state (R3-L8: nothing persists or publishes it).
			h.setMoveServer(id, src)
			if _, err := h.prepareUp(&view); err != nil {
				h.clearMoveServer(id)
				unmark()
				return err
			}
			up, err := h.upProject(ctx, &view)
			if err == nil {
				// The kept copy's volumes are adopted knowingly (M1).
				err = h.pushBundleAdopt(ctx, id, rt, true)
			}
			if err == nil {
				err = rt.Create(ctx, up)
			}
			if err == nil {
				err = rt.Up(ctx, up, nil)
			}
			if err != nil {
				h.clearMoveServer(id)
				if derr := rt.Down(context.Background(), up); derr == nil {
					unmark()
				} // else the marker stays: recovery takes the copy down
				return fmt.Errorf("starting %s on %s failed — nothing changed: %w", id, serverLabel(src), err)
			}
			h.clearMoveServer(id)
		}
		p.Done(MoveUndoStart)
		if !p.CloseStop() {
			if rt, err := h.rtForServer(src); err == nil {
				if rt.Down(context.Background(), h.runtimeProject(&view)) == nil {
					h.setMove(id, nil, cur, "")
				}
			}
			return ErrStopped
		}
		// switch: the current copy's routing off, the relays to src.
		p.Start(MoveSwitch)
		if cur == "" {
			if err := h.rt.Down(context.Background(), h.runtimeProject(&view)); err != nil {
				return fmt.Errorf("stopping %s on the primary: %w", id, err)
			}
		} else if err := h.relaysDown(context.Background(), id); err != nil {
			return err
		}
		commit()
		if err := h.newRelayToken(id); err != nil {
			return err
		}
		if enabled {
			if err := h.relaysUp(context.Background(), id); err != nil {
				return err
			}
		} else if err := h.publishLink(); err != nil {
			return err
		}
		p.Done(MoveSwitch)
		// Committed on src with its bundle pushed: an owed removal there
		// is moot (revised ruling; until here it stayed).
		h.settlePushed(src, id)
		// stop the current copy (a worker; the primary's went at the switch).
		p.Start(MoveUndoStop)
		if cur != "" {
			h.stopAndDropBundle(&view, cur, p)
		}
		p.Done(MoveUndoStop)
		return nil
	}

	// Back to the primary: the primary's copy is routed as soon as it
	// starts, so the worker's relays go first (the switch), then the
	// start; a failed start puts the relays back (nothing changed).
	p.Start(MoveUndoStart)
	p.Done(MoveUndoStart)
	p.Start(MoveSwitch)
	if err := h.relaysDown(context.Background(), id); err != nil {
		return err
	}
	commit()
	if enabled {
		if err := h.startAgain(&view); err != nil {
			// The primary copy must be down before the worker's relays
			// route again (R3-L9); if it can't be, neither is routed.
			if derr := h.rt.Down(context.Background(), h.runtimeProject(&view)); derr != nil {
				// The move record names the right pair after recovery
				// (R4-L7): MovedFrom back to the original source.
				h.mu.Lock()
				in := h.st.Instances[id]
				mf := origFrom
				in.MovedFrom = &mf
				h.st.Instances[id] = in
				h.mu.Unlock()
				h.setMove(id, &state.Move{From: cur, To: "", StartedAt: h.now().UTC(), Phase: MoveStuck}, "", state.InstanceMoving)
				return fmt.Errorf("starting %s on the primary failed (%v), and taking it down failed too (%v): it runs nowhere until that succeeds (retried; doctor server_move_stuck)", id, err, derr)
			}
			revert()
			h.mu.Lock()
			in := h.st.Instances[id]
			in.MovedFrom = &state.MovedFrom{Server: src, At: in.MovedFrom.At, Volumes: nil}
			h.st.Instances[id] = in
			h.saveLocked()
			h.mu.Unlock()
			if rerr := h.relaysUp(context.Background(), id); rerr != nil {
				return fmt.Errorf("starting %s on the primary failed (%v), and its relays couldn't come back: %w", id, err, rerr)
			}
			return fmt.Errorf("starting %s on the primary failed — nothing changed: %w", id, err)
		}
	}
	// Committed: a Stop now is too late — the stop step still runs
	// (R3-L9).
	p.CloseStop()
	removeRelayFiles(h, id)
	if err := h.publishLink(); err != nil {
		return err
	}
	p.Done(MoveSwitch)
	p.Start(MoveUndoStop)
	h.stopAndDropBundle(&view, cur, p)
	p.Done(MoveUndoStop)
	return nil
}

// stopAndDropBundle stops the copy an undo leaves on worker cur and
// removes its bundle there (env included), as a move's keep does (fix
// round 3).
func (h *Hub) stopAndDropBundle(t *templates.Template, cur string, p *Progress) {
	rt, err := h.rtForServer(cur)
	if err != nil {
		p.Warn(fmt.Sprintf("the copy on %s wasn't stopped: %v (retried every 30 s)", serverLabel(cur), err))
		h.oweBundle(cur, t.ID) // owed (R4-L3): downed and removed by the drain
		return
	}
	if err := unwrapRT(rt).Down(context.Background(), h.runtimeProject(t)); err != nil {
		p.Warn(fmt.Sprintf("stopping the copy on %s failed: %v (retried every 30 s)", serverLabel(cur), err))
		h.oweBundle(cur, t.ID) // owed (R4-L3): downed and removed by the drain
		return
	}
	if err := h.dropBundleOwed(context.Background(), cur, t.ID); err != nil {
		p.Warn(fmt.Sprintf("the bundle of %s on %s wasn't removed yet: %v (retried every 30 s)", t.ID, serverLabel(cur), err))
	}
}

// oweBundle records that instance id's bundle must go from server
// (persisted; R3-L10).
func (h *Hub) oweBundle(server, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, o := range h.st.OwedBundles {
		if o.Server == server && o.Instance == id {
			return
		}
	}
	h.st.OwedBundles = append(h.st.OwedBundles, state.OwedBundle{Server: server, Instance: id, Since: h.now().UTC()})
	h.saveLocked()
}

// dropBundleOwed owes the removal first, then tries it: success settles it.
func (h *Hub) dropBundleOwed(ctx context.Context, server, id string) error {
	h.oweBundle(server, id)
	if err := h.removeWorkerBundle(ctx, server, id); err != nil {
		return err
	}
	h.settleBundle(server, id)
	return nil
}

// settlePushed settles an owed (server, id) removal only when this Hub's
// last successful bundle push for id went to server.
func (h *Hub) settlePushed(server, id string) {
	if v, ok := h.lastPush.Load(id); ok && v.(string) == server {
		h.settleBundle(server, id)
	}
}

func (h *Hub) settleBundle(server, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.st.OwedBundles)
	h.st.OwedBundles = slices.DeleteFunc(h.st.OwedBundles, func(o state.OwedBundle) bool { return o.Server == server && o.Instance == id })
	if len(h.st.OwedBundles) != n {
		h.saveLocked()
	}
}

// drainOwedBundles retries the owed bundle removals (each tick): done,
// or its server is gone, settles one. The copy is down already; one the
// instance runs on again (an undo back) is never removed.
func (h *Hub) drainOwedBundles(ctx context.Context) {
	h.mu.RLock()
	owed := slices.Clone(h.st.OwedBundles)
	h.mu.RUnlock()
	for _, o := range owed {
		h.drainOwedBundle(ctx, o)
	}
}

// drainOwedBundle settles one owed removal under the instance's lock: an
// instance a move or an undo owns is left alone (it may be pushing its
// bundle back there); one that runs on that server (override included)
// keeps its bundle; a gone server settles it.
func (h *Hub) drainOwedBundle(ctx context.Context, o state.OwedBundle) {
	unlock, err := h.lockApp(o.Instance)
	if err != nil {
		return // busy: the next tick
	}
	defer unlock()
	if _, owned := h.moveOwners.Load(o.Instance); owned {
		return
	}
	h.mu.RLock()
	_, known := h.st.Servers[o.Server]
	in := h.st.Instances[o.Instance]
	v := h.findLocked(o.Instance)
	h.mu.RUnlock()
	// A move or undo record still open (stuck included, R4-L4) needs the
	// bundle for its recovery: left alone.
	if in.State == state.InstanceMoving || in.Move != nil {
		return
	}
	if !known || in.Server == o.Server || h.serverOf(o.Instance) == o.Server {
		h.settleBundle(o.Server, o.Instance)
		return
	}
	// The copy there must be down first (R4-L3: an undo's failed stop
	// left it running); the agent refuses to remove a running project.
	if v != nil {
		if rt, err := h.rtForServer(o.Server); err == nil {
			// Its 404: it holds nothing of the id (B4) — removable.
			if err := unwrapRT(rt).Down(ctx, h.runtimeProject(v)); err != nil && !workerNotFound(err) {
				return
			}
		}
	}
	if err := h.removeWorkerBundle(ctx, o.Server, o.Instance); err == nil {
		h.settleBundle(o.Server, o.Instance)
	}
}

// setMoveServer points instance id's runtime at server for a moment
// (an undo renders and starts the source copy before the switch): the
// registry's override only, never h.st.
func (h *Hub) setMoveServer(id, server string) {
	r := h.reg()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.override == nil {
		r.override = map[string]string{}
	}
	r.override[id] = server
}

// clearMoveServer ends setMoveServer's override.
func (h *Hub) clearMoveServer(id string) {
	r := h.reg()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.override, id)
}

// RemoveMoveLeftover removes the copies moves left (typed id): the
// source's volumes named at move time, and a failed move's on its
// target, through their servers' runtimes; then their worker bundles.
// Audited instance.move_leftover_removed.
func (h *Hub) RemoveMoveLeftover(ctx context.Context, id, confirm string, actor directory.Actor) (err error) {
	defer func() { h.auditOp(actor, "instance.move_leftover_removed", id, "", err) }()
	if actor.User == "" {
		return statusErr(401, "no acting user")
	}
	if confirm != id {
		return statusErr(400, "type the instance id (%s) to confirm", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	h.mu.RLock()
	in := h.st.Instances[id]
	h.mu.RUnlock()
	if in.State == state.InstanceMoving {
		return statusErr(409, "instance %s is being moved: wait for the move (or its recovery) to end", id)
	}
	lefts := keptCopies(in)
	for _, l := range lefts {
		if l.Server == in.Server {
			return statusErr(409, "the leftover of %s is on %s, where it runs now: refusing to touch it", id, serverLabel(l.Server))
		}
	}
	if len(lefts) == 0 {
		return statusErr(409, "%s has no move leftover", id)
	}
	if err := h.removeKeptCopies(ctx, id, lefts); err != nil {
		return statusErr(502, "removing the old copies of %s: %v (kept on record; retry)", id, err)
	}
	return nil
}

// removeKeptCopies removes copies (instance id's kept ones), each on its
// own: a record goes only once every volume it pinned is confirmed gone;
// a failure keeps it (and the move guard), and the doctor shows
// server_copy_not_removed. Caller holds id's lock.
func (h *Hub) removeKeptCopies(ctx context.Context, id string, copies []state.MovedFrom) error {
	var errs []error
	gone := map[string]bool{}
	for _, l := range copies {
		if err := h.removeCopy(ctx, id, l); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", serverLabel(l.Server), err))
			h.noteCopyRemoveFail(id, serverLabel(l.Server)+": "+untrusted(err.Error(), 200))
			continue
		}
		gone[l.Server] = true
	}
	h.mu.Lock()
	in := h.st.Instances[id]
	if in.MovedFrom != nil && gone[in.MovedFrom.Server] {
		in.MovedFrom = nil
	}
	if in.MoveTargetLeftover != nil && gone[in.MoveTargetLeftover.Server] {
		in.MoveTargetLeftover = nil
	}
	in.OlderCopies = slices.DeleteFunc(in.OlderCopies, func(c state.MovedFrom) bool { return gone[c.Server] })
	if _, ok := h.st.Instances[id]; ok {
		h.st.Instances[id] = in
		h.saveLocked()
	}
	h.mu.Unlock()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	h.noteCopyRemoveFail(id, "")
	return nil
}

// removeCopy removes kept copy l of instance id: only the volume names
// pinned at move time, never forced, then confirmed gone. On a worker the
// agent sees no volume of an unbundled project, so a volumes-only bundle
// (those names, no services, env or files) brings exactly them into scope
// first, and is removed after, whatever happened.
func (h *Hub) removeCopy(ctx context.Context, id string, l state.MovedFrom) (err error) {
	rt, err := h.rtForServer(l.Server)
	if err != nil {
		return err
	}
	if l.Server != "" {
		b, ok := unwrapRT(rt).(bundlePusher)
		if !ok {
			return errors.New("the worker's runtime takes no bundles")
		}
		files, m, err := volumesOnlyBundle(id, l)
		if err != nil {
			return fmt.Errorf("bringing the copy into scope: %w", err)
		}
		if err := b.PushBundle(ctx, id, files, m); err != nil {
			return fmt.Errorf("bringing the copy into scope: %w", err)
		}
		defer func() {
			if rerr := h.removeWorkerBundle(context.Background(), l.Server, id); rerr != nil && err == nil {
				err = fmt.Errorf("removing the volumes-only bundle: %w", rerr)
			}
		}()
	}
	vs, err := rt.ListVolumes(ctx, runtime.Filter{Instance: id})
	if err != nil {
		return fmt.Errorf("listing the volumes: %w", err)
	}
	var errs []error
	for _, v := range vs {
		// Only the names pinned at move time, still the project's.
		if !slices.Contains(l.Volumes, v.Name) || v.Labels[docker.LabelProject] != projectName(id) {
			continue
		}
		if err := rt.RemoveVolume(ctx, v.Name); err != nil && !docker.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("%s: %w", v.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	// Confirmed: none of the pinned names is left.
	vs, err = rt.ListVolumes(ctx, runtime.Filter{Instance: id})
	if err != nil {
		return fmt.Errorf("confirming the removal: %w", err)
	}
	for _, v := range vs {
		if slices.Contains(l.Volumes, v.Name) {
			return fmt.Errorf("%s is still there", v.Name)
		}
	}
	return nil
}

// volumesOnlyBundle is a bundle declaring only kept copy l's volumes,
// under the compose keys and the template id pinned at move time (final
// review H1): no services, no env, no overrides, no templates, appfiles
// or certificates. Validated here (agentapi.ValidateManifest, the
// agent's own manifest rules): a copy whose pins don't fit fails loudly.
func volumesOnlyBundle(id string, l state.MovedFrom) (memFS, agentapi.BundleManifest, error) {
	tmpl := l.Template
	if tmpl == "" {
		tmpl = id
	}
	var b strings.Builder
	b.WriteString("services: {}\nvolumes:\n")
	m := agentapi.BundleManifest{Instance: id, Template: tmpl, Volumes: map[string]string{}, Files: map[string]agentapi.FileEntry{}, AdoptVolumes: true}
	names := slices.Clone(l.Volumes)
	slices.Sort(names)
	for _, n := range names {
		k := l.Keys[n]
		if k == "" {
			return nil, m, fmt.Errorf("volume %s has no compose key pinned: remove it by hand on %s", n, serverLabel(l.Server))
		}
		if _, dup := m.Volumes[k]; dup {
			return nil, m, fmt.Errorf("two kept volumes pinned under key %s", k)
		}
		fmt.Fprintf(&b, "  %s:\n    name: %q\n", k, n)
		m.Volumes[k] = n
	}
	compose := []byte(b.String())
	sum := sha256.Sum256(compose)
	m.Files[bundleCompose] = agentapi.FileEntry{SHA256: hex.EncodeToString(sum[:]), Mode: 0o644, Size: int64(len(compose))}
	if err := agentapi.ValidateManifest(m, agentapi.MaxBundle); err != nil {
		return nil, m, fmt.Errorf("the volumes-only bundle: %w", err)
	}
	return memFS{bundleCompose: compose}, m, nil
}

// noteCopyRemoveFail records (why != "") or clears a kept copy's failed
// removal for the doctor's server_copy_not_removed.
func (h *Hub) noteCopyRemoveFail(id, why string) {
	h.srvMu.Lock()
	defer h.srvMu.Unlock()
	if why == "" {
		delete(h.copyRemoveFail, id)
		return
	}
	if h.copyRemoveFail == nil {
		h.copyRemoveFail = map[string]string{}
	}
	h.copyRemoveFail[id] = why
}

// RecoverMoves (Review Focus 2) settles moves a Hub restart interrupted,
// and retries stuck ones (each under the instance's lock; a busy one is
// left to the next call): from the restore on, the target is taken down
// first — when that fails, the instance runs nowhere (stuck) —; then the
// routing goes back to the source, which starts again. The target's
// half-restored volumes are recorded as its leftover.
func (h *Hub) RecoverMoves() {
	h.mu.RLock()
	var ids []string
	for id, in := range h.st.Instances {
		if in.State == state.InstanceMoving && in.Move != nil {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	slices.Sort(ids)
	for _, id := range ids {
		h.recoverMove(id)
	}
}

func (h *Hub) recoverMove(id string) {
	unlock, err := h.lockApp(id)
	if err != nil {
		return // its own move runs; or retried next time
	}
	defer unlock()
	defer h.ownMove(id)()
	h.mu.RLock()
	in := h.st.Instances[id]
	v := h.findLocked(id)
	enabled := h.st.IsEnabled(id)
	h.mu.RUnlock()
	if in.State != state.InstanceMoving || in.Move == nil {
		return
	}
	mv := *in.Move
	// An undo interrupted while starting its source copy (R4-L8): that
	// copy (unrouted) goes; the current one keeps its routing.
	if mv.Phase == MoveUndoStarting && v != nil {
		if rt, err := h.rtForServer(mv.To); err == nil {
			if err := unwrapRT(rt).Down(context.Background(), h.runtimeProject(v)); err != nil {
				log.Printf("move recovery: %s: taking the undo's copy down on %s failed (%v): retried", id, serverLabel(mv.To), err)
				return
			}
		} else {
			log.Printf("move recovery: %s: %s isn't reachable to take the undo's copy down: retried", id, serverLabel(mv.To))
			return
		}
		h.setMove(id, nil, mv.From, "")
		log.Printf("move recovery: %s: an interrupted undo's copy on %s was taken down", id, serverLabel(mv.To))
		return
	}
	// A worker target nothing was pushed to holds nothing (H2): no down.
	if mv.Phase != MoveBackup && mv.Phase != MoveCheck && v != nil && (mv.To == "" || mv.Pushed) {
		if err := h.downOn(context.Background(), mv.To, v); err != nil {
			mv.Phase = MoveStuck
			h.setMove(id, &mv, mv.From, state.InstanceMoving)
			h.relaysDown(context.Background(), id)
			log.Printf("move recovery: %s: taking it down on %s failed (%v): it runs nowhere, retried", id, serverLabel(mv.To), err)
			return
		}
		h.recordTargetLeftover(id, mv.To)
	}
	h.setMove(id, nil, mv.From, "")
	if mv.From == "" {
		removeRelayFiles(h, id)
	}
	if err := h.publishLink(); err != nil {
		log.Printf("move recovery: %s: %v", id, err)
	}
	log.Printf("move recovery: %s was interrupted at %s: it runs on %s again", id, mv.Phase, serverLabel(mv.From))
	if enabled && v != nil {
		if err := h.startAgain(v); err != nil {
			log.Printf("move recovery: starting %s on %s: %v", id, serverLabel(mv.From), err)
		}
	}
}

// stuckMovesLocked are the instances a move left routed to neither copy
// (doctor server_move_stuck). Caller holds mu.
func (h *Hub) stuckMovesLocked() map[string]string {
	out := map[string]string{}
	for id, in := range h.st.Instances {
		if in.State == state.InstanceMoving && in.Move != nil && in.Move.Phase == MoveStuck {
			out[id] = in.Move.To
		}
	}
	return out
}
