package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Moves between servers (contract §17, Task 11): the instance is backed
// up on its source (which stops it), restored into the same id on the
// target, then switched (relays follow, a new relay token) and started
// there. Until the switch has started the target, any failure or Stop
// puts the routing back on the source and starts it again: two routed
// copies never exist, and the instance is never left stopped. The
// source's volumes stay (MovedFrom) for an undo within 7 days, until
// removed.

const (
	OpMove = "move"
	// Move phases (the op's steps and Instance.Move.Phase).
	MoveCheck   = "check"
	MoveBackup  = "backup"
	MoveRestore = "restore"
	MoveSwitch  = "switch"
	MoveKeep    = "keep"
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

func normServer(s string) string {
	if s == servers.PrimaryID {
		return ""
	}
	return s
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
	in.Move, in.Server, in.State = mv, server, st
	h.st.Instances[id] = in
	h.noteInstanceServer(id, server)
	h.saveLocked()
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
	}
	view := *v
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
	}
	if from != "" {
		if _, err := h.rtForServer(from); err != nil {
			return err
		}
	}
	p.Done(MoveCheck)
	mv := &state.Move{From: from, To: to, StartedAt: h.now().UTC(), Phase: MoveBackup}
	h.setMove(id, mv, from, state.InstanceMoving)
	// back: before the switch, everything goes back to the source.
	back := func(cause error) error {
		h.setMove(id, nil, from, "")
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

	// restore (same id, target runtime, new volumes)
	p.Start(MoveRestore)
	if err := h.moveHook(MoveRestore); err != nil {
		return stopped(err)
	}
	if err := h.restoreForMove(ctx, id, entry.Archive, actor); err != nil {
		return stopped(fmt.Errorf("the restore on %s failed — %s runs on %s again: %w", serverLabel(to), id, serverLabel(from), err))
	}
	p.Done(MoveRestore)
	if ctx.Err() != nil {
		return stopped(ctx.Err())
	}

	// switch: relays follow (Up brings them up for a worker target; a
	// primary target needs the source's relays gone), a new relay token,
	// then the start on the target.
	mv.Phase = MoveSwitch
	h.setMove(id, mv, to, state.InstanceMoving)
	p.Start(MoveSwitch)
	if err := h.moveHook(MoveSwitch); err != nil {
		return stopped(err)
	}
	if to == "" {
		if err := h.relaysDown(context.Background(), id); err != nil {
			return stopped(err)
		}
		removeRelayFiles(h, id)
	} else if err := h.newRelayToken(id); err != nil {
		return stopped(statusErr(500, "the relay token: %v", err))
	}
	if enabled {
		if err := h.startAgain(&view); err != nil {
			// Not routed yet (the up failed): take the target down, back
			// to the source.
			h.rtOf(id).Down(context.Background(), h.runtimeProject(&view))
			return stopped(fmt.Errorf("starting %s on %s failed — it runs on %s again: %w", id, serverLabel(to), serverLabel(from), err))
		}
	}
	if !p.CloseStop() {
		h.rtOf(id).Down(context.Background(), h.runtimeProject(&view))
		return back(ErrStopped)
	}
	p.Done(MoveSwitch)

	// keep
	p.Start(MoveKeep)
	h.mu.Lock()
	in = h.st.Instances[id]
	in.Move, in.State = nil, ""
	in.MovedFrom = &state.MovedFrom{Server: from, At: h.now().UTC()}
	h.st.Instances[id] = in
	h.saveLocked()
	h.mu.Unlock()
	p.Done(MoveKeep)
	log.Printf("instance %s moved from %s to %s (archive %s)", id, serverLabel(from), serverLabel(to), entry.Archive)
	return nil
}

// moveHook runs the test hook at a phase's start (nil: none).
func (h *Hub) moveHook(phase string) error {
	if h.testHookMove != nil {
		return h.testHookMove(phase)
	}
	return nil
}

func removeRelayFiles(h *Hub, id string) {
	for _, p := range []string{h.relayComposePath(id), h.relayEnvPath(id)} {
		os.Remove(p)
	}
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

// UndoMove switches instance id back to the source of its last move
// (within 7 days; the API's confirm is the typed id — changes since the
// move are lost): it stops on the current server and starts on the
// source volumes. Audited instance.move_undo.
func (h *Hub) UndoMove(ctx context.Context, id, confirm string, actor directory.Actor) (err error) {
	defer func() { h.auditOp(actor, "instance.move_undo", id, "", err) }()
	if confirm != id {
		return statusErr(400, "type the instance id (%s) to confirm: changes since the move are lost", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	h.mu.RLock()
	in := h.st.Instances[id]
	v := h.findLocked(id)
	enabled := h.st.IsEnabled(id)
	h.mu.RUnlock()
	switch {
	case v == nil:
		return statusErr(404, "instance not found: %s", id)
	case in.MovedFrom == nil:
		return statusErr(409, "%s has no move to undo", id)
	case h.now().Sub(in.MovedFrom.At) > UndoWindow:
		return statusErr(409, "the move of %s is older than 7 days: it can't be undone (remove the source's data instead)", id)
	}
	src := in.MovedFrom.Server
	if src != "" {
		if _, err := h.rtForServer(src); err != nil {
			return err
		}
	}
	view := *v
	if err := h.composeDownFor(&view); err != nil {
		return err
	}
	if in.Server == "" {
		// Leaving the primary for a worker: its relays come with the up.
		if err := h.newRelayToken(id); err != nil {
			return err
		}
	}
	h.mu.Lock()
	in = h.st.Instances[id]
	in.Server, in.MovedFrom = src, nil
	h.st.Instances[id] = in
	h.noteInstanceServer(id, src)
	h.saveLocked()
	h.mu.Unlock()
	if src == "" {
		h.relaysDown(context.Background(), id)
		removeRelayFiles(h, id)
	}
	if enabled {
		if err := h.startAgain(&view); err != nil {
			return fmt.Errorf("starting %s on %s failed: %w", id, serverLabel(src), err)
		}
	}
	return nil
}

// composeDownFor takes instance t down on its current runtime.
func (h *Hub) composeDownFor(t *templates.Template) error {
	if err := h.rtOf(t.ID).Down(context.Background(), h.runtimeProject(t)); err != nil {
		return fmt.Errorf("stopping %s: %w", t.ID, err)
	}
	return nil
}

// RemoveMoveLeftover removes the volumes a move left on its source
// (typed id), through the source's runtime. Audited
// instance.move_leftover_removed.
func (h *Hub) RemoveMoveLeftover(ctx context.Context, id, confirm string, actor directory.Actor) (err error) {
	defer func() { h.auditOp(actor, "instance.move_leftover_removed", id, "", err) }()
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
	if in.MovedFrom == nil {
		return statusErr(409, "%s has no move leftover", id)
	}
	rt, err := h.rtForServer(in.MovedFrom.Server)
	if err != nil {
		return err
	}
	vs, err := rt.ListVolumes(ctx, runtime.Filter{Instance: id})
	if err != nil {
		return statusErr(502, "listing %s's volumes on %s: %v", id, serverLabel(in.MovedFrom.Server), err)
	}
	var errs []error
	for _, v := range vs {
		if v.Labels["com.docker.compose.project"] != projectName(id) {
			continue
		}
		if err := rt.RemoveVolume(ctx, v.Name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", v.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return statusErr(502, "removing the leftover volumes: %v", err)
	}
	h.mu.Lock()
	in = h.st.Instances[id]
	in.MovedFrom = nil
	h.st.Instances[id] = in
	h.saveLocked()
	h.mu.Unlock()
	return nil
}

// RecoverMoves (Review Focus 2) settles moves a Hub restart interrupted:
// before the switch, the routing goes back to the source, which starts
// again; one interrupted at the switch has its target taken down first
// (never two routed copies), then the same. The target's half-restored
// volumes are left for the move leftover cleanup. Run after the engine
// guard.
func (h *Hub) RecoverMoves() {
	h.mu.RLock()
	var ids []string
	for id, in := range h.st.Instances {
		if in.State == state.InstanceMoving && in.Move != nil {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range ids {
		h.mu.RLock()
		in := h.st.Instances[id]
		v := h.findLocked(id)
		enabled := h.st.IsEnabled(id)
		h.mu.RUnlock()
		mv := *in.Move
		if mv.Phase == MoveSwitch && v != nil {
			if rt, err := h.rtForServer(mv.To); err == nil {
				if err := rt.Down(context.Background(), h.runtimeProject(v)); err != nil {
					log.Printf("move recovery: %s: taking it down on %s: %v", id, serverLabel(mv.To), err)
				}
			}
			if mv.To != "" {
				h.relaysDown(context.Background(), id)
			}
		}
		h.mu.Lock()
		in = h.st.Instances[id]
		in.Server, in.Move, in.State = mv.From, nil, ""
		if mv.Archive != "" {
			in.MovedFrom = nil
		}
		h.st.Instances[id] = in
		h.noteInstanceServer(id, mv.From)
		h.saveLocked()
		h.mu.Unlock()
		log.Printf("move recovery: %s was interrupted at %s: it runs on %s again", id, mv.Phase, serverLabel(mv.From))
		if enabled && v != nil {
			if err := h.startAgain(v); err != nil {
				log.Printf("move recovery: starting %s on %s: %v", id, serverLabel(mv.From), err)
			}
		}
	}
}
