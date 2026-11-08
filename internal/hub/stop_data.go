package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/portcullis/hub/internal/state"
)

// Stop of a backup, a restore (same instance or into a new id), a create
// and a delete (contract §11.4–11.7 "Stop"). Each undo runs from the op
// record — its steps, Created ledger and Before — so a Stop of a record
// whose undo failed, or of an interrupted one, does the same. The
// interrupted cases the Hub recovers at start (a same-instance restore:
// rolled back; a restore into a new id: removed; a delete past its point
// of no return: stays deleting) are stoppable false (markInterrupted).

// Undo step keys of these operations.
const (
	UndoArchive  = UndoPrefix + "archive"
	UndoRollback = UndoPrefix + "rollback"
	UndoInstance = UndoPrefix + "instance"
	UndoDeleting = UndoPrefix + "deleting"
)

// removePartialBackups removes the partial archives (*.tar.partial) and
// staging directories (.staging-*) in id's backup directory: what a
// stopped or interrupted backup of id left. Caller holds id's lock (no
// backup of id runs meanwhile).
func (h *Hub) removePartialBackups(id string) error {
	dir := filepath.Join(h.backupsDir(), id)
	es, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range es {
		if strings.HasPrefix(e.Name(), ".staging-") || strings.HasSuffix(e.Name(), ".tar.partial") {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// holdAILock takes id's AI lock for an undo that the operation's own run
// doesn't hold it for (a Stop of an interrupted record, or one whose undo
// failed: resumeStop holds only lockApp) — lockApp → aiLock, as the
// operation itself; a no-op while the operation holds it.
func (h *Hub) holdAILock(id string) func() {
	if _, held := h.aiHeld.Load(id); held {
		return func() {}
	}
	return h.lifecycleAILock(id)
}

// startAgainIfEnabled starts id's project again with its current files
// when it is enabled (a backup stopped it); a disabled one is left.
func (h *Hub) startAgainIfEnabled(id string) error {
	if !h.IsEnabled(id) {
		return nil
	}
	t := h.Template(id)
	if t == nil {
		return statusErr(409, "the template of %s is gone: it can't be started again", id)
	}
	return h.startAgain(t)
}

// undoBackup: the partial archive deleted (the .partial file and the
// staging directory) and, when the backup stopped the app (Before
// running, the stop step ran), the app started again (contract §11.5).
// Caller holds id's lock.
func (h *Hub) undoBackup(id string, p *Progress) error {
	defer h.holdAILock(id)()
	rec := p.snapshot()
	var copied []string
	for _, s := range rec.Steps {
		if strings.HasPrefix(s.Key, StepVolumePrefix) || s.Key == StepArchive {
			copied = append(copied, s.Key)
		}
	}
	steps := []undoStep{{UndoArchive, "Deleting the partial archive", copied, func() error {
		return h.removePartialBackups(id)
	}}}
	if rec.Before[beforeStopped] == "true" {
		steps = append(steps, undoStep{UndoStart, "Starting the app again", []string{StepStop}, func() error {
			return h.startAgainIfEnabled(id)
		}})
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}

// undoRestore undoes a stopped restore (contract §11.6 "Stop"), from the
// record: a restore into a new id is removed (undoRestoreAs); a same-
// instance restore that recorded "restoring" is rolled back from its
// pre-restore backup exactly like a failure (rolled_back), the backup
// kept; one stopped before that changed nothing — its partial backup is
// deleted and the app started again if the pre-restore backup stopped
// it. Caller holds id's lock (and its AI lock: the restore's).
func (h *Hub) undoRestore(id string, p *Progress) error {
	defer h.holdAILock(id)()
	rec := p.snapshot()
	if rec.Before[beforeNewID] == "true" {
		return h.undoRestoreAs(id, p, rec)
	}
	wasEnabled := rec.Before[beforeEnabled] == "true"
	keep := ""
	if rec.Before[beforeState] == state.InstanceCreated {
		keep = state.InstanceCreated
	}
	var steps []undoStep
	if rec.Before[beforeRestoring] == "true" {
		pre := rec.Before[beforePreRestore]
		steps = append(steps, undoStep{UndoRollback, "Putting the previous data back", []string{StepVolumes, StepConfig, StepStart}, func() error {
			view := h.Template(id)
			if view == nil {
				return statusErr(409, "the template of %s is gone: the pre-restore backup %s can't be put back", id, pre)
			}
			if err := h.stagedRollback(id, view, pre, wasEnabled, p); err != nil {
				return err
			}
			if cerr := h.clearRestoring(id, keep); cerr != nil {
				p.Warn(cerr.Error())
			}
			h.writePolicyLogged()
			p.RolledBack()
			return nil
		}})
	} else {
		if stepRan(rec, StepPreBackup) {
			steps = append(steps, undoStep{UndoArchive, "Deleting the partial pre-restore backup", nil, func() error {
				return h.removePartialBackups(id)
			}})
		}
		if rec.Before[beforeStopped] == "true" {
			steps = append(steps, undoStep{UndoStart, "Starting the app again", []string{StepPreBackup}, func() error {
				return h.startAgainIfEnabled(id)
			}})
		}
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}

// undoRestoreAs removes the new instance a stopped restore into a new id
// made (contract §11.6 "Stop"): the volumes and groups of its Created
// ledger, then its state, files and settings. Caller holds id's lock.
func (h *Hub) undoRestoreAs(id string, p *Progress, rec OpRecord) error {
	return h.undoNewInstance(id, p, rec, []string{StepInstance, StepConfig})
}

// undoCreate removes the new instance a stopped create made (contract
// §11.7 "Stop"): exactly the groups of its Created ledger, then its state
// entry and settings. Caller holds id's lock.
func (h *Hub) undoCreate(id string, p *Progress) error {
	return h.undoNewInstance(id, p, p.snapshot(), []string{StepInstance})
}

// undoNewInstance is undoCreate / undoRestoreAs: undo:volumes (the
// ledger's), undo:groups (the ledger's, as the stopping admin), then
// undo:instance (reversing instanceSteps) when the instance step ran.
func (h *Hub) undoNewInstance(id string, p *Progress, rec OpRecord, instanceSteps []string) error {
	ctx := context.Background()
	stopper := p.stopActor()
	created := rec.Created
	if created == nil {
		created = &Created{}
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	var steps []undoStep
	if len(created.Volumes) > 0 {
		steps = append(steps, undoStep{UndoVolumes, "Removing the volumes it created", []string{StepVolumes}, func() error {
			return h.undoVolumes(ctx, p, id, created.Volumes)
		}})
	}
	if len(created.Groups) > 0 {
		steps = append(steps, undoStep{UndoGroups, "Removing the groups it created", []string{StepGroups}, func() error {
			return h.undoGroups(ctx, p, groupsAPI, stopper, created.Groups)
		}})
	}
	if stepRan(rec, StepInstance) {
		steps = append(steps, undoStep{UndoInstance, "Removing the new instance", instanceSteps, func() error {
			// Its values go with it: keep redacting them.
			if set, err := h.redactionSetErr(id); err == nil {
				p.Redact(set)
			}
			return h.removeNewInstance(id)
		}})
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}

// undoDelete cancels a delete stopped before its point of no return
// (contract §11.4 "Stopping a delete"), from the record: the deleting
// record cleared (the entry as before: its state, backup and
// restore_as; a default instance that had no entry gets none), then —
// it was enabled — the instance enabled again exactly like an enable,
// or (still enabled: the backup stopped it) started again. The delete's
// backup stays listed. Caller holds id's lock (and its AI lock).
func (h *Hub) undoDelete(id string, p *Progress) error {
	defer h.holdAILock(id)()
	rec := p.snapshot()
	if rec.PointOfNoReturn {
		return statusErr(409, "the delete of %s is past the point of no return — finishing", id)
	}
	b := rec.Before
	var steps []undoStep
	if b[beforeState] != state.InstanceDeleting && stepRan(rec, StepBackup) {
		steps = append(steps, undoStep{UndoDeleting, "Cancelling the delete", nil, func() error {
			h.mu.Lock()
			e, ok := h.st.Instances[id]
			if !ok || e.State != state.InstanceDeleting {
				h.mu.Unlock()
				return nil
			}
			prev := e
			if b[beforeHadEntry] == "false" && len(e.Hosts) == 0 {
				delete(h.st.Instances, id)
			} else {
				e.State, e.Backup, e.RestoreAs = b[beforeState], b[beforeStateBackup], b[beforeRestoreAs]
				h.st.Instances[id] = e
			}
			h.rebuildLocked()
			h.refreshPublishedLocked()
			if err := h.st.Save(h.statePath()); err != nil {
				h.st.Instances[id] = prev
				h.rebuildLocked()
				h.mu.Unlock()
				return statusErr(500, "saving state.yaml: %v", err)
			}
			h.mu.Unlock()
			h.writePolicyLogged()
			return nil
		}})
	}
	if b[beforeEnabled] == "true" && (stepRan(rec, StepBackup) || stepRan(rec, StepStop)) {
		steps = append(steps, undoStep{UndoStart, "Turning the app back on", []string{StepStop}, func() error {
			if !h.IsEnabled(id) {
				_, err := h.enableInner(context.Background(), id, false)
				return err
			}
			if b[beforeStopped] == "true" {
				return h.startAgainIfEnabled(id)
			}
			return nil
		}})
	}
	defer h.TriggerReconcile()
	return runUndo(p, rec, steps)
}
