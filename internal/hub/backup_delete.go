package hub

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// Deleting a backup archive (user ruling 2026-11-26, contract §11.5
// "Deleting a backup"): admin-only, typed confirmation, audited
// instance.backup_delete; only an archive GET /api/backups lists, never
// one a running restore uses or one the Hub still needs (an unfinished
// delete's or restore's, a move's, the pending core mail restore's).

// leaseArchive marks archive as used by a restore until the returned
// release runs: DeleteBackup refuses it meanwhile (409). Take it before
// checking that the archive exists (archiveExists): a delete that won
// the race leaves nothing to restore (404).
func (h *Hub) leaseArchive(archive string) (release func()) {
	h.archiveMu.Lock()
	if h.archiveLeases == nil {
		h.archiveLeases = map[string]int{}
	}
	h.archiveLeases[archive]++
	h.archiveMu.Unlock()
	return func() {
		h.archiveMu.Lock()
		if h.archiveLeases[archive]--; h.archiveLeases[archive] <= 0 {
			delete(h.archiveLeases, archive)
		}
		h.archiveMu.Unlock()
	}
}

// archiveNeededLocked names why the Hub still needs archive ("" none):
// the backup of an unfinished delete or the pre-restore backup of an
// unfinished restore (state.Instance.Backup), the archive a restore into
// a new instance is filling it from (RestoreAs), or a running move's.
// Caller holds mu (read).
func (h *Hub) archiveNeededLocked(archive string) string {
	for id, e := range h.st.Instances {
		switch {
		case e.Backup == archive && e.State == state.InstanceDeleting:
			return "it is the backup of the unfinished delete of " + id
		case e.Backup == archive && e.State == state.InstanceRestoring:
			return "it is the pre-restore backup of the unfinished restore of " + id + " (a rollback needs it)"
		case e.RestoreAs == archive:
			return "the unfinished restore into " + id + " is using it"
		case e.Move != nil && e.Move.Archive == archive:
			return "the move of " + id + " is using it"
		}
	}
	return ""
}

// DeleteBackup removes backup archive (relative to <data>/backups, as
// GET /api/backups lists it) for good. confirm must repeat the archive
// name (else 400). Refused: a name that isn't an archive name (400: no
// path is ever built from it), one that isn't listed (404: unreadable,
// not a regular file, another instance's manifest), one a running
// restore uses or the Hub still needs (409). Audited
// instance.backup_delete (target the archive's instance, detail
// archive=<name>), refusals included.
func (h *Hub) DeleteBackup(archive, confirm string, actor directory.Actor) (err error) {
	target := archive
	mm := archiveRe.FindStringSubmatch(archive)
	if mm != nil {
		target = mm[1]
	}
	defer func() {
		h.auditOp(actor, "instance.backup_delete", clip(target, 64), "archive="+clip(archive, 128), err)
	}()
	if mm == nil {
		return statusErr(400, "archive must be <instance-id>/<YYYYMMDDTHHMMSSZ>.tar, as the backups list names it")
	}
	if confirm != archive {
		return statusErr(400, "type the archive name (%s) to confirm the delete", archive)
	}
	// Only what the list shows (a regular file, its manifest readable and
	// naming its directory's instance).
	list, err := h.ListBackups(mm[1])
	if err != nil {
		return err
	}
	listed := false
	for _, b := range list {
		listed = listed || b.Archive == archive
	}
	if !listed {
		return statusErr(404, "no such backup: %s", archive)
	}
	h.archiveMu.Lock()
	defer h.archiveMu.Unlock()
	if h.archiveLeases[archive] > 0 {
		return statusErr(409, "a restore from %s is running: delete it when the restore has finished", archive)
	}
	// A running restore of the archive's instance: the pre-restore backup
	// it is writing or has just written is its rollback (state records it
	// only from the volumes step on), so none of its archives goes now.
	h.opsMu.Lock()
	r, ok := h.ops[mm[1]]
	h.opsMu.Unlock()
	if ok && r.Running && r.Op == OpRestore {
		return statusErr(409, "a restore of %s is running (its pre-restore backup is its rollback): delete %s when the restore has finished", mm[1], archive)
	}
	h.mu.RLock()
	why := h.archiveNeededLocked(archive)
	h.mu.RUnlock()
	if why != "" {
		return statusErr(409, "%s can't be deleted: %s", archive, why)
	}
	if want, pending, perr := h.mailRestorePendingArchive(); perr != nil {
		return statusErr(409, "the pending core restore can't be read (%v): no backup is deleted until it can", perr)
	} else if pending && want == archive {
		return statusErr(409, "%s can't be deleted: the pending core restore (./portcullis restore) names it", archive)
	}
	p := archivePathOf(h, archive)
	if err := os.Remove(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return statusErr(404, "no such backup: %s", archive)
		}
		return statusErr(500, "removing %s: %v", archive, err)
	}
	// The instance's directory goes with its last archive (anything else
	// in it keeps it: Remove refuses a non-empty directory).
	_ = os.Remove(filepath.Dir(p))
	log.Printf("backups: %s deleted by %s", archive, actor.User)
	return nil
}
