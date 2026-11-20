package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
)

// Scheduled backups (contract §11.5, Task 11; fix round 3): per server
// (the primary's schedule is AppState.PrimaryBackups) off, daily or
// weekly at an hour of the Hub's local time zone (TZ, default UTC). At
// the hour each of the server's enabled instances is backed up in turn
// as op backup with no actor (the usual consistency rule: stopped
// briefly, started again), reason "scheduled". The archives the
// scheduler wrote are listed in <backups>/<id>/.scheduled.json; only
// those are ever pruned (the 3 newest kept), never an archive anything
// else wrote or one copied in. A server offline at the hour is skipped
// with an op-record note (never over a running operation's record).

// ScheduledKeep: scheduled archives kept per instance.
const ScheduledKeep = 3

// scheduleDue: schedule s fires in the hour of now.
func scheduleDue(s state.BackupSchedule, now time.Time) bool {
	switch s.Mode {
	case "daily":
		return now.Hour() == s.Hour
	case "weekly":
		return now.Hour() == s.Hour && int(now.Weekday()) == s.Weekday
	}
	return false
}

// scheduleSlot is now's local date and hour (the DST fall-back hour is
// one slot).
func scheduleSlot(now time.Time) string { return now.Format("2006-01-02 15") }

// RunBackupSchedules checks the schedules every `every` until ctx ends.
func (h *Hub) RunBackupSchedules(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.backupSchedulesTick(ctx, h.now().Local())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// backupSchedulesTick runs the schedules due at now (each server once
// per slot, the slot persisted before the run).
func (h *Hub) backupSchedulesTick(ctx context.Context, now time.Time) {
	slot := scheduleSlot(now)
	h.mu.RLock()
	scheds := map[string]state.BackupSchedule{"": h.st.PrimaryBackups}
	for id, s := range h.st.Servers {
		if s.State != ServerRevoked && s.Revoke == nil && !s.ClusterNode() {
			scheds[id] = s.BackupSchedule
		}
	}
	h.mu.RUnlock()
	servers := make([]string, 0, len(scheds))
	for s := range scheds {
		servers = append(servers, s)
	}
	sort.Strings(servers)
	for _, server := range servers {
		if ctx.Err() != nil {
			return
		}
		if !scheduleDue(scheds[server], now) {
			continue
		}
		h.mu.Lock()
		done := h.st.ScheduleSlots[server] == slot
		if !done {
			if h.st.ScheduleSlots == nil {
				h.st.ScheduleSlots = map[string]string{}
			}
			h.st.ScheduleSlots[server] = slot
			h.saveLocked()
		}
		h.mu.Unlock()
		if !done {
			h.runScheduledBackups(ctx, server)
		}
	}
}

// runScheduledBackups backs up server's enabled instances in turn.
func (h *Hub) runScheduledBackups(ctx context.Context, server string) {
	h.mu.RLock()
	var ids []string
	for i := range h.instances {
		id := h.instances[i].ID
		if h.st.IsEnabled(id) && h.st.Instances[id].Server == server && h.st.Instances[id].State == "" {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	sort.Strings(ids)
	if server != "" {
		if _, err := h.rtForServer(server); err != nil {
			for _, id := range ids {
				h.scheduleNote(id, fmt.Errorf("scheduled backup skipped: %w", err))
			}
			log.Printf("scheduled backups: %s skipped: %v", serverLabel(server), err)
			return
		}
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := h.scheduledBackup(ctx, id); err != nil {
			log.Printf("scheduled backups: %s: %s", id, h.RedactErr(id, err))
		}
	}
}

// scheduleNote records a skipped backup on instance id: under its lock
// (an operation holding it keeps its record), never over a running
// record, redacted.
func (h *Hub) scheduleNote(id string, err error) {
	unlock, lerr := h.lockApp(id)
	if lerr != nil {
		return
	}
	defer unlock()
	h.recordOpUnlessOther(id, OpRecord{Op: OpBackup, At: h.now().UTC(), OK: false, Error: clipRunes(h.RedactErr(id, err), 300)})
}

// scheduledBackup backs instance id up as op backup (no actor; reason
// scheduled) under its lifecycle lock, lists the archive as the
// scheduler's and prunes the older ones.
func (h *Hub) scheduledBackup(ctx context.Context, id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	var entry *BackupEntry
	_, _, err = h.runOpSync(id, OpBackup, directory.Actor{}, nil, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		var berr error
		entry, berr = h.backupCtx(ctx, id, BackupScheduled, false)
		if berr != nil {
			return nil, nil, fmt.Errorf("scheduled backup: %w", berr)
		}
		return map[string]string{"archive": entry.Archive}, nil, nil
	})
	if err != nil {
		return err
	}
	if err := h.listScheduled(id, entry.Archive, entry.CreatedAt); err != nil {
		return err
	}
	return h.pruneScheduled(id)
}

// scheduledEntry is one archive the scheduler wrote.
type scheduledEntry struct {
	Archive string    `json:"archive"`
	At      time.Time `json:"at"`
}

func (h *Hub) scheduledIndex(id string) string {
	return filepath.Join(h.backupsDir(), id, ".scheduled.json")
}

func (h *Hub) readScheduled(id string) ([]scheduledEntry, error) {
	b, err := os.ReadFile(h.scheduledIndex(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []scheduledEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", h.scheduledIndex(id), err)
	}
	return out, nil
}

func (h *Hub) writeScheduled(id string, list []scheduledEntry) error {
	b, _ := json.Marshal(list)
	return fsutil.WriteFileAtomic(h.scheduledIndex(id), b, 0o600)
}

// listScheduled adds archive (written at at) to instance id's index.
func (h *Hub) listScheduled(id, archive string, at time.Time) error {
	list, err := h.readScheduled(id)
	if err != nil {
		return err
	}
	list = append(list, scheduledEntry{Archive: archive, At: at.UTC()})
	return h.writeScheduled(id, list)
}

// pruneScheduled keeps the ScheduledKeep newest archives the scheduler
// listed for instance id (by its recorded time); no other archive —
// manual, delete, restore, move, or one copied in that calls itself
// scheduled — is ever touched.
func (h *Hub) pruneScheduled(id string) error {
	list, err := h.readScheduled(id)
	if err != nil {
		return err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
	keep := list[:min(len(list), ScheduledKeep)]
	for _, e := range list[len(keep):] {
		if !archiveRe.MatchString(e.Archive) || filepath.Dir(filepath.FromSlash(e.Archive)) != id {
			continue
		}
		if err := fsutil.Remove(filepath.Join(h.backupsDir(), filepath.FromSlash(e.Archive))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		log.Printf("scheduled backups: %s pruned", e.Archive)
	}
	return h.writeScheduled(id, slices.Clone(keep))
}
