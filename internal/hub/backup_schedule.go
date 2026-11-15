package hub

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// Scheduled backups (contract §11.5, Task 11): per server (the primary's
// schedule is AppState.PrimaryBackups) off, daily or weekly at an hour of
// the Hub's local time zone (TZ, default UTC). At the hour each of the
// server's enabled instances is backed up in turn (the usual consistency
// rule: stopped briefly, started again), reason "scheduled"; the 3 newest
// scheduled archives per instance are kept, no other archive is ever
// touched. A server offline at the hour is skipped with an op-record note.

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
// per due hour).
func (h *Hub) backupSchedulesTick(ctx context.Context, now time.Time) {
	slot := now.Truncate(time.Hour).Format(time.RFC3339)
	h.mu.RLock()
	scheds := map[string]state.BackupSchedule{"": h.st.PrimaryBackups}
	for id, s := range h.st.Servers {
		if s.State != ServerRevoked && s.Revoke == nil {
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
		h.srvMu.Lock()
		if h.schedRan == nil {
			h.schedRan = map[string]string{}
		}
		done := h.schedRan[server] == slot
		h.schedRan[server] = slot
		h.srvMu.Unlock()
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
				h.recordOp(id, OpRecord{Op: OpBackup, At: h.now().UTC(), OK: false,
					Error: fmt.Sprintf("scheduled backup skipped: %v", err)})
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
			log.Printf("scheduled backups: %s: %v", id, err)
		}
	}
}

// scheduledBackup backs instance id up (reason scheduled) under its
// lifecycle lock, then prunes its older scheduled archives.
func (h *Hub) scheduledBackup(ctx context.Context, id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := h.backupCtx(ctx, id, BackupScheduled, false); err != nil {
		h.recordOp(id, OpRecord{Op: OpBackup, At: h.now().UTC(), OK: false, Error: "scheduled backup: " + clipRunes(err.Error(), 300)})
		return err
	}
	return h.pruneScheduled(id)
}

// pruneScheduled keeps the ScheduledKeep newest scheduled archives of
// instance id; every other archive (manual, delete, restore, move) is
// never touched.
func (h *Hub) pruneScheduled(id string) error {
	all, err := h.ListBackups(id)
	if err != nil {
		return err
	}
	var sch []BackupEntry
	for _, e := range all {
		if e.Reason == BackupScheduled && e.Instance == id {
			sch = append(sch, e)
		}
	}
	sort.Slice(sch, func(i, j int) bool { return sch[i].CreatedAt.After(sch[j].CreatedAt) })
	for _, e := range sch[min(len(sch), ScheduledKeep):] {
		if err := os.Remove(filepath.Join(h.backupsDir(), filepath.FromSlash(e.Archive))); err != nil {
			return err
		}
		log.Printf("scheduled backups: %s pruned", e.Archive)
	}
	return nil
}
