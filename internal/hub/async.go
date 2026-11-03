package hub

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/fsutil"
)

// OpBackup is a manual instance backup (the long operations below run in
// the background, contract §11.7).
const OpBackup = "backup"

// AsyncOp is a long instance operation (backup, restore, restore into a
// new id, guarded delete) the Hub accepted and runs in the background,
// holding the instance's lock. Its progress and outcome are the
// instance's op record (<data>/ops/<instance>.json, LastOp): running
// while it works, then ok/error with the result and warnings.
type AsyncOp struct {
	OpID     string `json:"op_id"`
	Op       string `json:"op"`
	Instance string `json:"instance"`
}

// archiveExists: 404 unless the archive file is there (cheap, before a
// restore is accepted; the archive is verified in the background).
func (h *Hub) archiveExists(archive string) error {
	if _, err := os.Lstat(archivePathOf(h, archive)); err != nil {
		return statusErr(404, "archive %s not found", archive)
	}
	return nil
}

// startAsync runs fn in the background. fn calls ready once the request
// is accepted — validated, the actor resolved, the per-instance lock held
// — and startAsync then returns the AsyncOp (the API answers 202). If fn
// returns before ready, its error is the synchronous answer (a 4xx: bad
// input, busy, not found). The outcome lands in the op record.
func (h *Hub) startAsync(id, op string, fn func(ready func()) (map[string]string, []string, error)) (*AsyncOp, error) {
	a := &AsyncOp{OpID: newOpID(), Op: op, Instance: id}
	accepted := make(chan struct{})
	var once sync.Once
	ready := func() {
		once.Do(func() {
			h.recordOp(id, OpRecord{Op: op, OpID: a.OpID, At: time.Now().UTC(), Running: true})
			close(accepted)
		})
	}
	done := make(chan error, 1)
	// Tracked in h.bg: the Hub waits (bounded) for it on shutdown
	// (WaitTimeout); a record still "running" at the next start is marked
	// interrupted (loadOps).
	h.bg.Add(1)
	go func() {
		defer h.bg.Done()
		result, warnings, err := fn(ready)
		select {
		case <-accepted:
			h.finishAsync(id, op, a.OpID, result, warnings, err)
		default:
		}
		done <- err
	}()
	select {
	case <-accepted:
		return a, nil
	case err := <-done:
		select {
		case <-accepted: // accepted and already finished
			return a, nil
		default:
		}
		if err == nil {
			err = statusErr(500, "%s %s finished without starting", op, id)
		}
		return nil, err
	}
}

// finishAsync records the outcome of an accepted operation: the
// operation's own OpError record when it has one (compose output, hint,
// rolled back), plus the op id, result, warnings and the HTTP status the
// error stands for.
func (h *Hub) finishAsync(id, op, opID string, result map[string]string, warnings []string, err error) {
	r := OpRecord{Op: op, At: time.Now().UTC(), OK: err == nil}
	var oe *OpError
	if errors.As(err, &oe) {
		r = oe.Record
		r.Op = op
	} else if err != nil {
		redact := h.secretRedactor(id, secretsOf(err))
		r.Error = clipRunes(redact(err.Error()), 600)
		var ce *compose.Error
		if errors.As(err, &ce) {
			r.Output = redact(ce.Output)
		}
		r.Hint = opHint(r.Error + "\n" + r.Output)
	}
	r.OpID, r.Running, r.Result, r.Warnings = opID, false, result, warnings
	if err != nil {
		r.Status = errStatus(err)
		log.Printf("%s %s failed: %s", op, id, r.Error)
	}
	h.recordOp(id, r)
}

// recordOp stores r as id's op record (memory and <data>/ops/<id>.json),
// also for an instance that no longer exists (a finished delete).
// The file is written first: a poller that sees the record finished
// finds it on disk too.
func (h *Hub) recordOp(id string, r OpRecord) {
	if data, err := json.MarshalIndent(r, "", "  "); err == nil {
		os.MkdirAll(filepath.Dir(h.opPath(id)), 0700)
		if err := fsutil.WriteFileAtomic(h.opPath(id), data, 0600); err != nil {
			log.Printf("ops: cannot record %s %s: %v", r.Op, id, err)
		}
	}
	h.opsMu.Lock()
	h.ops[id] = r
	h.opsMu.Unlock()
}

// errStatus is the HTTP status an operation error stands for.
func errStatus(err error) int {
	var se *StatusError
	var busy ErrBusy
	switch {
	case errors.As(err, &busy):
		return 409
	case errors.As(err, &se):
		return se.Status
	}
	return 500
}

func newOpID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// StartBackup starts a manual backup of id in the background (§11.7):
// refusals (busy, deleting / restoring, unknown, no Docker) are returned
// at once; the archive name is the op record's result "archive".
func (h *Hub) StartBackup(id, actor string) (*AsyncOp, error) {
	return h.startAsync(id, OpBackup, func(ready func()) (map[string]string, []string, error) {
		e, err := h.backupInstance(id, actor, ready)
		if e != nil {
			return map[string]string{"archive": e.Archive}, nil, err
		}
		return nil, nil, err
	})
}

// StartRestore starts a same-instance restore in the background; the
// result holds "pre_restore_backup".
func (h *Hub) StartRestore(id, archive, actor string) (*AsyncOp, error) {
	return h.startAsync(id, OpRestore, func(ready func()) (map[string]string, []string, error) {
		res, err := h.restoreInstance(id, archive, actor, ready)
		return restoreResult(res, archive, ""), restoreWarnings(res), err
	})
}

// StartRestoreAs starts a restore into the new instance newID in the
// background (its op record is newID's); the result holds "instance".
func (h *Hub) StartRestoreAs(archive, newID, actor string, hosts map[string]string) (*AsyncOp, error) {
	return h.startAsync(newID, OpRestore, func(ready func()) (map[string]string, []string, error) {
		res, err := h.restoreInstanceAs(archive, newID, actor, hosts, ready)
		return restoreResult(res, archive, newID), restoreWarnings(res), err
	})
}

// StartDelete starts a guarded delete in the background (confirm = the
// id typed: checked at once); the result holds "backup".
func (h *Hub) StartDelete(id, confirm, actor string) (*AsyncOp, error) {
	return h.startAsync(id, OpDelete, func(ready func()) (map[string]string, []string, error) {
		res, err := h.deleteInstance(id, confirm, actor, ready)
		if res == nil {
			return nil, nil, err
		}
		var result map[string]string
		if res.Backup != "" {
			result = map[string]string{"backup": res.Backup}
		}
		return result, res.Warnings, err
	})
}

func restoreResult(res *RestoreResult, archive, newID string) map[string]string {
	m := map[string]string{"archive": archive}
	if newID != "" {
		m["instance"] = newID
	}
	if res != nil && res.PreRestoreBackup != "" {
		m["pre_restore_backup"] = res.PreRestoreBackup
	}
	return m
}

func restoreWarnings(res *RestoreResult) []string {
	if res == nil {
		return nil
	}
	return res.Warnings
}
