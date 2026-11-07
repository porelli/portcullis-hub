package hub

import (
	"context"
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
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
)

// OpBackup is a manual instance backup (the long operations below run in
// the background, contract §11.7).
const OpBackup = "backup"

// Shared-folder operations (folderassign.go): their op record key is
// opKeyFolder(id) ("_folder.<id>", folders.go); the doctor's scans use
// opKeyDoctor (ruling 20). Instance ids can't start with "_".
const (
	OpFolderAssign = "folder_assign"
	OpFolderUndo   = "folder_undo"
	opKeyDoctor    = "_doctor"
)

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
// input, busy, not found) and nothing is recorded. The outcome lands in
// the op record.
//
// steps are the operation's planned steps (contract §11.7 "Steps per
// operation"); nil: it reports no progress and can't be stopped. ctx
// carries the reporter (progressFrom) and is cancelled by a Stop
// (cancelOp): fn then runs its undo and returns ErrStopped (or ctx's
// error) once it is done.
func (h *Hub) startAsync(id, op string, actor directory.Actor, steps []Step, fn func(ctx context.Context, ready func()) (map[string]string, []string, error)) (*AsyncOp, error) {
	a, _, err := h.startOp(id, op, actor, steps, fn)
	return a, err
}

// startOp is startAsync; finished is closed once the accepted operation's
// final record is written.
func (h *Hub) startOp(id, op string, actor directory.Actor, steps []Step, fn func(ctx context.Context, ready func()) (map[string]string, []string, error)) (a *AsyncOp, finished <-chan struct{}, err error) {
	a = &AsyncOp{OpID: newOpID(), Op: op, Instance: id}
	p := h.newProgress(id, op, steps)
	ctx, cancel := context.WithCancel(withProgress(context.Background(), p))
	run := &opRun{opID: a.OpID, p: p}
	accepted := make(chan struct{})
	fin := make(chan struct{})
	var once sync.Once
	ready := func() {
		once.Do(func() {
			h.registerOp(id, run)
			p.begin(a.OpID, actor.User, cancel)
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
		defer cancel()
		result, warnings, err := fn(ctx, ready)
		select {
		case <-accepted:
			h.finishAsync(id, op, p, result, warnings, err)
			h.unregisterOp(id, run)
			close(fin)
		default:
		}
		done <- err
	}()
	select {
	case <-accepted:
		return a, fin, nil
	case err := <-done:
		select {
		case <-accepted: // accepted and already finished
			return a, fin, nil
		default:
		}
		if err == nil {
			err = statusErr(500, "%s %s finished without starting", op, id)
		}
		return nil, nil, err
	}
}

// runOpSync is the synchronous form of startAsync for the Hub's own
// callers (tests, the MCP): the same lock, record and stop registry —
// one code path — then it waits for the operation to end and returns
// fn's own answer (a refusal before ready as startAsync returns it).
func (h *Hub) runOpSync(id, op string, actor directory.Actor, steps []Step, fn func(ctx context.Context, ready func()) (map[string]string, []string, error)) (map[string]string, []string, error) {
	var (
		result   map[string]string
		warnings []string
		ferr     error
	)
	_, finished, err := h.startOp(id, op, actor, steps, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		result, warnings, ferr = fn(ctx, ready)
		return result, warnings, ferr
	})
	if err != nil {
		return nil, nil, err
	}
	<-finished
	return result, warnings, ferr
}

// finishAsync records the outcome of an accepted operation: the
// operation's own OpError record when it has one (compose output, hint,
// rolled back), plus the op id, actor (the user), result, warnings, the
// HTTP status the error stands for and its progress (Progress.finish:
// steps, created, the Stop state).
func (h *Hub) finishAsync(id, op string, p *Progress, result map[string]string, warnings []string, err error) {
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
	p.mu.Lock()
	opID, actor := p.rec.OpID, p.rec.Actor
	p.mu.Unlock()
	r.OpID, r.Running, r.Result, r.Warnings, r.Actor = opID, false, result, warnings, actor
	if err != nil {
		r.Status = errStatus(err)
		if !(isStopErr(err) && p.stopAccepted()) {
			log.Printf("%s %s failed: %s", op, id, r.Error)
		}
	}
	p.finish(r, err)
	// A hook that failed while this operation's record was running: its
	// failure becomes the instance's record once the operation ended ok
	// (and no other operation took the record meanwhile).
	h.opsMu.Lock()
	held, ok := h.heldHook[id]
	delete(h.heldHook, id)
	if cur := h.ops[id]; ok && err == nil && cur.OpID == opID && !cur.Running {
		h.recordOpLocked(id, held)
		log.Printf("ops: %s %s succeeded; the failure of a hook that ran during it stays recorded", op, id)
	}
	h.opsMu.Unlock()
}

// recordOp stores r as id's op record (memory and <data>/ops/<id>.json),
// also for an instance that no longer exists (a finished delete).
// The file is written first, both under opsMu (as finishOpGuarded): a
// poller that sees the record finished finds it on disk too, and memory
// and disk never hold different writers' records.
func (h *Hub) recordOp(id string, r OpRecord) {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	h.recordOpLocked(id, r)
}

// recordOpLocked is recordOp; the caller holds opsMu.
func (h *Hub) recordOpLocked(id string, r OpRecord) {
	if data, err := json.MarshalIndent(r, "", "  "); err == nil {
		os.MkdirAll(filepath.Dir(h.opPath(id)), 0700)
		if err := fsutil.WriteFileAtomic(h.opPath(id), data, 0600); err != nil {
			log.Printf("ops: cannot record %s %s: %v", r.Op, id, err)
		}
	}
	h.ops[id] = r
}

// recordOpUnlessOther is recordOp, except over a running record of
// another operation (another op id), which it leaves in place: false.
func (h *Hub) recordOpUnlessOther(id string, r OpRecord) bool {
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if cur, ok := h.ops[id]; ok && cur.Running && cur.OpID != r.OpID {
		return false
	}
	h.recordOpLocked(id, r)
	return true
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
func (h *Hub) StartBackup(id string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpBackup, actor, nil, func(_ context.Context, ready func()) (map[string]string, []string, error) {
		e, err := h.backupInstance(id, actor, ready)
		if e != nil {
			return map[string]string{"archive": e.Archive}, nil, err
		}
		return nil, nil, err
	})
}

// StartRestore starts a same-instance restore in the background; the
// result holds "pre_restore_backup".
func (h *Hub) StartRestore(id, archive string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpRestore, actor, nil, func(_ context.Context, ready func()) (map[string]string, []string, error) {
		res, err := h.restoreInstance(id, archive, actor, ready)
		return restoreResult(res, archive, ""), restoreWarnings(res), err
	})
}

// StartRestoreAs starts a restore into the new instance newID in the
// background (its op record is newID's); the result holds "instance".
func (h *Hub) StartRestoreAs(archive, newID string, actor directory.Actor, hosts map[string]string) (*AsyncOp, error) {
	return h.startAsync(newID, OpRestore, actor, nil, func(_ context.Context, ready func()) (map[string]string, []string, error) {
		res, err := h.restoreInstanceAs(archive, newID, actor, hosts, ready)
		return restoreResult(res, archive, newID), restoreWarnings(res), err
	})
}

// StartDelete starts a guarded delete in the background (confirm = the
// id typed: checked at once); the result holds "backup".
func (h *Hub) StartDelete(id, confirm string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpDelete, actor, nil, func(_ context.Context, ready func()) (map[string]string, []string, error) {
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
