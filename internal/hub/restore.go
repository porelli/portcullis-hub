package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Restore (contract §11.6).

// RestoreResult is what a restore reports.
type RestoreResult struct {
	// PreRestoreBackup: the backup taken before a same-instance restore
	// (relative to <data>/backups).
	PreRestoreBackup string   `json:"pre_restore_backup,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// volumePlan is one volume a restore fills.
type volumePlan struct {
	key     string
	vol     docker.Volume // name, driver, labels, options to (re)create
	existed bool
	tar     string // staged inner tar; "" = leave the volume empty
}

// configProblem refuses (409, listing every problem) an archive whose
// per-instance configuration doesn't fit template t by SaveSettings'
// rules (configProblems): settings, sign-in mode, policy override, public
// exceptions. Archived per-person and per-group rows must be valid too
// (their group ids are kept). When it fits, c.Settings is made canonical
// for t (values parsed again, types recorded) — what applyConfigLocked
// stores.
func (h *Hub) configProblem(t *templates.Template, c *instanceConfig, archive string) error {
	var s state.InstanceSettings
	if c.Settings != nil {
		s = c.Settings.Clone()
	}
	u := SettingsUpdate{Ports: s.Ports, PublicAccess: c.PublicAccess, Values: map[string]json.RawMessage{}}
	if u.Ports == nil {
		u.Ports = map[string]string{}
	}
	var problems []error
	for k, v := range s.Values {
		b, err := json.Marshal(v)
		if err != nil {
			problems = append(problems, statusErr(400, "setting %s: %v", k, err))
			continue
		}
		u.Values[k] = b
	}
	if c.AuthPolicy != nil {
		// As state.yaml loads it (a legacy factor rewritten, never weaker)
		// and as applyConfigLocked stores it.
		n := policy.Normalize(*c.AuthPolicy)
		u.Policy = &n
	}
	if c.SignIn != "" {
		si := c.SignIn
		u.SignIn = &si
	}
	if c.PublicMode != "" {
		m := c.PublicMode
		u.PublicMode = &m
	}
	if len(c.PublicTokens) > 0 {
		tk := append([]string(nil), c.PublicTokens...)
		u.PublicTokens = &tk
	}
	h.mu.RLock()
	folders := h.folderSourceLocked()
	h.mu.RUnlock()
	parsed, more := configCheck(t, h.kinds, folders, u, c.SignIn == state.SignInNative)
	problems = append(problems, more...)
	canon := s
	canon.Values, canon.Types = nil, nil
	if parsed != nil {
		for k, v := range parsed.values {
			if v == nil {
				continue
			}
			if canon.Values == nil {
				canon.Values, canon.Types = map[string]any{}, map[string]string{}
			}
			canon.Values[k] = storedValue(v)
			canon.Types[k] = optionByKey(t, k).Type
		}
	}
	scoped := func(k, scope string) *templates.Option {
		o := optionByKey(t, k)
		if o == nil || o.EffectiveScope() != scope {
			problems = append(problems, statusErr(400, "setting %s is not a %s option of the template", clip(k, 64), scope))
			return nil
		}
		return o
	}
	for _, k := range slices.Sorted(maps.Keys(s.Person)) {
		o := scoped(k, templates.ScopePerson)
		if o == nil {
			continue
		}
		p, err := parsePerson(h.kinds, folders, o, s.Person[k])
		if err != nil {
			problems = append(problems, err)
			continue
		}
		canon.Person[k] = p
		if canon.Types == nil {
			canon.Types = map[string]string{}
		}
		canon.Types[k] = o.Type
	}
	for _, k := range slices.Sorted(maps.Keys(s.Groups)) {
		o := scoped(k, templates.ScopeGroup)
		if o == nil {
			continue
		}
		rows, err := parseRows(h.kinds, folders, o, s.Groups[k])
		if err != nil {
			problems = append(problems, err)
			continue
		}
		canon.Groups[k] = rows
		if canon.Types == nil {
			canon.Types = map[string]string{}
		}
		canon.Types[k] = o.Type
	}
	for _, k := range slices.Sorted(maps.Keys(s.Entered)) {
		o := scoped(k, templates.ScopePersonEntered)
		if o == nil {
			continue
		}
		vals := map[string]state.EnteredValue{}
		for _, u := range slices.Sorted(maps.Keys(s.Entered[k])) {
			e := s.Entered[k][u]
			v, err := h.kinds.Parse(o, e.Value)
			if err != nil {
				problems = append(problems, statusErr(400, "setting %s: the value of %s: %v", k, clip(u, 64), err))
				continue
			}
			e.Value = storedValue(v)
			lu := strings.ToLower(u)
			if _, dup := vals[lu]; dup {
				problems = append(problems, statusErr(400, "setting %s: two values for %s (names differ only in case)", k, clip(lu, 64)))
				continue
			}
			vals[lu] = e
		}
		if canon.Entered == nil {
			canon.Entered = map[string]map[string]state.EnteredValue{}
		}
		canon.Entered[k] = vals
		if canon.Types == nil {
			canon.Types = map[string]string{}
		}
		canon.Types[k] = o.Type
	}
	for k := range s.Secrets {
		if o := optionByKey(t, k); o == nil || o.Type != templates.TypeSecret {
			problems = append(problems, statusErr(400, "setting %s is not a secret option of the template", clip(k, 64)))
		}
	}
	if len(problems) == 0 {
		if c.Settings != nil {
			c.Settings = &canon
		}
		return nil
	}
	msgs := make([]string, 0, len(problems))
	for _, p := range problems {
		msgs = append(msgs, p.Error())
	}
	return statusErr(409, "archive %s refused (nothing was changed): its configuration doesn't fit template %s as it is now: %s", archive, t.TemplateID, strings.Join(msgs, "; "))
}

// RestoreInstance restores archive (<id>/<timestamp>.tar under
// <data>/backups; it must belong to id) into the existing instance id,
// replacing its data. The archive is verified first (400 bad name, 404
// missing, 409 checksum / layout / template mismatch, a configuration
// SaveSettings would refuse, a volume that can't be emptied — nothing
// changes on any of these). Then: a backup (reason restore; the instance
// is stopped), state "restoring" with that backup recorded (an
// interrupted restore is rolled back from it by the next RestoreInstance
// or at startup, RecoverRestores), every archived volume emptied and
// filled and every other volume of the project emptied (its data is in
// the pre-restore backup), the env, custom override and per-instance
// settings from the archive — the current hostnames are kept, the Hub
// override is regenerated —, and, if the instance was enabled, the full
// enable (Keycloak clients, access role, callbacks, policy, compose up).
// Any failure there puts the pre-restore backup back the same way (an
// *OpError with rolled_back; op "restore"). Audited as instance.restore.
func (h *Hub) RestoreInstance(id, archive string, actor directory.Actor) (res *RestoreResult, err error) {
	res = &RestoreResult{}
	_, _, err = h.runOpSync(id, OpRestore, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		var rerr error
		res, rerr = h.restoreInstance(ctx, id, archive, actor, ready)
		return restoreResult(res, archive, ""), restoreWarnings(res), rerr
	})
	return res, err
}

// Restore step keys (contract §11.7 "Steps per operation"): a same-
// instance restore is verify, pre_backup, volumes, config, start (only
// for an enabled instance); a restore into a new id verify, instance,
// groups, volumes, config.
const (
	StepVerify    = "verify"
	StepPreBackup = "pre_backup"
	StepVolumes   = "volumes"
	StepConfig    = "config"
	StepInstance  = "instance"
)

// The op record's Before keys of a restore (what its Stop puts back):
// enabled ("true" / "false") and the entry's state when it started, the
// pre-restore backup once written, restoring "true" once state.yaml says
// so (from then on a Stop rolls back), new_id "true" for a restore into
// a new id.
const (
	beforeEnabled    = "enabled"
	beforeState      = "state"
	beforePreRestore = "pre_restore_backup"
	beforeRestoring  = "restoring"
	beforeNewID      = "new_id"
)

// restoreInstance is the same-instance restore StartRestore and
// RestoreInstance run; ready is called once the request is accepted
// (archive name, lock held, instance restorable, the archive file
// exists), before the archive is verified (StartRestore answers 202
// then; a verification refusal is the operation's failure, with nothing
// changed). A Stop accepted before the commit runs its undo (settleOp:
// rolled back from the pre-restore backup once anything changed, else
// the app started again).
func (h *Hub) restoreInstance(ctx context.Context, id, archive string, actor directory.Actor, ready func()) (res *RestoreResult, err error) {
	res = &RestoreResult{}
	defer func() {
		h.auditOp(actor, "instance.restore", id, "archive="+archive+" pre_restore="+res.PreRestoreBackup, err)
	}()
	if mm := archiveRe.FindStringSubmatch(archive); mm == nil || mm[1] != id {
		return res, statusErr(400, "archive must be %s/<YYYYMMDDTHHMMSSZ>.tar (an archive of this instance)", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, h.busyErr(id, err)
	}
	defer unlock()
	defer h.lifecycleAILock(id)() // lockApp → aiLock (G35, §15.5)
	view, e, err := h.restoreTarget(id)
	if err != nil {
		return res, err
	}
	if err := h.archiveExists(archive); err != nil {
		return res, err
	}
	p := progressFrom(ctx)
	p.AddStep(StepVerify, "Checking the archive")
	p.AddStep(StepPreBackup, "Backing up the current data")
	p.AddStep(StepVolumes, "Restoring the volumes")
	p.AddStep(StepConfig, "Restoring the settings")
	if view.Enabled {
		p.AddStep(StepStart, "Starting the app")
	}
	ready()
	err = h.restoreSteps(ctx, p, id, archive, actor, view, e, res)
	return res, h.settleOp(id, OpRestore, p, err)
}

// restoreSteps is the accepted same-instance restore (caller holds id's
// lock): verify, pre_backup, volumes, config, start. Its failure path
// (the pre-restore backup put back) runs here unless a Stop was accepted
// first: then it returns ctx's error and settleOp runs the undo.
func (h *Hub) restoreSteps(ctx context.Context, p *Progress, id, archive string, actor directory.Actor, view *templates.Template, e state.Instance, res *RestoreResult) (err error) {
	p.Start(StepVerify)
	if e.State == state.InstanceRestoring {
		// An interrupted restore: put its pre-restore backup back first.
		if err := h.recoverRestoreLocked(id, view, e.Backup, p); err != nil {
			return err
		}
		if view, e, err = h.restoreTarget(id); err != nil {
			return err
		}
	}
	if err := h.checkFree(archivePathOf(h, archive), "staging the archive"); err != nil {
		return err
	}
	sb, err := h.stageArchiveCtx(ctx, archive, func(done, total int64) {
		p.Percent(StepVerify, pctOf(done, total), mib(done)+" of "+mib(total)+" checked")
	})
	if err != nil {
		return err
	}
	defer sb.cleanup()
	// Redacted from here on: the values the instance has now and the
	// archive's, whichever the instance holds when this ends.
	cur, unread := h.redactionSetErr(id)
	extra := append(cur, archiveSecrets(view, sb)...)
	p.Redact(extra)
	defer func() { err = hideIfUnread(withSecrets(err, extra), unread) }()
	if sb.m.Template != view.TemplateID {
		return statusErr(409, "archive %s is a backup of template %s, instance %s runs %s", archive, sb.m.Template, id, view.TemplateID)
	}
	// Values naming a shared folder that is gone are cleared (§11.6,
	// §13.15: restores never refuse folder values).
	res.Warnings = append(res.Warnings, dropMissingFolderRefs(&sb.cfg, h.folderDefs())...)
	if err := h.configProblem(view, &sb.cfg, archive); err != nil {
		return err
	}
	if sb.cfg.Settings != nil {
		if err := h.dockerRootValuesRule(context.Background(), view, sb.cfg.Settings.Values); err != nil {
			return err
		}
	}
	res.Warnings = append(res.Warnings, h.checkArchivedRows(context.Background(), view, sb.cfg.Settings, false)...)
	plan, err := h.restorePlan(id, view, sb)
	if err != nil {
		return err
	}
	for _, pl := range plan {
		if pl.tar == "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("volume %s is not in the archive: it was emptied (its data is in the pre-restore backup)", pl.vol.Name))
		}
	}
	wasEnabled := view.Enabled
	p.Before(beforeEnabled, strconv.FormatBool(wasEnabled))
	p.Before(beforeState, e.State)
	p.Done(StepVerify)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Back up what is there now (stops the instance; restarted by
	// backupCtx if the backup fails, by the Stop's undo if stopped).
	p.Start(StepPreBackup)
	pre, err := h.backupCtx(ctx, id, BackupRestore, true)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("%v: %w", err, cerr)
		}
		return prefixOpError(OpRestore, "the backup before the restore failed — nothing was restored: ", err)
	}
	res.PreRestoreBackup = pre.Archive
	p.Before(beforePreRestore, pre.Archive)
	p.Detail(StepPreBackup, pre.Archive)
	p.Done(StepPreBackup)
	if err := ctx.Err(); err != nil {
		return err
	}
	p.Start(StepVolumes)
	// The record survives a crash from here on.
	if err := h.markRestoring(id, pre.Archive); err != nil {
		if !p.CloseStop() {
			return context.Canceled // the Stop's undo starts it again
		}
		if wasEnabled {
			if rerr := h.startAgain(view); rerr != nil {
				log.Printf("instance %s: starting again after a refused restore: %v", id, rerr)
			}
		}
		return statusErr(500, "recording the restore failed — nothing was restored: %v", err)
	}
	p.Before(beforeRestoring, "true")
	// A never-enabled instance is "created" again afterwards.
	keep := ""
	if e.State == state.InstanceCreated {
		keep = state.InstanceCreated
	}
	air, applyErr := h.applyRestore(ctx, id, sb, plan, wasEnabled, true, actor, p)
	// The commit gate: a Stop accepted until here is rolled back by its
	// undo; none is accepted after (a failure's rollback below included).
	if !p.CloseStop() {
		if applyErr == nil {
			applyErr = context.Canceled
		}
		return applyErr
	}
	if applyErr == nil {
		if cerr := h.clearRestoring(id, keep); cerr != nil {
			res.Warnings = append(res.Warnings, cerr.Error())
		}
		// No longer restoring: the gate file lists its companions again
		// (those whose revoke_all succeeded).
		h.writePolicyLogged()
		res.Warnings = append(res.Warnings, air.warnings...)
		res.Warnings = append(res.Warnings, h.bindPlaceholderRows(context.Background(), id)...)
		log.Printf("instance %s restored from %s (pre-restore backup %s)", id, archive, pre.Archive)
		if air.err != nil {
			// The data is restored; a companion whose revoke_all failed is
			// off (§11.6): the instance's record shows why, once the
			// restore's own record is written (held for it).
			h.recordAfterOp(id, OpAI, withSecrets(air.err, extra))
		}
		return nil
	}
	// Put the previous data back.
	rerr := h.stagedRollback(id, view, pre.Archive, wasEnabled, p)
	if rerr != nil {
		applyErr = withSecrets(fmt.Errorf("restore from %s failed: %w — putting the pre-restore backup %s back failed too: %v (it stays \"restoring\": restore again once the cause is fixed, the pre-restore backup is put back first)", archive, applyErr, pre.Archive, rerr), extra)
		return &OpError{Record: h.opRecordOf(id, OpRestore, applyErr, false), Err: applyErr}
	}
	if cerr := h.clearRestoring(id, keep); cerr != nil {
		res.Warnings = append(res.Warnings, cerr.Error())
	}
	h.writePolicyLogged()
	applyErr = withSecrets(fmt.Errorf("restore from %s failed: %w — the previous data was put back (pre-restore backup %s)", archive, applyErr, pre.Archive), extra)
	return &OpError{Record: h.opRecordOf(id, OpRestore, applyErr, true), Err: applyErr}
}

// recordAfterOp records op's failure err on id after the running
// operation's own final record (finishAsync writes it once that ended
// ok, as a start hook's failure is), or at once when nothing runs.
func (h *Hub) recordAfterOp(id, op string, err error) {
	r := h.opRecordOf(id, op, err, false)
	h.opsMu.Lock()
	defer h.opsMu.Unlock()
	if cur, ok := h.ops[id]; ok && cur.Running {
		if h.heldHook == nil {
			h.heldHook = map[string]heldHookRec{}
		}
		h.heldHook[id] = heldHookRec{opID: cur.OpID, rec: r}
		return
	}
	h.recordOpLocked(id, r)
}

// pctOf is done of total in percent (0 for an unknown total).
func pctOf(done, total int64) int {
	if total <= 0 {
		return 0
	}
	return int(done * 100 / total)
}

func archivePathOf(h *Hub, archive string) string {
	return filepath.Join(h.backupsDir(), filepath.FromSlash(archive))
}

// restoreTarget is instance id's view and state entry for a restore.
func (h *Hub) restoreTarget(id string) (*templates.Template, state.Instance, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	e := h.st.Instances[id]
	reason := h.brokenInstances[id]
	v := h.findLocked(id)
	switch {
	case e.State == state.InstanceDeleting:
		return nil, e, statusErr(409, "instance %s is being deleted: restore its backup into a new instance instead", id)
	case e.State == state.InstanceRestoring && e.RestoreAs != "":
		return nil, e, statusErr(409, "instance %s is being restored from %s (a restore into a new id): wait for it — an interrupted one is removed at the next Hub start, or delete it", id, e.RestoreAs)
	case v == nil && reason != "":
		return nil, e, statusErr(409, "instance %s can't be resolved (%s): fix its template first", id, reason)
	case v == nil:
		return nil, e, statusErr(404, "instance not found: %s", id)
	}
	c := *v
	return &c, e, nil
}

// markRestoring records state "restoring" with the pre-restore backup and
// marks the instance disabled, before anything is replaced.
func (h *Hub) markRestoring(id, preArchive string) error {
	h.mu.Lock()
	e := h.st.Instances[id]
	if e.ID == "" {
		e = state.Instance{ID: id, Template: id}
	}
	prev, had := h.st.Instances[id]
	enabled := h.st.IsEnabled(id)
	e.State, e.Backup = state.InstanceRestoring, preArchive
	h.st.Instances[id] = e
	h.st.SetEnabled(id, false)
	err := h.st.Save(h.statePath())
	if err != nil {
		if had {
			h.st.Instances[id] = prev
		} else {
			delete(h.st.Instances, id)
		}
		h.st.SetEnabled(id, enabled)
		h.mu.Unlock()
		return err
	}
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	return nil
}

// clearRestoring ends state "restoring": the entry gets state keep
// ("created" for a never-enabled instance, else ""); a default
// instance's entry that only held it goes away. A failed save is
// returned as a warning (and logged loudly): the data is consistent, but
// state.yaml still says "restoring" until the next save.
func (h *Hub) clearRestoring(id, keep string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.st.Instances[id]
	if !ok || e.State != state.InstanceRestoring {
		return nil
	}
	e.State, e.Backup = keep, ""
	if e.Template == id && len(e.Hosts) == 0 && keep == "" && !e.HoldsIdentity() {
		delete(h.st.Instances, id)
	} else {
		h.st.Instances[id] = e
	}
	h.rebuildLocked()
	if err := h.st.Save(h.statePath()); err != nil {
		log.Printf("ERROR: instance %s: the restore completed but saving state.yaml failed (it still says \"restoring\" on disk: the next start rolls back to the pre-restore backup unless a later save succeeds): %v", id, err)
		return fmt.Errorf("the restore of %s completed, but saving state.yaml failed (%v): until the next successful save, a Hub restart would roll it back to the pre-restore backup", id, err)
	}
	return nil
}

// recoverRestoreLocked rolls an interrupted restore of id back from its
// pre-restore backup, enabled again if it was enabled when that backup
// was taken. The recorded archive must be this instance's own
// pre-restore backup (its directory and manifest name id, its template
// is the instance's, its reason is restore) and verify; anything else is
// refused (409) and nothing is touched. Caller holds the app lock.
// p: the restore operation it runs in (its outcome folded into that
// operation's: the failure returned, the rollback a warning), nil at
// start-up (RecoverRestores: recorded as the instance's restore record).
func (h *Hub) recoverRestoreLocked(id string, view *templates.Template, preArchive string, p *Progress) error {
	pre, err := h.stagePreRestore(id, view, preArchive)
	if err != nil {
		return err
	}
	defer pre.cleanup()
	if err := h.rollbackStaged(id, view, pre, pre.cfg.Enabled, p); err != nil {
		err = fmt.Errorf("rolling back the unfinished restore of %s from %s failed (it stays \"restoring\"): %w", id, preArchive, err)
		if p != nil {
			return err
		}
		return h.finishOp(id, OpRestore, err, false)
	}
	keep := ""
	if pre.cfg.State == state.InstanceCreated {
		keep = state.InstanceCreated
	}
	if cerr := h.clearRestoring(id, keep); cerr != nil {
		log.Printf("instance %s: %v", id, cerr)
	}
	log.Printf("instance %s: unfinished restore rolled back from %s", id, preArchive)
	// Recorded (the ops record says what happened), not returned: the
	// instance is consistent again.
	msg := fmt.Sprintf("an unfinished restore of %s was rolled back from its pre-restore backup %s", id, preArchive)
	if p != nil {
		p.Warn(msg)
		return nil
	}
	_ = h.finishOp(id, OpRestore, errors.New(msg), true)
	return nil
}

// stagePreRestore verifies and stages preArchive as instance id's own
// pre-restore backup.
func (h *Hub) stagePreRestore(id string, view *templates.Template, preArchive string) (*staged, error) {
	if mm := archiveRe.FindStringSubmatch(preArchive); mm == nil || mm[1] != id {
		return nil, statusErr(409, "instance %s has an unfinished restore whose recorded pre-restore backup %q isn't one of its own archives: nothing was touched (fix state.yaml or delete the instance)", id, preArchive)
	}
	pre, err := h.stageArchive(preArchive)
	if err != nil {
		return nil, fmt.Errorf("instance %s has an unfinished restore; its pre-restore backup %s can't be used (nothing was touched): %w", id, preArchive, err)
	}
	if pre.m.Instance != id || pre.m.Template != view.TemplateID || pre.m.Reason != BackupRestore {
		pre.cleanup()
		return nil, statusErr(409, "instance %s has an unfinished restore whose recorded archive %s is not its pre-restore backup (instance %s, template %s, reason %s): nothing was touched", id, preArchive, pre.m.Instance, pre.m.Template, pre.m.Reason)
	}
	return pre, nil
}

// RecoverRestores rolls back every interrupted same-instance restore
// (state "restoring") in the background (Init calls it).
func (h *Hub) RecoverRestores() {
	h.mu.RLock()
	var ids []string
	for id, e := range h.st.Instances {
		if e.State == state.InstanceRestoring {
			ids = append(ids, id)
		}
	}
	h.mu.RUnlock()
	sort.Strings(ids)
	for _, id := range ids {
		h.goBackground(func() {
			unlock, err := h.lockApp(id)
			if err != nil {
				log.Printf("instance %s: unfinished restore not rolled back now (%v): the next restore does it", id, err)
				return
			}
			defer unlock()
			defer h.lifecycleAILock(id)() // lockApp → aiLock (G35)
			h.mu.RLock()
			e := h.st.Instances[id]
			h.mu.RUnlock()
			if e.State == state.InstanceRestoring && e.RestoreAs != "" {
				h.removeUnfinishedRestoreAs(id, e.RestoreAs)
				return
			}
			view, e, err := h.restoreTarget(id)
			if err == nil && e.State == state.InstanceRestoring {
				err = h.recoverRestoreLocked(id, view, e.Backup, nil)
			}
			if err != nil {
				log.Printf("instance %s: unfinished restore: %v", id, err)
			}
		})
	}
}

// removeUnfinishedRestoreAs removes a new instance an interrupted restore
// into a new id left behind (state "restoring" with restore_as): its
// project's volumes, files, per-instance state and state entry — it was
// never enabled. Its groups stay (no acting admin at start-up; logged:
// delete them in Users & Groups). Caller holds the app lock.
func (h *Hub) removeUnfinishedRestoreAs(id, archive string) {
	ctx := context.Background()
	var errs []error
	if h.engine != nil {
		vols, err := h.projectVolumes(ctx, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("listing its volumes: %w", err))
		}
		for _, v := range vols {
			if err := h.engine.RemoveVolume(ctx, v.Name); err != nil && !docker.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("volume %s: %w", v.Name, err))
			}
		}
	}
	if len(errs) > 0 {
		log.Printf("instance %s: removing the unfinished restore from %s failed (it stays \"restoring\"; delete it): %v", id, archive, errors.Join(errs...))
		return
	}
	for _, p := range []string{h.envPath(id), h.overridePath(id), h.userOverridePath(id)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("instance %s: removing %s: %v", id, p, err)
		}
	}
	if err := h.removeSecrets(id); err != nil {
		log.Printf("instance %s: removing its settings store: %v", id, err)
	}
	h.mu.Lock()
	var groups []string
	if v := h.findLocked(id); v != nil {
		users, admins := h.instanceGroupsLocked(v)
		for _, g := range []string{users, admins} {
			if g != "" {
				groups = append(groups, g)
			}
		}
	}
	delete(h.st.Instances, id)
	delete(h.st.AIInstances, id)
	h.applyConfigLocked(id, instanceConfig{})
	h.rebuildLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	msg := fmt.Sprintf("an interrupted restore of %s into the new instance %s was removed (restore it again)", archive, id)
	if len(groups) > 0 {
		msg += "; its groups " + strings.Join(groups, ", ") + " may have been created: delete them in Users & Groups if unused"
	}
	log.Printf("instance %s: %s", id, msg)
	h.recordOp(id, OpRecord{Op: OpRestore, At: time.Now().UTC(), Error: msg, Status: 500})
}

// restorePlan maps the archive's volumes to instance id's: the project's
// existing volume of that key, else the derived name (§11.2); every other
// volume of the project is emptied (tar ""). Refused (409) before
// anything changes: a key the template doesn't have, a volume that isn't
// a plain local one (its data would survive the remove).
func (h *Hub) restorePlan(id string, view *templates.Template, sb *staged) ([]volumePlan, error) {
	if h.engine == nil {
		if len(sb.volumes) == 0 {
			return nil, nil
		}
		return nil, statusErr(503, "Docker is not available: cannot restore volumes")
	}
	cur, err := h.projectVolumes(context.Background(), id)
	if err != nil {
		return nil, statusErr(503, "cannot list the volumes of %s: %v", id, err)
	}
	derived := view.NamesFor(id).Volumes
	keys := make([]string, 0, len(sb.volumes))
	for k := range sb.volumes {
		keys = append(keys, k)
	}
	for k := range cur {
		if _, ok := sb.volumes[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []volumePlan
	for _, k := range keys {
		if v, ok := cur[k]; ok {
			if !plainVolume(v) {
				return nil, statusErr(409, "volume %s uses driver %q with options: the Hub can't empty it (restore it by hand)", v.Name, v.Driver)
			}
			out = append(out, volumePlan{key: k, vol: docker.Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels}, existed: true, tar: sb.volumes[k]})
			continue
		}
		name, ok := derived[k]
		if !ok {
			return nil, statusErr(409, "the archive has volume %s, which template %s no longer defines", k, view.TemplateID)
		}
		if existing, err := h.engine.InspectVolume(context.Background(), name); err == nil {
			return nil, statusErr(409, "volume %s exists but doesn't belong to %s (labels %v): refusing to overwrite it", existing.Name, projectName(id), existing.Labels)
		} else if !docker.IsNotFound(err) {
			return nil, statusErr(503, "volume %s: %v", name, err)
		}
		out = append(out, volumePlan{key: k, vol: composeVolume(id, k, name), tar: sb.volumes[k]})
	}
	return out, nil
}

// composeVolume is a volume as compose would create it for id's project.
func composeVolume(id, key, name string) docker.Volume {
	return docker.Volume{Name: name, Driver: "local", Labels: map[string]string{docker.LabelProject: projectName(id), docker.LabelVolume: key}}
}

// applyRestore writes sb into instance id (stopped): volumes, env, custom
// override, settings; then, with void (a restore, not a rollback), every
// credential of the instance is voided (§11.6, F12: after the volumes,
// before the start: the restored start never sees an old account); then
// it enables it again if it was enabled. It marks the instance disabled
// while its data is replaced.
//
// AI (§11.6): the instance's credential entries are deleted before the
// volumes are replaced; the archive's AI state is put back through the
// switch-on refusals (restoredAILocked: a failing companion off, with a
// warning); every switched-on companion with a revoke hook owes
// revoke_all, run by the start (under the restore's AI lock) before it
// is listed again; one whose revoke_all failed is switched off
// (restoreAIAfterStart); the scopes of companions now off are deleted.
// The returned aiRestore holds the warnings and the AI failure for the
// op record; actor audits the switch-offs.
//
// rep (nil for a rollback) gets a restore's volumes (with the bytes
// written of the archived volumes' size), config and start steps; a
// cancelled ctx (a Stop) ends it between them — and aborts a volume's
// upload — with ctx's error, nothing rolled back here.
func (h *Hub) applyRestore(ctx context.Context, id string, sb *staged, plan []volumePlan, wasEnabled, void bool, actor directory.Actor, rep *Progress) (air aiRestore, err error) {
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.saveLocked()
	scoped := h.scopedCompanionsLocked(id)
	h.mu.Unlock()
	h.writePolicyLogged()
	// The restored app may hold credentials these entries name, or not:
	// either way the gate never uses them again (revoke_all follows).
	if err := h.dropInstanceAIEntries(id); err != nil {
		return air, fmt.Errorf("removing the AI credentials of %s: %w", id, err)
	}
	defer func() {
		if err == nil {
			h.dropRestoredScopes(id, scoped)
		}
	}()
	if len(plan) > 0 {
		if err := h.engine.EnsureImage(ctx, HelperImage); err != nil {
			return air, fmt.Errorf("helper image %s: %w", HelperImage, err)
		}
	}
	var total, sent int64
	for _, p := range plan {
		if p.tar != "" {
			if fi, err := os.Stat(p.tar); err == nil {
				total += fi.Size()
			}
		}
	}
	for _, p := range plan {
		if err := ctx.Err(); err != nil {
			return air, err
		}
		base := sent
		_, err := h.fillVolumeWith(ctx, id, p.vol, p.existed, p.tar, fillOpts{count: func(n int64) {
			sent = base + n
			rep.Percent(StepVolumes, pctOf(sent, total), mib(sent)+" of "+mib(total)+" written")
		}})
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return air, fmt.Errorf("%v: %w", err, cerr)
			}
			return air, err
		}
	}
	if h.testHookApplyRestore != nil {
		if err := h.testHookApplyRestore("volumes"); err != nil {
			return air, err
		}
	}
	rep.Percent(StepVolumes, 100, mib(total)+" written")
	rep.Done(StepVolumes)
	if err := ctx.Err(); err != nil {
		return air, err
	}
	rep.Start(StepConfig)
	if err := writeOrRemove(h.envPath(id), sb.env); err != nil {
		return air, fmt.Errorf("env: %w", err)
	}
	if err := writeOrRemove(h.userOverridePath(id), sb.user); err != nil {
		return air, fmt.Errorf("custom override: %w", err)
	}
	members := h.groupSnapshot(id)
	h.mu.Lock()
	h.applyConfigLocked(id, sb.cfg)
	h.rebuildLocked()
	// The archive's AI state, judged against the restored policy.
	if v := h.findLocked(id); v != nil {
		next, has, w := h.restoredAILocked(v, sb.ai, sb.aiErr, false, h.st.AIInstances[id])
		h.setRestoredAILocked(id, next, has)
		air.warnings = append(air.warnings, w...)
	}
	// The app's data was replaced: its switched-on companions owe a
	// revoke_all before they are rendered or listed again (§15.4; run by
	// the start below, under this restore's AI lock).
	h.oweAIRevokeLocked(id)
	// app_oauth companions restored off (archive off, or refused) owe the
	// revoked leavers' replay too, and a revoke_all when the archive had
	// them on (final review I3); collected here, the replay marked after mu.
	archived := sb.ai
	if sb.aiErr != nil {
		archived = nil
	}
	oauthRefs := h.oweAIRestoredOffLocked(id, archived)
	// The secrets store as archived (config/settings-secrets.json; none =
	// no secrets), before the env is written from it.
	var secretsErr error
	if v := h.findLocked(id); v != nil {
		secretsErr = h.restoreSecretsLocked(v, sb.secrets, false)
	} else {
		secretsErr = h.writeArchivedSecrets(id, sb.secrets)
	}
	// The archive's env overrides, checked against the template and the
	// restored secrets (§11.9): after the store, so a value equal to a
	// restored secret is dropped.
	if v := h.findLocked(id); v != nil {
		air.warnings = append(air.warnings, h.restoredEnvOverridesLocked(v)...)
	}
	if v := h.findLocked(id); v != nil {
		h.seedSettingsLocked(v)
	}
	var envErr error
	if v := h.findLocked(id); v != nil && secretsErr == nil {
		envErr = h.refreshInstanceEnvLocked(v, members)
	}
	saveErr := h.st.Save(h.statePath())
	var voidErr error
	if void && secretsErr == nil && envErr == nil && saveErr == nil {
		_, voidErr = h.voidCredentialsLocked(id, state.CredentialReasonRestore)
	}
	h.mu.Unlock()
	h.markOAuthReplay(oauthRefs)
	if err := errors.Join(secretsErr, envErr, saveErr, voidErr); err != nil {
		return air, err
	}
	rep.Done(StepConfig)
	if err := ctx.Err(); err != nil {
		return air, err
	}
	if wasEnabled {
		rep.Start(StepStart)
		// The enable reports nothing into the restore's record (its own
		// commit gate is not the restore's) but stops with it.
		if _, err := h.enableInner(withProgress(ctx, nil), id, true); err != nil {
			return air, err
		}
		rep.Done(StepStart)
		w, aerr := h.restoreAIAfterStart(id, actor)
		air.warnings, air.err = append(air.warnings, w...), aerr
	} else {
		h.writePolicyLogged()
	}
	return air, nil
}

// aiRestore is what a restore's AI part reports: warnings for the
// result, err for the op record (op ai).
type aiRestore struct {
	warnings []string
	err      error
}

// stagedRollback puts the pre-restore backup preArchive back after a
// failed restore (verified as id's own first).
func (h *Hub) stagedRollback(id string, view *templates.Template, preArchive string, wasEnabled bool, p *Progress) error {
	pre, err := h.stagePreRestore(id, view, preArchive)
	if err != nil {
		return err
	}
	defer pre.cleanup()
	return h.rollbackStaged(id, view, pre, wasEnabled, p)
}

// rollbackStaged puts a staged pre-restore backup back: its volumes,
// files and settings; the project's volumes it doesn't have are emptied.
// A companion whose revoke_all failed is off (§11.6): within operation p
// a warning of it (the operation failed or was stopped: its own record
// is the instance's), without one (start-up) the instance's ai record.
func (h *Hub) rollbackStaged(id string, view *templates.Template, pre *staged, wasEnabled bool, p *Progress) error {
	// A failed enable already rolled its compose up back; make sure.
	if err := h.stopProject(&target{id: id, view: view}); err != nil {
		return fmt.Errorf("compose down: %w", err)
	}
	plan, err := h.restorePlan(id, view, pre)
	if err != nil {
		return err
	}
	air, err := h.applyRestore(context.Background(), id, pre, plan, wasEnabled, false, aiHubActor, nil)
	for _, w := range air.warnings {
		log.Printf("instance %s: rollback: %s", id, w)
	}
	if err == nil && air.err != nil {
		if p != nil {
			p.Warn("AI support: " + h.opRecordOf(id, OpAI, air.err, false).Error)
		} else {
			h.finishOp(id, OpAI, air.err, false)
		}
	}
	return err
}

// RestoreInstanceAs restores archive (any listed one, a deleted
// instance's included) into a NEW instance newID of the archive's
// template (§11.6): checks first — the archive verifies, the template
// exists and is multi, the id rules and collisions of CreateInstance
// (Docker volumes included), no hosts.immutable router whose hostname
// would change (its data is bound to it: 409, restore into the same id) —
// then the instance is created (state "created", not enabled) with its
// default hostnames on the main domain, new empty access / admin groups
// (as actor), new volumes filled from the archive, and the archive's
// settings, policy, public exceptions and env (each Keycloak client's
// secret_env regenerated). A failure after the create removes what it
// created. Audited as instance.restore.
func (h *Hub) RestoreInstanceAs(archive, newID string, actor directory.Actor) (res *RestoreResult, err error) {
	return h.RestoreInstanceAsWith(archive, newID, actor, nil)
}

// RestoreInstanceAsWith is RestoreInstanceAs with hostnames (host router
// → hostname) for the new instance: given ones are used as CreateInstance
// would (validated, collisions refused); the others default to the
// archive's hostname for hosts.immutable routers, else the new id's
// default on the main domain. StartRestoreAs's operation run to its end
// (runOpSync; the op record is newID's).
func (h *Hub) RestoreInstanceAsWith(archive, newID string, actor directory.Actor, hosts map[string]string) (res *RestoreResult, err error) {
	res = &RestoreResult{}
	_, _, err = h.runOpSync(newID, OpRestore, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		var rerr error
		res, rerr = h.restoreInstanceAs(ctx, archive, newID, actor, hosts, "", ready)
		return restoreResult(res, archive, newID), restoreWarnings(res), rerr
	})
	return res, err
}

// restoreInstanceAs is the restore into a new id StartRestoreAs and
// RestoreInstanceAsWith run; ready is called once the request is
// accepted (archive name and new id valid, lock held, the archive file
// exists, the actor resolves), before the archive is verified
// (StartRestoreAs answers 202 then). Its steps are verify, instance,
// groups, volumes and config; the groups and volumes it creates are the
// record's Created ledger, written as they exist. A Stop accepted before
// the commit (the instance marked complete) removes the new instance
// completely (settleOp → undoRestoreAs).
//
// label "" = the archive's (config/instance.yaml), else checked like any
// label (§11.9: 400).
func (h *Hub) restoreInstanceAs(ctx context.Context, archive, newID string, actor directory.Actor, hosts map[string]string, label string, ready func()) (res *RestoreResult, err error) {
	res = &RestoreResult{}
	defer func() {
		h.auditOp(actor, "instance.restore", newID, "archive="+archive+" new_instance=true", err)
	}()
	if !archiveRe.MatchString(archive) {
		return res, statusErr(400, "archive must be <instance-id>/<YYYYMMDDTHHMMSSZ>.tar, relative to the backups directory")
	}
	if !templates.InstanceIDRe.MatchString(newID) {
		return res, statusErr(400, "instance id %q must match %s", newID, templates.InstanceIDRe)
	}
	if err := templates.CheckIDShape(newID); err != nil {
		return res, statusErr(400, "instance %v", err)
	}
	if label != "" {
		if err := CheckLabel(label); err != nil {
			return res, err
		}
	}
	unlock, err := h.lockApp(newID)
	if err != nil {
		return res, h.busyErr(newID, err)
	}
	defer unlock()
	defer h.lifecycleAILock(newID)() // lockApp → aiLock (G35)
	h.mu.RLock()
	_, exists := h.st.Instances[newID]
	exists = exists || h.findLocked(newID) != nil
	groupsAPI := h.groups
	h.mu.RUnlock()
	if exists {
		return res, statusErr(409, "instance %s already exists", newID)
	}
	if err := h.archiveExists(archive); err != nil {
		return res, err
	}
	if groupsAPI != nil {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return res, fmt.Errorf("the acting admin %q can't create the instance's groups — nothing was changed: %w", actor.User, err)
		}
	}
	p := progressFrom(ctx)
	p.AddStep(StepVerify, "Checking the archive")
	p.AddStep(StepInstance, "Creating the instance")
	p.AddStep(StepGroups, "Groups")
	p.AddStep(StepVolumes, "Restoring the volumes")
	p.AddStep(StepConfig, "Restoring the settings")
	p.Before(beforeNewID, "true")
	ready()
	err = h.restoreAsSteps(ctx, p, archive, newID, actor, hosts, label, res)
	return res, h.settleOp(newID, OpRestore, p, err)
}

// restoreAsSteps is the accepted restore into newID (caller holds its
// lock). A failure after the create removes what it created (its own
// undo, below) unless a Stop was accepted first: then it returns ctx's
// error and the Stop's undo removes it from the record.
func (h *Hub) restoreAsSteps(ctx context.Context, p *Progress, archive, newID string, actor directory.Actor, hosts map[string]string, label string, res *RestoreResult) (err error) {
	p.Start(StepVerify)
	if err := h.checkFree(archivePathOf(h, archive), "staging the archive"); err != nil {
		return err
	}
	sb, err := h.stageArchiveCtx(ctx, archive, func(done, total int64) {
		p.Percent(StepVerify, pctOf(done, total), mib(done)+" of "+mib(total)+" checked")
	})
	if err != nil {
		return err
	}
	defer sb.cleanup()
	// Redacted from here on: the archive's values and (undo) the new
	// instance's before it is removed.
	var extra []string
	var undoUnread error // the new instance's redaction set couldn't be read during the undo
	defer func() { err = hideIfUnread(withSecrets(err, extra), undoUnread) }()

	h.mu.RLock()
	t := h.catalogLocked(sb.m.Template)
	var tmpl templates.Template
	if t != nil {
		tmpl = *t
	}
	domain := h.cfg.Domain
	h.mu.RUnlock()
	if t != nil {
		extra = archiveSecrets(&tmpl, sb)
	} else {
		extra = archiveSecrets(nil, sb)
	}
	p.Redact(extra)
	if t == nil {
		return statusErr(409, "template %s of archive %s is not in the catalog", sb.m.Template, archive)
	}
	if !tmpl.Manifest.Multi() {
		return statusErr(409, "template %s is instances: single — restore the archive into its default instance instead", tmpl.ID)
	}
	if err := aliasesFitInstance(&tmpl, newID); err != nil {
		return err
	}
	want, err := restoreAsHosts(&tmpl, newID, domain, sb.cfg.Hosts, hosts)
	if err != nil {
		return err
	}
	names := tmpl.NamesFor(newID)
	for k := range sb.volumes {
		if _, ok := names.Volumes[k]; !ok {
			return statusErr(409, "the archive has volume %s, which template %s no longer defines", k, tmpl.ID)
		}
	}
	if len(sb.volumes) > 0 && h.engine == nil {
		return statusErr(503, "Docker is not available: cannot restore volumes")
	}
	defs := h.folderDefs()
	res.Warnings = append(res.Warnings, dropMissingFolderRefs(&sb.cfg, defs)...)
	if err := h.configProblem(&tmpl, &sb.cfg, archive); err != nil {
		return err
	}
	if sb.cfg.Settings != nil {
		if err := h.dockerRootValuesRule(context.Background(), &tmpl, sb.cfg.Settings.Values); err != nil {
			return err
		}
	}
	res.Warnings = append(res.Warnings, h.checkArchivedRows(context.Background(), &tmpl, sb.cfg.Settings, true)...)
	// Kept folder values (spec call 17, S12): the new instance uses the
	// folder without an assignment preview, read-only unless its template
	// declares write (write confirmations are never copied).
	res.Warnings = append(res.Warnings, restoredFolderWarnings(&tmpl, newID, &sb.cfg, defs)...)
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI != nil && (names.AccessGroup != "" || names.AdminGroup != "") {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return fmt.Errorf("the acting admin %q can't create the instance's groups — nothing was changed: %w", actor.User, err)
		}
	}
	// Host paths are shared, not copied: say so.
	if sb.cfg.Settings != nil {
		for _, st := range tmpl.Manifest.Options() {
			if v, ok := sb.cfg.Settings.Values[st.Key]; ok && st.Type == templates.TypePath && v != nil && !isFolderValue(v) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("setting %s mounts host path %v, as instance %s did: the two instances share that directory unless you change it", st.Key, v, sb.m.Instance))
			}
		}
	}
	p.Done(StepVerify)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Validated as CreateInstance validates any hostname: an immutable
	// router's archived hostname that is taken or no longer placeable is
	// refused here (nothing created).
	p.Start(StepInstance)
	// The request's label, else the archive's (§11.9); a binding is never
	// restored into a new id: it gets new derived groups (§11.6).
	if label == "" && sb.cfg.Label != "" {
		if lerr := CheckLabel(sb.cfg.Label); lerr != nil {
			res.Warnings = append(res.Warnings, "the archive's label was dropped: "+lerr.Error())
		} else {
			label = sb.cfg.Label
		}
	}
	prior, err := h.createEntry(CreateRequest{Template: tmpl.ID, ID: newID, Label: label, Hosts: want}, "", "")
	if err != nil {
		return err
	}
	p.setPriorSettings(prior)
	// Marked "restoring" (restore_as) until complete: an interrupted one
	// is removed at the next start (RecoverRestores).
	h.mu.Lock()
	if e, ok := h.st.Instances[newID]; ok {
		e.State, e.RestoreAs = state.InstanceRestoring, archive
		h.st.Instances[newID] = e
	}
	// A new instance has no credentials (archives carry none, §11.6):
	// anything a former instance of that id left goes, unaudited.
	var credErr error
	if _, left := h.st.Credentials[newID]; left {
		credErr = h.forgetCredentialsLocked(newID)
	}
	markErr := errors.Join(h.st.Save(h.statePath()), credErr)
	h.mu.Unlock()
	var createdVols []string
	var createdGroups []string
	undo := func(cause error) error {
		// A Stop accepted first: its undo removes the instance from the
		// record (settleOp); none is accepted after this.
		if !p.CloseStop() {
			return fmt.Errorf("%v: %w", cause, context.Canceled)
		}
		ctx := context.Background()
		// Its regenerated secrets and env go with it: keep redacting them.
		set, unread := h.redactionSetErr(newID)
		extra = append(extra, set...)
		if unread != nil {
			undoUnread = unread
		}
		var errs []error
		for _, v := range createdVols {
			if err := h.engine.RemoveVolume(ctx, v); err != nil && !docker.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
		for _, g := range createdGroups {
			// Kept because Users & Groups didn't answer: left as before
			// (the group stays in LLDAP), not a failed removal.
			if _, err := groupsAPI.DeleteInstanceGroup(ctx, actor, g); err != nil && !errors.Is(err, directory.ErrKeptUnavailable) {
				errs = append(errs, err)
			}
		}
		if err := h.removeNewInstance(newID, prior); err != nil {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w — removing the half-restored instance failed too: %v", cause, err)
		}
		return fmt.Errorf("%w — the new instance %s was removed again", cause, newID)
	}

	if markErr != nil {
		return undo(statusErr(500, "recording the restore failed: %v", markErr))
	}
	// Settings, env (client secrets regenerated), custom override: the
	// instance step's (its state entry, env and generated secrets, as a
	// create's), before its groups and volumes.
	if sb.env != nil {
		env := parseEnvRaw(sb.env)
		for _, c := range tmpl.Manifest.Clients {
			if c.SecretEnv != "" {
				delete(env, c.SecretEnv)
			}
		}
		if err := writeEnvMap(h.envPath(newID), env); err != nil {
			return undo(statusErr(500, "env: %v", err))
		}
	}
	if err := writeOrRemove(h.userOverridePath(newID), sb.user); err != nil {
		return undo(statusErr(500, "custom override: %v", err))
	}
	members := h.groupSnapshot(newID)
	h.mu.Lock()
	h.applyConfigLocked(newID, sb.cfg)
	h.rebuildLocked()
	// Every companion off, modes and providers kept (§11.6); switching
	// one on runs revoke_all first (G34). A copy is never listed before a
	// revoke_all either way.
	if v := h.findLocked(newID); v != nil {
		next, has, w := h.restoredAILocked(v, sb.ai, sb.aiErr, true, state.AIInstance{})
		h.setRestoredAILocked(newID, next, has)
		res.Warnings = append(res.Warnings, w...)
	}
	h.oweAIRevokeLocked(newID)
	if v := h.findLocked(newID); v != nil {
		h.seedSettingsLocked(v)
	}
	var envErr error
	if v := h.findLocked(newID); v == nil {
		envErr = fmt.Errorf("instance %s does not resolve", newID)
	} else if envErr = h.restoreSecretsLocked(v, sb.secrets, true); envErr == nil {
		// The archive's env overrides, copied and checked against the
		// template and the copied secrets (§11.9).
		res.Warnings = append(res.Warnings, h.restoredEnvOverridesLocked(v)...)
		if sb.env != nil {
			// Secrets copied, generate-declared ones regenerated (as client
			// secret_envs are), before the env is written from them.
			envErr = h.generateAppEnvLocked(v, members)
		}
	}
	saveErr := h.st.Save(h.statePath())
	h.mu.Unlock()
	if err := errors.Join(envErr, saveErr); err != nil {
		return undo(statusErr(500, "%v", err))
	}
	p.Done(StepInstance)
	if err := ctx.Err(); err != nil {
		return err
	}

	// New empty groups.
	p.Start(StepGroups)
	var made []string
	for _, g := range []string{names.AccessGroup, names.AdminGroup} {
		if g == "" {
			continue
		}
		if groupsAPI == nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was not created: users & groups is not available", g))
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, w, err := groupsAPI.CreateInstanceGroup(context.Background(), actor, g)
		res.Warnings = append(res.Warnings, w...)
		if ok {
			createdGroups = append(createdGroups, g)
			made = append(made, g)
			p.Created(CreatedGroups, g)
		}
		if err != nil {
			return undo(fmt.Errorf("creating group %s: %w", g, err))
		}
	}
	if len(made) > 0 {
		p.Detail(StepGroups, strings.Join(made, ", ")+" created")
	}
	p.Done(StepGroups)
	if err := ctx.Err(); err != nil {
		return err
	}

	// New volumes.
	p.Start(StepVolumes)
	keys := make([]string, 0, len(sb.volumes))
	var total, sent int64
	for k := range sb.volumes {
		keys = append(keys, k)
		if fi, err := os.Stat(sb.volumes[k]); err == nil {
			total += fi.Size()
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		if err := h.engine.EnsureImage(context.Background(), HelperImage); err != nil {
			return undo(statusErr(503, "helper image %s: %v", HelperImage, err))
		}
	}
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		v := composeVolume(newID, k, names.Volumes[k])
		base := sent
		created, err := h.fillVolumeWith(ctx, newID, v, false, sb.volumes[k], fillOpts{
			created: func(n string) { p.Created(CreatedVolumes, n) },
			count: func(n int64) {
				sent = base + n
				p.Percent(StepVolumes, pctOf(sent, total), mib(sent)+" of "+mib(total)+" written")
			},
		})
		if created {
			createdVols = append(createdVols, v.Name)
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return fmt.Errorf("%v: %w", err, cerr)
			}
			return undo(statusErr(500, "%v", err))
		}
	}
	p.Percent(StepVolumes, 100, mib(total)+" written")
	p.Done(StepVolumes)
	if err := ctx.Err(); err != nil {
		return err
	}

	// The commit: the instance complete (its settings were restored with
	// it, in the instance step).
	p.Start(StepConfig)
	// The commit gate: a Stop accepted until here removes the instance
	// (its undo), none is accepted after.
	if !p.CloseStop() {
		return context.Canceled
	}
	// Complete: a new instance, never enabled.
	h.mu.Lock()
	if e, ok := h.st.Instances[newID]; ok {
		e.State, e.RestoreAs = state.InstanceCreated, ""
		h.st.Instances[newID] = e
	}
	h.rebuildLocked()
	saveErr = h.st.Save(h.statePath())
	h.mu.Unlock()
	if saveErr != nil {
		return undo(statusErr(500, "recording the completed restore failed: %v", saveErr))
	}
	p.Done(StepConfig)
	// Its starting rows, bound to the new id's groups.
	res.Warnings = append(res.Warnings, h.bindPlaceholderRows(context.Background(), newID)...)
	if v := h.Template(newID); v != nil {
		if w := h.oauthCopyForRestoreAs(v, sb.m.Instance, newID); w != "" {
			res.Warnings = append(res.Warnings, w)
		}
	}
	h.writePolicyLogged()
	log.Printf("instance %s of %s restored from %s", newID, tmpl.ID, archive)
	return nil
}

// removeNewInstance removes a new instance a restore into a new id (or a
// create) made: its files, settings store, per-instance state, AI state
// and state entry — never one that runs or completed (state "restoring"
// or, for a create, "created", or no entry: done). Caller holds id's
// lock.
//
// A default instance's first create (id = template id) removes only its
// state entry and puts its settings entry back exactly as prior holds it
// (the setup values the create stored go; nil: left as is): everything
// else the default instance had stays.
func (h *Hub) removeNewInstance(id string, prior *priorSettings) error {
	h.mu.RLock()
	e, ok := h.st.Instances[id]
	enabled := h.st.IsEnabled(id)
	// Keyed on the id being a template id, not on the entry: an undo
	// retried after its first save failed (entry already gone) must not
	// fall through to the wipe below.
	isTemplate := h.catalogLocked(id) != nil || (ok && e.Template == id)
	h.mu.RUnlock()
	if ok && (enabled || (e.State != state.InstanceRestoring && e.State != state.InstanceCreated)) {
		return statusErr(409, "instance %s is no longer new (state %q, enabled %v): it was not removed", id, e.State, enabled)
	}
	if isTemplate && !ok {
		return nil // a default instance with no entry: nothing the create added is left
	}
	if isTemplate {
		// A template's first instance is its default instance (§11.9):
		// the create added only the state entry (label, binding,
		// state "created") and its setup values. Whatever the default instance had before —
		// its .env, overrides, settings and secrets, policy, public and
		// sign-in choices, AI state — is its own and stays.
		h.mu.Lock()
		delete(h.st.Instances, id)
		switch {
		case prior == nil:
		case prior.had:
			h.st.Settings[id] = prior.s.Clone()
		default:
			delete(h.st.Settings, id)
		}
		h.rebuildLocked()
		saveErr := h.st.Save(h.statePath())
		h.mu.Unlock()
		h.writePolicyLogged()
		return saveErr
	}
	var errs []error
	for _, p := range []string{h.envPath(id), h.overridePath(id), h.userOverridePath(id)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := h.removeSecrets(id); err != nil {
		errs = append(errs, err)
	}
	h.mu.Lock()
	delete(h.st.Instances, id)
	delete(h.st.AIInstances, id)
	h.applyConfigLocked(id, instanceConfig{})
	h.rebuildLocked()
	saveErr := h.st.Save(h.statePath())
	h.mu.Unlock()
	h.writePolicyLogged()
	return errors.Join(append(errs, saveErr)...)
}

// restoreAsHosts are the hostnames of a restore into the new id newID:
// given (normalised) where the request names a router, else the
// archive's hostname for a hosts.immutable router (its data is bound to
// it), else newID's default on the main domain. An immutable router given
// another hostname than the archive's is refused (409).
func restoreAsHosts(t *templates.Template, newID, domain string, archived, given map[string]string) (map[string]string, error) {
	suffix := instanceSuffix(t.TemplateID, newID)
	out := map[string]string{}
	for r := range given {
		if _, ok := t.HostRouters[r]; !ok {
			return nil, statusErr(400, "%s is not a host router of template %s", r, t.TemplateID)
		}
	}
	routers := make([]string, 0, len(t.HostRouters))
	for r := range t.HostRouters {
		routers = append(routers, r)
	}
	sort.Strings(routers)
	for _, r := range routers {
		old := NormalizeHost(archived[r])
		immutable := t.Manifest.ImmutableHost(r) && old != ""
		if g, ok := given[r]; ok {
			g = NormalizeHost(g)
			if immutable && g != old {
				return nil, statusErr(409, "template %s fixes the hostname of %s once an instance exists (its data is bound to %s): the restored instance must keep %s", t.TemplateID, r, old, old)
			}
			out[r] = g
			continue
		}
		if immutable {
			out[r] = old
			continue
		}
		host, ok := defaultHost(t.HostRouters[r], suffix, domain)
		if !ok {
			return nil, statusErr(400, "host router %s: no valid default hostname for %s-%s.%s — give an explicit hostname", r, t.HostRouters[r], suffix, domain)
		}
		out[r] = host
	}
	return out, nil
}
