package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/portcullis/hub/internal/docker"
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
}

// RestoreInstance restores archive (<id>/<timestamp>.tar under
// <data>/backups; it must belong to id) into the existing instance id,
// replacing its data. The archive is verified first (400 bad name, 404
// missing, 409 checksum / layout / template mismatch, a volume that can't
// be emptied — nothing changes on any of these). Then: a backup (reason
// restore; the instance is stopped), every archived volume emptied and
// filled, the env, custom override and per-instance settings from the
// archive — the current hostnames are kept, the Hub override is
// regenerated —, and, if the instance was enabled, the full enable
// (Keycloak clients, access role, callbacks, policy, compose up). Any
// failure there puts the pre-restore backup back the same way (an
// *OpError with rolled_back; op "restore"). Audited as instance.restore.
func (h *Hub) RestoreInstance(id, archive, actor string) (res *RestoreResult, err error) {
	res = &RestoreResult{}
	defer func() {
		h.auditOp(actor, "instance.restore", id, "archive="+archive+" pre_restore="+res.PreRestoreBackup, err)
	}()
	if mm := archiveRe.FindStringSubmatch(archive); mm == nil || mm[1] != id {
		return res, statusErr(400, "archive must be %s/<YYYYMMDDTHHMMSSZ>.tar (an archive of this instance)", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, err
	}
	defer unlock()
	h.mu.RLock()
	var view *templates.Template
	if v := h.findLocked(id); v != nil {
		c := *v
		view = &c
	}
	e := h.st.Instances[id]
	reason := h.brokenInstances[id]
	h.mu.RUnlock()
	switch {
	case e.State == state.InstanceDeleting:
		return res, statusErr(409, "instance %s is being deleted: restore its backup into a new instance instead", id)
	case view == nil && reason != "":
		return res, statusErr(409, "instance %s can't be resolved (%s): fix its template first", id, reason)
	case view == nil:
		return res, statusErr(404, "instance not found: %s", id)
	}
	sb, err := h.stageArchive(archive)
	if err != nil {
		return res, err
	}
	defer sb.cleanup()
	if sb.m.Template != view.TemplateID {
		return res, statusErr(409, "archive %s is a backup of template %s, instance %s runs %s", archive, sb.m.Template, id, view.TemplateID)
	}
	plan, err := h.restorePlan(id, view, sb)
	if err != nil {
		return res, err
	}
	wasEnabled := view.Enabled

	// Back up what is there now (stops the instance; restarted by
	// backupLocked if the backup fails).
	pre, err := h.backupLocked(id, BackupRestore, true)
	if err != nil {
		return res, fmt.Errorf("the backup before the restore failed — nothing was restored: %w", err)
	}
	res.PreRestoreBackup = pre.Archive
	applyErr := h.applyRestore(id, sb, plan, wasEnabled)
	if applyErr == nil {
		log.Printf("instance %s restored from %s (pre-restore backup %s)", id, archive, pre.Archive)
		return res, h.finishOp(id, OpRestore, nil, false)
	}
	// Put the previous data back.
	rerr := h.rollbackRestore(id, view, pre.Archive, plan, wasEnabled)
	if rerr != nil {
		applyErr = fmt.Errorf("restore from %s failed: %w — putting the pre-restore backup %s back failed too: %v (restore it again once the cause is fixed)", archive, applyErr, pre.Archive, rerr)
		return res, h.finishOp(id, OpRestore, applyErr, false)
	}
	applyErr = fmt.Errorf("restore from %s failed: %w — the previous data was put back (pre-restore backup %s)", archive, applyErr, pre.Archive)
	return res, h.finishOp(id, OpRestore, applyErr, true)
}

// restorePlan maps the archive's volumes to instance id's: the project's
// existing volume of that key, else the derived name (§11.2). Refused
// (409) before anything changes: a key the template doesn't have, a
// volume that isn't a plain local one (its data would survive the
// remove).
func (h *Hub) restorePlan(id string, view *templates.Template, sb *staged) ([]volumePlan, error) {
	if len(sb.volumes) == 0 {
		return nil, nil
	}
	if h.engine == nil {
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
	sort.Strings(keys)
	var out []volumePlan
	for _, k := range keys {
		if v, ok := cur[k]; ok {
			if !plainVolume(v) {
				return nil, statusErr(409, "volume %s uses driver %q with options: the Hub can't empty it (restore it by hand)", v.Name, v.Driver)
			}
			out = append(out, volumePlan{key: k, vol: docker.Volume{Name: v.Name, Driver: v.Driver, Labels: v.Labels}, existed: true})
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
		out = append(out, volumePlan{key: k, vol: composeVolume(id, k, name)})
	}
	return out, nil
}

// composeVolume is a volume as compose would create it for id's project.
func composeVolume(id, key, name string) docker.Volume {
	return docker.Volume{Name: name, Driver: "local", Labels: map[string]string{docker.LabelProject: projectName(id), docker.LabelVolume: key}}
}

// applyRestore writes sb into instance id (stopped): volumes, env, custom
// override, settings; then enables it again if it was enabled. It marks
// the instance disabled while its data is replaced.
func (h *Hub) applyRestore(id string, sb *staged, plan []volumePlan, wasEnabled bool) error {
	ctx := context.Background()
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	if len(plan) > 0 {
		if err := h.engine.EnsureImage(ctx, HelperImage); err != nil {
			return fmt.Errorf("helper image %s: %w", HelperImage, err)
		}
	}
	for _, p := range plan {
		if err := h.fillVolume(ctx, id, p.vol, p.existed, sb.volumes[p.key]); err != nil {
			return err
		}
	}
	if err := writeOrRemove(h.envPath(id), sb.env); err != nil {
		return fmt.Errorf("env: %w", err)
	}
	if err := writeOrRemove(h.userOverridePath(id), sb.user); err != nil {
		return fmt.Errorf("custom override: %w", err)
	}
	h.mu.Lock()
	h.applyConfigLocked(id, sb.cfg)
	h.rebuildLocked()
	var envErr error
	if v := h.findLocked(id); v != nil {
		envErr = h.refreshInstanceEnvLocked(v)
	}
	saveErr := h.st.Save(h.statePath())
	h.mu.Unlock()
	if err := errors.Join(envErr, saveErr); err != nil {
		return err
	}
	if wasEnabled {
		if _, err := h.enableLocked(id); err != nil {
			return err
		}
	} else {
		h.writePolicyLogged()
	}
	return nil
}

// rollbackRestore puts the pre-restore backup back after a failed
// restore: its volumes, files and settings; volumes the failed restore
// created that weren't there before are removed.
func (h *Hub) rollbackRestore(id string, view *templates.Template, preArchive string, plan []volumePlan, wasEnabled bool) error {
	ctx := context.Background()
	// A failed enable already rolled its compose up back; make sure.
	if err := h.stopProject(&target{id: id, view: view}); err != nil {
		return fmt.Errorf("compose down: %w", err)
	}
	pre, err := h.stageArchive(preArchive)
	if err != nil {
		return err
	}
	defer pre.cleanup()
	var back []volumePlan
	for _, p := range plan {
		if _, ok := pre.volumes[p.key]; ok {
			back = append(back, volumePlan{key: p.key, vol: p.vol, existed: true})
			continue
		}
		if err := h.engine.RemoveVolume(ctx, p.vol.Name); err != nil && !docker.IsNotFound(err) {
			return fmt.Errorf("removing volume %s: %w", p.vol.Name, err)
		}
	}
	return h.applyRestore(id, pre, back, wasEnabled)
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
func (h *Hub) RestoreInstanceAs(archive, newID, actor string) (res *RestoreResult, err error) {
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
	unlock, err := h.lockApp(newID)
	if err != nil {
		return res, err
	}
	defer unlock()
	sb, err := h.stageArchive(archive)
	if err != nil {
		return res, err
	}
	defer sb.cleanup()

	h.mu.RLock()
	t := h.catalogLocked(sb.m.Template)
	var tmpl templates.Template
	if t != nil {
		tmpl = *t
	}
	domain := h.cfg.Domain
	h.mu.RUnlock()
	if t == nil {
		return res, statusErr(409, "template %s of archive %s is not in the catalog", sb.m.Template, archive)
	}
	if !tmpl.Manifest.Multi() {
		return res, statusErr(409, "template %s is instances: single — restore the archive into its default instance instead", tmpl.ID)
	}
	defaults, err := defaultHostsFor(&tmpl, newID, domain)
	if err != nil {
		return res, err
	}
	for r, old := range sb.cfg.Hosts {
		if tmpl.Manifest.ImmutableHost(r) && defaults[r] != old {
			return res, statusErr(409, "template %s fixes the hostname of %s once an instance exists (its data is bound to %s): a new id would get %s — restore the archive into instance %s instead", tmpl.ID, r, old, defaults[r], sb.m.Instance)
		}
	}
	names := tmpl.NamesFor(newID)
	for k := range sb.volumes {
		if _, ok := names.Volumes[k]; !ok {
			return res, statusErr(409, "the archive has volume %s, which template %s no longer defines", k, tmpl.ID)
		}
	}
	if len(sb.volumes) > 0 && h.engine == nil {
		return res, statusErr(503, "Docker is not available: cannot restore volumes")
	}

	if err := h.CreateInstance(tmpl.ID, newID, nil); err != nil {
		return res, err
	}
	var createdVols []string
	var createdGroups []string
	undo := func(cause error) error {
		ctx := context.Background()
		var errs []error
		for _, v := range createdVols {
			if err := h.engine.RemoveVolume(ctx, v); err != nil && !docker.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
		h.mu.RLock()
		groupsAPI := h.groups
		h.mu.RUnlock()
		for _, g := range createdGroups {
			if _, err := groupsAPI.DeleteInstanceGroup(ctx, actor, g); err != nil {
				errs = append(errs, err)
			}
		}
		for _, p := range []string{h.envPath(newID), h.overridePath(newID), h.userOverridePath(newID)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		h.mu.Lock()
		delete(h.st.Instances, newID)
		h.applyConfigLocked(newID, instanceConfig{})
		h.rebuildLocked()
		h.saveLocked()
		h.mu.Unlock()
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w — removing the half-restored instance failed too: %v", cause, err)
		}
		return fmt.Errorf("%w — the new instance %s was removed again", cause, newID)
	}

	// Settings, env (client secrets regenerated), custom override.
	if sb.env != nil {
		env := parseEnv(sb.env)
		for _, c := range tmpl.Manifest.Clients {
			if c.SecretEnv != "" {
				delete(env, c.SecretEnv)
			}
		}
		if err := writeEnvMap(h.envPath(newID), env); err != nil {
			return res, undo(statusErr(500, "env: %v", err))
		}
	}
	if err := writeOrRemove(h.userOverridePath(newID), sb.user); err != nil {
		return res, undo(statusErr(500, "custom override: %v", err))
	}
	h.mu.Lock()
	h.applyConfigLocked(newID, sb.cfg)
	h.rebuildLocked()
	var envErr error
	if v := h.findLocked(newID); v == nil {
		envErr = fmt.Errorf("instance %s does not resolve", newID)
	} else if sb.env != nil {
		envErr = h.generateAppEnvLocked(v)
	}
	saveErr := h.st.Save(h.statePath())
	groupsAPI := h.groups
	h.mu.Unlock()
	if err := errors.Join(envErr, saveErr); err != nil {
		return res, undo(statusErr(500, "%v", err))
	}

	// New empty groups.
	for _, g := range []string{names.AccessGroup, names.AdminGroup} {
		if g == "" {
			continue
		}
		if groupsAPI == nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was not created: users & groups is not available", g))
			continue
		}
		w, err := groupsAPI.CreateInstanceGroup(context.Background(), actor, g)
		res.Warnings = append(res.Warnings, w...)
		if err != nil {
			return res, undo(fmt.Errorf("creating group %s: %w", g, err))
		}
		if len(w) == 0 {
			createdGroups = append(createdGroups, g)
		}
	}

	// New volumes.
	keys := make([]string, 0, len(sb.volumes))
	for k := range sb.volumes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		if err := h.engine.EnsureImage(context.Background(), HelperImage); err != nil {
			return res, undo(statusErr(503, "helper image %s: %v", HelperImage, err))
		}
	}
	for _, k := range keys {
		v := composeVolume(newID, k, names.Volumes[k])
		createdVols = append(createdVols, v.Name)
		if err := h.fillVolume(context.Background(), newID, v, false, sb.volumes[k]); err != nil {
			return res, undo(statusErr(500, "%v", err))
		}
	}
	h.writePolicyLogged()
	log.Printf("instance %s of %s restored from %s", newID, tmpl.ID, archive)
	return res, nil
}
