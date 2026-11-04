package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Guarded delete (contract §11.4).

// DeleteResult is what a (completed) guarded delete reports.
type DeleteResult struct {
	// Backup is the archive the delete took (relative to <data>/backups).
	Backup   string   `json:"backup"`
	Warnings []string `json:"warnings,omitempty"`
}

// SetGroups wires the Users & Groups side of instance groups (delete,
// restore into a new id). Without it those steps are warnings.
func (h *Hub) SetGroups(g Groups) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.groups = g
}

// DeleteInstance permanently deletes instance id (default instances
// included). confirm must repeat the id (else 400). It backs the instance
// up first (reason delete) and stops if that fails, nothing removed; then
// records state "deleting" with the archive and removes, in order, the
// project and its volumes, the Keycloak access roles / flows, clients
// (only those tagged with the instance) and forward-auth callbacks, the
// access and admin groups (through the Users & Groups guardrails, as
// actor; protected, permission and shared groups are kept with a
// warning), and finally its files, ops record and state. Every step is
// idempotent: after a failure (an *OpError, the instance stays
// "deleting") the same call continues where it stopped, keeping the
// first backup. Audited as instance.delete.
func (h *Hub) DeleteInstance(id, confirm, actor string) (res *DeleteResult, err error) {
	return h.deleteInstance(id, confirm, actor, nil)
}

// deleteInstance is DeleteInstance; ready (if set) is called once the
// request is accepted (typed id, lock held, instance found, actor
// resolved), before the delete's backup (StartDelete answers 202 then).
func (h *Hub) deleteInstance(id, confirm, actor string, ready func()) (res *DeleteResult, err error) {
	res = &DeleteResult{}
	defer func() {
		detail := "backup=" + res.Backup
		if len(res.Warnings) > 0 {
			detail += fmt.Sprintf(" warnings=%d", len(res.Warnings))
		}
		h.auditOp(actor, "instance.delete", id, detail, err)
	}()
	if confirm != id {
		return res, statusErr(400, "type the instance id (%s) to confirm the delete", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, err
	}
	defer unlock()
	h.mu.RLock()
	tg, ok := h.targetLocked(id)
	h.mu.RUnlock()
	if !ok {
		return res, statusErr(404, "instance not found: %s", id)
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI != nil {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return res, fmt.Errorf("the acting admin %q can't delete the instance's groups — nothing was deleted: %w", actor, err)
		}
	}
	if ready != nil {
		ready()
	}
	// The store and env are removed part-way: redact what they hold now.
	extra := h.redactionSet(id)
	defer func() { err = withSecrets(err, extra) }()
	if tg.entry.State == state.InstanceRestoring && tg.entry.RestoreAs != "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s was being restored from %s and never finished: the delete backup holds its half-restored data", id, tg.entry.RestoreAs))
	} else if tg.entry.State == state.InstanceRestoring {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s had an unfinished restore: the delete backup holds its half-restored data; its data from before that restore is in the pre-restore backup %s", id, tg.entry.Backup))
	}
	if tg.entry.State == state.InstanceDeleting {
		res.Backup = tg.entry.Backup
	} else {
		entry, berr := h.backupLocked(id, BackupDelete, true)
		if berr != nil {
			return res, fmt.Errorf("the backup before the delete failed — nothing was deleted: %w", berr)
		}
		res.Backup = entry.Archive
		h.mu.Lock()
		e := h.st.Instances[id]
		if e.ID == "" {
			e = state.Instance{ID: id, Template: tg.templateID}
		}
		e.State, e.Backup = state.InstanceDeleting, entry.Archive
		h.st.Instances[id] = e
		// Disabled with it (the backup left it stopped): nothing may
		// start it again, drift included.
		h.st.SetEnabled(id, false)
		h.rebuildLocked()
		h.refreshPublishedLocked()
		h.saveLocked()
		h.mu.Unlock()
		h.writePolicyLogged()
		log.Printf("instance %s: deleting (backup %s)", id, entry.Archive)
	}
	if err := h.deleteSteps(id, actor, res); err != nil {
		return res, h.finishOp(id, OpDelete, withSecrets(fmt.Errorf("delete of %s stopped part-way (it stays \"deleting\"; delete again to continue, the backup %s is kept): %w", id, res.Backup, err), extra), false)
	}
	log.Printf("instance %s deleted (backup %s)", id, res.Backup)
	return res, nil
}

// deleteSteps runs steps 3–6 of §11.4. Caller holds the app lock.
func (h *Hub) deleteSteps(id, actor string, res *DeleteResult) error {
	ctx := context.Background()
	h.mu.RLock()
	tg, _ := h.targetLocked(id)
	snap, hasSnap := h.st.Published[id]
	groupsAPI := h.groups
	var hosts []string
	switch {
	case tg.view != nil:
		hosts = instanceHosts(tg.view)
	case len(tg.entry.Hosts) > 0:
		for _, v := range tg.entry.Hosts {
			hosts = append(hosts, v)
		}
	default:
		hosts = append(hosts, snap.Hosts...)
	}
	sort.Strings(hosts)
	var clients []string
	var groups []string
	switch {
	case tg.view != nil:
		n := tg.view.NamesFor(id)
		clients = n.Clients
		groups = []string{n.AccessGroup, n.AdminGroup}
	case hasSnap:
		clients = snap.Clients
		groups = []string{snap.AccessGroup, snap.AdminGroup}
	case id != tg.templateID:
		groups = []string{"users_" + id, "admin_" + id}
	}
	if tg.view == nil && len(clients) == 0 && id != tg.templateID {
		// The derived first client id (§11.2); further ones aren't known.
		clients = []string{id}
	}
	shared := map[string]string{}
	for _, g := range groups {
		if g != "" {
			if who := h.groupUserLocked(g, id); who != "" {
				shared[g] = who
			}
		}
	}
	h.mu.RUnlock()
	if tg.view == nil && (!hasSnap || len(snap.Clients) == 0) {
		if id != tg.templateID {
			res.Warnings = append(res.Warnings, fmt.Sprintf("the template of %s is missing and no published snapshot lists its Keycloak clients: only the derived client id %s is deleted, others may be left behind", id, id))
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("the template of %s is missing and no published snapshot lists its Keycloak clients: they may be left behind", id))
		}
	}

	// 3. Project down, then its volumes.
	if err := h.stopProject(tg); err != nil {
		return fmt.Errorf("compose down: %w", err)
	}
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	if h.engine == nil {
		res.Warnings = append(res.Warnings, "Docker is not available: the volumes of "+projectName(id)+" were not removed")
	} else {
		vols, err := h.projectVolumes(ctx, id)
		if err != nil {
			return fmt.Errorf("listing the volumes: %w", err)
		}
		for _, k := range sortedVolumeKeys(vols) {
			if err := h.engine.RemoveVolume(ctx, vols[k].Name); err != nil && !docker.IsNotFound(err) {
				return fmt.Errorf("removing volume %s: %w", vols[k].Name, err)
			}
		}
	}

	// 4. Keycloak: access role and flow, setting claims (with their LLDAP
	// attributes), clients, forward-auth callbacks.
	// Under the delivery lock: no delivery or background claims run is
	// mid-write meanwhile (lockApp → deliverLock, as composeUp; no
	// deliverLock holder ever waits for lockApp).
	dl := h.deliverLock(id)
	dl.Lock()
	err := h.removeInstanceClaims(ctx, h.idp, id, clients, h.instanceClaimAttrs(tg.view, id), res)
	dl.Unlock()
	if err != nil {
		return fmt.Errorf("setting claims: %w", err)
	}
	if h.idp == nil {
		res.Warnings = append(res.Warnings, "Keycloak is not configured: no clients, access roles or callbacks were removed")
	} else {
		var errs []error
		if tg.view != nil {
			if err := h.RemoveInstanceAccess(ctx, tg.view); err != nil {
				errs = append(errs, err)
			}
		} else {
			for _, c := range clients {
				if err := h.idp.RemoveClientAccess(ctx, c, id, hosts); err != nil {
					errs = append(errs, fmt.Errorf("client %s: %w", c, err))
				}
			}
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("Keycloak access role: %w", err)
		}
		for _, c := range clients {
			err := h.idp.DeleteClient(ctx, c, id)
			var ce *keycloak.ConflictError
			switch {
			case errors.As(err, &ce):
				res.Warnings = append(res.Warnings, fmt.Sprintf("Keycloak client %s was kept: it is not tagged as owned by %s", c, id))
			case err != nil:
				return fmt.Errorf("deleting Keycloak client %s: %w", c, err)
			}
		}
		// Every host's callback (only extra-domain ones exist; removing
		// an absent URI changes nothing).
		if err := h.idp.UpdateForwardAuthCallbacks(ctx, nil, callbackURIs(hosts)); err != nil {
			return fmt.Errorf("Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)
		}
	}

	// 5. Groups, through the Users & Groups guardrails.
	for _, g := range groups {
		switch {
		case g == "":
		case g != "users_"+id && g != "admin_"+id:
			// Only the instance's own names (§11.2): a manifest group
			// with another name is someone's on purpose.
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was kept: it isn't named users_%s / admin_%s (delete it on the Users & Groups page if nothing needs it)", g, id, id))
		case shared[g] != "":
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was kept: %s uses it too", g, shared[g]))
		case groupsAPI == nil:
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was kept: users & groups is not available", g))
		default:
			w, err := groupsAPI.DeleteInstanceGroup(ctx, actor, g)
			res.Warnings = append(res.Warnings, w...)
			if err != nil {
				return fmt.Errorf("deleting group %s: %w", g, err)
			}
		}
	}

	// 6. Files, ops record, state; policy and portal.
	for _, p := range []string{h.envPath(id), h.overridePath(id), h.userOverridePath(id), h.opPath(id), h.hostsOpPath(id)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", p, err)
		}
	}
	// Its settings data files (<appfiles>/<id>/) and delivery record,
	// under the delivery lock, before the settings store: a run that
	// started before the delete finishes first (its record would re-create
	// <data>/settings/<id>/), and later runs see the instance busy.
	if err := h.forgetDeliveries(id); err != nil {
		return fmt.Errorf("removing the data files of %s: %w", id, err)
	}
	// The settings store (<data>/settings/<id>/: secrets); its values
	// are in the delete's backup.
	if err := h.removeSecrets(id); err != nil {
		return fmt.Errorf("removing the settings store of %s: %w", id, err)
	}
	h.opsMu.Lock()
	delete(h.ops, id)
	delete(h.hostsOps, id)
	h.opsMu.Unlock()
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	delete(h.st.Instances, id)
	h.applyConfigLocked(id, instanceConfig{})
	delete(h.st.Published, id)
	// Its folder uses went with its values; its write confirmations go
	// too (contract §14.1).
	dropWriteConfirmed(h.st.Folders, id)
	delete(h.folderChanged, id)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	saveErr := h.st.Save(h.statePath())
	h.mu.Unlock()
	if saveErr != nil {
		return fmt.Errorf("saving state.yaml: %w", saveErr)
	}
	if err := h.WritePolicy(); err != nil {
		res.Warnings = append(res.Warnings, "the policy file write failed (it is retried with the next change): "+err.Error())
	}
	h.TriggerReconcile()
	return nil
}

func sortedVolumeKeys(vols map[string]docker.Volume) []string {
	keys := make([]string, 0, len(vols))
	for k := range vols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// groupUserLocked names another user of group g than instance id (""
// none): any other instance's access or admin group, any template's
// default groups (templates may share a group on purpose), published
// snapshots, and instances whose template is missing (users_<x> /
// admin_<x>). Caller must hold mu.
func (h *Hub) groupUserLocked(g, id string) string {
	same := func(x string) bool { return x != "" && strings.EqualFold(x, g) }
	for i := range h.instances {
		v := &h.instances[i]
		if v.ID == id {
			continue
		}
		if n := v.NamesFor(v.ID); same(n.AccessGroup) || same(n.AdminGroup) {
			return "instance " + v.ID
		}
	}
	for i := range h.allTemplates {
		tt := &h.allTemplates[i]
		if tt.ID == id {
			continue
		}
		if n := tt.NamesFor(tt.ID); same(n.AccessGroup) || same(n.AdminGroup) {
			return "template " + tt.ID
		}
	}
	for oid, snap := range h.st.Published {
		if oid != id && (same(snap.AccessGroup) || same(snap.AdminGroup)) {
			return "instance " + oid
		}
	}
	for oid, e := range h.st.Instances {
		if oid != id && oid != e.Template && (same("users_"+oid) || same("admin_"+oid)) {
			return "instance " + oid
		}
	}
	return ""
}

// removeCallbacks drops t's extra-domain sign-in callbacks (disable,
// contract §5); failures are logged (the next enable or delete retries).
func (h *Hub) removeCallbacks(t *templates.Template) {
	if h.idp == nil || len(t.ExtraHosts) == 0 {
		return
	}
	if err := h.idp.UpdateForwardAuthCallbacks(context.Background(), nil, callbackURIs(t.ExtraHosts)); err != nil {
		log.Printf("Warning: instance %s: removing its %s callbacks failed (removed on delete; harmless while no other instance holds its hosts): %v", t.ID, keycloak.ForwardAuthClient, err)
	}
}
