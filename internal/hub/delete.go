package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
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
func (h *Hub) DeleteInstance(id, confirm string, actor directory.Actor) (res *DeleteResult, err error) {
	return h.deleteInstance(id, confirm, actor, nil)
}

// deleteInstance is DeleteInstance; ready (if set) is called once the
// request is accepted (typed id, lock held, instance found, actor
// resolved), before the delete's backup (StartDelete answers 202 then).
func (h *Hub) deleteInstance(id, confirm string, actor directory.Actor, ready func()) (res *DeleteResult, err error) {
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
	// lockApp → aiLock (G35, §15.5): a mint that holds it finishes first
	// (its entry is dropped in step 6); one that waits sees the instance
	// deleting, then gone.
	defer h.lifecycleAILock(id)()
	h.mu.RLock()
	tg, ok := h.targetLocked(id)
	h.mu.RUnlock()
	if !ok {
		return res, statusErr(404, "instance not found: %s", id)
	}
	// A model provider pointing at it (a litellm provider's instance,
	// §15.12) would point nowhere: refused until it is deleted or
	// repointed (a delete in progress continues: nothing can point at a
	// deleting instance, checkProviderLocked refuses it).
	h.mu.RLock()
	pointing := h.providersAtInstanceLocked(id)
	h.mu.RUnlock()
	if len(pointing) > 0 && tg.entry.State != state.InstanceDeleting {
		return res, statusErr(409, "model provider %s uses instance %s: delete it or point it at another instance in Settings → AI first", strings.Join(pointing, ", "), id)
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI != nil {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return res, fmt.Errorf("the acting admin %q can't delete the instance's groups — nothing was deleted: %w", actor.User, err)
		}
	}
	if ready != nil {
		ready()
	}
	// The store and env are removed part-way: redact what they hold now.
	extra, unread := h.redactionSetErr(id)
	defer func() { err = hideIfUnread(withSecrets(err, extra), unread) }()
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
		if h.testHookDeleteBackedUp != nil {
			h.testHookDeleteBackedUp(id)
		}
		h.mu.Lock()
		// Again under the write lock that commits deleting (fix round 1):
		// a litellm provider added while the backup ran would point at a
		// deleted instance. Refused before any state change; the instance
		// runs again as it did (the backup is kept).
		if pointing := h.providersAtInstanceLocked(id); len(pointing) > 0 {
			h.mu.Unlock()
			err := statusErr(409, "model provider %s uses instance %s: delete it or point it at another instance in Settings → AI first (the backup %s was kept)", strings.Join(pointing, ", "), id, entry.Archive)
			if tg.enabled && tg.view != nil {
				if serr := h.startAgain(tg.view); serr != nil {
					return res, fmt.Errorf("%w — and starting %s again failed: %v", err, id, serr)
				}
			}
			return res, err
		}
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

// deleteTargets is what a delete of an instance removes (§11.4): its
// hosts, Keycloak clients and groups, and which groups another instance
// or template shares (kept). Shared by deleteSteps and DeletePlan.
type deleteTargets struct {
	tg      *target
	snap    state.PublishedApp
	hasSnap bool
	hosts   []string
	clients []string
	groups  []string
	shared  map[string]string // group → who else uses it
}

// deleteTargetsLocked computes id's deleteTargets. Caller holds mu (read).
func (h *Hub) deleteTargetsLocked(id string) deleteTargets {
	var d deleteTargets
	d.tg, _ = h.targetLocked(id)
	d.snap, d.hasSnap = h.st.Published[id]
	tg, snap, hasSnap := d.tg, d.snap, d.hasSnap
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
	d.hosts, d.clients, d.groups, d.shared = hosts, clients, groups, shared
	return d
}

// DeletePlan is what deleting instance id would do, as the lines a
// confirmation shows (§15.6, the Portcullis MCP's delete_instance):
// "Takes a backup, then permanently removes its containers, volumes,
// Keycloak client and groups users_x, admin_x", then the groups it would
// keep and why. Nothing changes. Unknown instance: 404.
func (h *Hub) DeletePlan(id string) ([]string, error) {
	h.mu.RLock()
	_, ok := h.targetLocked(id)
	if !ok {
		h.mu.RUnlock()
		return nil, statusErr(404, "instance not found: %s", id)
	}
	d := h.deleteTargetsLocked(id)
	h.mu.RUnlock()
	parts := []string{"containers", "volumes"}
	switch len(d.clients) {
	case 0:
	case 1:
		parts = append(parts, "Keycloak client")
	default:
		parts = append(parts, "Keycloak clients")
	}
	var del, kept []string
	for _, g := range d.groups {
		switch {
		case g == "":
		case g != "users_"+id && g != "admin_"+id:
			kept = append(kept, fmt.Sprintf("Keeps group %s: it isn't named users_%s / admin_%s.", g, id, id))
		case d.shared[g] != "":
			kept = append(kept, fmt.Sprintf("Keeps group %s: %s uses it too.", g, d.shared[g]))
		default:
			del = append(del, g)
		}
	}
	what := strings.Join(parts, ", ")
	if len(del) > 0 {
		group := "group"
		if len(del) > 1 {
			group = "groups"
		}
		what = strings.Join(parts, ", ") + " and " + group + " " + strings.Join(del, ", ")
	} else if len(parts) > 1 {
		what = strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
	lines := []string{"Takes a backup, then permanently removes its " + what + "."}
	if d.tg.entry.State == state.InstanceDeleting {
		lines[0] = "Continues an unfinished delete (its backup " + d.tg.entry.Backup + " is kept), permanently removing its " + what + "."
	}
	return append(lines, kept...), nil
}

// deleteSteps runs steps 3–6 of §11.4. Caller holds the app lock.
func (h *Hub) deleteSteps(id string, actor directory.Actor, res *DeleteResult) error {
	ctx := context.Background()
	h.mu.RLock()
	dt := h.deleteTargetsLocked(id)
	tg, snap, hasSnap, hosts, clients, groups, shared := dt.tg, dt.snap, dt.hasSnap, dt.hosts, dt.clients, dt.groups, dt.shared
	groupsAPI := h.groups
	// Named before step 3 drops AIInstances[id] (a retry names them from
	// the template).
	aiScopes := h.aiScopeNamesLocked(tg)
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
	// Its per-person secrets right after the down (§11.4 step 3, F13):
	// a delete that fails later leaves no credential behind. The project
	// is down, so no hook runs (§13.16: instance delete revokes at once);
	// each active credential is audited credential.revoke_leave reason
	// deleted, actor the deleting admin.
	var gone []revocation
	for key, users := range h.st.Credentials[id] {
		for u, c := range users {
			if c.Active() {
				gone = append(gone, revocation{key: key, user: u, by: actor.User, reason: state.CredentialReasonDeleted})
			}
		}
	}
	credErr := h.forgetCredentialsLocked(id)
	h.mu.Unlock()
	// Its AI state right then too (§11.4 step 3, G56): every AI
	// credential entry (audited ai.credential.revoke reason deleted; no
	// hook — the project is down and the app's tokens go with its
	// volumes), its oauth-seen records and orphans, AIInstances[id]; the
	// gate file below drops its resources.
	aiErr := h.forgetInstanceAI(id, actor)
	h.writePolicyLogged()
	if credErr != nil {
		return fmt.Errorf("removing the per-person passwords: %w", credErr)
	}
	if aiErr != nil {
		return fmt.Errorf("removing the AI state: %w", aiErr)
	}
	sort.Slice(gone, func(i, j int) bool {
		if gone[i].key != gone[j].key {
			return gone[i].key < gone[j].key
		}
		return gone[i].user < gone[j].user
	})
	for _, r := range gone {
		h.auditOp(actor, revokeAuditAction(r.reason), id+"/"+r.key+"/"+r.user, credentialDetail(id, r.key, r.user, actor.User, r.reason), nil)
	}
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
	// The AI page's ai_client carries no setting claims (G10).
	err := h.removeInstanceClaims(ctx, h.idp, id, withoutAIClients(tg.view, clients), h.instanceClaimAttrs(tg.view, id), res)
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
			// An ai_client's health goes with it (Task 23).
			h.forgetAIClientHealth(c)
		}
		// Every host's callback (only extra-domain ones exist; removing
		// an absent URI changes nothing).
		if err := h.idp.UpdateForwardAuthCallbacks(ctx, nil, callbackURIs(hosts)); err != nil {
			return fmt.Errorf("Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)
		}
	}

	// Its mcp:<id>.* scopes (§8: detached from every client first, every
	// consent naming them goes with them).
	if h.aiKeycloak() == nil {
		if len(aiScopes) > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Keycloak's AI scope calls are not configured: the client scopes mcp:%s.* were not removed", id))
		}
	} else if err := h.deleteAIScopes(ctx, id, aiScopes); err != nil {
		return fmt.Errorf("Keycloak AI scopes: %w", err)
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
	delete(h.st.FolderChanged, id)
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
func (h *Hub) removeCallbacks(t *templates.Template) error {
	if h.idp == nil || len(t.ExtraHosts) == 0 {
		return nil
	}
	if err := h.idp.UpdateForwardAuthCallbacks(context.Background(), nil, callbackURIs(t.ExtraHosts)); err != nil {
		log.Printf("Warning: instance %s: removing its %s callbacks failed (removed on delete; harmless while no other instance holds its hosts): %v", t.ID, keycloak.ForwardAuthClient, err)
		return err
	}
	return nil
}
