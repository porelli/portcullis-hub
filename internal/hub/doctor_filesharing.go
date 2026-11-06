package hub

import (
	"context"
	"fmt"
	"log"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor's file-sharing inputs and fixes (contract §14.5 "File
// sharing", §14.6 revoke_leaver / person_tree_owner; plan 3 Task 11,
// F8, F31, F33, F35, F56). doctorInputs reads the stored hook reports
// before mu (fileSharingReports) and builds doctor.FileSharingIn under the
// read lock (fileSharingInputsLocked). The canary (credential_without_
// access) judges the active credentials with the very holder check the
// revoker runs (credentialRevocations); its fix is the admin revoke. A
// per-person tree's one-click fix is the fixer's childfix mode on one
// directory, previewed by a read-only probe.

// The fixes' operations (the instance's own op record).
const (
	OpRevokeLeaver    = "revoke_leaver"
	OpPersonTreeOwner = "person_tree_owner"
)

func init() {
	RegisterFixer(revokeLeaverFixer{})
	RegisterFixer(personTreeOwnerFixer{})
}

// fileSharingReports are the stored hook reports of the enabled instances
// that have hooks, by id (read from disk, never under mu).
func (h *Hub) fileSharingReports() map[string]*StoredHookReport {
	h.mu.RLock()
	var ids []string
	for i := range h.instances {
		t := &h.instances[i]
		if h.st.IsEnabled(t.ID) && len(t.Manifest.Hooks) > 0 {
			ids = append(ids, t.ID)
		}
	}
	h.mu.RUnlock()
	out := map[string]*StoredHookReport{}
	for _, id := range ids {
		if r, ok := h.HookReport(id); ok {
			out[id] = r
		}
	}
	return out
}

// fileSharingTemplate: t has something the file-sharing checks judge.
func fileSharingTemplate(t *templates.Template) bool {
	if len(personSecretOptions(t)) > 0 || len(personIDOptions(t)) > 0 || t.UsesLocalNetworks {
		return true
	}
	for _, o := range t.Manifest.Options() {
		if len(o.RequiresAny) > 0 || settings.PerPersonTree(&o) {
			return true
		}
	}
	return false
}

// fileSharingInputsLocked is the doctor's FileSharing input: every
// enabled file-sharing instance (or one with a hook report), plus any
// instance holding a credential the holder check would revoke (the
// canary judges those whatever their enabled flag). m nil (the directory
// is unavailable): no holders and no tree people, nothing judged on them.
// paths are the doctor's PathIns (enabled instances). Caller holds mu
// (read).
func (h *Hub) fileSharingInputsLocked(m *directory.Membership, paths []doctor.PathIn, reports map[string]*StoredHookReport) []doctor.FileSharingIn {
	revoked := map[[3]string]bool{}
	ids := map[string]bool{}
	if m != nil {
		for _, r := range credentialRevocations(m, h.st.Credentials, h.credentialTemplatesLocked()) {
			revoked[[3]string{r.Instance, r.Key, r.User}] = true
			ids[r.Instance] = true
		}
	}
	for i := range h.instances {
		t := &h.instances[i]
		if h.st.IsEnabled(t.ID) && (fileSharingTemplate(t) || reports[t.ID] != nil) {
			ids[t.ID] = true
		}
	}
	empty := h.st.LocalNetworks != nil && len(*h.st.LocalNetworks) == 0
	var out []doctor.FileSharingIn
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		t := h.findLocked(id)
		fs := doctor.FileSharingIn{Instance: id, Label: id}
		if t != nil {
			fs.Label = appName(t)
		}
		if m != nil {
			for _, key := range slices.Sorted(maps.Keys(h.st.Credentials[id])) {
				users := h.st.Credentials[id][key]
				for _, u := range slices.Sorted(maps.Keys(users)) {
					if users[u].Active() {
						fs.Holders = append(fs.Holders, doctor.HolderIn{Key: key, User: u, HasAccess: !revoked[[3]string{id, key, u}]})
					}
				}
			}
		}
		if t != nil && h.st.IsEnabled(id) {
			fs.Trees = h.treeInputsLocked(t, m, paths)
			fs.LocalNetworksEmpty = empty && t.UsesLocalNetworks
			fs.Unserved = h.unservedLocked(t)
			if r := reports[id]; r != nil {
				rep := r.Report
				fs.Report, fs.ReportAt = &rep, r.ReceivedAt
			}
		}
		out = append(out, fs)
	}
	return out
}

// treeInputsLocked are t's per-person trees with a host path (paths: the
// enabled instances' usages), each with the uid every person of the
// population who has an id must own their directory with. Caller holds mu.
func (h *Hub) treeInputsLocked(t *templates.Template, m *directory.Membership, paths []doctor.PathIn) []doctor.TreeIn {
	var out []doctor.TreeIn
	var pop *Population
	for _, u := range paths {
		if u.Instance != t.ID || !u.PersonTree || u.Source != doctor.SourceSetting || u.HostPath == "" {
			continue
		}
		ti := doctor.TreeIn{Instance: t.ID, Key: u.Key, Label: u.Label, HostPath: path.Clean(u.HostPath)}
		if pool := h.treePoolLocked(t.ID, u.Key); m != nil && pool != "" {
			if pop == nil {
				p := h.populationLocked(t, m)
				pop = &p
			}
			ti.People = map[string]int{}
			for _, p := range pop.People {
				if id, ok := h.personIDForLocked(pool, p.User, m.UUIDs[p.User]); ok {
					ti.People[p.User] = id
				}
			}
		}
		out = append(out, ti)
	}
	return out
}

// unservedLocked are t's options with a value whose requires_any options
// are all unset (settings.UnmetRequiresAny on the stored values). Caller
// holds mu.
func (h *Hub) unservedLocked(t *templates.Template) []doctor.UnservedIn {
	keys := settings.UnmetRequiresAny(t.Manifest.Settings, h.requiresValuesLocked(t, h.st.Settings[t.ID]))
	var out []doctor.UnservedIn
	for _, k := range keys {
		o := optionByKey(t, k)
		u := doctor.UnservedIn{Key: k, Label: o.Label, Requires: slices.Clone(o.RequiresAny)}
		for _, r := range o.RequiresAny {
			l := r
			if ro := optionByKey(t, r); ro != nil && ro.Label != "" {
				l = ro.Label
			}
			u.RequiresLabels = append(u.RequiresLabels, l)
		}
		out = append(out, u)
	}
	return out
}

// ── revoke_leaver ───────────────────────────────────────

type revokeLeaverFixer struct{}

func (revokeLeaverFixer) Kind() string { return doctor.FixRevokeLeaver }

func (revokeLeaverFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	if len(f.Instances) == 1 {
		return f.Instances[0]
	}
	return ""
}

// leaverCalc is revoke_leaver's plan: the credential the canary found.
type leaverCalc struct {
	inst, key, user, app, id string
	hash                     string
}

// leaverPlan finds finding f's credential: active, and the holder check
// still revokes it (else 409: the setup changed). Nothing changes.
func (h *Hub) leaverPlan(ctx context.Context, f doctor.Finding, params map[string]string) (*leaverCalc, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, r := range credentialRevocations(m, h.st.Credentials, h.credentialTemplatesLocked()) {
		if doctor.CredentialFP(r.Instance, r.Key, r.User) != f.FP {
			continue
		}
		c := &leaverCalc{inst: r.Instance, key: r.Key, user: r.User, app: r.Instance, id: r.ID}
		if t := h.findLocked(r.Instance); t != nil {
			c.app = appName(t)
		}
		c.hash = fixHash(struct{ Kind, FP, Instance, Key, User, ID string }{doctor.FixRevokeLeaver, f.FP, c.inst, c.key, c.user, c.id})
		return c, nil
	}
	return nil, errSetupChanged()
}

func (revokeLeaverFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	c, err := h.leaverPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: []string{fmt.Sprintf("revoke %s's file-share password for %s", c.user, c.app)}, Hash: c.hash}, nil
}

// Apply: op revoke_leaver on the instance's record; the plan recomputed
// (another credential, or one revoked meanwhile: 409), then the admin
// revoke (§13.16: reason admin, revoked_by the admin, audited
// credential.revoke with the admin as actor, applied live like every
// revocation).
func (revokeLeaverFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	ctx := context.Background()
	c, err := h.leaverPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	if planHash == "" || c.hash != planHash {
		return nil, errCredentialChanged()
	}
	return h.startAsync(c.inst, OpRevokeLeaver, actor, func(ready func()) (map[string]string, []string, error) {
		ready()
		// Only the previewed credential (fix round 1): one regenerated or
		// created since is left alone, under the same lock as the revoke.
		if err := h.adminRevokeCredentialID(ctx, c.inst, c.key, c.user, actor, c.id); err != nil {
			return nil, nil, err
		}
		return map[string]string{"user": c.user, "key": c.key}, nil, nil
	})
}

// errCredentialChanged: revoke_leaver's credential isn't the previewed one.
func errCredentialChanged() error {
	return statusErr(http.StatusConflict, "the credential changed since the preview: preview it again")
}

// adminRevokeCredentialID is the admin revoke of exactly credential id
// (409 when the active credential is another one, or none).
func (h *Hub) adminRevokeCredentialID(ctx context.Context, instance, key, user string, actor directory.Actor, id string) error {
	if id == "" {
		return errCredentialChanged()
	}
	n, err := h.revokeCredentialsN(ctx, instance, []revocation{{key: key, user: user, by: strings.ToLower(actor.User), reason: state.CredentialReasonAdmin, id: id, via: actor.Via, client: actor.Client}})
	if err != nil {
		return err
	}
	if n == 0 {
		return errCredentialChanged()
	}
	return nil
}

// ── person_tree_owner ───────────────────────────────────

type personTreeOwnerFixer struct{}

func (personTreeOwnerFixer) Kind() string { return doctor.FixPersonTreeOwner }

func (personTreeOwnerFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	if len(f.Instances) == 1 && len(f.Paths) == 1 {
		return f.Instances[0] + " " + f.Paths[0]
	}
	return ""
}

// treeCalc is person_tree_owner's plan: one person's directory of a tree
// and the probe's identity of it.
type treeCalc struct {
	inst, key, user, tree string
	uid, owner            int
	pools                 []string
	dev, ino              uint64
	mountRoot             string
	line, hash            string
}

// treePlan finds finding f's directory (an enabled instance's tree, a
// person of its population with an id), checks the tree like a doctor
// scan target (cleanFolderPath, folderPathRule, dockerRootRule) and
// probes <tree>/<user> read-only: it must exist, with no symlink on the
// way. The plan hash covers the child's device, inode and mount root.
func (h *Hub) treePlan(ctx context.Context, f doctor.Finding, params map[string]string) (*treeCalc, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	m, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	var c *treeCalc
	h.mu.RLock()
	var paths []doctor.PathIn
	for _, u := range h.pathUsagesLocked() {
		paths = append(paths, pathIn(u))
	}
	for i := range h.instances {
		t := &h.instances[i]
		if c != nil || !h.st.IsEnabled(t.ID) {
			continue
		}
		for _, ti := range h.treeInputsLocked(t, m, paths) {
			for _, user := range slices.Sorted(maps.Keys(ti.People)) {
				if doctor.TreeFP(doctor.KindPersonTreeOwner, t.ID, ti.Key, user) == f.FP {
					c = &treeCalc{inst: t.ID, key: ti.Key, user: user, tree: ti.HostPath, uid: ti.People[user]}
					if pool := h.treePoolLocked(t.ID, ti.Key); pool != "" {
						c.pools = []string{pool}
					}
				}
			}
		}
	}
	h.mu.RUnlock()
	if c == nil {
		return nil, errSetupChanged()
	}
	if cl, err := cleanFolderPath(c.tree); err != nil || cl != c.tree {
		if err == nil {
			err = badPath("%s is not a clean path", c.tree)
		}
		return nil, err
	}
	if err := h.folderPathRule(c.tree); err != nil {
		return nil, err
	}
	if err := h.dockerRootRule(ctx, c.tree); err != nil {
		return nil, err
	}
	child := path.Join(c.tree, c.user)
	pr, err := h.probePath(ctx, child, false, "")
	if err != nil {
		return nil, err
	}
	if !pr.Exists {
		return nil, statusErr(http.StatusConflict, "%s doesn't exist (any more): run the disk check again", child)
	}
	if !path.IsAbs(pr.RelMountRoot) || templates.HasControlChars(pr.RelMountRoot) {
		return nil, statusErr(http.StatusInternalServerError, "person_tree_owner: the probe reported no mount root for %s", child)
	}
	if pr.UID != c.uid {
		// Fix round 1: only a folder the person already owns has its
		// group and mode corrected; another owner's is a former
		// account's — the Hub never moves data.
		return nil, statusErr(http.StatusConflict, "explain-only: %s belongs to uid %d, not %s's (uid %d): a former account's folder; move it by hand (the Hub never moves data)", child, pr.UID, c.user, c.uid)
	}
	c.dev, c.ino, c.mountRoot, c.owner = pr.Dev, pr.Ino, pr.RelMountRoot, pr.UID
	c.line = fmt.Sprintf("chown %d:%d + chmod 0700 %s (not recursive)", c.uid, c.uid, child)
	c.hash = fixHash(struct {
		Kind, FP, Instance, Key, User, Tree, MountRoot string
		UID, Owner                                     int
		Dev, Ino                                       uint64
	}{doctor.FixPersonTreeOwner, f.FP, c.inst, c.key, c.user, c.tree, c.mountRoot, c.uid, c.owner, c.dev, c.ino})
	return c, nil
}

func (personTreeOwnerFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	c, err := h.treePlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: []string{c.line}, Hash: c.hash}, nil
}

// Apply: op person_tree_owner on the instance's record, under its
// lockApp: the plan recomputed (probing again; another hash is 409), then
// the fixer's childfix on that one directory (§6: CHOWN FOWNER, the bind
// root read-write at /broot; the fixer opens the child O_NOFOLLOW|
// O_DIRECTORY and refuses a symlink, a non-directory, another mount or
// another inode), then the tree scanned again so the doctor sees the
// result. Audited doctor.fix (ApplyFix).
func (personTreeOwnerFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash string, actor directory.Actor) (*AsyncOp, error) {
	ctx := context.Background()
	c0, err := h.treePlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	inst := c0.inst
	return h.startAsync(inst, OpPersonTreeOwner, actor, func(ready func()) (map[string]string, []string, error) {
		unlock, err := h.lockApp(inst)
		if err != nil {
			return nil, nil, err
		}
		defer unlock()
		c, err := h.treePlan(ctx, f, params)
		if err != nil {
			return nil, nil, err
		}
		if planHash == "" || c.hash != planHash || c.inst != inst {
			return nil, nil, errSetupChanged()
		}
		ready()
		root, rel := h.bindRootOf(c.tree)
		if root == "" {
			return nil, nil, badPath("%s is not under a bind root", c.tree)
		}
		rep, err := h.runFixer(ctx, fixerRun{Mode: "childfix", Source: root,
			Opts:  folderfix.Options{ExpectDev: c.dev, ExpectIno: c.ino, ExpectMountRoot: c.mountRoot},
			Extra: folderfix.ArgsExtra{Rel: rel, Child: folderfix.ChildFix{Name: c.user, UID: c.uid, Owner: c.owner}}})
		if err != nil {
			return nil, nil, err
		}
		child := path.Join(c.tree, c.user)
		if len(rep.Children) != 1 || rep.Dev != c.dev || rep.Ino != c.ino {
			return nil, nil, statusErr(http.StatusInternalServerError, "person_tree_owner: the fixer's report doesn't describe %s", child)
		}
		if got := rep.Children[0]; got.UID != c.uid || got.GID != c.uid || got.Mode != folderfix.ChildMode || !got.Dir {
			return nil, nil, statusErr(http.StatusInternalServerError, "person_tree_owner: %s is %d:%d %04o after the fix, want %d:%d 0700", child, got.UID, got.GID, got.Mode, c.uid, c.uid)
		}
		// The tree's cached check, again (best effort: the next disk
		// check does it otherwise).
		var warns []string
		if e, why := h.scanOne(ctx, ScanTarget{Path: c.tree, Children: true, Pools: c.pools}); why == "" && e.Err == "" {
			h.putScan(e)
		} else {
			log.Printf("doctor: %s: checking %s again after the fix: %s%s", inst, c.tree, why, e.Err)
			warns = append(warns, fmt.Sprintf("%s was fixed, but checking %s again failed: run the disk check", child, c.tree))
		}
		return map[string]string{"path": child, "uid": fmt.Sprint(c.uid), "changed": fmt.Sprint(rep.Changed)}, warns, nil
	})
}
