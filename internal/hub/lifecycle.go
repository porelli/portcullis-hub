package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// ErrBusy is returned when another lifecycle operation holds the app lock.
type ErrBusy struct{ ID string }

func (e ErrBusy) Error() string {
	return fmt.Sprintf("another operation on %s is in progress — try again shortly", e.ID)
}

func (h *Hub) lockApp(id string) (func(), error) {
	if _, busy := h.appOps.LoadOrStore(id, struct{}{}); busy {
		return nil, ErrBusy{ID: id}
	}
	return func() {
		h.opsMu.Lock()
		delete(h.startHookFailed, id)
		h.opsMu.Unlock()
		h.appOps.Delete(id)
	}, nil
}

func (h *Hub) appBusy(id string) bool {
	_, busy := h.appOps.Load(id)
	return busy
}

// project builds the compose invocation for a template: the template's
// compose.yml, the Hub's generated override, then the admin's custom
// override (Expert mode) — later files win.
func (h *Hub) project(t *templates.Template) compose.Project {
	p := compose.Project{
		Name:       projectName(t.ID),
		Files:      []string{t.ComposePath()},
		ProjectDir: h.cfg.ProjectHostDir,
		EnvFile:    h.envPath(t.ID),
	}
	for _, f := range []string{h.overridePath(t.ID), h.userOverridePath(t.ID)} {
		if _, err := os.Stat(f); err == nil {
			p.Files = append(p.Files, f)
		}
	}
	return p
}

// composeUp regenerates the Hub override, re-checks the custom override
// against the template as it is now, syncs the template's files and runs
// compose up. Failures before compose are *StatusError; anything else
// came from compose (it may have created containers).
func (h *Hub) composeUp(t *templates.Template) error {
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return nil
	}
	seq := h.owedSeqOf(t.ID)
	live, err := h.prepareUp(t)
	if err != nil {
		return err
	}
	if err := h.startUp(live); err != nil {
		return err
	}
	// The containers run what is configured now: nothing is owed.
	h.clearOwed(t.ID, seq, settings.EffectRestart)
	return nil
}

// prepareUp is everything composeUp does before compose runs: the Hub
// override, the .env, the custom override check, the template's files
// and the start's data files. restartLocked runs it before stopping
// anything (an app is never left down by a refusal). Returns the live
// view the up uses. Failures are *StatusError.
func (h *Hub) prepareUp(t *templates.Template) (*templates.Template, error) {
	members := h.groupSnapshot(t.ID)
	h.mu.Lock()
	live := t
	if l := h.findLocked(t.ID); l != nil {
		c := *l
		live = &c
	}
	// The secrets volume's hash directories first (F14: unusable =
	// refused, 503).
	err := h.ensureSecretDirsLocked(live)
	if err == nil {
		err = h.generateOverrideLocked(live, h.st.Settings[t.ID])
	}
	if err == nil {
		err = h.refreshInstanceEnvLocked(live, members)
	}
	h.mu.Unlock()
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return nil, err // a refusal (a folder-range gid: 409)
		}
		return nil, statusErr(500, "override generation failed: %v", err)
	}
	if err := h.checkUserOverride(live); err != nil {
		return nil, err
	}
	// The rendered project mounts the secrets volume only as the Hub's
	// override does (F15).
	if err := h.checkSecretsMounts(context.Background(), live); err != nil {
		return nil, err
	}
	if err := h.syncTemplateFiles(live); err != nil {
		return nil, statusErr(500, "sync template files: %v", err)
	}
	// The settings data files before the containers exist (P6): an init
	// one-shot reads them at start, and Docker would create a missing
	// bind source as a root-owned directory. Trigger start: never a
	// reload or restart.
	if err := h.deliverForStart(context.Background(), live.ID); err != nil {
		return nil, err
	}
	return live, nil
}

// startUp is composeUp after prepareUp: create, the image-label check,
// up, the start hooks and the background claims. Shared-folder values
// (the folder root always, H1; a subpath with it, one run per folder)
// are probed before anything is created, again right before the up and
// right after it (ruling 24, R44).
func (h *Hub) startUp(live *templates.Template) error {
	ctx := context.Background()
	// Read under mu, probed outside it.
	h.mu.RLock()
	probes, err := h.folderProbesLocked(live)
	h.mu.RUnlock()
	if err != nil {
		return err
	}
	// Before Create: a refusal touches nothing (a running app keeps
	// running on the mounts it started with).
	if len(probes) > 0 {
		if p, detail, err := h.probeFolders(ctx, probes, false); err != nil {
			log.Printf("shared folders: %s: not started: %s", live.ID, detail)
			if p != nil && isFolderChanged(err) {
				h.recordFolderChange(live.ID, p, detail)
			}
			return err
		}
	}
	// Create without starting, inspect the labels (image LABELs merge in),
	// only then start: an image-label router is never live.
	if err := h.compose.Create(ctx, h.project(live)); err != nil {
		return err
	}
	if p := h.imageLabelProblem(live); p != "" {
		return h.refuseImageLabels(live, p, "was not started")
	}
	// Right before the up: Docker resolves bind sources on the host, so a
	// subpath a writer app swapped for a symlink would mount its target.
	if len(probes) > 0 {
		if p, detail, err := h.probeFolders(ctx, probes, false); err != nil {
			log.Printf("shared folders: %s: not started: %s", live.ID, detail)
			return h.folderTakeDown(ctx, live, p, detail, err)
		}
	}
	// Before every up (F15), again: the files are those compose reads.
	if err := h.checkSecretsMounts(ctx, live); err != nil {
		if derr := h.forceDown(ctx, live); derr != nil {
			return statusErr(500, "%v — and taking the created project down failed: %v", err, derr)
		}
		return err
	}
	if err := h.compose.Up(ctx, h.project(live)); err != nil {
		if len(probes) > 0 {
			// Some services may have started on a swapped subpath: probe
			// again (record a change) and always take the project down.
			p, detail, perr := h.probeFolders(ctx, probes, true)
			if perr != nil {
				log.Printf("shared folders: WARNING: %s: %s after a failed up", live.ID, detail)
				return h.folderTakeDown(ctx, live, p, detail, perr)
			}
			if derr := h.forceDown(ctx, live); derr != nil {
				return statusErr(500, "compose up of %s failed (%v) and taking it down failed too: the project may still be running (%v)", live.ID, err, derr)
			}
		}
		return err
	}
	if err := h.checkImageLabels(live); err != nil {
		return err
	}
	// Right after the start: the same folders, the same subpaths. A
	// change takes the project down at once (volumes kept).
	if len(probes) > 0 {
		if p, detail, err := h.probeFolders(ctx, probes, true); err != nil {
			log.Printf("shared folders: WARNING: %s: %s after the start: taken down", live.ID, detail)
			return h.folderTakeDown(ctx, live, p, detail, err)
		}
	}
	// A clean start: no folder changed (M2); the runtime gids read before
	// it are stale (H11 M6).
	h.recordFolderChange(live.ID, nil, "")
	h.mu.Lock()
	if h.startedAt == nil {
		h.startedAt = map[string]time.Time{}
	}
	h.startedAt[live.ID] = time.Now().UTC()
	h.mu.Unlock()
	// The start hooks (when: start) after the up, under the lifecycle
	// lock still held: reported and op-recorded, never a rollback.
	h.runStartHooks(context.Background(), live.ID)
	// AI companions owing a revoke_all (switched while stopped): run it
	// now, before they are rendered (contract §15.5).
	h.pendingRevokesAfterStart(live)
	// The claims (LLDAP and Keycloak) in the background: a start never
	// waits for them.
	h.deliverClaimsAfterStart(live.ID)
	return nil
}

// syncTemplateFiles publishes the template's support files, serialised per
// TEMPLATE id: every instance of a template shares <core>/templates/<id>/.
func (h *Hub) syncTemplateFiles(t *templates.Template) error {
	m, _ := h.syncMu.LoadOrStore(templateDir(t), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	dir := templateDir(t)
	h.syncHashMu.Lock()
	last := h.syncHashes[dir]
	h.syncHashMu.Unlock()
	sum, err := templates.SyncFilesIfChanged(t, h.templatesRoot(), last)
	if err != nil {
		return err
	}
	if sum != last {
		h.recordSyncHash(dir, sum)
	}
	return nil
}

func (h *Hub) syncHashPath() string { return filepath.Join(h.cfg.DataDir, "template-sync.json") }

// loadSyncHashes reads the tree hashes the Hub last published per template
// dir (kept in its data dir: <core>/templates is writable by others).
// Unreadable = none known: every template is re-synced once.
func (h *Hub) loadSyncHashes() {
	h.syncHashes = map[string]string{}
	if data, err := os.ReadFile(h.syncHashPath()); err == nil {
		if err := json.Unmarshal(data, &h.syncHashes); err != nil {
			log.Printf("template sync record unreadable (%v): re-syncing every template", err)
			h.syncHashes = map[string]string{}
		}
	}
}

func (h *Hub) recordSyncHash(dir, sum string) {
	h.syncHashMu.Lock()
	defer h.syncHashMu.Unlock()
	h.syncHashes[dir] = sum
	data, _ := json.MarshalIndent(h.syncHashes, "", "  ")
	if err := fsutil.WriteFileAtomic(h.syncHashPath(), data, 0600); err != nil {
		// Only costs a re-sync next time.
		log.Printf("template sync record: %v", err)
	}
}

func (h *Hub) composeDown(t *templates.Template) error {
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return nil
	}
	h.awaitDelivery(t.ID)
	return h.compose.Down(context.Background(), h.project(t))
}

// awaitDelivery waits up to lifecycleDeliverWait for instance id's
// delivery lock to be free (T18 c3, §13.9): a lifecycle down (backup,
// restore, restart, delete, disable — the caller holds lockApp: lockApp
// → deliverLock) lets an in-flight revocation hook finish first, then
// proceeds either way. Once per down (N4): composeDown calls it, and a
// down by name without composeDown before it. Never call it holding the
// delivery lock.
func (h *Hub) awaitDelivery(id string) {
	if h.testHookAwaitDelivery != nil {
		h.testHookAwaitDelivery(id)
	}
	l := h.deliverLock(id)
	if tryLockFor(l, h.lifecycleDeliverWait) {
		l.Unlock()
		return
	}
	log.Printf("%s: a delivery still holds the delivery lock after %s: stopping anyway", id, h.lifecycleDeliverWait)
}

// rollbackUp removes what a failed compose up left behind (containers,
// network; volumes are kept), by project name if the files don't work.
func (h *Hub) rollbackUp(t *templates.Template) error {
	err := h.compose.Down(context.Background(), h.project(t))
	if err != nil && h.compose.DownByName(context.Background(), projectName(t.ID)) == nil {
		return nil
	}
	return err
}

// composeFailed reports whether err came from compose itself rather than
// from the Hub's checks before it.
func composeFailed(err error) bool {
	var se *StatusError
	return err != nil && !errors.As(err, &se)
}

// redirectURIs expands {{DOMAIN}} in a client's redirect URIs.
func (h *Hub) redirectURIs(c templates.KeycloakClient) []string {
	var out []string
	if len(c.RedirectURIs) > 0 {
		for _, u := range c.RedirectURIs {
			out = append(out, strings.ReplaceAll(u, "{{DOMAIN}}", h.cfg.Domain))
		}
	} else if c.RedirectURI != "" {
		out = []string{strings.ReplaceAll(c.RedirectURI, "{{DOMAIN}}", h.cfg.Domain)}
	}
	return out
}

func (h *Hub) clientSpec(t *templates.Template, c templates.KeycloakClient, acr string) keycloak.ClientSpec {
	bcl := strings.ReplaceAll(c.BackchannelLogoutURL, "{{DOMAIN}}", h.cfg.Domain)
	// Secret: per-app .env first, then core .env.
	secret := ""
	if c.SecretEnv != "" {
		for _, p := range []string{h.envPath(t.ID), filepath.Join(h.cfg.ProjectDir, ".env")} {
			if v := readEnvFile(p)[c.SecretEnv]; v != "" {
				secret = v
				break
			}
		}
	}
	hosts := make([]string, 0, len(t.Hosts))
	for _, host := range t.Hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return keycloak.ClientSpec{
		AllowedHosts: hosts,
		ClientID:     c.ClientID,
		Name:         c.Name,
		Secret:       secret,
		RedirectURIs: h.redirectURIs(c),
		TemplateID:   t.ID, // the owner tag: the instance id (§11.2)
		ACR:          acr,
		// Most apps get the realm's email scope; email_verified_claim: false
		// swaps it for email-unverified.
		OmitEmailVerified:    !c.SendsEmailVerified(),
		BackchannelLogoutURL: bcl,
	}
}

// Enable writes the app's env/override, registers its OIDC clients and runs
// compose up. The app is recorded as enabled only if compose succeeds; a
// failed compose up is rolled back (compose down) so no half-created
// project stays behind. The outcome is recorded (LastOp).
func (h *Hub) Enable(id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	rolledBack, err := h.enableLocked(id)
	return h.finishOp(id, OpEnable, err, rolledBack)
}

func (h *Hub) enableLocked(id string) (rolledBack bool, err error) {
	return h.enableInner(id, false)
}

// enableInner is enableLocked; restoring lets a restore enable the
// instance it is restoring (state "restoring").
func (h *Hub) enableInner(id string, restoring bool) (rolledBack bool, err error) {

	// Phase 1 (under mu): validate and write local files — fast filesystem
	// work that needs a consistent view of state. The directory snapshot
	// for group records first (network: outside mu).
	members := h.groupSnapshot(id)
	h.mu.Lock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.Unlock()
		return false, statusErr(400, "app instance not found: %s", id)
	}
	tmpl := *t // the catalog slice may be replaced meanwhile
	if err := h.pendingLocked(id); err != nil && !restoring {
		h.mu.Unlock()
		return false, err
	}
	if h.st.IsEnabled(id) {
		h.mu.Unlock()
		return false, nil
	}
	if err := h.checkPortCollisionsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return false, err
	}
	if err := h.checkSubdomainCollisionsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return false, err
	}
	// Per-person passwords need a usable secrets volume (F14).
	if err := h.ensureSecretDirsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return false, err
	}
	// The template's starting per-person rows (after EnableAs created
	// the instance's missing groups).
	h.seedSettingsLocked(&tmpl)
	if err := h.generateAppEnvLocked(&tmpl, members); err != nil {
		h.mu.Unlock()
		return false, statusErr(500, "env setup failed: %v", err)
	}
	if err := h.generateOverrideLocked(&tmpl, h.st.Settings[tmpl.ID]); err != nil {
		h.mu.Unlock()
		var se *StatusError
		if errors.As(err, &se) {
			return false, err // a refusal (a folder-range gid: 409)
		}
		return false, statusErr(500, "override write failed: %v", err)
	}
	acr := policy.ACR(h.effectivePolicyLocked(&tmpl))
	callbacks := callbackURIs(h.signInExtraHostsLocked(&tmpl))
	h.mu.Unlock()

	h.copyConfigFiles(&tmpl)

	// Phase 2 (no mu): network / docker work that may take minutes.
	if h.idp != nil {
		for _, c := range tmpl.Manifest.Clients {
			err := h.idp.RegisterClient(context.Background(), h.clientSpec(&tmpl, c, acr))
			var conflict *keycloak.ConflictError
			switch {
			case errors.As(err, &conflict):
				// Fail closed: never start an app wired to a client it
				// doesn't own (its secret/redirects would be someone else's).
				return false, &StatusError{Status: 409, Err: err}
			case err != nil:
				log.Printf("Warning: failed to register client %s: %v", c.ClientID, err)
			}
		}
		// The access role (contract §8): never start an app whose sign-in
		// should be restricted but isn't. A missing access group is only a
		// warning — the client then denies everybody until it exists.
		if err := h.ensureAccess(context.Background(), &tmpl); err != nil {
			return false, err
		}
		// Sign-in callbacks of its extra-domain hosts (contract §5).
		if err := h.idp.UpdateForwardAuthCallbacks(context.Background(), callbacks, nil); err != nil {
			return false, &StatusError{Status: 502, Err: fmt.Errorf("Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)}
		}
		// A failed enable takes them away again (the instance stays
		// disabled; an unused callback must not linger).
		defer func() {
			if err == nil || len(callbacks) == 0 {
				return
			}
			if cerr := h.idp.UpdateForwardAuthCallbacks(context.Background(), nil, callbacks); cerr != nil {
				log.Printf("instance %s: removing the %s callbacks after a failed enable failed: %v", id, keycloak.ForwardAuthClient, cerr)
			}
		}()
	}
	if err := h.composeUp(&tmpl); err != nil {
		if !composeFailed(err) {
			return false, err
		}
		defer h.TriggerReconcile()
		if rbErr := h.rollbackUp(&tmpl); rbErr != nil {
			return false, &StatusError{Status: 500, Err: fmt.Errorf("compose up failed: %w — rolling back (compose down) failed too: %v; stop the leftovers from the drift banner", err, rbErr)}
		}
		return true, &StatusError{Status: 500, Err: fmt.Errorf("compose up failed: %w — rolled back: its containers and network were removed (volumes kept), the app stays disabled", err)}
	}

	// Phase 3 (under mu): commit.
	h.mu.Lock()
	h.st.SetEnabled(id, true)
	if e, ok := h.st.Instances[id]; ok && e.State == state.InstanceCreated {
		e.State = ""
		h.st.Instances[id] = e
	}
	// A default instance's hosts.immutable hostnames are pinned once it
	// first runs: a later main-domain change keeps them (its data is bound
	// to them) instead of moving it to <sub>.<new domain>.
	if _, ok := h.st.Instances[id]; !ok && tmpl.IsDefault() && hasImmutableHosts(&tmpl) {
		h.st.Instances[id] = state.Instance{ID: id, Template: id, Hosts: copyMap(tmpl.Hosts)}
	}
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	h.TriggerReconcile()
	return false, nil
}

// checkSubdomainCollisionsLocked refuses to enable a template that routes a
// subdomain another enabled app already routes: group-gate keys policies,
// groups and path groups by subdomain, so the two would share (and fight
// over) one entry. Caller must hold mu.
func (h *Hub) checkSubdomainCollisionsLocked(t *templates.Template) error {
	mine := map[string]bool{}
	for _, s := range t.Subdomains {
		mine[s] = true
	}
	for _, id := range h.st.Enabled {
		if id == t.ID {
			continue
		}
		other := h.findLocked(id)
		if other == nil {
			continue
		}
		for _, s := range other.Subdomains {
			if mine[s] {
				return statusErr(409, "subdomain %s.%s is already routed by enabled app %s", s, h.cfg.Domain, id)
			}
		}
	}
	return nil
}

// copyConfigFiles copies manifest config_files into the core checkout. Both
// ends must stay inside their trees, and top-level core files (.env,
// docker-compose.yml, …) are off limits.
func (h *Hub) copyConfigFiles(t *templates.Template) {
	root := filepath.Clean(h.cfg.ProjectDir)
	for _, cf := range t.Manifest.ConfigFiles {
		src := filepath.Join(t.Path, cf.Src)
		dest := filepath.Join(root, cf.Dest)
		if !fsutil.Within(t.Path, src) || !fsutil.Within(root, dest) || dest == root || filepath.Dir(dest) == root {
			log.Printf("Warning: refusing config_files entry %s → %s for %s (outside allowed paths)", cf.Src, cf.Dest, t.ID)
			continue
		}
		os.MkdirAll(filepath.Dir(dest), 0755)
		if err := fsutil.CopyFile(src, dest); err != nil {
			log.Printf("Warning: failed to copy %s → %s: %v", src, dest, err)
		}
	}
}

// Disable stops the app and marks it disabled once its containers are gone.
// If the template is gone or its compose file is broken, it falls back to
// stopping by project name.
func (h *Hub) Disable(id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	return h.finishOp(id, OpDisable, h.disableLocked(id), false)
}

func (h *Hub) disableLocked(id string) error {
	h.mu.RLock()
	enabled := h.st.IsEnabled(id)
	var tmpl *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		tmpl = &c
	}
	h.mu.RUnlock()
	if !enabled {
		return statusErr(400, "app not enabled: %s", id)
	}
	var downErr error
	if tmpl != nil {
		downErr = h.composeDown(tmpl)
	} else {
		h.awaitDelivery(id) // composeDown waits otherwise (N4)
	}
	if tmpl == nil || downErr != nil {
		if err := h.compose.DownByName(context.Background(), projectName(id)); err != nil {
			if downErr == nil {
				downErr = err
			}
			return fmt.Errorf("compose down failed (app left enabled, retry): %w", downErr)
		}
	}
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	// Its extra-domain sign-in callbacks go with it (enable adds them).
	if tmpl != nil {
		h.removeCallbacks(tmpl)
	}
	h.TriggerReconcile()
	return nil
}

// Restart recreates an app's containers (down + up) so new env, override
// and labels take effect. It waits for any in-flight operation on the app
// instead of dropping the restart: that operation may have read the old
// files, and compose reads them at run time, so a queued restart always
// applies the latest ones. The outcome is recorded (LastOp).
func (h *Hub) Restart(t templates.Template) {
	deadline := time.Now().Add(h.restartWait)
	var unlock func()
	for {
		u, err := h.lockApp(t.ID)
		if err == nil {
			unlock = u
			break
		}
		if time.Now().After(deadline) {
			// Recorded (never over another operation's running record);
			// the restart stays owed: Init queues it again.
			log.Printf("restart %s gave up: %v", t.ID, err)
			h.finishOpGuarded(t.ID, OpRestart, fmt.Errorf("the restart gave up after waiting %s for another operation (%s): restart the app", h.restartWait, err.Error()), false, true)
			return
		}
		time.Sleep(h.lockPoll)
	}
	defer unlock()
	if !h.IsEnabled(t.ID) {
		return // disabled while we waited
	}
	seq := h.owedSeqOf(t.ID)
	h.finishOp(t.ID, OpRestart, h.restartLocked(&t), false)
	h.clearOwed(t.ID, seq, settings.EffectRestart)
	h.TriggerReconcile()
}

// RestartApp restarts an enabled app now and returns the outcome (the API's
// Restart button: its error carries compose's output).
func (h *Hub) RestartApp(id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()
	t := h.Template(id)
	if t == nil {
		return ErrNotFound
	}
	if !t.Enabled {
		return statusErr(400, "app not enabled")
	}
	defer h.TriggerReconcile()
	return h.finishOp(id, OpRestart, h.restartLocked(t), false)
}

func (h *Hub) restartLocked(t *templates.Template) error {
	_, downErr, err := h.restartSteps(t)
	if err != nil {
		return err
	}
	if downErr != nil {
		return fmt.Errorf("compose down failed (the containers may not have been recreated): %w", downErr)
	}
	return nil
}

// restartSteps is restartLocked telling apart what happened: stopped
// false = refused before anything was stopped (the app runs as it was);
// downErr = compose down failed but the up that followed worked (err
// nil).
func (h *Hub) restartSteps(t *templates.Template) (stopped bool, downErr, err error) {
	// Refuse before stopping anything: an override that no longer fits
	// the template would leave the app down.
	if err := h.checkUserOverride(t); err != nil {
		return false, nil, err
	}
	// Then everything the up needs (override, .env, data files): a
	// refusal there leaves the app running as it was.
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return false, nil, nil
	}
	seq := h.owedSeqOf(t.ID)
	live, err := h.prepareUp(t)
	if err != nil {
		return false, nil, err
	}
	// The shared-folder subpaths too (H15): a missing or changed one is
	// refused while the app still runs on the mounts it started with.
	h.mu.RLock()
	probes, err := h.folderProbesLocked(live)
	h.mu.RUnlock()
	if err != nil {
		return false, nil, err
	}
	if len(probes) > 0 {
		if p, detail, err := h.probeFolders(context.Background(), probes, false); err != nil {
			log.Printf("shared folders: %s: not restarted (still running): %s", live.ID, detail)
			if p != nil && isFolderChanged(err) {
				h.recordFolderChange(live.ID, p, detail)
			}
			return false, nil, err
		}
	}
	downErr = h.composeDown(t)
	if err := h.startUp(live); err != nil {
		if composeFailed(err) {
			return true, downErr, fmt.Errorf("compose up failed: %w", err)
		}
		return true, downErr, err
	}
	h.clearOwed(t.ID, seq, settings.EffectRestart)
	return true, downErr, nil
}

// hasImmutableHosts: t declares a hosts.immutable host router.
func hasImmutableHosts(t *templates.Template) bool {
	for r := range t.HostRouters {
		if t.Manifest.ImmutableHost(r) {
			return true
		}
	}
	return false
}
