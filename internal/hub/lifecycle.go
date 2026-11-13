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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
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
// came from compose (it may have created containers). ctx carries the
// operation's reporter (startUp's steps; Background: none) and its Stop.
func (h *Hub) composeUp(ctx context.Context, t *templates.Template) error {
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return nil
	}
	seq := h.owedSeqOf(t.ID)
	live, err := h.prepareUp(t)
	if err != nil {
		return err
	}
	if err := h.startUp(ctx, live); err != nil {
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
		// A locked setup choice the template no longer fits: never
		// started on other data (§13.18).
		err = h.fixedChoicesErrLocked(live)
	}
	if err == nil {
		err = h.generateOverrideLocked(live, h.st.Settings[t.ID])
	}
	if err == nil {
		err = h.refreshInstanceEnvLocked(live, members)
	}
	h.mu.Unlock()
	// A stored env override the template now refuses was skipped: the
	// running operation's record says so (§11.9).
	h.warnEnvOverrideDrops(t.ID)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return nil, err // a refusal (a folder-range gid: 409)
		}
		return nil, statusErr(500, "override generation failed: %v", err)
	}
	// Rootless Podman (contract §11.10): an instance that can't run here
	// (its own ports, devices and env, as just written) never starts.
	if h.rootlessOn() {
		h.mu.RLock()
		s := h.st.Settings[t.ID]
		h.mu.RUnlock()
		if err := rootlessRefusal(t.ID, h.instanceCompat(live, s)); err != nil {
			return nil, err
		}
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
//
// With a reporter in opCtx (progressFrom) it reports the steps images
// (every image compose would pull, downloaded first through the Engine
// API: create then finds them present), create, start and healthy
// (startprogress.go) — each only when the operation planned it. An
// unplanned images step means no own pre-pull (compose pulls); healthy's
// project-wide wait exists only to be reported, so it runs only when
// planned — it never existed without a reporter. Every wait that ran
// before still runs, reporter or not, planned or not: the AI hooks'
// post-up readiness wait (runAIHookAfterUp, from pendingAIAfterStart
// below) never looks at the reporter —, and a Stop (opCtx cancelled) ends it between them
// — the downloads stop at once — with opCtx's error (isStopErr), nothing
// rolled back. Without one (Background) it pulls nothing itself and waits
// for nothing: compose does what it always did. compose create and up
// run on opCtx too: a Stop kills them (the undo's compose down removes
// whatever they made). With a reporter the project's volumes are listed
// before and after the create, the new ones written to the operation's
// Created ledger (recordCreatedVolumes), and the start hooks are the
// settings step (a failure an operation warning). Every other Docker
// call — probes, take-downs, the label checks — runs on its own
// Background context: a Stop never cuts a take-down short.
func (h *Hub) startUp(opCtx context.Context, live *templates.Template) error {
	ctx := context.Background()
	var p *startSteps
	if pr := progressFrom(opCtx); pr != nil {
		p = newStartSteps(pr)
	}
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
	// The project's volumes before the create (with a reporter): the ones
	// the create adds are the operation's (Created) — a Stop removes only
	// those. Not knowing them is a refusal: an undo must never guess.
	var volsBefore map[string]bool
	if p != nil {
		if p.keys[StepImages] {
			if err := h.pullImages(opCtx, p, live); err != nil {
				return err
			}
		}
		// Only an operation that plans the create keeps its volumes (an
		// enable: its Stop removes them); a restart's or an AI switch's
		// Stop never removes a volume.
		if h.engine != nil && p.keys[StepCreate] {
			if volsBefore, err = h.volumeSet(ctx, live.ID); err != nil {
				return statusErr(502, "listing the volumes of %s before creating it: %v", projectName(live.ID), err)
			}
			// The volumes the create will make, in the ledger before it
			// runs: a Hub stop mid-create still knows them (undo treats a
			// volume that doesn't exist as removed).
			h.recordExpectedVolumes(ctx, p.p, live, volsBefore)
		}
		if err := opCtx.Err(); err != nil {
			return err
		}
		p.Start(StepCreate)
	}
	// Create without starting, inspect the labels (image LABELs merge in),
	// only then start: an image-label router is never live. On the
	// operation's context: a Stop kills compose (compose down — the
	// undo's — removes whatever it had made).
	createErr := h.compose.Create(opCtx, h.project(live))
	if volsBefore != nil {
		h.recordCreatedVolumes(ctx, p.p, live.ID, volsBefore)
	}
	if createErr != nil {
		if err := opCtx.Err(); err != nil {
			return fmt.Errorf("compose create: %w", err)
		}
		return createErr
	}
	if p != nil {
		p.Done(StepCreate)
		if err := opCtx.Err(); err != nil {
			return err
		}
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
	var upErr error
	if p != nil {
		if err := opCtx.Err(); err != nil {
			return err
		}
		p.Start(StepStart)
		wctx, stopWatch := context.WithCancel(opCtx)
		watched := make(chan struct{})
		if p.keys[StepStart] {
			go func() {
				defer close(watched)
				h.watchStart(wctx, p, live)
			}()
		} else {
			close(watched)
		}
		upErr = h.compose.Up(opCtx, h.project(live))
		stopWatch()
		<-watched
	} else {
		upErr = h.compose.Up(opCtx, h.project(live))
	}
	if err := upErr; err != nil {
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
		if cerr := opCtx.Err(); cerr != nil {
			return fmt.Errorf("compose up: %w", cerr)
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
	if p != nil {
		if p.keys[StepStart] {
			h.startStepDone(ctx, p, live)
		}
		if p.keys[StepHealthy] {
			if err := h.waitHealthy(opCtx, p, live); err != nil {
				return err
			}
		}
	}
	// The start hooks (when: start) after the up, under the lifecycle
	// lock still held: reported and op-recorded, never a rollback (with a
	// reporter, whose running record keeps the hook's own from being
	// written: each failure an operation warning).
	if p != nil {
		p.Start(StepSettings)
	}
	failures := h.runStartHooks(context.Background(), live.ID)
	// AI companions owing a revoke_all (switched while stopped): run it
	// now, before they are rendered (contract §15.5).
	h.pendingAIAfterStart(live)
	if p != nil {
		for _, f := range failures {
			p.Warn(f)
		}
		p.Done(StepSettings)
	}
	// The claims (LLDAP and Keycloak) in the background: a start never
	// waits for them.
	h.deliverClaimsAfterStart(live.ID)
	// The first successful start locks the fixed_after_start setup
	// choices (§13.18), saved at once — never on a failed start (every
	// failure above returned first). An operation that planned the
	// create (an enable: its Stop removes the volumes it made) stamps it
	// at its commit instead, in the commit's state save.
	if p == nil || !p.keys[StepCreate] {
		h.mu.Lock()
		if h.stampFirstStartLocked(live.ID) {
			h.saveLocked()
		}
		h.mu.Unlock()
	}
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

func (h *Hub) clientSpec(t *templates.Template, c templates.KeycloakClient) keycloak.ClientSpec {
	bcl := strings.ReplaceAll(c.BackchannelLogoutURL, "{{DOMAIN}}", h.cfg.Domain)
	// Secret: per-app .env first, then core .env.
	secret := h.clientSecret(t, c)
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
	return h.enableInner(context.Background(), id, false)
}

// enableInner is enableLocked; restoring lets a restore enable the
// instance it is restoring (state "restoring"). ctx carries the
// operation's reporter (the keycloak step and startUp's, each only when
// planned; the clients this call created go into its Created ledger)
// and its Stop: a cancelled ctx ends it between the steps — and kills a
// running compose — with ctx's error (isStopErr), nothing rolled back
// here (the Stop's undo does it) and nothing committed.
func (h *Hub) enableInner(ctx context.Context, id string, restoring bool) (rolledBack bool, err error) {
	prog := progressFrom(ctx)
	kc := prog.planned(StepKeycloak)

	// Phase 1 (under mu): validate and write local files — fast filesystem
	// work that needs a consistent view of state. The directory snapshot
	// for group records first (network: outside mu).
	// A bound users group that became privileged since the create is
	// never started on (§11.9, fail closed). Only when not enabled yet:
	// an enabled instance has nothing to start.
	if !h.IsEnabled(id) {
		if err := h.checkBoundUsersGroup(ctx, id); err != nil {
			return false, err
		}
	}
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
	if err := h.fixedChoicesErrLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return false, err
	}
	// Per-person passwords need a usable secrets volume (F14).
	if err := h.ensureSecretDirsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return false, err
	}
	// The template's starting per-person rows (after EnableAs created
	// the instance's missing groups), and an AI page's default provider
	// selection when it never chose (Task 23).
	h.seedSettingsLocked(&tmpl)
	h.seedAIProvidersLocked(&tmpl)
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
	callbacks := callbackURIs(h.signInExtraHostsLocked(&tmpl))
	h.mu.Unlock()

	h.copyConfigFiles(&tmpl)

	// Phase 2 (no mu): network / docker work that may take minutes.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if h.idp != nil {
		kc.Start(StepKeycloak)
		kcEnded := false
		defer func() {
			// Ended here before the step did: it failed (a Stop's stopped
			// step is frozen).
			if err != nil && !kcEnded && !isStopErr(err) {
				kc.Fail(StepKeycloak, err)
			}
		}()
		var made []string
		for _, c := range tmpl.Manifest.Clients {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			var err error
			if c.AIClient {
				// The AI page's MCP client goes through the AI client path
				// (G10): never RegisterClient. A failure leaves it unhealthy
				// (out of mcp-gate.json's clients), retried by every pass.
				var created bool
				created, err = h.ensureInstanceAIClient(context.Background(), &tmpl)
				if created {
					prog.Created(CreatedKeycloakClients, c.ClientID)
					made = append(made, c.ClientID)
				}
			} else {
				var created bool
				created, err = h.idp.RegisterClient(context.Background(), h.clientSpec(&tmpl, c))
				if created {
					// Written at once: a Stop — also after a Hub restart —
					// deletes exactly the clients this enable made.
					prog.Created(CreatedKeycloakClients, c.ClientID)
					made = append(made, c.ClientID)
				}
			}
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
		if len(made) > 0 {
			kc.Detail(StepKeycloak, strings.Join(made, ", ")+" created")
		}
		kc.Done(StepKeycloak)
		kcEnded = true
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	if err := h.composeUp(ctx, &tmpl); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			// Stopped: the Stop's undo takes the project down.
			return false, fmt.Errorf("%v: %w", err, cerr)
		}
		if !composeFailed(err) {
			return false, err
		}
		defer h.TriggerReconcile()
		if rbErr := h.rollbackUp(&tmpl); rbErr != nil {
			return false, &StatusError{Status: 500, Err: fmt.Errorf("compose up failed: %w — rolling back (compose down) failed too: %v; stop the leftovers from the drift banner", err, rbErr)}
		}
		return true, &StatusError{Status: 500, Err: fmt.Errorf("compose up failed: %w — rolled back: its containers and network were removed (volumes kept), the app stays disabled", err)}
	}

	// Phase 3 (under mu): commit — unless a Stop came first: the commit
	// gate (CloseStop, atomic with cancelOp) either finds the Stop (its
	// undo takes the started project down) or closes stopping for good
	// (a later Stop is refused "finishing").
	if h.testHookCommit != nil {
		h.testHookCommit(id, "before")
	}
	if !prog.CloseStop() {
		return false, fmt.Errorf("stopped before the commit: %w", context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if h.testHookCommit != nil {
		h.testHookCommit(id, "after")
	}
	h.mu.Lock()
	h.st.SetEnabled(id, true)
	if e, ok := h.st.Instances[id]; ok && e.State == state.InstanceCreated {
		e.State = ""
		h.st.Instances[id] = e
	}
	// A default instance's hosts.immutable hostnames are pinned once it
	// first runs: a later main-domain change keeps them (its data is bound
	// to them) instead of moving it to <sub>.<new domain>.
	if e, ok := h.st.Instances[id]; len(e.Hosts) == 0 && tmpl.IsDefault() && hasImmutableHosts(&tmpl) {
		if !ok {
			e = state.Instance{ID: id, Template: id}
		}
		e.Hosts = copyMap(tmpl.Hosts)
		h.st.Instances[id] = e
	}
	// Its first start succeeded and can no longer be undone (§13.18).
	h.stampFirstStartLocked(id)
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

// Disable steps (contract §11.7 "Steps per operation"; stop.go has
// the undo).
const (
	StepStop      = "stop"
	StepCallbacks = "callbacks"
	StepDown      = "down"
)

// disablePlan is a disable's steps: stop, then callbacks (the
// extra-domain sign-in callbacks) when Keycloak is wired.
func (h *Hub) disablePlan() []Step {
	steps := []Step{{Key: StepStop, Label: "Stopping the app"}}
	h.mu.RLock()
	idp := h.idp != nil
	h.mu.RUnlock()
	if idp {
		steps = append(steps, Step{Key: StepCallbacks, Label: "Keycloak callbacks"})
	}
	return steps
}

// StartDisable starts disabling instance id as actor in the background
// (202, contract §11.7). Refused at once, nothing recorded: busy
// (*BusyError), an unknown instance (404), one not enabled (400). A Stop
// before its commit turns the app back on (undoDisable). Audited
// instance.disable with the outcome (a refusal at once, else at its end).
func (h *Hub) StartDisable(id string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpDisable, actor, h.disablePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		err := h.runDisable(ctx, id, ready)
		h.auditOp(actor, "instance.disable", id, "", err)
		return nil, nil, err
	})
}

// Disable stops the app and marks it disabled once its containers are
// gone — StartDisable's operation run to its end (runOpSync: the same
// lock, record, steps and Stop), started by the Hub (no actor). If the
// template is gone or its compose file is broken, it falls back to
// stopping by project name. An unknown instance is the 400 "not
// enabled", as it always was.
func (h *Hub) Disable(id string) error {
	_, _, err := h.runOpSync(id, OpDisable, directory.Actor{}, h.disablePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.runDisable(ctx, id, ready)
	})
	var se *StatusError
	var oe *OpError
	if !errors.As(err, &oe) && errors.As(err, &se) && se.Status == 404 {
		err = statusErr(400, "app not enabled: %s", id)
	}
	return err
}

// runDisable is the disable StartDisable and Disable run: lock (lockApp
// → aiLock for the whole run, G35), the refusals, ready, the steps, then
// the commit — or, a Stop accepted first, the undo (settleOp).
func (h *Hub) runDisable(ctx context.Context, id string, ready func()) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	defer h.lifecycleAILock(id)() // lockApp → aiLock (G35): no mint meanwhile
	h.mu.RLock()
	enabled := h.st.IsEnabled(id)
	var tmpl *templates.Template
	if t := h.findLocked(id); t != nil {
		c := *t
		tmpl = &c
	}
	h.mu.RUnlock()
	switch {
	case tmpl == nil && !enabled:
		return statusErr(404, "app instance not found: %s", id)
	case !enabled:
		return statusErr(400, "app not enabled: %s", id)
	}
	ready()
	p := progressFrom(ctx)
	return h.settleOp(id, OpDisable, p, h.disableSteps(ctx, p, id, tmpl))
}

// disableSteps: stop (compose down; by project name when the template is
// gone or the files fail), callbacks (its extra-domain sign-in callbacks
// go with it; a Keycloak failure is a warning, as it always was), then
// the commit gate and the commit: not enabled, policy and portal
// rewritten. A Stop is checked between the steps (the down itself runs
// to its end: a Stop never cuts a take-down short). Caller holds id's
// lock.
func (h *Hub) disableSteps(ctx context.Context, p *Progress, id string, tmpl *templates.Template) error {
	p.Start(StepStop)
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
			err := fmt.Errorf("compose down failed (app left enabled, retry): %w", downErr)
			p.Fail(StepStop, err)
			return err
		}
	}
	p.Done(StepStop)
	if err := ctx.Err(); err != nil {
		return err
	}
	cb := p.planned(StepCallbacks)
	cb.Start(StepCallbacks)
	if tmpl != nil {
		if err := h.removeCallbacks(tmpl); err != nil {
			p.Warn(fmt.Sprintf("the %s callbacks of %s could not be removed (%v): they go with its delete", keycloak.ForwardAuthClient, id, err))
		}
	}
	cb.Done(StepCallbacks)
	if err := ctx.Err(); err != nil {
		return err
	}
	// The commit gate (atomic with cancelOp): a Stop accepted before it is
	// undone, one after it refused "finishing".
	if h.testHookCommit != nil {
		h.testHookCommit(id, "disable")
	}
	if !p.CloseStop() {
		return fmt.Errorf("stopped before the commit: %w", context.Canceled)
	}
	if h.testHookCommit != nil {
		h.testHookCommit(id, "disable:after")
	}
	h.mu.Lock()
	h.st.SetEnabled(id, false)
	h.rebuildLocked()
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	h.TriggerReconcile()
	return nil
}

// restartPlan is a restart's steps (create is no step of it: unplanned,
// startUp doesn't report it).
func restartPlan() []Step {
	return []Step{
		{Key: StepDown, Label: "Stopping the app"},
		{Key: StepImages, Label: "Downloading images"},
		{Key: StepStart, Label: "Starting services"},
		{Key: StepHealthy, Label: "Waiting until healthy"},
		{Key: StepSettings, Label: "Applying settings"},
	}
}

// StartRestart starts restarting instance id as actor in the background
// (202, contract §11.7). Refused at once, nothing recorded: busy
// (*BusyError), unknown (404), not enabled (400). A Stop leaves the app
// running as before (undoRestart). Audited instance.restart with the
// outcome (a refusal at once, else at its end).
func (h *Hub) StartRestart(id string, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(id, OpRestart, actor, restartPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		err := h.runRestartApp(ctx, id, ready)
		h.auditOp(actor, "instance.restart", id, "", err)
		return nil, nil, err
	})
}

// Restart recreates an app's containers (down + up) so new env, override
// and labels take effect — StartRestart's operation started by the Hub
// (the delivery engine, revocations, the master switch: no actor) and
// run to its end. It waits for any in-flight operation on the app
// instead of dropping the restart: that operation may have read the old
// files, and compose reads them at run time, so a queued restart always
// applies the latest ones. The outcome is recorded (LastOp); like any
// restart it can be stopped. Only a restart that committed clears the
// owed restart.
func (h *Hub) Restart(t templates.Template) {
	h.runOpSync(t.ID, OpRestart, directory.Actor{}, restartPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		deadline := time.Now().Add(h.restartWait)
		var unlock func()
		for {
			u, err := h.lockApp(t.ID)
			if err == nil {
				unlock = u
				break
			}
			if time.Now().After(deadline) {
				// Recorded (never over another operation's running
				// record); the restart stays owed: Init queues it again.
				log.Printf("restart %s gave up: %v", t.ID, err)
				err = fmt.Errorf("the restart gave up after waiting %s for another operation (%s): restart the app", h.restartWait, err.Error())
				h.finishOpGuarded(t.ID, OpRestart, err, false, true)
				return nil, nil, err
			}
			time.Sleep(h.lockPoll)
		}
		defer unlock()
		if !h.IsEnabled(t.ID) {
			return nil, nil, statusErr(400, "app not enabled: %s", t.ID) // disabled while we waited
		}
		ready()
		// The owed restart is cleared only by a restart that committed
		// (restartSteps, right after its gate): a refused, failed or
		// stopped one leaves it owed — queued again (requeueOwed), never
		// dropped (fail closed: it may carry a revoked value).
		err := h.restartOp(ctx, &t)
		h.TriggerReconcile()
		return nil, nil, err
	})
}

// RestartApp restarts an enabled app now and returns the outcome
// (StartRestart's operation run to its end: its error carries compose's
// output).
func (h *Hub) RestartApp(id string) error {
	_, _, err := h.runOpSync(id, OpRestart, directory.Actor{}, restartPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		return nil, nil, h.runRestartApp(ctx, id, ready)
	})
	return err
}

func (h *Hub) runRestartApp(ctx context.Context, id string, ready func()) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
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
	ready()
	return h.restartOp(ctx, t)
}

// restartOp is an accepted restart: whether the app runs now (what a
// Stop puts back: OpRecord.Before "running"), the restart, then
// settleOp. Caller holds t's lock.
func (h *Hub) restartOp(ctx context.Context, t *templates.Template) error {
	p := progressFrom(ctx)
	running := true // not known (no Docker, a failed listing): a Stop starts it again
	if h.engine != nil {
		if r, err := h.projectRunning(context.Background(), t.ID); err == nil {
			running = r
		}
	}
	p.Before("running", strconv.FormatBool(running))
	return h.settleOp(t.ID, OpRestart, p, h.restartLocked(ctx, t))
}

func (h *Hub) restartLocked(ctx context.Context, t *templates.Template) error {
	_, downErr, err := h.restartSteps(ctx, t)
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
// nil). ctx carries the operation's reporter (the down step, startUp's
// steps) and its Stop, checked between the steps (the pull and compose
// up are killed); its commit gate (CloseStop) is right after the start,
// before the owed restart is cleared.
func (h *Hub) restartSteps(ctx context.Context, t *templates.Template) (stopped bool, downErr, err error) {
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
	if err := ctx.Err(); err != nil {
		return false, nil, err
	}
	prog := progressFrom(ctx)
	dp := prog.planned(StepDown)
	dp.Start(StepDown)
	downErr = h.composeDown(t)
	if downErr != nil {
		dp.Detail(StepDown, "compose down failed: "+downErr.Error())
	}
	dp.Done(StepDown)
	if err := ctx.Err(); err != nil {
		return true, downErr, err
	}
	if err := h.startUp(ctx, live); err != nil {
		if composeFailed(err) {
			return true, downErr, fmt.Errorf("compose up failed: %w", err)
		}
		return true, downErr, err
	}
	if !prog.CloseStop() {
		return true, downErr, fmt.Errorf("stopped before the commit: %w", context.Canceled)
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
