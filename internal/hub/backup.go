package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Instance backups (contract §11.5): <data>/backups/<id>/<UTC>.tar, an
// uncompressed tar of MANIFEST.json (first; sha256 of every other member),
// config/instance.yaml, config/env (secret settings' variables blanked),
// config/override.yml, config/user.yml, config/settings-secrets.json
// (the secrets store, when there is one) and volumes/<key>.tar (one inner tar per volume, as the daemon's archive
// endpoint produces it: entries "data/…", numeric uid/gid, modes, mtimes).
//
// Volume I/O never runs a process: a helper container (HelperImage)
// mounting only the volume, with no network, every capability dropped,
// no-new-privileges and nobody's uid, is created but never started; the
// daemon reads and writes the mounted volume itself (GET / PUT
// /containers/{id}/archive). Both go through the Hub's socket proxy
// (contract §6: containers, images, volumes and POST/PUT/DELETE — no
// change needed).
//
// Consistency: a running instance is stopped (compose down, volumes kept)
// while its volumes are copied, so databases (SQLite included) are copied
// at rest. Templates have no manifest field marking database files: no
// per-file online-backup step exists or is needed while the app is down.

// HelperImage is the volume I/O helper's image: core's
// PORTCULLIS_HELPER_IMAGE (scripts/lib/common.sh; TestHelperImageMatchesCore
// keeps them equal), pinned by digest. It is only ever created, never
// started, so its content never runs.
const HelperImage = "alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

// Backup reasons (MANIFEST.json "reason").
const (
	BackupManual  = "manual"
	BackupDelete  = "delete"
	BackupRestore = "restore"
)

const (
	backupVersion   = 1
	manifestMember  = "MANIFEST.json"
	maxManifestSize = 1 << 20
	maxConfigSize   = 16 << 20
	backupTimeFmt   = "20060102T150405Z"
	helperMount     = "/data"
)

// archiveRe is an archive name relative to <data>/backups.
var archiveRe = regexp.MustCompile(`^([a-z0-9][a-z0-9_-]{0,63})/([0-9]{8}T[0-9]{6}Z)\.tar$`)

// volumeKeyRe is a compose volume key.
var volumeKeyRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BackupManifest is MANIFEST.json.
type BackupManifest struct {
	Version        int               `json:"version"`
	Instance       string            `json:"instance"`
	Template       string            `json:"template"`
	TemplateCommit string            `json:"template_commit,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	Reason         string            `json:"reason"`
	Volumes        map[string]string `json:"volumes"`
	Files          map[string]string `json:"files"`
}

// BackupEntry is one archive as GET /api/backups lists it (§11.7).
type BackupEntry struct {
	Archive        string    `json:"archive"`
	Instance       string    `json:"instance"`
	Template       string    `json:"template"`
	CreatedAt      time.Time `json:"created_at"`
	Reason         string    `json:"reason"`
	Size           int64     `json:"size"`
	InstanceExists bool      `json:"instance_exists"`
}

// secretsMember is the archive member with the instance's secret settings
// (its secrets store; 0600 like every member, the archive is 0600 too).
const secretsMember = "config/settings-secrets.json"

// aiMember is the archive member with the instance's AI state (§11.5;
// switches, modes and provider selection — never a credential).
const aiMember = "config/ai.json"

// instanceConfig is config/instance.yaml: the instance's state entry.
type instanceConfig struct {
	ID       string            `yaml:"id"`
	Template string            `yaml:"template"`
	Default  bool              `yaml:"default"`
	Hosts    map[string]string `yaml:"hosts,omitempty"`
	Enabled  bool              `yaml:"enabled"`
	// Settings: ports and option values (canonical), per-person and
	// per-group rows, secret metadata — never secret values.
	Settings     *state.InstanceSettings `yaml:"settings,omitempty"`
	AuthPolicy   *policy.AuthPolicy      `yaml:"auth_policy,omitempty"`
	PublicAccess *bool                   `yaml:"public_access,omitempty"`
	PublicMode   string                  `yaml:"public_mode,omitempty"`
	PublicTokens []string                `yaml:"public_tokens,omitempty"`
	SignIn       string                  `yaml:"sign_in,omitempty"`
	// State is the state entry's state ("created" for a never-enabled
	// instance; a restore keeps it).
	State     string              `yaml:"state,omitempty"`
	Published *state.PublishedApp `yaml:"published,omitempty"`
}

func (h *Hub) backupsDir() string { return filepath.Join(h.cfg.DataDir, "backups") }

// target is an instance as backup / delete see it: its view when it
// resolves, else what state remembers. Caller must hold mu.
type target struct {
	id, templateID string
	view           *templates.Template // copy; nil = can't be resolved
	enabled        bool
	entry          state.Instance
	inState        bool
}

func (h *Hub) targetLocked(id string) (*target, bool) {
	tg := &target{id: id, enabled: h.st.IsEnabled(id)}
	tg.entry, tg.inState = h.st.Instances[id]
	if v := h.findLocked(id); v != nil {
		c := *v
		tg.view = &c
		tg.templateID = v.TemplateID
	} else if tg.inState {
		tg.templateID = tg.entry.Template
	} else {
		tg.templateID = id
	}
	_, published := h.st.Published[id]
	_, broken := h.brokenInstances[id]
	return tg, tg.view != nil || tg.inState || tg.enabled || published || broken
}

// instanceConfigLocked is config/instance.yaml of tg. Caller must hold mu.
func (h *Hub) instanceConfigLocked(tg *target) instanceConfig {
	id := tg.id
	c := instanceConfig{ID: id, Template: tg.templateID, Default: id == tg.templateID, Enabled: tg.enabled}
	switch {
	case tg.view != nil:
		c.Hosts = copyMap(tg.view.Hosts)
	case len(tg.entry.Hosts) > 0:
		c.Hosts = copyMap(tg.entry.Hosts)
	}
	if s, ok := h.st.Settings[id]; ok {
		cs := s.Clone()
		c.Settings = &cs
	}
	if p, ok := h.st.AuthPolicies[id]; ok {
		p.Factors = append([]string(nil), p.Factors...)
		c.AuthPolicy = &p
	}
	if v, ok := h.st.PublicAccess[id]; ok {
		c.PublicAccess = &v
	}
	c.PublicMode = h.st.PublicMode[id]
	c.PublicTokens = append([]string(nil), h.st.PublicTokens[id]...)
	c.SignIn = h.st.SignIn[id]
	if tg.entry.State == state.InstanceCreated {
		c.State = state.InstanceCreated
	}
	if p, ok := h.st.Published[id]; ok {
		c.Published = &p
	}
	return c
}

// applyConfigLocked writes c's per-instance settings into state for id
// (hostnames, enabled and published snapshot are not touched). Caller
// must hold mu (write).
func (h *Hub) applyConfigLocked(id string, c instanceConfig) {
	if c.Settings != nil && !c.Settings.IsZero() {
		h.st.Settings[id] = c.Settings.Clone()
	} else {
		delete(h.st.Settings, id)
	}
	old, had := h.st.AuthPolicies[id]
	if c.AuthPolicy != nil {
		// Stored like SaveSettings stores it (never weaker).
		h.st.AuthPolicies[id] = policy.Normalize(*c.AuthPolicy)
	} else {
		delete(h.st.AuthPolicies, id)
	}
	if now, has := h.st.AuthPolicies[id]; had != has || !reflect.DeepEqual(old, now) {
		delete(h.st.LegacyPassword, id)
	}
	if c.PublicAccess != nil {
		h.st.PublicAccess[id] = *c.PublicAccess
	} else {
		delete(h.st.PublicAccess, id)
	}
	if c.PublicMode != "" {
		h.st.PublicMode[id] = c.PublicMode
	} else {
		delete(h.st.PublicMode, id)
	}
	if len(c.PublicTokens) > 0 {
		h.st.PublicTokens[id] = append([]string(nil), c.PublicTokens...)
	} else {
		delete(h.st.PublicTokens, id)
	}
	if c.SignIn != "" {
		h.st.SignIn[id] = c.SignIn
	} else {
		delete(h.st.SignIn, id)
	}
}

// projectVolumes are the volumes compose created for instance id's
// project, by volume key (compose labels them; external volumes aren't
// the instance's and carry no label).
func (h *Hub) projectVolumes(ctx context.Context, id string) (map[string]docker.Volume, error) {
	vs, err := h.engine.ListVolumes(ctx, docker.Filters{"label": {docker.LabelProject + "=" + projectName(id)}})
	if err != nil {
		return nil, err
	}
	out := map[string]docker.Volume{}
	for _, v := range vs {
		if v.Labels[docker.LabelProject] != projectName(id) {
			continue
		}
		// The Hub's secrets volume is never an instance's (contract §11.5):
		// never archived, replaced or removed, whatever its labels say.
		if v.Name == h.cfg.SecretsVolume {
			log.Printf("WARNING: volume %s carries the project label of %s: it is the Hub's secrets volume and is left out", v.Name, projectName(id))
			continue
		}
		key := v.Labels[docker.LabelVolume]
		if !volumeKeyRe.MatchString(key) {
			return nil, fmt.Errorf("volume %s of %s has no valid %s label", v.Name, projectName(id), docker.LabelVolume)
		}
		if o, dup := out[key]; dup {
			return nil, fmt.Errorf("volumes %s and %s both claim key %s of %s", o.Name, v.Name, key, projectName(id))
		}
		out[key] = v
	}
	return out, nil
}

// projectRunning reports whether any container of id's project runs.
func (h *Hub) projectRunning(ctx context.Context, id string) (bool, error) {
	cs, err := h.engine.ListContainers(ctx, docker.ProjectFilter(projectName(id)))
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.Project() == projectName(id) && (c.State == "running" || c.State == "restarting" || c.State == "paused") {
			return true, nil
		}
	}
	return false, nil
}

// BackupInstance backs instance id up now (reason manual, §11.5): a
// running instance is stopped while its volumes are copied and started
// again. Audited as instance.backup. Errors: 404 unknown, 409 deleting /
// busy / can't be restarted, 503 Docker unavailable, 500 otherwise (the
// archive isn't written; a failed restart after a written backup is an
// OpError that names the archive). StartBackup's operation run to its
// end (runOpSync: the same lock, record, steps and Stop).
func (h *Hub) BackupInstance(id string, actor directory.Actor) (entry *BackupEntry, err error) {
	_, _, err = h.runOpSync(id, OpBackup, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		var berr error
		entry, berr = h.backupInstance(ctx, id, actor, ready)
		if entry != nil {
			return map[string]string{"archive": entry.Archive}, nil, berr
		}
		return nil, nil, berr
	})
	return entry, err
}

// backupInstance is the manual backup StartBackup and BackupInstance
// run: ready is called once the request is accepted (lock held, instance
// found, Docker available) and the backup itself starts (StartBackup
// answers 202 then); a Stop accepted before the archive's rename runs
// its undo (settleOp: the partial archive deleted, the app started again
// if it ran).
func (h *Hub) backupInstance(ctx context.Context, id string, actor directory.Actor, ready func()) (entry *BackupEntry, err error) {
	defer func() {
		detail := ""
		if entry != nil {
			detail = "archive=" + entry.Archive
		}
		h.auditOp(actor, "instance.backup", id, detail, err)
	}()
	unlock, err := h.lockApp(id)
	if err != nil {
		return nil, h.busyErr(id, err)
	}
	defer unlock()
	// lockApp → aiLock (G35, 13a carry): no mint or revoke runs a hook
	// while the backup stops and copies the app.
	defer h.lifecycleAILock(id)()
	if err := h.pending(id); err != nil {
		return nil, err
	}
	h.mu.RLock()
	_, ok := h.targetLocked(id)
	h.mu.RUnlock()
	if !ok {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	if h.engine == nil {
		return nil, statusErr(503, "Docker is not available: cannot back up %s", id)
	}
	ready()
	p := progressFrom(ctx)
	entry, err = h.backupCtx(ctx, id, BackupManual, false)
	if serr := h.settleOp(id, OpBackup, p, err); serr != err {
		return nil, serr
	}
	return entry, err
}

// Backup step keys (contract §11.7 "Steps per operation"): stop, one
// volume:<key> per volume, archive, start.
const (
	StepArchive      = "archive"
	StepVolumePrefix = "volume:"
)

// beforeRunning: the op record's Before key saying whether the project
// ran when the backup started ("true" / "false"; a Stop starts it again).
const beforeRunning = "running"

// beforeStopped: the op record's Before key set ("true") right before
// the operation's backup takes the running project down: only then does
// a Stop start it again.
const beforeStopped = "stopped"

// backupLocked is backupCtx without a reporter or a Stop.
func (h *Hub) backupLocked(id, reason string, keepStopped bool) (*BackupEntry, error) {
	return h.backupCtx(context.Background(), id, reason, keepStopped)
}

// backupCtx writes a backup of id (caller holds its app lock). A running
// instance is stopped first; it is started again afterwards unless
// keepStopped (delete, restore) — after a failure always, so a failed
// backup leaves the instance as it was — except after a Stop (ctx
// cancelled): the archive isn't written and the Stop's undo starts it.
// Whether it ran is the op record's Before "running". A manual backup
// reports its own steps (stop, volume:<key>, archive, start) into ctx's
// reporter and closes its Stop gate right before the archive's rename
// (its commit); a delete's or restore's is one step of theirs.
func (h *Hub) backupCtx(ctx context.Context, id, reason string, keepStopped bool) (*BackupEntry, error) {
	op := progressFrom(ctx)
	var p *Progress // the backup's own steps: a manual backup's only
	if reason == BackupManual {
		p = op
	}
	h.mu.RLock()
	tg, ok := h.targetLocked(id)
	cfg := h.instanceConfigLocked(tg)
	aiCfg := h.aiArchiveLocked(tg)
	h.mu.RUnlock()
	if !ok {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	if h.engine == nil {
		return nil, statusErr(503, "Docker is not available: cannot back up %s", id)
	}
	vols, err := h.projectVolumes(ctx, id)
	if err != nil {
		return nil, statusErr(503, "cannot list the volumes of %s: %v", id, err)
	}
	running, err := h.projectRunning(ctx, id)
	if err != nil {
		return nil, statusErr(503, "cannot check whether %s runs: %v", id, err)
	}
	op.Before(beforeRunning, strconv.FormatBool(running))
	restart := running && tg.enabled
	if restart && tg.view == nil && !keepStopped {
		return nil, statusErr(409, "instance %s can't be resolved (its template is missing or no longer fits): it would not start again after the backup — delete it, or fix its template first", id)
	}
	keys := sortedVolumeKeys(vols)
	if running {
		p.AddStep(StepStop, "Stopping the app")
	}
	for _, k := range keys {
		p.AddStep(StepVolumePrefix+k, "Copying volume "+k)
	}
	p.AddStep(StepArchive, "Writing the archive")
	if restart && !keepStopped {
		p.AddStep(StepStart, "Starting the app again")
	}
	if len(vols) > 0 {
		if err := h.engine.EnsureImage(ctx, HelperImage); err != nil {
			return nil, statusErr(503, "helper image %s: %v", HelperImage, err)
		}
	}

	dir := filepath.Join(h.backupsDir(), id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, statusErr(500, "backup directory: %v", err)
	}
	os.Chmod(h.backupsDir(), 0700)
	os.Chmod(dir, 0700)
	if err := needFree(dir, 0, "the backup of "+id); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(dir, ".staging-")
	if err != nil {
		return nil, statusErr(500, "backup staging: %v", err)
	}
	defer os.RemoveAll(stage)

	m := &BackupManifest{Version: backupVersion, Instance: id, Template: tg.templateID, Reason: reason,
		Volumes: map[string]string{}, Files: map[string]string{}}
	if tg.view != nil {
		m.TemplateCommit = templateCommit(tg.view.Path)
	}
	inst, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, statusErr(500, "instance config: %v", err)
	}
	add := func(member string, data []byte) error {
		p := filepath.Join(stage, filepath.FromSlash(member))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		m.Files[member] = hex.EncodeToString(sum[:])
		return nil
	}
	if err := add("config/instance.yaml", inst); err != nil {
		return nil, statusErr(500, "backup: %v", err)
	}
	if aiCfg != nil {
		if err := add(aiMember, aiCfg); err != nil {
			return nil, statusErr(500, "backup: %v", err)
		}
	}
	// Secret settings are in config/settings-secrets.json only: their
	// env variables are blanked in config/env (a restore writes them
	// from the store again).
	// With a view, matching by value only blanks variables the template
	// doesn't declare (lines an update left behind); without one, any.
	var secretEnv, declared map[string]bool
	if tg.view != nil {
		secretEnv = secretOptionEnvNames(tg.view)
		declared = declaredEnvNames(tg.view)
	}
	secrets, err := h.secretValues(id)
	if err != nil {
		return nil, statusErr(500, "backup: %v", err)
	}
	if len(secrets) > 0 {
		data, err := json.MarshalIndent(secrets, "", "  ")
		if err == nil {
			err = add(secretsMember, data)
		}
		if err != nil {
			return nil, statusErr(500, "backup %s failed", secretsMember)
		}
	}
	for member, src := range map[string]string{"config/env": h.envPath(id), "config/override.yml": h.overridePath(id), "config/user.yml": h.userOverridePath(id)} {
		data, err := os.ReadFile(src)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			if member == "config/env" {
				data = blankEnvNamesExcept(data, withProviderVars(secretEnv, data), secrets, declared)
			}
			err = add(member, data)
		}
		if err != nil {
			return nil, statusErr(500, "backup %s: %v", member, err)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err // stopped before anything was stopped
	}
	if running {
		p.Start(StepStop)
		op.Before(beforeStopped, "true")
		if err := h.stopProject(tg); err != nil {
			err = statusErr(500, "stopping %s for the backup failed (nothing was written): %v", id, err)
			p.Fail(StepStop, err)
			return nil, err
		}
		p.Done(StepStop)
	}
	// The commit gate (a manual backup's): a Stop accepted before the
	// rename is undone (the partial archive deleted), none is accepted
	// after it.
	commit := func() bool { return ctx.Err() == nil && p.CloseStop() }
	entry, err := h.writeBackup(ctx, p, id, dir, stage, m, vols, commit)
	if err != nil && (ctx.Err() != nil || p.Stopping()) {
		// Stopped: nothing written; the Stop's undo starts it again.
		return nil, fmt.Errorf("%v: %w", err, context.Canceled)
	}
	if err != nil || (!keepStopped && restart) {
		if restart {
			p.Start(StepStart)
			if rerr := h.startAgain(tg.view); rerr != nil {
				if err == nil {
					err = fmt.Errorf("the backup %s was written, but starting %s again failed: %w", entry.Archive, id, rerr)
				} else {
					err = fmt.Errorf("%w — and starting %s again failed: %v", err, id, rerr)
				}
				p.Fail(StepStart, rerr)
				// The operation's own outcome (every caller runs inside
				// one: a manual backup, a delete's or restore's
				// pre-backup): never a separate record over its running
				// one. An OpError, so a written archive stays the
				// result.
				return entry, &OpError{Record: h.opRecordOf(id, OpBackup, err, false), Err: err}
			}
			p.Done(StepStart)
		}
	}
	if err != nil {
		return nil, err
	}
	log.Printf("instance %s: backup %s written (%s)", id, entry.Archive, reason)
	return entry, nil
}

// stopProject stops tg's project (compose down, volumes kept), by name
// when its files don't work.
func (h *Hub) stopProject(tg *target) error {
	var downErr error
	if tg.view == nil {
		// composeDown waits otherwise (N4: once per down).
		h.awaitDelivery(tg.id)
	}
	if tg.view != nil {
		downErr = h.composeDown(tg.view)
		if downErr == nil {
			return nil
		}
	}
	if err := h.compose.DownByName(context.Background(), projectName(tg.id)); err != nil {
		if downErr != nil {
			return downErr
		}
		return err
	}
	return nil
}

// startAgain brings a stopped instance back up (rolled back if compose
// fails, like enable).
func (h *Hub) startAgain(t *templates.Template) error {
	if t == nil {
		return errors.New("its template can't be resolved")
	}
	if err := h.composeUp(context.Background(), t); err != nil {
		if !composeFailed(err) {
			return err
		}
		if rb := h.rollbackUp(t); rb != nil {
			return fmt.Errorf("compose up failed: %w — rolling back failed too: %v", err, rb)
		}
		return fmt.Errorf("compose up failed: %w", err)
	}
	return nil
}

// writeBackup copies the volumes into stage and assembles the archive,
// reporting each volume:<key> step and the archive step into p (nil:
// none). commit is called right before the archive's rename: false (a
// Stop) leaves no archive.
func (h *Hub) writeBackup(ctx context.Context, p *Progress, id, dir, stage string, m *BackupManifest, vols map[string]docker.Volume, commit func() bool) (*BackupEntry, error) {
	for _, k := range sortedVolumeKeys(vols) {
		key := StepVolumePrefix + k
		member := "volumes/" + k + ".tar"
		dst := filepath.Join(stage, "volumes", k+".tar")
		os.MkdirAll(filepath.Dir(dst), 0700)
		p.Start(key)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var copied int64
		sum, err := h.copyVolumeOut(ctx, id, vols[k].Name, dst, func(n int64) {
			copied = n
			p.DetailThrottled(key, mib(n)+" copied")
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			err = statusErr(500, "backup of volume %s failed (no archive written): %v", vols[k].Name, err)
			p.Fail(key, err)
			return nil, err
		}
		p.Detail(key, mib(copied)+" copied")
		p.Done(key)
		m.Volumes[k] = vols[k].Name
		m.Files[member] = sum
	}
	p.Start(StepArchive)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Assembling copies the staged members once more.
	if err := needFree(dir, dirSize(stage), "the backup archive of "+id); err != nil {
		p.Fail(StepArchive, err)
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	var final string
	for i := 0; ; i++ {
		final = filepath.Join(dir, now.Format(backupTimeFmt)+".tar")
		if _, err := os.Lstat(final); errors.Is(err, os.ErrNotExist) {
			break
		}
		if i > 120 {
			return nil, statusErr(409, "a backup of %s was just written: try again", id)
		}
		now = now.Add(time.Second)
	}
	m.CreatedAt = now
	if err := assembleArchive(final, stage, m, commit); err != nil {
		if errors.Is(err, errUncommitted) {
			return nil, context.Canceled
		}
		err = statusErr(500, "writing the backup archive failed: %v", err)
		p.Fail(StepArchive, err)
		return nil, err
	}
	fi, err := os.Stat(final)
	if err != nil {
		return nil, statusErr(500, "backup archive: %v", err)
	}
	p.Detail(StepArchive, id+"/"+filepath.Base(final))
	p.Done(StepArchive)
	return &BackupEntry{Archive: id + "/" + filepath.Base(final), Instance: id, Template: m.Template,
		CreatedAt: m.CreatedAt, Reason: m.Reason, Size: fi.Size(), InstanceExists: true}, nil
}

// errUncommitted: assembleArchive's commit said no (a Stop): the partial
// archive was removed, nothing renamed.
var errUncommitted = errors.New("the archive was not committed")

// mib is n bytes as "12.3 MB" (1 MB = 2^20 bytes, as the images step).
func mib(n int64) string {
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

// assembleArchive writes final (via final.partial + rename): MANIFEST.json
// first, then every member of m.Files from stage, sorted by path. commit
// (nil: always) is asked right before the rename: false removes the
// partial archive and returns errUncommitted.
func assembleArchive(final, stage string, m *BackupManifest, commit func() bool) (err error) {
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := final + ".partial"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	tw := tar.NewWriter(f)
	hdr := func(name string, size int64) *tar.Header {
		return &tar.Header{Name: name, Mode: 0600, Size: size, ModTime: m.CreatedAt, Typeflag: tar.TypeReg,
			Uid: os.Getuid(), Gid: os.Getgid(), Format: tar.FormatPAX}
	}
	if err := tw.WriteHeader(hdr(manifestMember, int64(len(mj)))); err != nil {
		return err
	}
	if _, err := tw.Write(mj); err != nil {
		return err
	}
	names := make([]string, 0, len(m.Files))
	for n := range m.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		src, err := os.Open(filepath.Join(stage, filepath.FromSlash(n)))
		if err != nil {
			return err
		}
		fi, err := src.Stat()
		if err == nil {
			err = tw.WriteHeader(hdr(n, fi.Size()))
		}
		if err == nil {
			_, err = io.Copy(tw, src)
		}
		src.Close()
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if commit != nil && !commit() {
		os.Remove(tmp)
		return errUncommitted
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	if d, derr := os.Open(filepath.Dir(final)); derr == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// withHelper runs fn with a helper container mounting volume name at
// helperMount (read-only for backups) and removes it afterwards.
func (h *Hub) withHelper(ctx context.Context, id, name string, readOnly bool, fn func(helper string) error) error {
	hid, err := h.engine.CreateHelper(ctx, docker.HelperSpec{Image: HelperImage, Volumes: map[string]string{name: helperMount}, ReadOnly: readOnly, Instance: id})
	if err != nil {
		return fmt.Errorf("helper container: %w", err)
	}
	defer func() {
		if rerr := h.engine.RemoveContainer(context.WithoutCancel(ctx), hid); rerr != nil {
			log.Printf("instance %s: removing helper container %s: %v", id, hid, rerr)
		}
	}()
	return fn(hid)
}

// copyVolumeOut streams volume name into the file dst (an inner tar) and
// returns its sha256; every entry is checked (checkVolumeEntry). count
// (nil: none) gets the bytes copied so far; a cancelled ctx ends the
// copy at once.
func (h *Hub) copyVolumeOut(ctx context.Context, id, name, dst string, count func(int64)) (string, error) {
	var sum string
	err := h.withHelper(ctx, id, name, true, func(hid string) error {
		rc, err := h.engine.CopyFromContainer(ctx, hid, helperMount)
		if err != nil {
			return err
		}
		defer rc.Close()
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		hash := sha256.New()
		tee := io.TeeReader(&ctxReader{ctx: ctx, r: rc, count: count}, io.MultiWriter(f, hash))
		tr := tar.NewReader(tee)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("reading the volume archive: %w", err)
			}
			if err := checkVolumeEntry(hdr); err != nil {
				return err
			}
		}
		if _, err := io.Copy(io.Discard, tee); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		sum = hex.EncodeToString(hash.Sum(nil))
		return f.Close()
	})
	return sum, err
}

// ctxReader reads r until ctx is cancelled (then ctx's error), telling
// count (nil: nobody) the bytes read so far.
type ctxReader struct {
	ctx   context.Context
	r     io.Reader
	count func(int64)
	n     int64
}

func (c *ctxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(b)
	c.n += int64(n)
	if n > 0 && c.count != nil {
		c.count(c.n)
	}
	return n, err
}

// checkVolumeEntry accepts the entries of a volume archive: under "data"
// (the helper's mount, base name of the archived path), no "..", regular
// files, directories, symlinks, hard links within the volume and FIFOs.
func checkVolumeEntry(hdr *tar.Header) error {
	inVolume := func(n string) bool {
		c := path.Clean("/" + strings.TrimPrefix(n, "./"))
		return (c == helperMount || strings.HasPrefix(c, helperMount+"/")) && !strings.Contains(n, "..")
	}
	if !inVolume(hdr.Name) {
		return fmt.Errorf("volume archive entry %q is outside the volume", hdr.Name)
	}
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeFifo:
	case tar.TypeLink:
		if !inVolume(hdr.Linkname) {
			return fmt.Errorf("volume archive entry %q links outside the volume", hdr.Name)
		}
	default:
		return fmt.Errorf("volume archive entry %q has unsupported type %q", hdr.Name, hdr.Typeflag)
	}
	return nil
}

// templateCommit is the git commit of the template's checkout ("" if
// unknown).
func templateCommit(dir string) string {
	if dir == "" {
		return ""
	}
	out, err := runGit(10*time.Second, "-C", dir, "rev-parse", "HEAD")
	if s := strings.TrimSpace(string(out)); err == nil && regexp.MustCompile(`^[0-9a-f]{40,64}$`).MatchString(s) {
		return s
	}
	return ""
}

// ── listing ──────────────────────────────────────────────

// ListBackups lists the archives under <data>/backups (instance "" =
// every instance, deleted ones included), newest first (§11.7).
// Unreadable archives are logged and left out.
func (h *Hub) ListBackups(instance string) ([]BackupEntry, error) {
	if instance != "" && !templates.ValidID(instance) {
		return nil, statusErr(400, "invalid instance id %q", instance)
	}
	dirs, err := os.ReadDir(h.backupsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []BackupEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []BackupEntry{}
	for _, d := range dirs {
		if !d.IsDir() || (instance != "" && d.Name() != instance) || !templates.ValidID(d.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(h.backupsDir(), d.Name()))
		if err != nil {
			log.Printf("backups: %v", err)
			continue
		}
		for _, f := range files {
			rel := d.Name() + "/" + f.Name()
			if !f.Type().IsRegular() || !archiveRe.MatchString(rel) {
				continue
			}
			p := filepath.Join(h.backupsDir(), d.Name(), f.Name())
			m, err := readManifest(p)
			if err != nil || m.Instance != d.Name() {
				log.Printf("backups: %s is unreadable, not listed: %v", rel, err)
				continue
			}
			fi, err := f.Info()
			if err != nil {
				continue
			}
			out = append(out, BackupEntry{Archive: rel, Instance: m.Instance, Template: m.Template, CreatedAt: m.CreatedAt, Reason: m.Reason, Size: fi.Size()})
		}
	}
	h.mu.RLock()
	for i := range out {
		e, inState := h.st.Instances[out[i].Instance]
		_, ok := h.targetLocked(out[i].Instance)
		out[i].InstanceExists = ok && !(inState && e.State == state.InstanceDeleting)
	}
	h.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Archive > out[j].Archive
	})
	return out, nil
}

// readManifest reads and validates the first member of an archive.
func readManifest(p string) (*BackupManifest, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, _, err := nextManifest(tar.NewReader(f))
	return m, err
}

func nextManifest(tr *tar.Reader) (*BackupManifest, []byte, error) {
	hdr, err := tr.Next()
	if err != nil {
		return nil, nil, fmt.Errorf("not a tar archive: %w", err)
	}
	if hdr.Name != manifestMember || hdr.Typeflag != tar.TypeReg || hdr.Size > maxManifestSize {
		return nil, nil, fmt.Errorf("the first member must be %s (≤ 1 MiB)", manifestMember)
	}
	data, err := io.ReadAll(io.LimitReader(tr, maxManifestSize))
	if err != nil {
		return nil, nil, err
	}
	var m BackupManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", manifestMember, err)
	}
	if err := m.validate(); err != nil {
		return nil, nil, err
	}
	return &m, data, nil
}

// validate checks the manifest's shape (not the members).
func (m *BackupManifest) validate() error {
	if m.Version != backupVersion {
		return fmt.Errorf("%s: unsupported version %d", manifestMember, m.Version)
	}
	if !templates.ValidID(m.Instance) || !templates.ValidID(m.Template) {
		return fmt.Errorf("%s: invalid instance or template id", manifestMember)
	}
	switch m.Reason {
	case BackupManual, BackupDelete, BackupRestore:
	default:
		return fmt.Errorf("%s: invalid reason %q", manifestMember, m.Reason)
	}
	if _, ok := m.Files["config/instance.yaml"]; !ok {
		return fmt.Errorf("%s: config/instance.yaml is not listed", manifestMember)
	}
	for name, sum := range m.Files {
		if !sha256Re.MatchString(sum) {
			return fmt.Errorf("%s: bad sha256 for %s", manifestMember, name)
		}
		switch name {
		case "config/instance.yaml", "config/env", "config/override.yml", "config/user.yml", secretsMember, aiMember:
			continue
		}
		key, ok := strings.CutPrefix(name, "volumes/")
		key, ok2 := strings.CutSuffix(key, ".tar")
		if !ok || !ok2 || !volumeKeyRe.MatchString(key) {
			return fmt.Errorf("%s: unexpected member %q", manifestMember, name)
		}
		if _, ok := m.Volumes[key]; !ok {
			return fmt.Errorf("%s: volume %s has no source volume name", manifestMember, key)
		}
	}
	for key, name := range m.Volumes {
		if _, ok := m.Files["volumes/"+key+".tar"]; !ok || !volumeKeyRe.MatchString(key) || name == "" {
			return fmt.Errorf("%s: volume %s is not in the archive", manifestMember, key)
		}
	}
	return nil
}

// ── verification and staging (restore) ────────────────────

// staged is a verified archive unpacked under <data>/backups/.staging.
type staged struct {
	archive string
	dir     string
	m       *BackupManifest
	cfg     instanceConfig
	env     []byte            // nil: no config/env
	user    []byte            // nil: no config/user.yml
	secrets []byte            // nil: no config/settings-secrets.json
	volumes map[string]string // key → staged inner tar
	// ai: config/ai.json (nil: none); aiErr: it didn't decode (the
	// restore turns AI off with a warning, never refuses: §11.6).
	ai    *aiArchive
	aiErr error
}

func (s *staged) cleanup() {
	if s != nil && s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

// stageArchive verifies archive (relative to <data>/backups) before
// anything is touched — MANIFEST.json first and valid, every member
// listed exactly once with a matching sha256, nothing unlisted, every
// volume archive's entries inside the volume, config/instance.yaml
// naming the same instance and template — and unpacks it into a staging
// directory. 400 bad name, 404 missing, 409 anything that doesn't verify.
func (h *Hub) stageArchive(archive string) (*staged, error) {
	return h.stageArchiveCtx(context.Background(), archive, nil)
}

// stageArchiveCtx is stageArchive; report (nil: none) gets the bytes of
// the archive read (checked) so far and its size, and a cancelled ctx
// ends it (nothing staged).
func (h *Hub) stageArchiveCtx(ctx context.Context, archive string, report func(done, total int64)) (*staged, error) {
	mm := archiveRe.FindStringSubmatch(archive)
	if mm == nil {
		return nil, statusErr(400, "archive must be <instance-id>/<YYYYMMDDTHHMMSSZ>.tar, relative to the backups directory")
	}
	p := filepath.Join(h.backupsDir(), filepath.FromSlash(archive))
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, statusErr(404, "archive %s not found", archive)
	}
	if !fi.Mode().IsRegular() {
		return nil, statusErr(409, "archive %s is not a regular file", archive)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, statusErr(500, "archive %s: %v", archive, err)
	}
	defer f.Close()
	var count func(int64)
	if report != nil {
		count = func(n int64) { report(n, fi.Size()) }
	}
	tr := tar.NewReader(&ctxReader{ctx: ctx, r: f, count: count})
	m, _, err := nextManifest(tr)
	if err != nil {
		return nil, statusErr(409, "archive %s refused: %v", archive, err)
	}
	if m.Instance != mm[1] {
		return nil, statusErr(409, "archive %s refused: its manifest names instance %s", archive, m.Instance)
	}
	root := filepath.Join(h.backupsDir(), ".staging")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, statusErr(500, "staging: %v", err)
	}
	dir, err := os.MkdirTemp(root, "restore-")
	if err != nil {
		return nil, statusErr(500, "staging: %v", err)
	}
	s := &staged{archive: archive, dir: dir, m: m, volumes: map[string]string{}}
	if err := s.unpack(tr); err != nil {
		s.cleanup()
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, statusErr(409, "archive %s refused (nothing was changed): %v", archive, err)
	}
	return s, nil
}

func (s *staged) unpack(tr *tar.Reader) error {
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("corrupt archive: %w", err)
		}
		want, listed := s.m.Files[hdr.Name]
		switch {
		case !listed:
			return fmt.Errorf("member %q is not listed in %s", hdr.Name, manifestMember)
		case seen[hdr.Name]:
			return fmt.Errorf("member %q appears twice", hdr.Name)
		case hdr.Typeflag != tar.TypeReg:
			return fmt.Errorf("member %q is not a regular file", hdr.Name)
		case strings.HasPrefix(hdr.Name, "config/") && hdr.Size > maxConfigSize:
			return fmt.Errorf("member %q is too large", hdr.Name)
		}
		seen[hdr.Name] = true
		dst := filepath.Join(s.dir, fmt.Sprintf("m%d", len(seen)))
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, err = io.Copy(io.MultiWriter(out, hash), tr)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("member %q: %w", hdr.Name, err)
		}
		if got := hex.EncodeToString(hash.Sum(nil)); got != want {
			return fmt.Errorf("checksum mismatch for %s", hdr.Name)
		}
		if key, ok := strings.CutPrefix(hdr.Name, "volumes/"); ok {
			s.volumes[strings.TrimSuffix(key, ".tar")] = dst
			continue
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		switch hdr.Name {
		case "config/instance.yaml":
			var probe struct {
				ID       string    `yaml:"id"`
				Settings yaml.Node `yaml:"settings"`
			}
			if yaml.Unmarshal(data, &probe) == nil && state.IsLegacySettings(&probe.Settings) {
				return fmt.Errorf("config/instance.yaml: the settings of instance %s are in the old flat form (before contract v3): this archive can't be restored by this Hub (settings are not migrated)", probe.ID)
			}
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			if err := dec.Decode(&s.cfg); err != nil {
				return fmt.Errorf("config/instance.yaml: %w", err)
			}
		case "config/env":
			s.env = data
		case "config/user.yml":
			s.user = data
		case aiMember:
			s.ai, s.aiErr = parseAIArchive(data)
		case secretsMember:
			if _, err := parseSecrets(data); err != nil {
				return fmt.Errorf("%s: %w", secretsMember, err)
			}
			s.secrets = data
		}
	}
	for name := range s.m.Files {
		if !seen[name] {
			return fmt.Errorf("member %s is missing", name)
		}
	}
	if s.cfg.ID != s.m.Instance || s.cfg.Template != s.m.Template {
		return fmt.Errorf("config/instance.yaml names %s of %s, the manifest %s of %s", s.cfg.ID, s.cfg.Template, s.m.Instance, s.m.Template)
	}
	for key, p := range s.volumes {
		if err := checkVolumeArchive(p); err != nil {
			return fmt.Errorf("volumes/%s.tar: %w", key, err)
		}
	}
	return nil
}

func checkVolumeArchive(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := checkVolumeEntry(hdr); err != nil {
			return err
		}
	}
}

// fillVolume makes volume name hold exactly the staged inner tar: an
// existing volume is removed and created again with the same driver,
// labels and options (only plain local volumes — checked before), a
// missing one is created with labels; then the daemon extracts the tar
// at "/" of a never-started helper mounting it at helperMount (owners,
// modes, mtimes and the volume root's own metadata as archived).
func (h *Hub) fillVolume(ctx context.Context, id string, v docker.Volume, existed bool, tarPath string) (created bool, err error) {
	return h.fillVolumeWith(ctx, id, v, existed, tarPath, fillOpts{})
}

// fillOpts are fillVolumeWith's reporting hooks (each may be nil):
// created gets the volume's name the moment it was created (a restore
// into a new id's ledger), count the bytes of the inner tar sent so far.
type fillOpts struct {
	created func(name string)
	count   func(n int64)
}

// fillVolumeWith is fillVolume with o's hooks; a cancelled ctx ends the
// upload at once.
func (h *Hub) fillVolumeWith(ctx context.Context, id string, v docker.Volume, existed bool, tarPath string, o fillOpts) (created bool, err error) {
	if existed {
		if err := h.engine.RemoveVolume(ctx, v.Name); err != nil && !docker.IsNotFound(err) {
			return false, fmt.Errorf("emptying volume %s: %w", v.Name, err)
		}
	} else {
		// Creating an existing volume is a no-op for Docker: it must
		// really be new (nobody else's appeared meanwhile).
		if old, err := h.engine.InspectVolume(ctx, v.Name); err == nil {
			return false, fmt.Errorf("volume %s appeared meanwhile (labels %v): not touching it", old.Name, old.Labels)
		} else if !docker.IsNotFound(err) {
			return false, fmt.Errorf("volume %s: %w", v.Name, err)
		}
	}
	if err := h.engine.CreateVolume(ctx, v); err != nil {
		return false, fmt.Errorf("creating volume %s: %w", v.Name, err)
	}
	if o.created != nil && !existed {
		o.created(v.Name)
	}
	got, err := h.engine.InspectVolume(ctx, v.Name)
	if err != nil {
		return false, fmt.Errorf("volume %s after creating it: %w", v.Name, err)
	}
	if got.Labels[docker.LabelProject] != v.Labels[docker.LabelProject] || got.Labels[docker.LabelVolume] != v.Labels[docker.LabelVolume] {
		return false, fmt.Errorf("volume %s is not the one created for %s (labels %v): not touching it", v.Name, v.Labels[docker.LabelProject], got.Labels)
	}
	if tarPath == "" {
		return true, nil
	}
	return true, h.withHelper(ctx, id, v.Name, false, func(hid string) error {
		f, err := os.Open(tarPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := h.engine.CopyToContainer(ctx, hid, "/", &ctxReader{ctx: ctx, r: f, count: o.count}); err != nil {
			return fmt.Errorf("restoring volume %s: %w", v.Name, err)
		}
		return nil
	})
}

// freeMargin is the free space a backup or restore leaves on the data
// volume at least.
const freeMargin = 64 << 20

// freeSpace returns the bytes available to the Hub on dir's filesystem
// (a var for tests).
var freeSpace = func(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// needFree refuses (507) when dir's filesystem has less than need bytes
// plus freeMargin available.
func needFree(dir string, need int64, what string) error {
	avail, err := freeSpace(dir)
	if err != nil {
		return statusErr(500, "checking free space for %s: %v", what, err)
	}
	if need < 0 {
		need = 0
	}
	if avail < uint64(need)+freeMargin {
		return statusErr(507, "not enough free space for %s: %d MiB available, %d MiB needed (plus a %d MiB margin) on the Hub's data volume — free some space (old backups under <data>/backups) and try again",
			what, avail>>20, need>>20, freeMargin>>20)
	}
	return nil
}

// checkFree is needFree for staging the archive at p (its size).
func (h *Hub) checkFree(p, what string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return nil // stageArchive answers 404
	}
	return needFree(h.backupsDir(), fi.Size(), what)
}

// dirSize sums the regular files under dir.
func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// SweepBackupLeftovers removes what an interrupted backup, restore or
// shared-folder fixer run left behind: helper containers (LabelHelper:
// volume helpers and fixers, "folder:<id>" / "path-check" — a fixer still
// running when the Hub stopped is killed with it), staging directories and
// .partial archives. Init calls it before anything can start one.
func (h *Hub) SweepBackupLeftovers() {
	if h.engine != nil {
		cs, err := h.engine.ListContainers(context.Background(), docker.Filters{"label": {docker.LabelHelper}})
		if err != nil {
			log.Printf("backups: cannot list leftover helper containers: %v", err)
		}
		for _, c := range cs {
			if err := h.engine.RemoveContainer(context.Background(), c.ID); err != nil {
				log.Printf("backups: removing leftover helper container %s: %v", c.Name(), err)
			} else {
				log.Printf("backups: removed leftover helper container %s", c.Name())
			}
		}
	}
	os.RemoveAll(filepath.Join(h.backupsDir(), ".staging"))
	dirs, _ := os.ReadDir(h.backupsDir())
	for _, d := range dirs {
		if !d.IsDir() || !templates.ValidID(d.Name()) {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(h.backupsDir(), d.Name()))
		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".staging-") || strings.HasSuffix(f.Name(), ".tar.partial") {
				p := filepath.Join(h.backupsDir(), d.Name(), f.Name())
				if err := os.RemoveAll(p); err == nil {
					log.Printf("backups: removed leftover %s", p)
				}
			}
		}
	}
}

// plainVolume reports whether v can be emptied by removing and creating
// it again (a local volume without driver options: no bind or NFS device
// whose data would survive the remove).
func plainVolume(v docker.Volume) bool {
	return (v.Driver == "" || v.Driver == "local") && len(v.Options) == 0
}

// writeOrRemove writes data to p (0600), or removes p when data is nil.
func writeOrRemove(p string, data []byte) error {
	if data == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return fsutil.WriteFileAtomic(p, data, 0600)
}
