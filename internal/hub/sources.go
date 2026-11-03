package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// DefaultSourceName is the auto-cloned marketplace; it cannot be removed.
const DefaultSourceName = "portcullis"

var sourceURLRe = regexp.MustCompile(`^(https?://[^\s]+|ssh://[^\s]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+)$`)

// ValidSourceURL reports whether u is an accepted git URL. It never starts
// with "-" (no option injection into git).
func ValidSourceURL(u string) bool { return sourceURLRe.MatchString(u) }

func runGit(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.WaitDelay = 5 * time.Second
	// Never prompt for credentials on a TTY-less server.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.CombinedOutput()
}

func (h *Hub) autoLoadDefaultTemplates() {
	if h.cfg.DefaultTemplatesURL == "" || len(h.Sources()) > 0 {
		return
	}
	log.Printf("First run: cloning default templates from %s", h.cfg.DefaultTemplatesURL)
	if err := h.AddSource(DefaultSourceName, h.cfg.DefaultTemplatesURL); err != nil {
		log.Printf("Warning: could not clone default templates: %v", err)
	} else {
		log.Println("Default templates loaded successfully")
	}
}

// AddSource clones a template repository and adds it to the catalog.
func (h *Hub) AddSource(name, repoURL string) error {
	if !templates.ValidID(name) {
		return statusErr(400, "invalid source name (use lowercase letters, digits, - and _)")
	}
	if !ValidSourceURL(repoURL) {
		return statusErr(400, "invalid source URL (https://, http://, ssh:// or user@host:path)")
	}
	exists := func() bool {
		for _, s := range h.st.Sources {
			if s.Name == name {
				return true
			}
		}
		return false
	}
	h.mu.RLock()
	dup := exists()
	h.mu.RUnlock()
	if dup {
		return statusErr(400, "source already exists: %s", name)
	}
	if _, busy := h.sourceOps.LoadOrStore(name, struct{}{}); busy {
		return statusErr(409, "source %s is already being added", name)
	}
	defer h.sourceOps.Delete(name)

	repoDir := filepath.Join(h.cfg.DataDir, "repos", name)
	if _, err := os.Stat(repoDir); err == nil {
		return statusErr(400, "directory for source %s already exists", name)
	}
	// Clone without holding mu. "--" stops a URL from being parsed as an option.
	if out, err := runGit(gitTimeout, "clone", "--depth=1", "--", repoURL, repoDir); err != nil {
		os.RemoveAll(repoDir)
		log.Printf("git clone %s: %v: %s", name, err, strings.TrimSpace(string(out)))
		return statusErr(400, "git clone failed: %v", err)
	}

	h.mu.Lock()
	if exists() { // lost a race with a concurrent add
		h.mu.Unlock()
		return statusErr(400, "source already exists: %s", name)
	}
	h.st.Sources = append(h.st.Sources, state.Source{Name: name, URL: repoURL, Path: repoDir})
	h.saveLocked()
	h.mu.Unlock()

	h.Discover()
	h.writePolicyLogged()
	return nil
}

// RemoveSource stops the source's enabled apps, then removes it.
func (h *Hub) RemoveSource(name string) error {
	if name == DefaultSourceName {
		return statusErr(400, "cannot remove the default template source")
	}
	h.mu.RLock()
	var src *state.Source
	for i := range h.st.Sources {
		if h.st.Sources[i].Name == name {
			c := h.st.Sources[i]
			src = &c
		}
	}
	var running []string
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil && t.Source == name {
			running = append(running, id)
		}
	}
	h.mu.RUnlock()
	if src == nil {
		return statusErr(400, "source not found: %s", name)
	}
	// Stop apps while their compose files still exist — deleting the repo
	// first would orphan the containers.
	for _, id := range running {
		if err := h.Disable(id); err != nil {
			return statusErr(400, "could not stop %s before removing source: %v", id, err)
		}
	}
	h.mu.Lock()
	kept := make([]state.Source, 0, len(h.st.Sources))
	for _, s := range h.st.Sources {
		if s.Name != name {
			kept = append(kept, s)
		}
	}
	h.st.Sources = kept
	h.saveLocked()
	h.mu.Unlock()

	if src.Path != "" && fsutil.Within(filepath.Join(h.cfg.DataDir, "repos"), src.Path) {
		os.RemoveAll(src.Path)
	}
	h.Discover()
	return h.WritePolicy()
}

// Source sync (fail-safe): every git source the Hub cloned is
// fast-forwarded (`git pull --ff-only`: a failed fetch or a refused merge
// leaves the checkout as it was — the last good copy keeps serving), the
// catalog is rediscovered, and a source whose new version leaves an
// enabled instance without a (valid) template is reset to the commit it
// had before (`git reset --keep`, local edits kept): an update never takes
// a running app's template away. Nothing here opens access: an enabled
// instance whose template is missing stays denied (fail closed, the
// policy writer's published snapshot) whatever the sync's outcome.
//
// The outcome is the SourceSyncStatus, kept in memory and in
// <data>/source-sync.json (core's `./portcullis upgrade` reads it there:
// the Hub syncs at start and on SIGHUP, upgrading.md).

// Sync triggers.
const (
	SyncStartup = "startup"
	SyncSignal  = "signal"
	SyncAPI     = "api"
)

// StartupSyncTimeout bounds each git pull of the start-up sync (the Hub
// isn't listening yet; a slow remote must not keep it down for long).
const StartupSyncTimeout = time.Minute

// SourceSyncResult is one source's part of a sync.
type SourceSyncResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Before string `json:"before,omitempty"` // commit before the sync
	After  string `json:"after,omitempty"`  // commit after it (= Before: unchanged or kept)
	// Updated: the checkout moved to a new commit (and kept it).
	Updated bool `json:"updated"`
	// RolledBack: the new commit was reverted (it broke an enabled
	// instance's template, RolledBackFor).
	RolledBack    bool     `json:"rolled_back,omitempty"`
	RolledBackFor []string `json:"rolled_back_for,omitempty"`
	// Error is fixed text (no git output: it may carry a credential URL;
	// the Hub log has the details).
	Error string `json:"error,omitempty"`
}

// SourceSyncStatus is the outcome of the last source sync.
type SourceSyncStatus struct {
	Trigger    string    `json:"trigger"`
	Running    bool      `json:"running"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// StartedUnix / FinishedUnix: the same times in seconds (shell readers).
	StartedUnix  int64              `json:"started_unix"`
	FinishedUnix int64              `json:"finished_unix,omitempty"`
	OK           bool               `json:"ok"`
	Sources      []SourceSyncResult `json:"sources"`
	// MissingTemplates: enabled instances that have no (valid) template
	// after the sync (they stay denied: fail closed).
	MissingTemplates []string `json:"missing_templates,omitempty"`
}

func (h *Hub) sourceSyncPath() string { return filepath.Join(h.cfg.DataDir, "source-sync.json") }

// SourceSync returns the last sync's status (nil: none since start).
func (h *Hub) SourceSync() *SourceSyncStatus {
	h.sourceSyncStMu.Lock()
	defer h.sourceSyncStMu.Unlock()
	if h.sourceSyncSt == nil {
		return nil
	}
	c := *h.sourceSyncSt
	c.Sources = append([]SourceSyncResult(nil), c.Sources...)
	c.MissingTemplates = append([]string(nil), c.MissingTemplates...)
	return &c
}

func (h *Hub) publishSourceSync(st SourceSyncStatus) {
	h.sourceSyncStMu.Lock()
	h.sourceSyncSt = &st
	h.sourceSyncStMu.Unlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = fsutil.WriteFileAtomic(h.sourceSyncPath(), append(data, '\n'), 0600)
	}
	if err != nil {
		log.Printf("sources: writing %s failed: %v", h.sourceSyncPath(), err)
	}
}

// enabledSourcesLocked maps every enabled instance that has a view to its
// template's source. Caller holds mu.
func (h *Hub) enabledSourcesLocked() map[string]string {
	out := map[string]string{}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil {
			out[id] = t.Source
		}
	}
	return out
}

func gitHead(dir string) string {
	out, err := runGit(10*time.Second, "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// syncSources runs one sync (serialised; callers write the policy file).
// timeout bounds each git command.
func (h *Hub) syncSources(trigger string, timeout time.Duration) SourceSyncStatus {
	h.sourceSyncMu.Lock()
	defer h.sourceSyncMu.Unlock()
	now := time.Now().UTC()
	st := SourceSyncStatus{Trigger: trigger, Running: true, StartedAt: now, StartedUnix: now.Unix(), Sources: []SourceSyncResult{}}
	h.publishSourceSync(st)

	h.mu.RLock()
	before := h.enabledSourcesLocked()
	h.mu.RUnlock()

	byName := map[string]int{}
	for _, s := range h.Sources() {
		// Only git checkouts the Hub cloned itself are pulled.
		if s.Path == "" || s.URL == "" {
			continue
		}
		r := SourceSyncResult{Name: s.Name, Before: gitHead(s.Path)}
		if out, err := runGit(timeout, "-C", s.Path, "pull", "--ff-only"); err != nil {
			log.Printf("sync %s: %v: %s", s.Name, err, strings.TrimSpace(string(out)))
			r.Error = "git pull --ff-only failed (unreachable remote, or local edits from Expert mode block the fast-forward; see the Hub log) — the previous version is kept"
		} else {
			r.OK = true
		}
		r.After = gitHead(s.Path)
		r.Updated = r.OK && r.After != "" && r.After != r.Before
		byName[s.Name] = len(st.Sources)
		st.Sources = append(st.Sources, r)
	}
	h.Discover()

	// A new version that takes an enabled instance's template away is
	// reverted: the last good copy keeps serving it.
	h.mu.RLock()
	after := h.enabledSourcesLocked()
	h.mu.RUnlock()
	broke := map[string][]string{}
	for id, src := range before {
		if _, ok := after[id]; !ok {
			broke[src] = append(broke[src], id)
		}
	}
	reverted := false
	for src, ids := range broke {
		i, ok := byName[src]
		if !ok || !st.Sources[i].Updated || st.Sources[i].Before == "" {
			continue
		}
		r := &st.Sources[i]
		sort.Strings(ids)
		var path string
		for _, s := range h.Sources() {
			if s.Name == src {
				path = s.Path
			}
		}
		if out, err := runGit(timeout, "-C", path, "reset", "--keep", r.Before); err != nil {
			log.Printf("sync %s: reverting to %s failed: %v: %s", src, r.Before, err, strings.TrimSpace(string(out)))
			r.OK = false
			r.Error = fmt.Sprintf("the new version has no valid template for enabled %s, and going back to %s failed (see the Hub log) — those apps stay denied until fixed", strings.Join(ids, ", "), short(r.Before))
			continue
		}
		log.Printf("sync %s: the new version %s has no valid template for enabled %s — kept %s", src, short(r.After), strings.Join(ids, ", "), short(r.Before))
		r.OK, r.Updated, r.RolledBack, r.RolledBackFor = false, false, true, ids
		r.Error = fmt.Sprintf("version %s has no valid template for enabled %s (a newer Hub may be needed, or disable them first) — the previous version %s is kept", short(r.After), strings.Join(ids, ", "), short(r.Before))
		r.After = gitHead(path)
		reverted = true
	}
	if reverted {
		h.Discover()
	}
	// Only after the final Discover (a rolled-back update drops nothing).
	h.pruneSettings()

	h.mu.RLock()
	for _, id := range h.st.Enabled {
		if h.findLocked(id) == nil {
			st.MissingTemplates = append(st.MissingTemplates, id)
		}
	}
	h.mu.RUnlock()
	sort.Strings(st.MissingTemplates)
	st.OK = true
	for _, r := range st.Sources {
		if !r.OK {
			st.OK = false
		}
	}
	end := time.Now().UTC()
	st.Running, st.FinishedAt, st.FinishedUnix = false, end, end.Unix()
	h.publishSourceSync(st)
	return st
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// SyncSourcesAs runs a sync (trigger SyncSignal / SyncAPI) and rewrites
// the policy file.
func (h *Hub) SyncSourcesAs(trigger string) SourceSyncStatus {
	st := h.syncSources(trigger, gitTimeout)
	h.writePolicyLogged()
	return st
}

// SyncSources fast-forwards every cloned source and rediscovers templates
// (the API's sync).
func (h *Hub) SyncSources() error {
	st := h.SyncSourcesAs(SyncAPI)
	var failed []string
	for _, r := range st.Sources {
		if !r.OK {
			failed = append(failed, r.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("sync failed for: %s (unreachable remote, local edits from Expert mode blocking the fast-forward, or a version without a template for an enabled app — the previous version is kept; see the Hub log)", strings.Join(failed, ", "))
	}
	return nil
}
