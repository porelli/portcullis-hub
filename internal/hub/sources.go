package hub

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// SyncSources fast-forwards every cloned source and rediscovers templates.
func (h *Hub) SyncSources() error {
	var failed []string
	for _, s := range h.Sources() {
		// Only git checkouts the Hub cloned itself are pulled.
		if s.Path == "" || s.URL == "" {
			continue
		}
		if out, err := runGit(gitTimeout, "-C", s.Path, "pull", "--ff-only"); err != nil {
			log.Printf("sync %s: %v: %s", s.Name, err, strings.TrimSpace(string(out)))
			failed = append(failed, s.Name)
		}
	}
	h.Discover()
	h.writePolicyLogged()
	if len(failed) > 0 {
		return fmt.Errorf("sync failed for: %s (local edits from Expert mode block fast-forward pulls; see hub logs)", strings.Join(failed, ", "))
	}
	return nil
}
