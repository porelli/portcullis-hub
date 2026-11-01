package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
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
	return func() { h.appOps.Delete(id) }, nil
}

func (h *Hub) appBusy(id string) bool {
	_, busy := h.appOps.Load(id)
	return busy
}

// project builds the compose invocation for a template.
func (h *Hub) project(t *templates.Template) compose.Project {
	p := compose.Project{
		Name:       projectName(t.ID),
		Files:      []string{t.ComposePath()},
		ProjectDir: h.cfg.ProjectHostDir,
		EnvFile:    h.envPath(t.ID),
	}
	if _, err := os.Stat(h.overridePath(t.ID)); err == nil {
		p.Files = append(p.Files, h.overridePath(t.ID))
	}
	return p
}

func (h *Hub) composeUp(t *templates.Template) error {
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return nil
	}
	if err := templates.SyncFiles(t, h.templatesRoot()); err != nil {
		return fmt.Errorf("sync template files: %w", err)
	}
	return h.compose.Up(context.Background(), h.project(t))
}

func (h *Hub) composeDown(t *templates.Template) error {
	if _, err := os.Stat(t.ComposePath()); err != nil {
		return nil
	}
	return h.compose.Down(context.Background(), h.project(t))
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
	hosts := make([]string, 0, len(t.Subdomains))
	for _, sub := range t.Subdomains {
		hosts = append(hosts, sub+"."+h.cfg.Domain)
	}
	return keycloak.ClientSpec{
		AllowedHosts: hosts,
		ClientID:     c.ClientID,
		Name:         c.Name,
		Secret:       secret,
		RedirectURIs: h.redirectURIs(c),
		TemplateID:   t.ID,
		ACR:          acr,
		// Most apps get the realm's email scope; email_verified_claim: false
		// swaps it for email-unverified.
		OmitEmailVerified: !c.SendsEmailVerified(),
	}
}

// Enable writes the app's env/override, registers its OIDC clients and runs
// compose up. The app is recorded as enabled only if compose succeeds.
func (h *Hub) Enable(id string) error {
	unlock, err := h.lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()

	// Phase 1 (under mu): validate and write local files — fast filesystem
	// work that needs a consistent view of state.
	h.mu.Lock()
	t := h.findLocked(id)
	if t == nil {
		h.mu.Unlock()
		return statusErr(400, "template not found: %s", id)
	}
	tmpl := *t // the catalog slice may be replaced meanwhile
	if h.st.IsEnabled(id) {
		h.mu.Unlock()
		return nil
	}
	if err := h.checkPortCollisionsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return err
	}
	if err := h.checkSubdomainCollisionsLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return err
	}
	if err := h.generateAppEnvLocked(&tmpl); err != nil {
		h.mu.Unlock()
		return fmt.Errorf("env setup failed: %w", err)
	}
	if err := h.generateOverrideLocked(&tmpl, h.st.Settings[tmpl.ID]); err != nil {
		h.mu.Unlock()
		return fmt.Errorf("override write failed: %w", err)
	}
	acr := policy.ACR(h.effectivePolicyLocked(&tmpl))
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
				return &StatusError{Status: 409, Err: err}
			case err != nil:
				log.Printf("Warning: failed to register client %s: %v", c.ClientID, err)
			}
		}
	}
	if err := h.composeUp(&tmpl); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	// Phase 3 (under mu): commit.
	h.mu.Lock()
	h.st.SetEnabled(id, true)
	if t := h.findLocked(id); t != nil {
		t.Enabled = true
	}
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	h.TriggerReconcile()
	return nil
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
	return h.disableLocked(id)
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
	if t := h.findLocked(id); t != nil {
		t.Enabled = false
	}
	h.refreshPublishedLocked()
	h.saveLocked()
	h.mu.Unlock()
	h.writePolicyLogged()
	h.TriggerReconcile()
	return nil
}

// Restart recreates an app's containers (down + up) so new env, override
// and labels take effect. It waits for any in-flight operation on the app
// instead of dropping the restart: that operation may have read the old
// files, and compose reads them at run time, so a queued restart always
// applies the latest ones.
func (h *Hub) Restart(t templates.Template) {
	deadline := time.Now().Add(20 * time.Minute)
	var unlock func()
	for {
		u, err := h.lockApp(t.ID)
		if err == nil {
			unlock = u
			break
		}
		if time.Now().After(deadline) {
			log.Printf("restart %s gave up: %v", t.ID, err)
			return
		}
		time.Sleep(h.lockPoll)
	}
	defer unlock()
	if !h.IsEnabled(t.ID) {
		return // disabled while we waited
	}
	if err := h.composeDown(&t); err != nil {
		log.Printf("restart %s: compose down failed: %v", t.ID, err)
	}
	if err := h.composeUp(&t); err != nil {
		log.Printf("restart %s: compose up failed: %v", t.ID, err)
	}
	h.TriggerReconcile()
}

// RestartAsync validates and queues a restart.
func (h *Hub) RestartAsync(id string) error {
	t := h.Template(id)
	if t == nil {
		return ErrNotFound
	}
	if !t.Enabled {
		return statusErr(400, "app not enabled")
	}
	tmpl := *t
	h.goBackground(func() { h.Restart(tmpl) })
	return nil
}
