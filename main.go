package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed web/*
var webFS embed.FS

// Auth describes how an app handles authentication.
type Auth struct {
	Method      string      `yaml:"method" json:"method"`
	SSO         interface{} `yaml:"sso" json:"sso"` // true, false, or "partial"
	GroupAccess bool        `yaml:"group_access" json:"group_access"`
	GroupAdmin  bool        `yaml:"group_admin" json:"group_admin"`
	AccessGroup string      `yaml:"access_group" json:"access_group"`
	AdminGroup  string      `yaml:"admin_group" json:"admin_group"`
	Notes       string      `yaml:"notes" json:"notes"`
}

// SettingTarget maps a setting to a compose service volume mount.
type SettingTarget struct {
	Service string `yaml:"service" json:"service"`
	Mount   string `yaml:"mount" json:"mount"`
}

// Setting is a user-configurable option defined in a manifest.
type Setting struct {
	Key         string         `yaml:"key" json:"key"`
	Label       string         `yaml:"label" json:"label"`
	Description string         `yaml:"description" json:"description"`
	Type        string         `yaml:"type" json:"type"` // text, path, paths, boolean, select
	Required    bool           `yaml:"required" json:"required"`
	Default     string         `yaml:"default" json:"default"`
	Options     []string       `yaml:"options" json:"options"`
	Target      *SettingTarget `yaml:"target" json:"target"`
}

// Port is a host port binding declared by a manifest. The Hub checks these
// for collisions at enable-time and emits the effective bindings into the
// per-app compose override so users can rebind or disable them from the UI.
type Port struct {
	Key             string `yaml:"key" json:"key"`
	Label           string `yaml:"label" json:"label"`
	Description     string `yaml:"description" json:"description"`
	Container       int    `yaml:"container" json:"container"`
	Protocol        string `yaml:"protocol" json:"protocol"` // tcp, udp
	Default         int    `yaml:"default" json:"default"`
	Bind            string `yaml:"bind" json:"bind"` // default "0.0.0.0"
	Required        bool   `yaml:"required" json:"required"`
	Service         string `yaml:"service" json:"service"`
	NetworkModeHost bool   `yaml:"network_mode_host" json:"network_mode_host"`
	Range           string `yaml:"range" json:"range"` // e.g. "49152-65535" (coturn media relays)
}

// ContainerStatus holds Docker container state info.
type ContainerStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Status string `json:"status"`
}

// Manifest describes an app template.
type Manifest struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Icon        string           `yaml:"icon" json:"icon"`
	Category    string           `yaml:"category" json:"category"`
	Tags        []string         `yaml:"tags" json:"tags"`
	Auth        Auth             `yaml:"auth" json:"auth"`
	Settings    []Setting        `yaml:"settings" json:"settings"`
	Ports       []Port           `yaml:"ports" json:"ports"`
	Env         []EnvVar         `yaml:"env" json:"env"`
	Clients     []KeycloakClient `yaml:"keycloak_clients" json:"keycloak_clients"`
	ConfigFiles []ConfigFile     `yaml:"config_files" json:"config_files"`
	URLs        []AppURL         `yaml:"urls" json:"urls"`
}

type EnvVar struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	Generate    string `yaml:"generate" json:"generate"` // "random", "none", ""
	Required    *bool  `yaml:"required" json:"required"`
}

type KeycloakClient struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	SecretEnv    string   `yaml:"secret_env" json:"secret_env"`
	RedirectURI  string   `yaml:"redirect_uri" json:"redirect_uri"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
	Name         string   `yaml:"name" json:"name"`
}

type ConfigFile struct {
	Src  string `yaml:"src" json:"src"`
	Dest string `yaml:"dest" json:"dest"`
}

type AppURL struct {
	Label string `yaml:"label" json:"label"`
	URL   string `yaml:"url" json:"url"`
}

// Source is a template repository.
type Source struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
	Path string `json:"path" yaml:"path"` // local path after clone
}

// AuthPolicy is a per-app (or global default) authentication requirement.
// Factors is a subset of {"mtls","webauthn","password"}. Op is "any" or "all"
// (ignored when len(Factors) <= 1). An empty Factors list means public.
type AuthPolicy struct {
	Factors []string `json:"factors" yaml:"factors"`
	Op      string   `json:"op" yaml:"op"`
}

// AppState tracks which apps are enabled and their settings.
type AppState struct {
	Enabled        []string                     `json:"enabled" yaml:"enabled"`
	Sources        []Source                     `json:"sources" yaml:"sources"`
	Settings       map[string]map[string]string `json:"settings" yaml:"settings"`
	AuthPolicies   map[string]AuthPolicy        `json:"auth_policies" yaml:"auth_policies"`
	DefaultPolicy  AuthPolicy                   `json:"default_auth_policy" yaml:"default_auth_policy"`
	MigrateVersion int                          `json:"migrate_version" yaml:"migrate_version"`
}

// Template is a discovered template with its source info.
type Template struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"` // name of the source (template repo) this came from
	Manifest Manifest `json:"manifest"`
	Path     string   `json:"-"` // filesystem path
	Enabled  bool     `json:"enabled"`
}

var (
	projectDir     string
	projectHostDir string // host path for --project-directory (Docker daemon resolves bind mounts here)
	dataDir        string
	templates      []Template
	state          AppState
	stateMu        sync.RWMutex
	domain         string
	lldapURL       string
	lldapUser      string
	lldapPass      string
)

// ── Limits, validation and shared clients ───────────────

const (
	composeUpTimeout    = 15 * time.Minute // includes image pulls
	composeDownTimeout  = 5 * time.Minute
	composeQueryTimeout = 30 * time.Second // ps / logs
	execTimeout         = 15 * time.Minute
	gitTimeout          = 5 * time.Minute
	maxBodyBytes        = 1 << 20
)

var (
	// Template / source identifiers end up in file paths, compose project
	// names, URLs and HTML attributes — keep them boring.
	idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	// Setting / port / env keys become .env keys.
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// Keycloak user IDs are UUIDs.
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F-]{1,64}$`)
	// Subdomain routed by a template: Host(`<sub>.${PORTCULLIS_DOMAIN...}`).
	hostRuleRe = regexp.MustCompile("Host\\(`([A-Za-z0-9-]+)\\.\\$\\{PORTCULLIS_DOMAIN")

	// All outbound HTTP (Keycloak admin API, LLDAP) goes through this client
	// so nothing can hang the Hub indefinitely.
	httpClient = &http.Client{Timeout: 20 * time.Second}
)

// newCmd builds a command bound to ctx with a hard timeout. WaitDelay makes
// sure Wait returns even if a killed child left pipes open.
func newCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	return cmd, cancel
}

// hasControlChars reports whether s contains newlines or other control
// characters — such values would inject extra lines into .env / YAML files.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// within reports whether path p is inside (or equal to) base.
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// writeFileAtomic writes via temp file + rename so readers never observe a
// partially written file and a crash can't truncate the original.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// decodeJSON decodes a size-limited JSON request body, writing a 400 on error.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), 400)
		return false
	}
	return true
}

// csrfGuard rejects cross-origin state-changing requests. The Hub sits behind
// forward-auth with a SameSite=Lax cookie scoped to the parent domain, so any
// sibling app subdomain counts as same-site — cookies alone don't stop a
// malicious page on another app from POSTing here. CrossOriginProtection uses
// Sec-Fetch-Site / Origin; additionally require a JSON body so plain HTML
// forms (which can't set Content-Type: application/json) are refused.
func csrfGuard(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	return cop.Handler(inner)
}

// resolveUsername converts an email (from forward-auth) to an LLDAP username.
func resolveUsername(email string) string {
	if lldapPass == "" || !strings.Contains(email, "@") {
		return email
	}
	loginBody, _ := json.Marshal(map[string]string{"username": lldapUser, "password": lldapPass})
	resp, err := httpClient.Post(lldapURL+"/auth/simple/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		return email
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return email
	}
	var tokenResp struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(resp.Body).Decode(&tokenResp) != nil || tokenResp.Token == "" {
		return email
	}
	// Pass the email as a GraphQL variable — never splice it into the query.
	query, _ := json.Marshal(map[string]interface{}{
		"query":     `query($email: String!) { users(filters: {eq: {field: "email", value: $email}}) { id } }`,
		"variables": map[string]string{"email": email},
	})
	req, _ := http.NewRequest("POST", lldapURL+"/api/graphql", bytes.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	resp2, err := httpClient.Do(req)
	if err != nil {
		return email
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		return email
	}
	var gqlResp struct {
		Data struct {
			Users []struct {
				ID string `json:"id"`
			} `json:"users"`
		} `json:"data"`
	}
	if json.NewDecoder(resp2.Body).Decode(&gqlResp) != nil || len(gqlResp.Data.Users) == 0 {
		return email
	}
	return gqlResp.Data.Users[0].ID
}

func main() {
	projectDir = os.Getenv("PROJECT_DIR")
	if projectDir == "" {
		projectDir = "/app/project"
	}
	projectHostDir = os.Getenv("PROJECT_HOST_DIR")
	if projectHostDir == "" {
		projectHostDir = projectDir // fallback: same as container path (works if not in Docker)
	}
	dataDir = os.Getenv("HUB_DATA_DIR")
	if dataDir == "" {
		dataDir = filepath.Join(projectDir, ".hub")
	}
	domain = os.Getenv("PORTCULLIS_DOMAIN")
	if domain == "" {
		domain = "portcullis.local"
	}
	lldapURL = os.Getenv("LLDAP_HTTP_URL")
	if lldapURL == "" {
		lldapURL = "http://lldap:17170"
	}
	lldapUser = os.Getenv("LLDAP_ADMIN_USER")
	if lldapUser == "" {
		lldapUser = "admin"
	}
	lldapPass = os.Getenv("LLDAP_ADMIN_PASSWORD")

	os.MkdirAll(dataDir, 0755)
	os.MkdirAll(filepath.Join(dataDir, "repos"), 0755)

	loadState()
	autoLoadDefaultTemplates()
	discoverTemplates()
	migrateToIsolatedStacks()

	// Seed the group-gate policy file so first-request enforcement has a
	// valid document to read even on a brand-new deployment.
	if err := writeGroupGatePolicy(); err != nil {
		log.Printf("auth-policy: initial group-gate policy write failed: %v", err)
	}

	mux := http.NewServeMux()

	// Pages
	mux.HandleFunc("/", handleIndex)

	// API
	mux.HandleFunc("/api/templates", handleTemplates)
	mux.HandleFunc("/api/templates/enable", handleEnable)
	mux.HandleFunc("/api/templates/disable", handleDisable)
	mux.HandleFunc("/api/sources", handleSources)
	mux.HandleFunc("/api/sources/add", handleAddSource)
	mux.HandleFunc("/api/sources/remove", handleRemoveSource)
	mux.HandleFunc("/api/sources/sync", handleSyncSources)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/settings", handleSettings)
	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/users/", handleUserActions)
	mux.HandleFunc("/api/templates/settings/", handleTemplateSettings)
	mux.HandleFunc("/api/templates/status/", handleTemplateStatus)
	mux.HandleFunc("/api/templates/logs/", handleTemplateLogs)
	mux.HandleFunc("/api/templates/compose/", handleTemplateCompose)
	mux.HandleFunc("/api/templates/env/", handleTemplateEnv)
	mux.HandleFunc("/api/templates/exec/", handleTemplateExec)
	mux.HandleFunc("/api/templates/restart/", handleTemplateRestart)

	// Static assets
	mux.HandleFunc("/static/", handleStatic)

	addr := ":8888"
	srv := &http.Server{
		Addr:              addr,
		Handler:           csrfGuard(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("Hub listening on %s (domain: %s)", addr, domain)
	log.Fatal(srv.ListenAndServe())
}

// ── State persistence ────────────────────────────────────

func statePath() string {
	return filepath.Join(dataDir, "state.yaml")
}

func loadState() {
	data, err := os.ReadFile(statePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("cannot read %s: %v", statePath(), err)
		}
		state = AppState{
			Settings:     make(map[string]map[string]string),
			AuthPolicies: make(map[string]AuthPolicy),
		}
		return
	}
	// Refuse to start on a corrupt state file: continuing with empty state
	// would overwrite it on the next save and lose every enabled app/source.
	if len(bytes.TrimSpace(data)) == 0 {
		log.Fatalf("%s is empty (interrupted write?) — restore it from backup or delete it to start fresh", statePath())
	}
	if err := yaml.Unmarshal(data, &state); err != nil {
		log.Fatalf("corrupt %s (%v) — fix or move it aside, then restart", statePath(), err)
	}
	if state.Settings == nil {
		state.Settings = make(map[string]map[string]string)
	}
	if state.AuthPolicies == nil {
		state.AuthPolicies = make(map[string]AuthPolicy)
	}
}

// saveState persists state atomically. Caller must hold stateMu.
func saveState() {
	data, err := yaml.Marshal(&state)
	if err != nil {
		log.Printf("ERROR: marshal state: %v", err)
		return
	}
	if err := writeFileAtomic(statePath(), data, 0600); err != nil {
		log.Printf("ERROR: save state: %v", err)
	}
}

// ── Template discovery ───────────────────────────────────

func discoverTemplates() {
	stateMu.Lock()
	defer stateMu.Unlock()

	templates = nil

	// Templates come exclusively from configured sources (git repos).
	// The default source (porelli/portcullis-templates) is auto-added on first
	// startup by autoLoadDefaultTemplates() — see DEFAULT_TEMPLATES_URL.
	for _, src := range state.Sources {
		if src.Path != "" {
			discoverFrom(src.Path, src.Name)
		}
	}

	// Mark enabled
	enabledSet := make(map[string]bool)
	for _, id := range state.Enabled {
		enabledSet[id] = true
	}
	found := make(map[string]bool, len(templates))
	for i := range templates {
		templates[i].Enabled = enabledSet[templates[i].ID]
		found[templates[i].ID] = true
	}
	for id := range enabledSet {
		if !found[id] {
			log.Printf("WARNING: enabled app %s has no (valid) template any more — its containers keep running; disable it to stop them", id)
		}
	}

	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Manifest.Category != templates[j].Manifest.Category {
			return templates[i].Manifest.Category < templates[j].Manifest.Category
		}
		return templates[i].Manifest.Name < templates[j].Manifest.Name
	})
}

func discoverFrom(dir, source string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		manifestPath := filepath.Join(dir, e.Name(), "manifest.yaml")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		if !idRe.MatchString(e.Name()) {
			log.Printf("Skipping template %q: directory name must match %s", e.Name(), idRe)
			continue
		}
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			log.Printf("Bad manifest in %s: %v", manifestPath, err)
			continue
		}
		if err := validateManifest(&m); err != nil {
			log.Printf("Skipping template %s: %v", e.Name(), err)
			continue
		}
		// Substitute {{DOMAIN}} in app URLs
		for i := range m.URLs {
			m.URLs[i].URL = strings.ReplaceAll(m.URLs[i].URL, "{{DOMAIN}}", domain)
		}
		templates = append(templates, Template{
			ID:       e.Name(),
			Source:   source,
			Manifest: m,
			Path:     filepath.Join(dir, e.Name()),
		})
	}
}

// validateManifest rejects manifests whose keys/values would be unsafe to
// splice into .env files, compose overrides or the UI's HTML.
func validateManifest(m *Manifest) error {
	for _, st := range m.Settings {
		if !envKeyRe.MatchString(st.Key) {
			return fmt.Errorf("invalid setting key %q", st.Key)
		}
		if hasControlChars(st.Default) {
			return fmt.Errorf("setting %s: default contains control characters", st.Key)
		}
	}
	for _, p := range m.Ports {
		if !envKeyRe.MatchString(p.Key) {
			return fmt.Errorf("invalid port key %q", p.Key)
		}
		if p.Bind != "" && net.ParseIP(p.Bind) == nil {
			return fmt.Errorf("port %s: bind %q is not an IP address", p.Key, p.Bind)
		}
	}
	for _, v := range m.Env {
		if !envKeyRe.MatchString(v.Key) {
			return fmt.Errorf("invalid env key %q", v.Key)
		}
	}
	for _, c := range m.Clients {
		if c.SecretEnv != "" && !envKeyRe.MatchString(c.SecretEnv) {
			return fmt.Errorf("client %s: invalid secret_env %q", c.ClientID, c.SecretEnv)
		}
	}
	return nil
}

// templateSubdomains returns the lowercase subdomains a template routes via
// Traefik Host() rules in its compose.yml.
func templateSubdomains(tmpl *Template) []string {
	data, err := os.ReadFile(filepath.Join(tmpl.Path, "compose.yml"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range hostRuleRe.FindAllStringSubmatch(string(data), -1) {
		sub := strings.ToLower(m[1])
		if !seen[sub] {
			seen[sub] = true
			out = append(out, sub)
		}
	}
	sort.Strings(out)
	return out
}

// ── Auto-load default templates ──────────────────────────

func autoLoadDefaultTemplates() {
	defaultURL := os.Getenv("DEFAULT_TEMPLATES_URL")
	if defaultURL == "" {
		return
	}

	stateMu.RLock()
	hasSources := len(state.Sources) > 0
	stateMu.RUnlock()

	if hasSources {
		return // already has sources, don't auto-add
	}

	log.Printf("First run: cloning default templates from %s", defaultURL)
	if err := addSource("portcullis", defaultURL); err != nil {
		log.Printf("Warning: could not clone default templates: %v", err)
	} else {
		log.Println("Default templates loaded successfully")
	}
}

// ── Migration ────────────────────────────────────────────

// migrateToIsolatedStacks migrates apps from the shared portcullis project
// to per-app isolated projects (portcullis-<app-id>).
func migrateToIsolatedStacks() {
	if state.MigrateVersion >= 2 {
		return // already migrated
	}

	stateMu.Lock()
	enabledApps := make([]string, len(state.Enabled))
	copy(enabledApps, state.Enabled)
	stateMu.Unlock()

	if len(enabledApps) == 0 {
		stateMu.Lock()
		state.MigrateVersion = 2
		saveState()
		stateMu.Unlock()
		return
	}

	log.Printf("Migrating %d apps to isolated stacks...", len(enabledApps))

	for _, id := range enabledApps {
		tmpl := findTemplate(id)
		if tmpl == nil {
			continue
		}

		// Generate per-app .env
		if err := generateAppEnv(tmpl); err != nil {
			log.Printf("Migration warning: could not generate env for %s: %v", id, err)
		}

		// Stop under old shared project name
		composePath := filepath.Join(tmpl.Path, "compose.yml")
		if _, err := os.Stat(composePath); err != nil {
			continue
		}
		envFile := appEnvPath(tmpl)
		oldArgs := []string{"compose", "-p", "portcullis", "-f", composePath,
			"--project-directory", projectHostDir, "--env-file", envFile, "down"}
		cmd, cancel := newCmd(context.Background(), composeDownTimeout, "docker", oldArgs...)
		cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Migration: old stack down for %s: %v (may already be stopped)", id, err)
		}
		cancel()

		// Start under new isolated project name
		if err := composeUp(tmpl); err != nil {
			log.Printf("Migration warning: could not start %s under new project: %v", id, err)
		} else {
			log.Printf("Migrated %s → %s", id, appProjectName(tmpl))
		}
	}

	stateMu.Lock()
	state.MigrateVersion = 2
	saveState()
	stateMu.Unlock()
	log.Println("Migration complete")
}

// ── Enable / Disable ─────────────────────────────────────

// appOps serialises lifecycle operations per app (enable/disable/restart) so
// the slow parts can run without holding the global stateMu.
var appOps sync.Map

func lockApp(id string) (func(), error) {
	if _, busy := appOps.LoadOrStore(id, struct{}{}); busy {
		return nil, fmt.Errorf("another operation on %s is in progress — try again shortly", id)
	}
	return func() { appOps.Delete(id) }, nil
}

func isEnabled(id string) bool {
	for _, e := range state.Enabled {
		if e == id {
			return true
		}
	}
	return false
}

func enableApp(id string) error {
	unlock, err := lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()

	// Phase 1 (under lock): validate and write local files. Everything here is
	// fast filesystem work that needs a consistent view of state.
	stateMu.Lock()
	t := findTemplate(id)
	if t == nil {
		stateMu.Unlock()
		return fmt.Errorf("template not found: %s", id)
	}
	tmpl := *t // work on a copy; the templates slice may be replaced meanwhile
	if isEnabled(id) {
		stateMu.Unlock()
		return nil
	}
	if err := checkPortCollisions(&tmpl); err != nil {
		stateMu.Unlock()
		return err
	}
	if err := generateAppEnv(&tmpl); err != nil {
		stateMu.Unlock()
		return fmt.Errorf("env setup failed: %w", err)
	}
	if err := generateComposeOverride(&tmpl, state.Settings[tmpl.ID]); err != nil {
		stateMu.Unlock()
		return fmt.Errorf("override write failed: %w", err)
	}
	acr := policyACR(resolvePolicy(tmpl.ID))
	stateMu.Unlock()

	// Copy config files — both ends must stay inside their trees, and the
	// core .env / compose files are off limits.
	for _, cf := range tmpl.Manifest.ConfigFiles {
		src := filepath.Join(tmpl.Path, cf.Src)
		dest := filepath.Join(projectDir, cf.Dest)
		if !within(tmpl.Path, src) || !within(projectDir, dest) || dest == projectDir ||
			filepath.Dir(dest) == filepath.Clean(projectDir) {
			log.Printf("Warning: refusing config_files entry %s → %s for %s (outside allowed paths)", cf.Src, cf.Dest, id)
			continue
		}
		os.MkdirAll(filepath.Dir(dest), 0755)
		if err := copyFile(src, dest); err != nil {
			log.Printf("Warning: failed to copy %s → %s: %v", src, dest, err)
		}
	}

	// Phase 2 (no lock): network / docker work that may take minutes.
	for _, client := range tmpl.Manifest.Clients {
		if err := registerKeycloakClient(client, &tmpl, acr); err != nil {
			log.Printf("Warning: failed to register client %s: %v", client.ClientID, err)
		}
	}
	// Only record the enable if compose succeeds — otherwise the UI would show
	// a running app that never started.
	if err := composeUp(&tmpl); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	// Phase 3 (under lock): commit.
	stateMu.Lock()
	if !isEnabled(id) {
		state.Enabled = append(state.Enabled, id)
	}
	if t := findTemplate(id); t != nil {
		t.Enabled = true
	}
	saveState()
	stateMu.Unlock()
	if err := writeGroupGatePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
	return nil
}

func disableApp(id string) error {
	unlock, err := lockApp(id)
	if err != nil {
		return err
	}
	defer unlock()

	stateMu.RLock()
	enabled := isEnabled(id)
	var tmpl *Template
	if t := findTemplate(id); t != nil {
		c := *t
		tmpl = &c
	}
	stateMu.RUnlock()
	if !enabled {
		return fmt.Errorf("app not enabled: %s", id)
	}

	// Stop first; only mark disabled once the containers are actually gone,
	// otherwise a failed down leaves orphans the UI can no longer stop. If
	// the template is gone (source removed, now fails validation) or its
	// compose file is broken, fall back to stopping by project name.
	var downErr error
	if tmpl != nil {
		downErr = composeDown(tmpl)
	}
	if tmpl == nil || downErr != nil {
		if err := composeDownByProject(id); err != nil {
			if downErr == nil {
				downErr = err
			}
			return fmt.Errorf("compose down failed (app left enabled, retry): %w", downErr)
		}
	}

	stateMu.Lock()
	newEnabled := make([]string, 0, len(state.Enabled))
	for _, e := range state.Enabled {
		if e != id {
			newEnabled = append(newEnabled, e)
		}
	}
	state.Enabled = newEnabled
	if t := findTemplate(id); t != nil {
		t.Enabled = false
	}
	saveState()
	stateMu.Unlock()
	if err := writeGroupGatePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
	return nil
}

// findTemplate returns a pointer into the templates slice. Caller must hold
// stateMu; use getTemplate from handlers.
func findTemplate(id string) *Template {
	for i := range templates {
		if templates[i].ID == id {
			return &templates[i]
		}
	}
	return nil
}

// getTemplate returns a copy of a template, safe to use without holding
// stateMu (discoverTemplates may replace the slice at any time).
func getTemplate(id string) *Template {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if t := findTemplate(id); t != nil {
		c := *t
		return &c
	}
	return nil
}

// portBinding is the effective (resolved) binding for one declared port after
// applying user overrides from state.Settings.
type portBinding struct {
	AppID           string
	Key             string
	Bind            string
	Port            int
	Protocol        string
	NetworkModeHost bool
	RangeStart      int
	RangeEnd        int
}

// resolvePortBindings returns the effective bindings for an app given the
// current state.Settings. Caller MUST hold stateMu (read or write).
func resolvePortBindings(tmpl *Template) []portBinding {
	values := state.Settings[tmpl.ID]
	out := make([]portBinding, 0, len(tmpl.Manifest.Ports))
	for _, p := range tmpl.Manifest.Ports {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		bind := p.Bind
		if v, ok := values[p.Key+"_BIND"]; ok && v != "" {
			bind = v
		}
		if bind == "" {
			bind = "0.0.0.0"
		}
		pb := portBinding{
			AppID:           tmpl.ID,
			Key:             p.Key,
			Bind:            bind,
			Protocol:        proto,
			NetworkModeHost: p.NetworkModeHost,
		}
		// Port ranges (e.g. coturn media relays) — not user-configurable.
		if p.Range != "" {
			if a, b, ok := parsePortRange(p.Range); ok {
				pb.RangeStart, pb.RangeEnd = a, b
				out = append(out, pb)
				continue
			}
		}
		port := p.Default
		if v, ok := values[p.Key]; ok {
			if v == "" && !p.Required {
				continue // user disabled this port
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				port = n
			}
		}
		if port <= 0 {
			continue
		}
		pb.Port = port
		out = append(out, pb)
	}
	return out
}

func parsePortRange(s string) (int, int, bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || a <= 0 || b < a {
		return 0, 0, false
	}
	return a, b, true
}

// bindsOverlap returns true if two bind addresses could conflict on the host.
// 0.0.0.0 claims every interface, so it conflicts with any other bind.
func bindsOverlap(a, b string) bool {
	if a == b {
		return true
	}
	if a == "0.0.0.0" || b == "0.0.0.0" {
		return true
	}
	return false
}

// portOverlap returns true if two bindings claim overlapping (port|range, protocol).
func portOverlap(a, b portBinding) bool {
	if a.Protocol != b.Protocol {
		return false
	}
	if !bindsOverlap(a.Bind, b.Bind) {
		return false
	}
	aStart, aEnd := a.Port, a.Port
	if a.RangeEnd > 0 {
		aStart, aEnd = a.RangeStart, a.RangeEnd
	}
	bStart, bEnd := b.Port, b.Port
	if b.RangeEnd > 0 {
		bStart, bEnd = b.RangeStart, b.RangeEnd
	}
	return aStart <= bEnd && bStart <= aEnd
}

// checkPortCollisions refuses enable if the candidate's ports overlap with any
// already-enabled app's ports. Caller MUST hold stateMu.
func checkPortCollisions(tmpl *Template) error {
	candidate := resolvePortBindings(tmpl)
	if len(candidate) == 0 {
		return nil
	}
	for _, enabledID := range state.Enabled {
		if enabledID == tmpl.ID {
			continue
		}
		other := findTemplate(enabledID)
		if other == nil {
			continue
		}
		existing := resolvePortBindings(other)
		for _, c := range candidate {
			for _, e := range existing {
				if !portOverlap(c, e) {
					continue
				}
				portDesc := fmt.Sprintf("%d/%s", c.Port, c.Protocol)
				if c.RangeEnd > 0 {
					portDesc = fmt.Sprintf("%d-%d/%s", c.RangeStart, c.RangeEnd, c.Protocol)
				}
				return fmt.Errorf("port %s already claimed by enabled app %s — change %s in its settings to free it", portDesc, enabledID, e.Key)
			}
		}
	}
	return nil
}

// ── Auth policies (mTLS / WebAuthn / Password, AND / OR) ─

// Mapping of factor name to (LoA level, amr claim value, acr claim value).
var factorLoA = map[string]int{"password": 1, "webauthn": 2, "mtls": 3}
var factorACR = map[string]string{"password": "pwd", "webauthn": "hwk", "mtls": "mtls"}

// resolvePolicy returns the effective policy for an app: the per-app override
// if set, else the global default, else an empty (public) policy. Caller must
// hold stateMu (read or write).
func resolvePolicy(appID string) AuthPolicy {
	if p, ok := state.AuthPolicies[appID]; ok {
		return p
	}
	return state.DefaultPolicy
}

// normalizePolicy trims and lower-cases factor names, drops unknown values,
// and normalizes the op field (forces "" when ≤1 factor, forces "any" otherwise
// when missing).
func normalizePolicy(p AuthPolicy) AuthPolicy {
	out := AuthPolicy{}
	seen := map[string]bool{}
	for _, f := range p.Factors {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := factorLoA[f]; !ok {
			continue
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		out.Factors = append(out.Factors, f)
	}
	sort.Strings(out.Factors)
	if len(out.Factors) <= 1 {
		out.Op = ""
	} else {
		op := strings.ToLower(strings.TrimSpace(p.Op))
		if op != "all" {
			op = "any"
		}
		out.Op = op
	}
	return out
}

// policyToLoA returns the Level of Authentication a client should request to
// satisfy the policy. 0 for public; min-factor-LoA for "any"; max-factor-LoA
// for "all" (the strongest path).
func policyToLoA(p AuthPolicy) int {
	if len(p.Factors) == 0 {
		return 0
	}
	if p.Op == "all" {
		max := 0
		for _, f := range p.Factors {
			if l, ok := factorLoA[f]; ok && l > max {
				max = l
			}
		}
		return max
	}
	// "any" or single factor
	min := 0
	for _, f := range p.Factors {
		if l, ok := factorLoA[f]; ok && (min == 0 || l < min) {
			min = l
		}
	}
	return min
}

// policyACR returns the acr string an OIDC client should request via
// default.acr.values to prompt Keycloak for the right LoA step-up.
func policyACR(p AuthPolicy) string {
	loa := policyToLoA(p)
	switch loa {
	case 1:
		return "pwd"
	case 2:
		return "hwk"
	case 3:
		return "mtls"
	}
	return "public"
}

// tierForPolicy returns the Traefik TLS options tier for an app based on its
// policy. "protected@file" requires a cert at TLS handshake and is used when
// every allowed login path goes through mTLS (i.e. "all of ... mtls" or
// "single mtls factor"). Otherwise "authaware@file" accepts connections with
// or without a cert and lets Keycloak or group-gate handle enforcement.
func tierForPolicy(p AuthPolicy) string {
	if len(p.Factors) == 0 {
		return "public@file"
	}
	hasMTLS := false
	for _, f := range p.Factors {
		if f == "mtls" {
			hasMTLS = true
		}
	}
	if !hasMTLS {
		return "authaware@file"
	}
	// mTLS is one of the allowed factors.
	if p.Op == "all" || len(p.Factors) == 1 {
		return "protected@file"
	}
	// mTLS is optional (any-of multiple) — tolerate cert-less connections.
	return "authaware@file"
}

// safetyScore is a cosmetic float surfaced in the UI.
func safetyScore(p AuthPolicy) float64 {
	loa := float64(policyToLoA(p))
	if len(p.Factors) <= 1 || p.Op != "all" {
		return loa
	}
	return loa + 0.5*float64(len(p.Factors)-1)
}

// writeGroupGatePolicy serializes the per-app auth policies, the global
// default and the access groups of enabled templates to the JSON file that
// group-gate reads. Takes stateMu itself — callers must NOT hold it.
//
// group-gate keys everything by the request's subdomain, while the Hub keys
// policies by template ID; the two differ for many apps (gitlab → git,
// vaultwarden → passwords, …). So every per-app policy is written under the
// template ID *and* under each subdomain the template routes.
//
// Atomic write via temp-file + rename so group-gate never sees a partial
// document.
var policyWriteMu sync.Mutex

// coreSubdomains are owned by the core stack; templates may never publish
// policies or groups for them.
var coreSubdomains = map[string]bool{"auth": true, "traefik": true, "hub": true, "directory": true, "enroll": true}

func writeGroupGatePolicy() error {
	// Serialise snapshot → rename so an older snapshot can never overwrite a
	// newer one (a stale file could drop groups and fail open).
	policyWriteMu.Lock()
	defer policyWriteMu.Unlock()
	stateMu.RLock()
	policies := make(map[string]AuthPolicy, len(state.AuthPolicies))
	for id, p := range state.AuthPolicies {
		if !coreSubdomains[id] {
			policies[id] = p
		}
	}
	groups := map[string]string{}
	for i := range templates {
		t := &templates[i]
		if !t.Enabled {
			continue // only live apps publish subdomain entries
		}
		var subs []string
		for _, sub := range templateSubdomains(t) {
			if coreSubdomains[sub] {
				log.Printf("auth-policy: template %s routes core subdomain %q — ignored for policies/groups", t.ID, sub)
				continue
			}
			subs = append(subs, sub)
		}
		if p, ok := state.AuthPolicies[t.ID]; ok {
			for _, sub := range subs {
				if _, taken := policies[sub]; !taken {
					policies[sub] = p
				}
			}
		}
		// Only apps that opt into group-based access (group_access: true)
		// get a required group; for the others access_group is informational.
		if t.Manifest.Auth.GroupAccess && t.Manifest.Auth.AccessGroup != "" {
			for _, sub := range subs {
				groups[sub] = t.Manifest.Auth.AccessGroup
			}
		}
	}
	doc := map[string]interface{}{
		"policies": policies,
		"default":  state.DefaultPolicy,
		"groups":   groups,
	}
	stateMu.RUnlock()

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	// 0644: group-gate reads this from a read-only mount as another user.
	return writeFileAtomic(filepath.Join(dataDir, "group-gate-policy.json"), payload, 0644)
}

// ── Keycloak admin API (net/http, no curl) ───────────────
//
// Using net/http instead of shelling out to curl keeps the admin password and
// bearer tokens out of process arguments (visible in `ps` on the host), gives
// every call a timeout, and verifies TLS if KEYCLOAK_URL is ever https.

func keycloakBaseURL() string {
	if u := os.Getenv("KEYCLOAK_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://keycloak:8080"
}

// keycloakAdminToken fetches a short-lived admin access token by password
// grant against the master realm (tokens expire in ~60s by default).
func keycloakAdminToken() (string, string, error) {
	kcURL := keycloakBaseURL()
	form := url.Values{
		"client_id":  {"admin-cli"},
		"username":   {os.Getenv("KEYCLOAK_ADMIN")},
		"password":   {os.Getenv("KEYCLOAK_ADMIN_PASSWORD")},
		"grant_type": {"password"},
	}
	resp, err := httpClient.PostForm(kcURL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		return "", "", fmt.Errorf("keycloak auth failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("keycloak auth failed: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&tr); err != nil {
		return "", "", fmt.Errorf("keycloak auth response parse: %w", err)
	}
	if tr.AccessToken == "" {
		return "", "", fmt.Errorf("no access token from keycloak")
	}
	return kcURL, tr.AccessToken, nil
}

// kcDo performs an authenticated admin API call. body (if non-nil) is sent as
// JSON; out (if non-nil) receives the decoded 2xx response. Returns the HTTP
// status code.
func kcDo(method, fullURL, token string, body, out interface{}) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, fullURL, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("parse response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// listRealmUsers returns users in the Portcullis realm (up to 1000). Used by
// the Hub's enrollment-trigger UI to populate the user dropdown.
type keycloakUser struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Enabled         bool     `json:"enabled"`
	RequiredActions []string `json:"requiredActions"`
}

func listRealmUsers() ([]keycloakUser, error) {
	kcURL, tok, err := keycloakAdminToken()
	if err != nil {
		return nil, err
	}
	var users []keycloakUser
	code, err := kcDo("GET", kcURL+"/admin/realms/portcullis/users?max=1000&briefRepresentation=false", tok, nil, &users)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("list users: HTTP %d", code)
	}
	// IDs are spliced into onclick handlers in the UI; drop anything odd.
	out := users[:0]
	for _, u := range users {
		if uuidRe.MatchString(u.ID) {
			out = append(out, u)
		}
	}
	return out, nil
}

// setUserRequiredActions replaces the Keycloak user's requiredActions array.
// Passing an empty slice clears pending actions; passing
// ["webauthn-register-passwordless"] forces the user to enroll a key on next
// login before the LoA-2+ subflows can succeed.
func setUserRequiredActions(userID string, actions []string) error {
	if !uuidRe.MatchString(userID) {
		return fmt.Errorf("invalid user id")
	}
	kcURL, tok, err := keycloakAdminToken()
	if err != nil {
		return err
	}
	userURL := kcURL + "/admin/realms/portcullis/users/" + url.PathEscape(userID)
	var user map[string]interface{}
	code, err := kcDo("GET", userURL, tok, nil, &user)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("get user: HTTP %d", code)
	}
	// Keycloak is strict about this being a JSON array of strings.
	if actions == nil {
		actions = []string{}
	}
	user["requiredActions"] = actions
	code, err = kcDo("PUT", userURL, tok, user, nil)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	if code != 204 {
		return fmt.Errorf("user %s required-actions update: HTTP %d", userID, code)
	}
	return nil
}

// findKeycloakClient looks up a client representation by clientId.
func findKeycloakClient(kcURL, token, clientID string) (map[string]interface{}, error) {
	var clients []map[string]interface{}
	code, err := kcDo("GET", kcURL+"/admin/realms/portcullis/clients?clientId="+url.QueryEscape(clientID), token, nil, &clients)
	if err != nil {
		return nil, fmt.Errorf("client lookup failed: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("client lookup: HTTP %d", code)
	}
	for _, c := range clients {
		if c["clientId"] == clientID {
			if id, _ := c["id"].(string); id != "" {
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not found in keycloak", clientID)
}

// withACR sets default.acr.values and makes sure the "acr" default client
// scope is present on a client representation.
func withACR(client map[string]interface{}, acrValue string) {
	attrs, _ := client["attributes"].(map[string]interface{})
	if attrs == nil {
		attrs = map[string]interface{}{}
	}
	attrs["default.acr.values"] = acrValue
	client["attributes"] = attrs
	scopes, _ := client["defaultClientScopes"].([]interface{})
	for _, sc := range scopes {
		if sc == "acr" {
			return
		}
	}
	client["defaultClientScopes"] = append(scopes, "acr")
}

func putKeycloakClient(kcURL, token string, client map[string]interface{}) error {
	uuid, _ := client["id"].(string)
	code, err := kcDo("PUT", kcURL+"/admin/realms/portcullis/clients/"+url.PathEscape(uuid), token, client, nil)
	if err != nil {
		return fmt.Errorf("client update failed: %w", err)
	}
	if code != 204 {
		return fmt.Errorf("client %v update: unexpected HTTP %d", client["clientId"], code)
	}
	return nil
}

// updateClientAcrLoAMap pushes a new default.acr.values to a Keycloak client
// so its own authorize requests include the needed acr_values, triggering
// step-up if the session doesn't already meet the level.
func updateClientAcrLoAMap(clientID, acrValue string) error {
	kcURL, token, err := keycloakAdminToken()
	if err != nil {
		return err
	}
	existing, err := findKeycloakClient(kcURL, token, clientID)
	if err != nil {
		return err
	}
	withACR(existing, acrValue)
	return putKeycloakClient(kcURL, token, existing)
}

// composeRoutersByService returns, for each service in the base compose.yml,
// the Traefik router names declared under its labels. Handles the common
// 2-space-per-level indentation used throughout the templates.
func composeRoutersByService(tmpl *Template) map[string][]string {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil
	}

	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	var currentService string

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Service header: two-space indent, ends with ":" and no further nesting.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":") {
			name := strings.TrimSuffix(trimmed, ":")
			// Only accept bare identifiers as service names (skip labels like "environment:")
			if !strings.ContainsAny(name, " \t") {
				currentService = name
				if _, ok := out[name]; !ok {
					seen[name] = map[string]bool{}
				}
				continue
			}
		}
		if currentService == "" {
			continue
		}
		idx := strings.Index(line, "traefik.http.routers.")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("traefik.http.routers."):]
		dot := strings.Index(rest, ".")
		if dot <= 0 {
			continue
		}
		router := rest[:dot]
		if router == "" || seen[currentService][router] {
			continue
		}
		seen[currentService][router] = true
		out[currentService] = append(out[currentService], router)
	}

	// Top-level keys like "volumes:", "networks:" accidentally match the
	// service-header heuristic. Drop any that didn't accumulate router labels.
	for svc, routers := range out {
		if len(routers) == 0 {
			delete(out, svc)
		}
	}
	return out
}

// ── Compose management ───────────────────────────────────

func appProjectName(tmpl *Template) string {
	return "portcullis-" + tmpl.ID
}

func appEnvPath(tmpl *Template) string {
	// Store per-app .env in Hub data dir (writable), not in templates (read-only)
	envDir := filepath.Join(dataDir, "env")
	os.MkdirAll(envDir, 0755)
	return filepath.Join(envDir, tmpl.ID+".env")
}

func appOverridePath(tmpl *Template) string {
	overrideDir := filepath.Join(dataDir, "overrides")
	os.MkdirAll(overrideDir, 0755)
	return filepath.Join(overrideDir, tmpl.ID+".override.yml")
}

func composeBaseArgs(tmpl *Template) []string {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	envFile := appEnvPath(tmpl)
	args := []string{"compose", "-p", appProjectName(tmpl), "-f", composePath}
	// Include hub-generated override if present
	overridePath := appOverridePath(tmpl)
	if _, err := os.Stat(overridePath); err == nil {
		args = append(args, "-f", overridePath)
	}
	args = append(args, "--project-directory", projectHostDir, "--env-file", envFile)
	return args
}

func composeUp(tmpl *Template) error {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	if err := syncTemplateFiles(tmpl); err != nil {
		return fmt.Errorf("sync template files: %w", err)
	}
	args := append(composeBaseArgs(tmpl), "up", "-d", "--no-deps")
	cmd, cancel := newCmd(context.Background(), composeUpTimeout, "docker", args...)
	defer cancel()
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// syncTemplateFiles publishes a template's support files (config templates,
// entrypoint scripts) to <project>/templates/<id>/ so that relative bind
// mounts like ./templates/<id>/setup.sh resolve on the HOST: compose runs
// with --project-directory = the core checkout on the host, while the
// template itself lives in the Hub's data volume, which the host daemon
// can't address by path. Core mounts ./templates read-write for this.
//
// The copy is staged next to the target and swapped in by rename, so a
// running container never sees a half-written directory.
func syncTemplateFiles(tmpl *Template) error {
	root := filepath.Join(projectDir, "templates")
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	dest := filepath.Join(root, tmpl.ID)
	stage, err := os.MkdirTemp(root, "."+tmpl.ID+".stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	err = filepath.WalkDir(tmpl.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(tmpl.Path, path)
		if rel == "." {
			return nil
		}
		if d.Name() == ".git" {
			return filepath.SkipDir
		}
		target := filepath.Join(stage, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0755)
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			if err := copyFile(path, target); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm())
		default:
			return nil // skip symlinks/devices: never follow out of the template
		}
	})
	if err != nil {
		return err
	}
	old := dest + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return err
		}
	}
	if err := os.Rename(stage, dest); err != nil {
		os.Rename(old, dest) // best-effort rollback
		return err
	}
	return os.RemoveAll(old)
}

func composeDown(tmpl *Template) error {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	args := append(composeBaseArgs(tmpl), "down")
	cmd, cancel := newCmd(context.Background(), composeDownTimeout, "docker", args...)
	defer cancel()
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// composeDownByProject stops an app using only its project name — works even
// without the template's compose file.
func composeDownByProject(id string) error {
	cmd, cancel := newCmd(context.Background(), composeDownTimeout, "docker", "compose", "-p", "portcullis-"+id, "down")
	defer cancel()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// generateComposeOverride writes a compose override file with user-configured
// volume mounts and port bindings. Port ranges and network_mode: host entries
// are declared in the base compose.yml, not the override.
func generateComposeOverride(tmpl *Template, values map[string]string) error {
	overridePath := appOverridePath(tmpl)
	serviceMounts := make(map[string][]string)
	for _, s := range tmpl.Manifest.Settings {
		val := values[s.Key]
		if val == "" || s.Target == nil || s.Target.Mount == "" {
			continue
		}
		if s.Type == "path" {
			if err := validatePathSetting(val); err != nil {
				return fmt.Errorf("setting %s: %w", s.Key, err)
			}
			// JSON string == valid YAML double-quoted scalar: safe for
			// spaces, quotes and '#'.
			mountJSON, _ := json.Marshal(val + ":" + s.Target.Mount)
			mount := string(mountJSON)
			serviceMounts[s.Target.Service] = append(serviceMounts[s.Target.Service], mount)
		}
	}

	servicePorts := make(map[string][]string)
	for _, p := range tmpl.Manifest.Ports {
		if p.Service == "" || p.NetworkModeHost || p.Range != "" {
			continue
		}
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		bind := p.Bind
		if v, ok := values[p.Key+"_BIND"]; ok && v != "" {
			bind = v
		}
		if bind == "" {
			bind = "0.0.0.0"
		}
		if net.ParseIP(bind) == nil {
			return fmt.Errorf("port %s: bind %q is not an IP address", p.Key, bind)
		}
		host := p.Default
		if v, ok := values[p.Key]; ok {
			if v == "" && !p.Required {
				continue
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				host = n
			}
		}
		if host <= 0 || p.Container <= 0 {
			continue
		}
		hostIP := bind
		if strings.Contains(bind, ":") { // IPv6 needs brackets in compose port syntax
			hostIP = "[" + bind + "]"
		}
		entry := fmt.Sprintf("\"%s:%d:%d/%s\"", hostIP, host, p.Container, proto)
		servicePorts[p.Service] = append(servicePorts[p.Service], entry)
	}

	// Traefik per-router tls.options labels driven by the app's auth policy.
	// The policy determines the tier:
	//   - Public (no factors)                 → public@file
	//   - Any path allows mTLS (all-mtls, or  → protected@file (require cert at TLS)
	//     single-mTLS-factor)
	//   - Otherwise                           → authaware@file (cert tolerated)
	policy := resolvePolicy(tmpl.ID)
	tier := tierForPolicy(policy)
	serviceRouterLabels := composeRoutersByService(tmpl)

	services := make(map[string]bool)
	for svc := range serviceMounts {
		services[svc] = true
	}
	for svc := range servicePorts {
		services[svc] = true
	}
	for svc := range serviceRouterLabels {
		services[svc] = true
	}
	if len(services) == 0 {
		os.Remove(overridePath)
		return nil
	}
	svcNames := make([]string, 0, len(services))
	for svc := range services {
		svcNames = append(svcNames, svc)
	}
	sort.Strings(svcNames)

	var buf strings.Builder
	buf.WriteString("# Auto-generated by Portcullis Hub -- do not edit\nservices:\n")
	for _, svc := range svcNames {
		buf.WriteString(fmt.Sprintf("  %s:\n", svc))
		if mounts := serviceMounts[svc]; len(mounts) > 0 {
			buf.WriteString("    volumes:\n")
			for _, m := range mounts {
				buf.WriteString(fmt.Sprintf("      - %s\n", m))
			}
		}
		if ports := servicePorts[svc]; len(ports) > 0 {
			buf.WriteString("    ports:\n")
			for _, p := range ports {
				buf.WriteString(fmt.Sprintf("      - %s\n", p))
			}
		}
		if routers := serviceRouterLabels[svc]; len(routers) > 0 {
			buf.WriteString("    labels:\n")
			for _, r := range routers {
				buf.WriteString(fmt.Sprintf("      traefik.http.routers.%s.tls.options: %s\n", r, tier))
			}
		}
	}
	return writeFileAtomic(overridePath, []byte(buf.String()), 0600)
}

// validatePathSetting checks a host path destined for a "<host>:<container>"
// volume entry in the override YAML.
func validatePathSetting(v string) error {
	// ":" would be parsed by compose as host:container[:mode].
	if hasControlChars(v) || strings.Contains(v, ":") {
		return fmt.Errorf("path %q may not contain ':' or control characters", v)
	}
	return nil
}

// ── Env var management ───────────────────────────────────

// generateAppEnv creates a per-app .env file with only the variables this app needs.
func generateAppEnv(tmpl *Template) error {
	envFile := appEnvPath(tmpl)
	vars := make(map[string]string)

	// Always include PORTCULLIS_DOMAIN
	vars["PORTCULLIS_DOMAIN"] = domain

	// Read existing per-app env (preserve user edits)
	existing, _ := os.ReadFile(envFile)
	for _, line := range strings.Split(string(existing), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}

	// Generate manifest env vars (secrets, API keys)
	for _, v := range tmpl.Manifest.Env {
		if _, exists := vars[v.Key]; exists {
			continue // don't overwrite existing
		}
		switch v.Generate {
		case "random":
			b := make([]byte, 24)
			rand.Read(b)
			vars[v.Key] = hex.EncodeToString(b)[:32]
		default:
			vars[v.Key] = ""
		}
	}

	// Include user settings.
	// NOTE: Caller MUST already hold stateMu (write or read). Do NOT RLock here —
	// Go's sync.RWMutex does not support lock upgrade; if the caller holds a
	// write lock (e.g. enableApp), attempting RLock on the same goroutine
	// deadlocks the entire Hub.
	if settings, ok := state.Settings[tmpl.ID]; ok {
		for k, v := range settings {
			vars[k] = v
		}
	}

	// Also pull any ${VAR} references from compose that might come from core .env
	coreEnv := readEnvFile(filepath.Join(projectDir, ".env"))
	composeData, _ := os.ReadFile(filepath.Join(tmpl.Path, "compose.yml"))
	for ref := range extractEnvRefs(string(composeData)) {
		if _, exists := vars[ref]; !exists {
			if coreVal, ok := coreEnv[ref]; ok {
				vars[ref] = coreVal
			}
		}
	}

	// Write the per-app .env
	var lines []string
	lines = append(lines, "# Auto-generated by Portcullis Hub — do not edit manually")
	lines = append(lines, fmt.Sprintf("# App: %s", tmpl.Manifest.Name))

	// Sort keys for deterministic output
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", k, vars[k]))
	}
	// 0600: contains generated secrets.
	return writeFileAtomic(envFile, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

// readEnvFile parses a .env file into a map.
func readEnvFile(path string) map[string]string {
	result := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// ensureEnvVars appends missing vars to root .env (legacy, used by core services).
func ensureEnvVars(vars []EnvVar) error {
	envFile := filepath.Join(projectDir, ".env")
	existing, _ := os.ReadFile(envFile)
	existingStr := string(existing)
	var additions []string
	for _, v := range vars {
		if strings.Contains(existingStr, v.Key+"=") {
			continue
		}
		var value string
		switch v.Generate {
		case "random":
			b := make([]byte, 24)
			rand.Read(b)
			value = hex.EncodeToString(b)[:32]
		default:
			value = ""
		}
		additions = append(additions, fmt.Sprintf("%s=%s", v.Key, value))
	}
	if len(additions) > 0 {
		f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		for _, line := range additions {
			f.WriteString(line + "\n")
		}
	}
	return nil
}

// ── Keycloak client registration ─────────────────────────

// hubOwnerAttr marks Keycloak clients created by the Hub with the template
// that owns them, so a template can only ever reconcile its own client.
const hubOwnerAttr = "portcullis.hub.template"

// protectedClients are core/built-in clients no template may touch.
var protectedClients = map[string]bool{
	"portcullis-forward-auth": true, "admin-cli": true, "account": true, "account-console": true,
	"broker": true, "realm-management": true, "security-admin-console": true,
}

// hubMayReconcile decides whether an existing client (409 on create) may be
// updated for template id. Tagged clients must carry this template's tag.
// Untagged clients (created before tagging existed) are adopted only if every
// existing redirect URI points at a host the template itself declares.
func hubMayReconcile(existing map[string]interface{}, id string, wantURIs []string) bool {
	cid, _ := existing["clientId"].(string)
	if protectedClients[cid] {
		return false
	}
	if attrs, ok := existing["attributes"].(map[string]interface{}); ok {
		if owner, ok := attrs[hubOwnerAttr].(string); ok && owner != "" {
			return owner == id
		}
	}
	hosts := map[string]bool{}
	for _, u := range wantURIs {
		if pu, err := url.Parse(u); err == nil && pu.Host != "" {
			hosts[strings.ToLower(pu.Host)] = true
		}
	}
	if len(hosts) == 0 {
		return false
	}
	existingURIs, _ := existing["redirectUris"].([]interface{})
	for _, raw := range existingURIs {
		str, _ := raw.(string)
		pu, err := url.Parse(str)
		if err != nil || !hosts[strings.ToLower(pu.Host)] {
			return false
		}
	}
	return true
}

// registerKeycloakClient creates (or, if it already exists, reconciles) the
// app's OIDC client. acrValue is the policy-derived default.acr.values.
func registerKeycloakClient(client KeycloakClient, tmpl *Template, acrValue string) error {
	// Read secret from per-app .env first, then fall back to core .env
	secretVal := ""
	if client.SecretEnv != "" {
		for _, envPath := range []string{appEnvPath(tmpl), filepath.Join(projectDir, ".env")} {
			if v := readEnvFile(envPath)[client.SecretEnv]; v != "" {
				secretVal = v
				break
			}
		}
	}

	var redirectURIs []string
	if len(client.RedirectURIs) > 0 {
		for _, uri := range client.RedirectURIs {
			redirectURIs = append(redirectURIs, strings.ReplaceAll(uri, "{{DOMAIN}}", domain))
		}
	} else if client.RedirectURI != "" {
		redirectURIs = []string{strings.ReplaceAll(client.RedirectURI, "{{DOMAIN}}", domain)}
	}

	kcURL, token, err := keycloakAdminToken()
	if err != nil {
		return err
	}

	// Policy-driven client attributes: surface the app's acr to Keycloak via
	// default.acr.values so step-up fires for the right LoA, and include the
	// "acr" client scope so the acr/amr claims land in tokens.
	rep := map[string]interface{}{
		"clientId":                  client.ClientID,
		"name":                      client.Name,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"secret":                    secretVal,
		"redirectUris":              redirectURIs,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": false,
		"attributes": map[string]string{
			"default.acr.values": acrValue,
			hubOwnerAttr:         tmpl.ID,
		},
		"defaultClientScopes": []string{"openid", "profile", "email", "acr"},
	}
	code, err := kcDo("POST", kcURL+"/admin/realms/portcullis/clients", token, rep, nil)
	if err != nil {
		return fmt.Errorf("client registration failed: %w", err)
	}
	switch code {
	case 201:
		log.Printf("Registered Keycloak client %s", client.ClientID)
		return nil
	case 409:
		// Already exists (re-enable, or env regenerated). Reconcile secret,
		// redirect URIs and ACR so the app's .env and Keycloak agree —
		// otherwise logins fail with "invalid client credentials".
		existing, err := findKeycloakClient(kcURL, token, client.ClientID)
		if err != nil {
			return err
		}
		if !hubMayReconcile(existing, tmpl.ID, redirectURIs) {
			log.Printf("Keycloak client %s already exists and is not owned by template %s — left untouched", client.ClientID, tmpl.ID)
			return nil
		}
		attrs, _ := existing["attributes"].(map[string]interface{})
		if attrs == nil {
			attrs = map[string]interface{}{}
		}
		attrs[hubOwnerAttr] = tmpl.ID
		existing["attributes"] = attrs
		if secretVal != "" {
			existing["secret"] = secretVal
		}
		if len(redirectURIs) > 0 {
			existing["redirectUris"] = redirectURIs
		}
		withACR(existing, acrValue)
		if err := putKeycloakClient(kcURL, token, existing); err != nil {
			return err
		}
		log.Printf("Updated existing Keycloak client %s", client.ClientID)
		return nil
	default:
		return fmt.Errorf("client %s registration: unexpected HTTP %d", client.ClientID, code)
	}
}

// ── Source management ────────────────────────────────────

var (
	sourceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	sourceURLRe  = regexp.MustCompile(`^(https?://[^\s]+|ssh://[^\s]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+)$`)
)

var sourceOps sync.Map

func addSource(name, repoURL string) error {
	if !sourceNameRe.MatchString(name) {
		return fmt.Errorf("invalid source name (use lowercase letters, digits, - and _)")
	}
	if !sourceURLRe.MatchString(repoURL) {
		return fmt.Errorf("invalid source URL (https://, http://, ssh:// or user@host:path)")
	}

	stateMu.RLock()
	for _, s := range state.Sources {
		if s.Name == name {
			stateMu.RUnlock()
			return fmt.Errorf("source already exists: %s", name)
		}
	}
	stateMu.RUnlock()

	if _, busy := sourceOps.LoadOrStore(name, struct{}{}); busy {
		return fmt.Errorf("source %s is already being added", name)
	}
	defer sourceOps.Delete(name)

	repoDir := filepath.Join(dataDir, "repos", name)
	if _, err := os.Stat(repoDir); err == nil {
		return fmt.Errorf("directory for source %s already exists", name)
	}
	// Clone without holding the lock — a slow network must not freeze the Hub.
	// "--" stops a URL starting with "-" from being parsed as an option.
	cmd, cancel := newCmd(context.Background(), gitTimeout, "git", "clone", "--depth=1", "--", repoURL, repoDir)
	defer cancel()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(repoDir)
		return fmt.Errorf("git clone failed: %w", err)
	}

	stateMu.Lock()
	for _, s := range state.Sources {
		if s.Name == name { // lost a race with a concurrent add
			stateMu.Unlock()
			return fmt.Errorf("source already exists: %s", name)
		}
	}
	state.Sources = append(state.Sources, Source{Name: name, URL: repoURL, Path: repoDir})
	saveState()
	stateMu.Unlock()

	discoverTemplates()
	if err := writeGroupGatePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
	return nil
}

func removeSource(name string) error {
	if name == "portcullis" {
		return fmt.Errorf("cannot remove the default template source")
	}

	stateMu.RLock()
	var src *Source
	for i := range state.Sources {
		if state.Sources[i].Name == name {
			c := state.Sources[i]
			src = &c
		}
	}
	var running []Template
	for _, id := range state.Enabled {
		if t := findTemplate(id); t != nil && t.Source == name {
			running = append(running, *t)
		}
	}
	stateMu.RUnlock()
	if src == nil {
		return fmt.Errorf("source not found: %s", name)
	}

	// Stop this source's apps while their compose files still exist —
	// deleting the repo first would orphan the containers.
	for i := range running {
		if err := disableApp(running[i].ID); err != nil {
			return fmt.Errorf("could not stop %s before removing source: %w", running[i].ID, err)
		}
	}

	stateMu.Lock()
	newSources := make([]Source, 0, len(state.Sources))
	for _, s := range state.Sources {
		if s.Name != name {
			newSources = append(newSources, s)
		}
	}
	state.Sources = newSources
	saveState()
	stateMu.Unlock()

	if src.Path != "" && within(filepath.Join(dataDir, "repos"), src.Path) {
		os.RemoveAll(src.Path)
	}
	discoverTemplates()
	return writeGroupGatePolicy()
}

func syncSources() error {
	stateMu.RLock()
	sources := make([]Source, len(state.Sources))
	copy(sources, state.Sources)
	stateMu.RUnlock()

	var failed []string
	for _, s := range sources {
		if s.Path == "" {
			continue
		}
		cmd, cancel := newCmd(context.Background(), gitTimeout, "git", "-C", s.Path, "pull", "--ff-only")
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			log.Printf("sync %s: %v: %s", s.Name, err, strings.TrimSpace(string(out)))
			failed = append(failed, s.Name)
		}
	}

	discoverTemplates()
	if err := writeGroupGatePolicy(); err != nil {
		log.Printf("auth-policy: group-gate policy write failed: %v", err)
	}
	if len(failed) > 0 {
		return fmt.Errorf("sync failed for: %s (local edits from Expert mode block fast-forward pulls; see hub logs)", strings.Join(failed, ", "))
	}
	return nil
}

// ── HTTP Handlers ────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tmpl, err := template.ParseFS(webFS, "web/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Network lookup first, without holding stateMu.
	user := r.Header.Get("X-Forwarded-User")
	if user != "" {
		user = resolveUsername(user)
	}

	stateMu.RLock()
	defer stateMu.RUnlock()

	// Group by category
	categories := make(map[string][]Template)
	for _, t := range templates {
		categories[t.Manifest.Category] = append(categories[t.Manifest.Category], t)
	}

	portalName := os.Getenv("PORTAL_DISPLAY_NAME")
	if portalName == "" {
		portalName = "Portcullis"
	}

	data := map[string]interface{}{
		"Domain":     domain,
		"PortalName": portalName,
		"Templates":  templates,
		"Categories": categories,
		"Sources":    state.Sources,
		"User":       user,
	}
	tmpl.Execute(w, data)
}

func handleTemplates(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

func handleEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := enableApp(req.ID); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "enabled", "id": req.ID})
}

func handleDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := disableApp(req.ID); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "disabled", "id": req.ID})
}

func handleSources(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state.Sources)
}

func handleAddSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Name == "" || req.URL == "" {
		http.Error(w, "name and url required", 400)
		return
	}

	if err := addSource(req.Name, req.URL); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "name": req.Name})
}

func handleRemoveSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := removeSource(req.Name); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "name": req.Name})
}

func handleSyncSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if err := syncSources(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	defer stateMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":    domain,
		"templates": len(templates),
		"enabled":   len(state.Enabled),
		"sources":   len(state.Sources),
	})
}

func handleTemplateSettings(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/settings/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		stateMu.RLock()
		values := state.Settings[id]
		override, hasOverride := state.AuthPolicies[id]
		effective := resolvePolicy(id)
		defaultPolicy := state.DefaultPolicy
		stateMu.RUnlock()
		resp := map[string]interface{}{
			"definitions":      tmpl.Manifest.Settings,
			"ports":            tmpl.Manifest.Ports,
			"values":           values,
			"effective_policy": effective,
			"default_policy":   defaultPolicy,
			"safety_score":     safetyScore(effective),
		}
		if hasOverride {
			resp["auth_policy"] = override
		}
		json.NewEncoder(w).Encode(resp)
	case http.MethodPut:
		// Request body accepts the existing key=value settings map plus two
		// reserved keys: _auth_policy (a JSON object) and _auth_policy_inherit
		// ("true" clears the per-app override and falls back to the default).
		var raw map[string]interface{}
		if !decodeJSON(w, r, &raw) {
			return
		}
		var policyUpdate *AuthPolicy
		var policyInherit bool
		if v, ok := raw["_auth_policy_inherit"]; ok {
			switch tv := v.(type) {
			case bool:
				policyInherit = tv
			case string:
				policyInherit = tv == "true"
			}
			delete(raw, "_auth_policy_inherit")
		}
		if v, ok := raw["_auth_policy"]; ok && v != nil {
			if m, ok := v.(map[string]interface{}); ok {
				p := AuthPolicy{}
				if fs, ok := m["factors"].([]interface{}); ok {
					for _, f := range fs {
						if s, ok := f.(string); ok {
							p.Factors = append(p.Factors, s)
						}
					}
				}
				if s, ok := m["op"].(string); ok {
					p.Op = s
				}
				norm := normalizePolicy(p)
				policyUpdate = &norm
			}
			delete(raw, "_auth_policy")
		}
		values := make(map[string]string, len(raw))
		for k, v := range raw {
			if s, ok := v.(string); ok {
				values[k] = s
			}
		}
		// Every key/value ends up in the per-app .env and possibly the
		// compose override: no odd keys, no newlines.
		for k, v := range values {
			if !envKeyRe.MatchString(k) {
				http.Error(w, fmt.Sprintf("invalid setting key %q", k), 400)
				return
			}
			if hasControlChars(v) {
				http.Error(w, fmt.Sprintf("setting %s contains control characters", k), 400)
				return
			}
		}
		for _, st := range tmpl.Manifest.Settings {
			if v := values[st.Key]; v != "" && st.Type == "path" {
				if err := validatePathSetting(v); err != nil {
					http.Error(w, fmt.Sprintf("setting %s: %v", st.Key, err), 400)
					return
				}
			}
		}
		// Validate declared ports: numeric, in range, or empty (only if
		// optional); bind addresses must be IPs.
		for _, p := range tmpl.Manifest.Ports {
			if b := values[p.Key+"_BIND"]; b != "" && net.ParseIP(b) == nil {
				http.Error(w, fmt.Sprintf("bind address for %s must be an IP address", p.Key), 400)
				return
			}
			v, ok := values[p.Key]
			if !ok {
				continue
			}
			if v == "" {
				if p.Required {
					http.Error(w, fmt.Sprintf("port %s is required", p.Key), 400)
					return
				}
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				http.Error(w, fmt.Sprintf("port %s must be 1-65535", p.Key), 400)
				return
			}
		}
		stateMu.Lock()
		prev := state.Settings[id]
		state.Settings[id] = values
		live := findTemplate(id)
		enabled := live != nil && live.Enabled
		// Re-check port collisions if this app is currently enabled.
		if enabled {
			if err := checkPortCollisions(tmpl); err != nil {
				state.Settings[id] = prev
				stateMu.Unlock()
				http.Error(w, err.Error(), 409)
				return
			}
		}

		// Apply auth-policy update alongside the settings save so a single UI
		// submission is one atomic state change.
		policyChanged := false
		if policyInherit {
			if _, had := state.AuthPolicies[id]; had {
				delete(state.AuthPolicies, id)
				policyChanged = true
			}
		} else if policyUpdate != nil {
			if state.AuthPolicies == nil {
				state.AuthPolicies = map[string]AuthPolicy{}
			}
			state.AuthPolicies[id] = *policyUpdate
			policyChanged = true
		}

		saveState()
		effective := resolvePolicy(id)
		// The override reads state (policy → TLS tier), so render it while
		// still holding the lock.
		overrideErr := generateComposeOverride(tmpl, values)
		stateMu.Unlock()
		if overrideErr != nil {
			http.Error(w, "settings saved but override generation failed: "+overrideErr.Error(), 500)
			return
		}

		// Write text/boolean/select settings to the per-app .env — including
		// empty values, so clearing a field actually clears it.
		envPath := appEnvPath(tmpl)
		for _, st := range tmpl.Manifest.Settings {
			if st.Type != "text" && st.Type != "boolean" && st.Type != "select" {
				continue
			}
			if v, ok := values[st.Key]; ok {
				if err := setEnvVar(envPath, st.Key, v); err != nil {
					http.Error(w, "failed to write env: "+err.Error(), 500)
					return
				}
			}
		}

		if policyChanged {
			if err := writeGroupGatePolicy(); err != nil {
				log.Printf("auth-policy: failed to write group-gate policy file: %v", err)
			}
			// Push default.acr.values to any Keycloak clients this app owns.
			acr := policyACR(effective)
			for _, client := range tmpl.Manifest.Clients {
				if err := updateClientAcrLoAMap(client.ClientID, acr); err != nil {
					log.Printf("auth-policy: keycloak client %s update failed: %v", client.ClientID, err)
				}
			}
		}

		if enabled {
			go restartApp(*tmpl)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

func samePolicy(a, b AuthPolicy) bool {
	return a.Op == b.Op && strings.Join(a.Factors, ",") == strings.Join(b.Factors, ",")
}

// restartApp recreates an app's containers so new env/override/labels take
// effect. Runs in the background; serialised with other ops on the same app.
func restartApp(tmpl Template) {
	// Wait for any in-flight op on this app instead of dropping the restart —
	// the in-flight op may have read the old env/override. compose reads the
	// files at run time, so a queued restart always applies the latest ones.
	deadline := time.Now().Add(composeUpTimeout + composeDownTimeout)
	var unlock func()
	for {
		u, err := lockApp(tmpl.ID)
		if err == nil {
			unlock = u
			break
		}
		if time.Now().After(deadline) {
			log.Printf("restart %s gave up: %v", tmpl.ID, err)
			return
		}
		time.Sleep(2 * time.Second)
	}
	defer unlock()
	if err := composeDown(&tmpl); err != nil {
		log.Printf("restart %s: compose down failed: %v", tmpl.ID, err)
	}
	if err := composeUp(&tmpl); err != nil {
		log.Printf("restart %s: compose up failed: %v", tmpl.ID, err)
	}
}

// applyDefaultPolicy propagates a changed global default to every enabled
// app that inherits it: regenerate overrides (Traefik TLS tier), push the
// Keycloak acr, and recreate the containers so the new labels apply.
var defaultPolicyMu sync.Mutex

func applyDefaultPolicy() {
	defaultPolicyMu.Lock()
	defer defaultPolicyMu.Unlock()
	stateMu.Lock()
	var affected []Template
	for _, id := range state.Enabled {
		if _, override := state.AuthPolicies[id]; override {
			continue
		}
		t := findTemplate(id)
		if t == nil {
			continue
		}
		before, _ := os.ReadFile(appOverridePath(t))
		if err := generateComposeOverride(t, state.Settings[id]); err != nil {
			log.Printf("default-policy: override for %s failed: %v", id, err)
			continue
		}
		after, _ := os.ReadFile(appOverridePath(t))
		if !bytes.Equal(before, after) {
			affected = append(affected, *t) // TLS tier changed → needs recreate
		} else if len(t.Manifest.Clients) > 0 {
			affected = append(affected, Template{ID: t.ID, Manifest: t.Manifest}) // acr only
		}
	}
	acr := policyACR(state.DefaultPolicy)
	stateMu.Unlock()

	for _, t := range affected {
		for _, client := range t.Manifest.Clients {
			if err := updateClientAcrLoAMap(client.ClientID, acr); err != nil {
				log.Printf("default-policy: keycloak client %s update failed: %v", client.ClientID, err)
			}
		}
		if t.Path != "" {
			restartApp(t)
		}
	}
}

// handleSettings exposes Hub-global settings — today just the default auth
// policy. GET returns it; PUT accepts {factors, op} and writes through to the
// group-gate policy file.
func handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		stateMu.RLock()
		dp := state.DefaultPolicy
		stateMu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"default_auth_policy":  dp,
			"default_safety_score": safetyScore(dp),
		})
	case http.MethodPut:
		var req struct {
			DefaultAuthPolicy *AuthPolicy `json:"default_auth_policy"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.DefaultAuthPolicy == nil {
			http.Error(w, "expected {default_auth_policy: {factors, op}}", 400)
			return
		}
		norm := normalizePolicy(*req.DefaultAuthPolicy)
		stateMu.Lock()
		changed := !samePolicy(state.DefaultPolicy, norm)
		state.DefaultPolicy = norm
		saveState()
		stateMu.Unlock()
		if !changed {
			json.NewEncoder(w).Encode(map[string]string{"status": "unchanged"})
			return
		}
		if err := writeGroupGatePolicy(); err != nil {
			log.Printf("settings: failed to write group-gate policy file: %v", err)
		}
		go applyDefaultPolicy()
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

// handleUsers lists users in the Keycloak realm so the admin UI can pick
// one to push a required action onto.
func handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	users, err := listRealmUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// handleUserActions replaces a user's requiredActions. Today the only
// action the UI surfaces is webauthn-register-passwordless.
func handleUserActions(w http.ResponseWriter, r *http.Request) {
	// Path shape: /api/users/{id}/required-actions
	path := strings.TrimPrefix(r.URL.Path, "/api/users/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[1] != "required-actions" {
		http.NotFound(w, r)
		return
	}
	userID := parts[0]
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", 405)
		return
	}
	var req struct {
		Actions []string `json:"actions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// Allowlist to prevent arbitrary action injection.
	allowed := map[string]bool{
		"webauthn-register-passwordless": true,
		"webauthn-register":              true,
		"UPDATE_PASSWORD":                true,
	}
	clean := make([]string, 0, len(req.Actions))
	for _, a := range req.Actions {
		if allowed[a] {
			clean = append(clean, a)
		}
	}
	if err := setUserRequiredActions(userID, clean); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "saved", "actions": clean})
}

// composeServices reads the compose.yml and returns the list of service names.
func composeServices(tmpl *Template) []string {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil
	}
	var compose struct {
		Services map[string]interface{} `yaml:"services"`
	}
	if yaml.Unmarshal(data, &compose) != nil {
		return nil
	}
	names := make([]string, 0, len(compose.Services))
	for name := range compose.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func handleTemplateStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/status/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	// Get service names from compose file, pass them to ps to filter
	services := composeServices(tmpl)
	args := append(composeBaseArgs(tmpl), "ps", "--format", "json")
	args = append(args, services...)
	cmd, cancel := newCmd(r.Context(), composeQueryTimeout, "docker", args...)
	defer cancel()
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, err := cmd.Output()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode([]ContainerStatus{})
		return
	}
	var statuses []ContainerStatus
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		statuses = append(statuses, ContainerStatus{
			Name:   fmt.Sprint(raw["Name"]),
			State:  fmt.Sprint(raw["State"]),
			Status: fmt.Sprint(raw["Status"]),
		})
	}
	json.NewEncoder(w).Encode(statuses)
}

func handleTemplateLogs(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/logs/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "200"
	}
	if n, err := strconv.Atoi(lines); err != nil || n < 1 || n > 10000 {
		http.Error(w, "lines must be 1-10000", 400)
		return
	}
	services := composeServices(tmpl)
	// Only services from this app's compose file — and never anything that
	// could be parsed as a flag (e.g. service=-f would follow forever).
	if service := r.URL.Query().Get("service"); service != "" {
		valid := false
		for _, svc := range services {
			if svc == service {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid service", 400)
			return
		}
		services = []string{service}
	}
	args := append(composeBaseArgs(tmpl), "logs", "--tail", lines, "--no-color", "--")
	args = append(args, services...)
	cmd, cancel := newCmd(r.Context(), composeQueryTimeout, "docker", args...)
	defer cancel()
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, _ := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(out)
}

// ── Expert mode handlers ─────────────────────────────────

func handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/compose/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	composePath := filepath.Join(tmpl.Path, "compose.yml")

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(composePath)
		if err != nil {
			http.Error(w, "compose.yml not found", 404)
			return
		}
		// Also read override if present
		overridePath := appOverridePath(tmpl)
		override, _ := os.ReadFile(overridePath)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"compose":  string(data),
			"override": string(override),
		})
	case http.MethodPut:
		var req struct {
			Compose  string `json:"compose"`
			Override string `json:"override"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		// Validate both documents before writing anything.
		var check interface{}
		if err := yaml.Unmarshal([]byte(req.Compose), &check); err != nil {
			http.Error(w, "Invalid YAML: "+err.Error(), 400)
			return
		}
		if req.Override != "" {
			if err := yaml.Unmarshal([]byte(req.Override), &check); err != nil {
				http.Error(w, "Invalid override YAML: "+err.Error(), 400)
				return
			}
		}
		if err := writeFileAtomic(composePath, []byte(req.Compose), 0644); err != nil {
			http.Error(w, "Failed to write: "+err.Error(), 500)
			return
		}
		overridePath := appOverridePath(tmpl)
		if req.Override != "" {
			if err := writeFileAtomic(overridePath, []byte(req.Override), 0600); err != nil {
				http.Error(w, "Failed to write override: "+err.Error(), 500)
				return
			}
		} else {
			os.Remove(overridePath)
		}
		// Host() rules may have changed → refresh subdomain policy/groups.
		if err := writeGroupGatePolicy(); err != nil {
			log.Printf("auth-policy: group-gate policy write failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

func handleTemplateEnv(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/env/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}

	// Read the per-app .env file
	appEnv := appEnvPath(tmpl)
	envData, _ := os.ReadFile(appEnv)
	services := composeServices(tmpl)

	switch r.Method {
	case http.MethodGet:
		// Build key-value map from per-app .env
		result := make(map[string]string)
		for _, line := range strings.Split(string(envData), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			result[parts[0]] = parts[1]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"variables": result,
			"services":  services,
		})
	case http.MethodPut:
		var req map[string]string
		if !decodeJSON(w, r, &req) {
			return
		}
		for key, val := range req {
			if !envKeyRe.MatchString(key) || hasControlChars(val) {
				http.Error(w, fmt.Sprintf("invalid variable %q (keys: [A-Za-z_][A-Za-z0-9_]*, values: no newlines)", key), 400)
				return
			}
		}
		for key, val := range req {
			if err := setEnvVar(appEnv, key, val); err != nil {
				http.Error(w, "failed to write env: "+err.Error(), 500)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

// extractEnvRefs finds all ${VAR} and ${VAR:-default} references in a string.
func extractEnvRefs(s string) map[string]bool {
	refs := make(map[string]bool)
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				continue
			}
			varExpr := s[i+2 : i+end]
			// Strip :-default suffix
			if idx := strings.Index(varExpr, ":-"); idx >= 0 {
				varExpr = varExpr[:idx]
			}
			refs[varExpr] = true
		}
	}
	return refs
}

func handleTemplateExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/exec/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Service string `json:"service"`
		Command string `json:"command"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Service == "" || req.Command == "" {
		http.Error(w, "service and command required", 400)
		return
	}
	// Validate service name is in the compose file
	valid := false
	for _, svc := range composeServices(tmpl) {
		if svc == req.Service {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, "invalid service: "+req.Service, 400)
		return
	}
	// Execute: docker compose exec <service> <shell> -c <command>
	args := append(composeBaseArgs(tmpl), "exec", "-T", req.Service, "/bin/sh", "-c", req.Command)
	// Bounded: the docker CLI is killed on timeout or when the browser goes
	// away. Note this does not kill the process inside the container.
	ctx, cancelCtx := context.WithTimeout(r.Context(), execTimeout)
	defer cancelCtx()
	cmd, cancel := newCmd(ctx, execTimeout, "docker", args...)
	defer cancel()
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		out = append(out, []byte(fmt.Sprintf("\n[hub: command timed out after %s]\n", execTimeout))...)
	}
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"output":   string(out),
		"exitCode": exitCode,
	})
}

func handleTemplateRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/restart/")
	tmpl := getTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	if !tmpl.Enabled {
		http.Error(w, "app not enabled", 400)
		return
	}
	go restartApp(*tmpl)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	data, err := webFS.ReadFile("web/" + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	}
	w.Write(data)
}

// setEnvVar updates or appends a key=value in the given .env file.
func setEnvVar(envFile, key, value string) error {
	data, err := os.ReadFile(envFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[i] = key + "=" + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	return writeFileAtomic(envFile, []byte(strings.Join(lines, "\n")), 0600)
}

// ── Helpers ──────────────────────────────────────────────

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
