package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Icon        string            `yaml:"icon" json:"icon"`
	Category    string            `yaml:"category" json:"category"`
	Tags        []string          `yaml:"tags" json:"tags"`
	Auth        Auth              `yaml:"auth" json:"auth"`
	Settings    []Setting         `yaml:"settings" json:"settings"`
	Ports       []Port            `yaml:"ports" json:"ports"`
	Env         []EnvVar          `yaml:"env" json:"env"`
	Clients     []KeycloakClient  `yaml:"keycloak_clients" json:"keycloak_clients"`
	ConfigFiles []ConfigFile      `yaml:"config_files" json:"config_files"`
	URLs        []AppURL          `yaml:"urls" json:"urls"`
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
	Enabled         []string                     `json:"enabled" yaml:"enabled"`
	Sources         []Source                     `json:"sources" yaml:"sources"`
	Settings        map[string]map[string]string `json:"settings" yaml:"settings"`
	AuthPolicies    map[string]AuthPolicy        `json:"auth_policies" yaml:"auth_policies"`
	DefaultPolicy   AuthPolicy                   `json:"default_auth_policy" yaml:"default_auth_policy"`
	MigrateVersion  int                          `json:"migrate_version" yaml:"migrate_version"`
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
	lldapUser       string
	lldapPass      string
)

// resolveUsername converts an email (from forward-auth) to an LLDAP username.
func resolveUsername(email string) string {
	if lldapPass == "" || !strings.Contains(email, "@") {
		return email
	}
	// Get LLDAP auth token
	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, lldapUser, lldapPass)
	resp, err := http.Post(lldapURL+"/auth/simple/login", "application/json", strings.NewReader(loginBody))
	if err != nil || resp.StatusCode != 200 {
		return email
	}
	defer resp.Body.Close()
	var tokenResp struct{ Token string `json:"token"` }
	if json.NewDecoder(resp.Body).Decode(&tokenResp) != nil || tokenResp.Token == "" {
		return email
	}
	// Query for user by email
	query := fmt.Sprintf(`{"query":"{users(filters:{eq:{field:\"email\",value:\"%s\"}}){id}}"}`, email)
	req, _ := http.NewRequest("POST", lldapURL+"/api/graphql", strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil || resp2.StatusCode != 200 {
		return email
	}
	defer resp2.Body.Close()
	var gqlResp struct {
		Data struct {
			Users []struct{ ID string `json:"id"` } `json:"users"`
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
	log.Printf("Hub listening on %s (domain: %s)", addr, domain)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ── State persistence ────────────────────────────────────

func statePath() string {
	return filepath.Join(dataDir, "state.yaml")
}

func loadState() {
	data, err := os.ReadFile(statePath())
	if err != nil {
		state = AppState{
			Settings:     make(map[string]map[string]string),
			AuthPolicies: make(map[string]AuthPolicy),
		}
		return
	}
	yaml.Unmarshal(data, &state)
	if state.Settings == nil {
		state.Settings = make(map[string]map[string]string)
	}
	if state.AuthPolicies == nil {
		state.AuthPolicies = make(map[string]AuthPolicy)
	}
}

func saveState() {
	data, _ := yaml.Marshal(&state)
	os.WriteFile(statePath(), data, 0644)
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
	for i := range templates {
		templates[i].Enabled = enabledSet[templates[i].ID]
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
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			log.Printf("Bad manifest in %s: %v", manifestPath, err)
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
		cmd := exec.Command("docker", oldArgs...)
		cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Migration: old stack down for %s: %v (may already be stopped)", id, err)
		}

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

func enableApp(id string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	var tmpl *Template
	for i := range templates {
		if templates[i].ID == id {
			tmpl = &templates[i]
			break
		}
	}
	if tmpl == nil {
		return fmt.Errorf("template not found: %s", id)
	}

	// Check for host port collisions with already-enabled apps.
	if err := checkPortCollisions(tmpl); err != nil {
		return err
	}

	// Check if already enabled
	for _, enabled := range state.Enabled {
		if enabled == id {
			return nil
		}
	}

	// Generate per-app .env file
	if err := generateAppEnv(tmpl); err != nil {
		return fmt.Errorf("env setup failed: %w", err)
	}

	// Write compose override (ports + volume mounts) from current settings.
	if err := generateComposeOverride(tmpl, state.Settings[tmpl.ID]); err != nil {
		return fmt.Errorf("override write failed: %w", err)
	}

	// Copy config files
	for _, cf := range tmpl.Manifest.ConfigFiles {
		src := filepath.Join(tmpl.Path, cf.Src)
		dest := filepath.Join(projectDir, cf.Dest)
		os.MkdirAll(filepath.Dir(dest), 0755)
		if err := copyFile(src, dest); err != nil {
			log.Printf("Warning: failed to copy %s → %s: %v", src, dest, err)
		}
	}

	// Register Keycloak clients
	for _, client := range tmpl.Manifest.Clients {
		if err := registerKeycloakClient(client, tmpl); err != nil {
			log.Printf("Warning: failed to register client %s: %v", client.ClientID, err)
		}
	}

	// Bring up just this app's services. Only record the enable if compose
	// succeeds — otherwise the UI would show a running app that never started.
	if err := composeUp(tmpl); err != nil {
		return fmt.Errorf("compose up failed: %w", err)
	}

	state.Enabled = append(state.Enabled, id)
	tmpl.Enabled = true
	saveState()
	return nil
}

func disableApp(id string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	found := false
	newEnabled := make([]string, 0, len(state.Enabled))
	for _, enabled := range state.Enabled {
		if enabled == id {
			found = true
			continue
		}
		newEnabled = append(newEnabled, enabled)
	}
	if !found {
		return fmt.Errorf("app not enabled: %s", id)
	}

	state.Enabled = newEnabled
	for i := range templates {
		if templates[i].ID == id {
			templates[i].Enabled = false
			break
		}
	}
	saveState()

	// Stop the app's services
	tmpl := findTemplate(id)
	if tmpl != nil {
		return composeDown(tmpl)
	}
	return nil
}

func findTemplate(id string) *Template {
	for i := range templates {
		if templates[i].ID == id {
			return &templates[i]
		}
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

// writeGroupGatePolicy serializes the current per-app auth policies and the
// global default to the JSON file that group-gate reads. Atomic write via
// temp-file + rename so group-gate never sees a partial document.
func writeGroupGatePolicy() error {
	doc := map[string]interface{}{
		"policies": state.AuthPolicies,
		"default":  state.DefaultPolicy,
	}
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	policyDir := dataDir
	target := filepath.Join(policyDir, "group-gate-policy.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, payload, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// updateClientAcrLoAMap pushes a new default.acr.values to a Keycloak client
// so its own authorize requests include the needed acr_values, triggering
// step-up if the session doesn't already meet the level.
func updateClientAcrLoAMap(clientID, acrValue string) error {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}

	// Admin token
	tokenCmd := exec.Command("curl", "-sk",
		keycloakURL+"/realms/master/protocol/openid-connect/token",
		"-d", "client_id=admin-cli",
		"-d", "username="+os.Getenv("KEYCLOAK_ADMIN"),
		"-d", "password="+os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		"-d", "grant_type=password")
	out, err := tokenCmd.Output()
	if err != nil {
		return fmt.Errorf("keycloak auth failed: %w", err)
	}
	var tokenResp map[string]interface{}
	json.Unmarshal(out, &tokenResp)
	token, _ := tokenResp["access_token"].(string)
	if token == "" {
		return fmt.Errorf("no access token from keycloak")
	}

	// Find the internal UUID for this clientId
	listCmd := exec.Command("curl", "-sk",
		keycloakURL+"/admin/realms/portcullis/clients?clientId="+clientID,
		"-H", "Authorization: Bearer "+token)
	out, err = listCmd.Output()
	if err != nil {
		return fmt.Errorf("client lookup failed: %w", err)
	}
	var clients []map[string]interface{}
	if err := json.Unmarshal(out, &clients); err != nil || len(clients) == 0 {
		return fmt.Errorf("client %s not found in keycloak", clientID)
	}
	uuid, _ := clients[0]["id"].(string)
	if uuid == "" {
		return fmt.Errorf("client %s has no uuid", clientID)
	}
	existing := clients[0]

	attrs, _ := existing["attributes"].(map[string]interface{})
	if attrs == nil {
		attrs = map[string]interface{}{}
	}
	attrs["default.acr.values"] = acrValue
	existing["attributes"] = attrs

	scopes, _ := existing["defaultClientScopes"].([]interface{})
	hasACR := false
	for _, s := range scopes {
		if s == "acr" {
			hasACR = true
			break
		}
	}
	if !hasACR {
		scopes = append(scopes, "acr")
	}
	existing["defaultClientScopes"] = scopes

	payload, _ := json.Marshal(existing)
	putCmd := exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
		"-X", "PUT",
		keycloakURL+"/admin/realms/portcullis/clients/"+uuid,
		"-H", "Authorization: Bearer "+token,
		"-H", "Content-Type: application/json",
		"-d", string(payload))
	out, err = putCmd.Output()
	if err != nil {
		return fmt.Errorf("client update failed: %w", err)
	}
	code := strings.TrimSpace(string(out))
	if code != "204" {
		return fmt.Errorf("client %s update: unexpected HTTP %s", clientID, code)
	}
	return nil
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
	args := append(composeBaseArgs(tmpl), "up", "-d", "--no-deps")
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func composeDown(tmpl *Template) error {
	composePath := filepath.Join(tmpl.Path, "compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return nil
	}
	args := append(composeBaseArgs(tmpl), "down")
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
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
			mount := fmt.Sprintf("%s:%s", val, s.Target.Mount)
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
		entry := fmt.Sprintf("\"%s:%d:%d/%s\"", bind, host, p.Container, proto)
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
	return os.WriteFile(overridePath, []byte(buf.String()), 0644)
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
	return os.WriteFile(envFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
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

func registerKeycloakClient(client KeycloakClient, tmpl *Template) error {
	// Read secret from per-app .env first, then fall back to core .env
	secretVal := ""
	for _, envPath := range []string{appEnvPath(tmpl), filepath.Join(projectDir, ".env")} {
		data, err := os.ReadFile(envPath)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, client.SecretEnv+"=") {
				secretVal = strings.TrimPrefix(line, client.SecretEnv+"=")
				break
			}
		}
		if secretVal != "" {
			break
		}
	}

	// Build redirect URI list
	var redirectURIs []string
	if len(client.RedirectURIs) > 0 {
		for _, uri := range client.RedirectURIs {
			redirectURIs = append(redirectURIs, strings.ReplaceAll(uri, "{{DOMAIN}}", domain))
		}
	} else if client.RedirectURI != "" {
		redirectURIs = []string{strings.ReplaceAll(client.RedirectURI, "{{DOMAIN}}", domain)}
	}

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}

	// Get admin token
	cmd := exec.Command("curl", "-sk",
		keycloakURL+"/realms/master/protocol/openid-connect/token",
		"-d", "client_id=admin-cli",
		"-d", "username="+os.Getenv("KEYCLOAK_ADMIN"),
		"-d", "password="+os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		"-d", "grant_type=password")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("keycloak auth failed: %w", err)
	}

	var tokenResp map[string]interface{}
	json.Unmarshal(out, &tokenResp)
	token, _ := tokenResp["access_token"].(string)
	if token == "" {
		return fmt.Errorf("no access token from keycloak")
	}

	// Policy-driven Keycloak client attributes: surface the app's acr to
	// Keycloak via default.acr.values so step-up fires for the right LoA,
	// and include the "acr" client scope so the acr/amr claims land in tokens.
	acrValue := policyACR(resolvePolicy(tmpl.ID))

	// Register client
	payload, _ := json.Marshal(map[string]interface{}{
		"clientId":                client.ClientID,
		"name":                    client.Name,
		"enabled":                 true,
		"protocol":                "openid-connect",
		"publicClient":            false,
		"secret":                  secretVal,
		"redirectUris":            redirectURIs,
		"standardFlowEnabled":     true,
		"directAccessGrantsEnabled": false,
		"attributes": map[string]string{
			"default.acr.values": acrValue,
		},
		"defaultClientScopes": []string{"openid", "profile", "email", "acr"},
	})

	cmd = exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
		keycloakURL+"/admin/realms/portcullis/clients",
		"-H", "Authorization: Bearer "+token,
		"-H", "Content-Type: application/json",
		"-d", string(payload))
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("client registration failed: %w", err)
	}

	code := strings.TrimSpace(string(out))
	if code != "201" && code != "409" {
		return fmt.Errorf("unexpected response: %s", code)
	}
	log.Printf("Registered Keycloak client %s (HTTP %s)", client.ClientID, code)
	return nil
}

// ── Source management ────────────────────────────────────

func addSource(name, url string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	for _, s := range state.Sources {
		if s.Name == name {
			return fmt.Errorf("source already exists: %s", name)
		}
	}

	repoDir := filepath.Join(dataDir, "repos", name)
	cmd := exec.Command("git", "clone", "--depth=1", url, repoDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	state.Sources = append(state.Sources, Source{
		Name: name,
		URL:  url,
		Path: repoDir,
	})
	saveState()

	// Re-discover templates
	stateMu.Unlock()
	discoverTemplates()
	stateMu.Lock()

	return nil
}

func removeSource(name string) error {
	if name == "portcullis" {
		return fmt.Errorf("cannot remove the default template source")
	}
	stateMu.Lock()
	defer stateMu.Unlock()

	found := false
	newSources := make([]Source, 0)
	for _, s := range state.Sources {
		if s.Name == name {
			found = true
			os.RemoveAll(s.Path)
			continue
		}
		newSources = append(newSources, s)
	}
	if !found {
		return fmt.Errorf("source not found: %s", name)
	}

	// Disable any apps from this source
	newEnabled := make([]string, 0)
	for _, id := range state.Enabled {
		tmpl := findTemplate(id)
		if tmpl != nil && tmpl.Source == name {
			continue
		}
		newEnabled = append(newEnabled, id)
	}
	state.Enabled = newEnabled
	state.Sources = newSources
	saveState()

	stateMu.Unlock()
	discoverTemplates()
	stateMu.Lock()

	return nil
}

func syncSources() error {
	stateMu.RLock()
	sources := make([]Source, len(state.Sources))
	copy(sources, state.Sources)
	stateMu.RUnlock()

	for _, s := range sources {
		if s.Path != "" {
			cmd := exec.Command("git", "-C", s.Path, "pull", "--ff-only")
			cmd.Run()
		}
	}

	discoverTemplates()
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

	stateMu.RLock()
	defer stateMu.RUnlock()

	// Group by category
	categories := make(map[string][]Template)
	for _, t := range templates {
		categories[t.Manifest.Category] = append(categories[t.Manifest.Category], t)
	}

	user := r.Header.Get("X-Forwarded-User")
	if user != "" {
		user = resolveUsername(user)
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
	json.NewDecoder(r.Body).Decode(&req)

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
	json.NewDecoder(r.Body).Decode(&req)

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
	json.NewDecoder(r.Body).Decode(&req)

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
	json.NewDecoder(r.Body).Decode(&req)

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
	tmpl := findTemplate(id)
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
		json.NewDecoder(r.Body).Decode(&raw)
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
		// Validate declared ports: numeric, in range, or empty (only if optional).
		for _, p := range tmpl.Manifest.Ports {
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
		// Re-check port collisions if this app is currently enabled.
		var collisionErr error
		if tmpl.Enabled {
			collisionErr = checkPortCollisions(tmpl)
		}
		if collisionErr != nil {
			state.Settings[id] = prev
			stateMu.Unlock()
			http.Error(w, collisionErr.Error(), 409)
			return
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
		stateMu.Unlock()

		// Write text/boolean/select settings to per-app .env
		for _, s := range tmpl.Manifest.Settings {
			if (s.Type == "text" || s.Type == "boolean" || s.Type == "select") && values[s.Key] != "" {
				setEnvVar(appEnvPath(tmpl), s.Key, values[s.Key])
			}
		}
		generateComposeOverride(tmpl, values)

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

		if tmpl.Enabled {
			go func() {
				composeDown(tmpl)
				composeUp(tmpl)
			}()
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
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
			"default_auth_policy": dp,
			"default_safety_score": safetyScore(dp),
		})
	case http.MethodPut:
		var req struct {
			DefaultAuthPolicy *AuthPolicy `json:"default_auth_policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DefaultAuthPolicy == nil {
			http.Error(w, "expected {default_auth_policy: {factors, op}}", 400)
			return
		}
		norm := normalizePolicy(*req.DefaultAuthPolicy)
		stateMu.Lock()
		state.DefaultPolicy = norm
		saveState()
		stateMu.Unlock()
		if err := writeGroupGatePolicy(); err != nil {
			log.Printf("settings: failed to write group-gate policy file: %v", err)
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
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
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	// Get service names from compose file, pass them to ps to filter
	services := composeServices(tmpl)
	args := append(composeBaseArgs(tmpl), "ps", "--format", "json")
	args = append(args, services...)
	cmd := exec.Command("docker", args...)
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
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "200"
	}
	service := r.URL.Query().Get("service")
	args := append(composeBaseArgs(tmpl), "logs", "--tail", lines, "--no-color")
	if service != "" {
		args = append(args, service)
	} else {
		// Only show logs for services defined in this app's compose file
		args = append(args, composeServices(tmpl)...)
	}
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, _ := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

// ── Expert mode handlers ─────────────────────────────────

func handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/compose/")
	tmpl := findTemplate(id)
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
		json.NewDecoder(r.Body).Decode(&req)
		// Validate YAML
		var check interface{}
		if err := yaml.Unmarshal([]byte(req.Compose), &check); err != nil {
			http.Error(w, "Invalid YAML: "+err.Error(), 400)
			return
		}
		if err := os.WriteFile(composePath, []byte(req.Compose), 0644); err != nil {
			http.Error(w, "Failed to write: "+err.Error(), 500)
			return
		}
		overridePath := appOverridePath(tmpl)
		if req.Override != "" {
			os.WriteFile(overridePath, []byte(req.Override), 0644)
		} else {
			os.Remove(overridePath)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", 405)
	}
}

func handleTemplateEnv(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/env/")
	tmpl := findTemplate(id)
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
		json.NewDecoder(r.Body).Decode(&req)
		for key, val := range req {
			setEnvVar(appEnv, key, val)
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
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Service string `json:"service"`
		Command string `json:"command"`
	}
	json.NewDecoder(r.Body).Decode(&req)
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
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=true")
	out, err := cmd.CombinedOutput()
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
	tmpl := findTemplate(id)
	if tmpl == nil {
		http.NotFound(w, r)
		return
	}
	if !tmpl.Enabled {
		http.Error(w, "app not enabled", 400)
		return
	}
	go func() {
		composeDown(tmpl)
		composeUp(tmpl)
	}()
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
func setEnvVar(envFile, key, value string) {
	data, _ := os.ReadFile(envFile)
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
	os.WriteFile(envFile, []byte(strings.Join(lines, "\n")), 0644)
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
