package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

const maxBodyBytes = 1 << 20

// Users manages realm users (implemented by *keycloak.Client).
type Users interface {
	ListUsers(ctx context.Context) ([]keycloak.User, error)
	SetRequiredActions(ctx context.Context, userID string, actions []string) error
}

// UsernameResolver maps a forward-auth email to a display username.
type UsernameResolver interface {
	ResolveUsername(ctx context.Context, email string) string
}

// Server holds the HTTP handlers' dependencies.
type Server struct {
	Hub        *hub.Hub
	Users      Users
	Resolver   UsernameResolver
	PortalName string
	Secret     string // HUB_PROXY_SECRET
	Web        fs.FS  // contains index.html

	index *template.Template
}

// Handler returns the full handler chain: proxy secret → CSRF → routes.
func (s *Server) Handler() (http.Handler, error) {
	idx, err := template.ParseFS(s.Web, "index.html")
	if err != nil {
		return nil, err
	}
	s.index = idx
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/static/", s.handleStatic)

	mux.HandleFunc("/api/templates", s.handleTemplates)
	mux.HandleFunc("/api/templates/enable", s.handleEnable)
	mux.HandleFunc("/api/templates/disable", s.handleDisable)
	mux.HandleFunc("/api/templates/settings/", s.handleTemplateSettings)
	mux.HandleFunc("/api/templates/status/", s.handleTemplateStatus)
	mux.HandleFunc("/api/templates/logs/", s.handleTemplateLogs)
	mux.HandleFunc("/api/templates/compose/", s.handleTemplateCompose)
	mux.HandleFunc("/api/templates/env/", s.handleTemplateEnv)
	mux.HandleFunc("/api/templates/exec/", s.handleTemplateExec)
	mux.HandleFunc("/api/templates/restart/", s.handleTemplateRestart)
	mux.HandleFunc("/api/sources", s.handleSources)
	mux.HandleFunc("/api/sources/add", s.handleAddSource)
	mux.HandleFunc("/api/sources/remove", s.handleRemoveSource)
	mux.HandleFunc("/api/sources/sync", s.handleSyncSources)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/drift", s.handleDrift)
	mux.HandleFunc("/api/drift/resolve", s.handleDriftResolve)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/", s.handleUserActions)
	return ProxySecret(s.Secret, CSRF(mux)), nil
}

// ── helpers ──────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// writeErr maps hub errors to HTTP statuses; def is used for plain errors.
func writeErr(w http.ResponseWriter, err error, def int) {
	code := def
	var se *hub.StatusError
	var busy hub.ErrBusy
	switch {
	case errors.As(err, &se):
		code = se.Status
	case errors.As(err, &busy):
		code = http.StatusConflict
	}
	http.Error(w, err.Error(), code)
}

// decodeJSON decodes a size-limited JSON body, writing a 400 on error.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func methodIs(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method != m {
		http.Error(w, m+" only", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// appID extracts and validates the {id} suffix of prefix-routed paths.
func appID(w http.ResponseWriter, r *http.Request, prefix string) (string, bool) {
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if !templates.ValidID(id) {
		http.NotFound(w, r)
		return "", false
	}
	return id, true
}

// ── pages ────────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("ok\n"))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	user := r.Header.Get("X-Forwarded-User")
	if user != "" && s.Resolver != nil {
		user = s.Resolver.ResolveUsername(r.Context(), user)
	}
	ts := s.Hub.Templates()
	categories := make(map[string][]templates.Template)
	for _, t := range ts {
		categories[t.Manifest.Category] = append(categories[t.Manifest.Category], t)
	}
	name := s.PortalName
	if name == "" {
		name = "Portcullis"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.index.Execute(w, map[string]interface{}{
		"Domain":     s.Hub.Domain(),
		"PortalName": name,
		"Templates":  ts,
		"Categories": categories,
		"Sources":    s.Hub.Sources(),
		"User":       user,
	}); err != nil {
		log.Printf("render index: %v", err)
	}
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	data, err := fs.ReadFile(s.Web, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	}
	w.Write(data)
}

// ── catalog & lifecycle ──────────────────────────────────

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.Templates())
}

func (s *Server) handleEnable(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !templates.ValidID(req.ID) {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := s.Hub.Enable(req.ID); err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "enabled", "id": req.ID})
}

func (s *Server) handleDisable(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !templates.ValidID(req.ID) {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := s.Hub.Disable(req.ID); err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "disabled", "id": req.ID})
}

func (s *Server) handleTemplateRestart(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	id, ok := appID(w, r, "/api/templates/restart/")
	if !ok {
		return
	}
	if err := s.Hub.RestartAsync(id); err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "restarting"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	nt, ne, ns := s.Hub.Counts()
	writeJSON(w, map[string]interface{}{
		"domain":    s.Hub.Domain(),
		"templates": nt,
		"enabled":   ne,
		"sources":   ns,
	})
}

// ── drift ────────────────────────────────────────────────

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Hub.Drift())
	case http.MethodPost: // re-check now
		writeJSON(w, s.Hub.Reconcile(r.Context()))
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDriftResolve(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Hub.ResolveDrift(req.ID, req.Action); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "id": req.ID, "action": req.Action})
}

// ── sources ──────────────────────────────────────────────

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.Sources())
}

func (s *Server) handleAddSource(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
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
		http.Error(w, "name and url required", http.StatusBadRequest)
		return
	}
	if err := s.Hub.AddSource(req.Name, req.URL); err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "added", "name": req.Name})
}

func (s *Server) handleRemoveSource(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Hub.RemoveSource(req.Name); err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "removed", "name": req.Name})
}

func (s *Server) handleSyncSources(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	if err := s.Hub.SyncSources(); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "synced"})
}

// ── settings ─────────────────────────────────────────────

func (s *Server) handleTemplateSettings(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/settings/")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, err := s.Hub.AppSettings(id)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, v)
	case http.MethodPut:
		var raw map[string]interface{}
		if !decodeJSON(w, r, &raw) {
			return
		}
		u, err := parseSettingsUpdate(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.Hub.SaveSettings(id, u); err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// parseSettingsUpdate splits the settings PUT body: string values are
// settings, plus two reserved keys — _auth_policy ({factors, op}) and
// _auth_policy_inherit (true/"true" drops the per-app override).
func parseSettingsUpdate(raw map[string]interface{}) (hub.SettingsUpdate, error) {
	var u hub.SettingsUpdate
	if v, ok := raw["_auth_policy_inherit"]; ok {
		switch tv := v.(type) {
		case bool:
			u.Inherit = tv
		case string:
			u.Inherit = tv == "true"
		}
		delete(raw, "_auth_policy_inherit")
	}
	if v, ok := raw["_auth_policy"]; ok && v != nil {
		if m, ok := v.(map[string]interface{}); ok {
			p := policy.AuthPolicy{}
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
			u.Policy = &p
		}
	}
	delete(raw, "_auth_policy")
	u.Values = make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			u.Values[k] = s
		}
	}
	return u, nil
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dp := s.Hub.DefaultPolicy()
		writeJSON(w, map[string]interface{}{
			"default_auth_policy":  dp,
			"default_safety_score": policy.SafetyScore(dp),
		})
	case http.MethodPut:
		var req struct {
			DefaultAuthPolicy *policy.AuthPolicy `json:"default_auth_policy"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.DefaultAuthPolicy == nil {
			http.Error(w, "expected {default_auth_policy: {factors, op}}", http.StatusBadRequest)
			return
		}
		if !s.Hub.SetDefaultPolicy(*req.DefaultAuthPolicy) {
			writeJSON(w, map[string]string{"status": "unchanged"})
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// ── users ────────────────────────────────────────────────

// allowedActions limits what the UI can push onto a user.
var allowedActions = map[string]bool{
	"webauthn-register-passwordless": true,
	"webauthn-register":              true,
	"UPDATE_PASSWORD":                true,
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodGet) {
		return
	}
	if s.Users == nil {
		http.Error(w, "user management not configured", http.StatusServiceUnavailable)
		return
	}
	users, err := s.Users.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, users)
}

func (s *Server) handleUserActions(w http.ResponseWriter, r *http.Request) {
	// /api/users/{id}/required-actions
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/", 2)
	if len(parts) != 2 || parts[1] != "required-actions" || !keycloak.ValidUserID(parts[0]) {
		http.NotFound(w, r)
		return
	}
	if !methodIs(w, r, http.MethodPut) {
		return
	}
	var req struct {
		Actions []string `json:"actions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	clean := make([]string, 0, len(req.Actions))
	for _, a := range req.Actions {
		if allowedActions[a] {
			clean = append(clean, a)
		}
	}
	if s.Users == nil {
		http.Error(w, "user management not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.Users.SetRequiredActions(r.Context(), parts[0], clean); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "saved", "actions": clean})
}

// ── runtime (Engine API) ─────────────────────────────────

func (s *Server) handleTemplateStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/status/")
	if !ok {
		return
	}
	st, err := s.Hub.Status(r.Context(), id)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, st)
}

func (s *Server) handleTemplateLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/logs/")
	if !ok {
		return
	}
	lines := 200
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, "lines must be 1-10000", http.StatusBadRequest)
			return
		}
		lines = n
	}
	out, err := s.Hub.Logs(r.Context(), id, r.URL.Query().Get("service"), lines)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(out)
}

func (s *Server) handleTemplateExec(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	id, ok := appID(w, r, "/api/templates/exec/")
	if !ok {
		return
	}
	var req struct {
		Service string `json:"service"`
		Command string `json:"command"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.Hub.Exec(r.Context(), id, req.Service, req.Command)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
}

// ── expert mode ──────────────────────────────────────────

func (s *Server) handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/compose/")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		c, o, err := s.Hub.ComposeFiles(id)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"compose": c, "override": o})
	case http.MethodPut:
		var req struct {
			Compose  string `json:"compose"`
			Override string `json:"override"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.Hub.SaveComposeFiles(id, req.Compose, req.Override); err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTemplateEnv(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/env/")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		vars, services, err := s.Hub.Env(id)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"variables": vars, "services": services})
	case http.MethodPut:
		var req map[string]string
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := s.Hub.SaveEnv(id, req); err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}
