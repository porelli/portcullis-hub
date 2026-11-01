package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

const maxBodyBytes = 1 << 20

// Server holds the HTTP handlers' dependencies.
type Server struct {
	Hub       *hub.Hub
	Directory *directory.Service // users & groups (nil: page disabled)
	// Audit is the Hub's audit log (audit.jsonl), shared with Directory:
	// app sign-in mode changes and custom override saves go here too.
	Audit      *directory.AuditLog
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
	mux.HandleFunc("/api/templates/lastop/", s.handleTemplateLastOp)
	mux.HandleFunc("/api/sources", s.handleSources)
	mux.HandleFunc("/api/sources/add", s.handleAddSource)
	mux.HandleFunc("/api/sources/remove", s.handleRemoveSource)
	mux.HandleFunc("/api/sources/sync", s.handleSyncSources)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/drift", s.handleDrift)
	mux.HandleFunc("/api/drift/resolve", s.handleDriftResolve)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("GET /api/portal/apps", s.handlePortalApps)
	s.registerDirectory(mux)
	return ProxySecret(s.Secret, CSRF(mux)), nil
}

// PeopleHandler is the people listener (contract §5.1, people.<domain>,
// any signed-in user): the same chain as Handler (proxy secret → CSRF),
// but only /healthz, the people page and the directory API. No app,
// policy, drift, compose, settings, sources or template routes.
func (s *Server) PeopleHandler() (http.Handler, error) {
	if _, err := fs.Stat(s.Web, "people.html"); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handlePeoplePage)
	mux.HandleFunc("/static/", s.handlePeopleStatic)
	s.registerDirectory(mux)
	return ProxySecret(s.Secret, CSRF(mux)), nil
}

// ── helpers ──────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// writeErr maps hub errors to HTTP statuses; def is used for plain errors.
// A failed lifecycle operation (*hub.OpError) is answered as JSON
// {error, op, output, hint, rolled_back}: compose's output is the cause.
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
	var oe *hub.OpError
	if errors.As(err, &oe) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       oe.Record.Error,
			"op":          oe.Record.Op,
			"output":      oe.Record.Output,
			"hint":        oe.Record.Hint,
			"rolled_back": oe.Record.RolledBack,
		})
		return
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
	// Core's group-gate passes the LLDAP username in X-Forwarded-User
	// (and the email in X-Forwarded-Email); the proxy secret guarantees
	// the request came through Traefik. html/template escapes it.
	user := r.Header.Get("X-Forwarded-User")
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
		"Failed":     s.Hub.FailedOps(), // app ID → op, last operation failed
		"User":       user,
	}); err != nil {
		log.Printf("render index: %v", err)
	}
}

// handlePeoplePage serves people.html (static: the page asks the API who
// the caller is).
func (s *Server) handlePeoplePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.Web, "people.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

// handlePeopleStatic serves only the .js and .css assets on the people
// listener (not the Hub's index.html template).
func (s *Server) handlePeopleStatic(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/static/")
	if !strings.HasSuffix(p, ".js") && !strings.HasSuffix(p, ".css") {
		http.NotFound(w, r)
		return
	}
	s.handleStatic(w, r)
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
	if err := s.Hub.RestartApp(id); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "restarted"})
}

// handleTemplateLastOp returns the app's last lifecycle operation (JSON
// null if none) — also for apps that are not enabled (a failed enable).
func (s *Server) handleTemplateLastOp(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodGet) {
		return
	}
	id, ok := appID(w, r, "/api/templates/lastop/")
	if !ok {
		return
	}
	if s.Hub.Template(id) == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, s.Hub.LastOp(id))
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
		before := s.Hub.SignInMode(id)
		err = s.Hub.SaveSettings(id, u)
		if u.SignIn != nil && (err != nil || s.Hub.SignInMode(id) != before) {
			s.auditSignIn(r, id, before, *u.SignIn, err)
		}
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// auditSignIn records a change (or refused change) of an app's sign-in
// mode in the Hub's audit log: switching to the app's own login removes
// Portcullis from in front of it.
func (s *Server) auditSignIn(r *http.Request, id, before, want string, err error) {
	e := directory.AuditEntry{
		Actor:  r.Header.Get("X-Forwarded-User"),
		Action: "app.sign_in",
		Target: id,
		Detail: before + " -> " + want,
		Result: "ok",
	}
	if want == hub.SignInNative {
		e.Detail += " (app's own login only: no Portcullis sign-in)"
	}
	s.audit(e, err)
}

// audit appends e (Result from err) to the Hub's audit log.
func (s *Server) audit(e directory.AuditEntry, err error) {
	l := s.Audit
	if l == nil && s.Directory != nil {
		l = s.Directory.Audit
	}
	if l == nil {
		return
	}
	e.Result = "ok"
	if err != nil {
		e.Result, e.Error = "error", err.Error()
		var se *hub.StatusError
		if errors.As(err, &se) && se.Status < 500 {
			e.Result = "refused"
		}
	}
	if aerr := l.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}

// parseSettingsUpdate splits the settings PUT body: string values are
// settings, plus reserved keys — _sign_in ("gateway"/"native", apps with
// their own login), _auth_policy ({factors, op}),
// _auth_policy_inherit (true/"true" drops the per-app override),
// _public_access (true/false/"default"), _public_mode ("all"/"listed"/""
// for the template default) and _public_tokens (share URLs or tokens).
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
	if v, ok := raw["_sign_in"]; ok {
		m, isStr := v.(string)
		if !isStr {
			return u, fmt.Errorf("_sign_in must be %q or %q", hub.SignInGateway, hub.SignInNative)
		}
		u.SignIn = &m
		delete(raw, "_sign_in")
	}
	if v, ok := raw["_public_access"]; ok {
		// true / false: the admin's choice; "default": back to the
		// template's enabled_by_default.
		switch tv := v.(type) {
		case bool:
			u.PublicAccess = &tv
		case string:
			switch tv {
			case "true", "false":
				on := tv == "true"
				u.PublicAccess = &on
			case "default":
				u.PublicAccessDefault = true
			default:
				return u, fmt.Errorf("_public_access must be true, false or \"default\"")
			}
		default:
			return u, fmt.Errorf("_public_access must be true, false or \"default\"")
		}
		delete(raw, "_public_access")
	}
	if v, ok := raw["_public_mode"]; ok {
		m, isStr := v.(string)
		if !isStr {
			return u, fmt.Errorf("_public_mode must be a string")
		}
		u.PublicMode = &m
		delete(raw, "_public_mode")
	}
	if v, ok := raw["_public_tokens"]; ok {
		list, isList := v.([]interface{})
		if !isList {
			return u, fmt.Errorf("_public_tokens must be a list of share URLs or tokens")
		}
		toks := make([]string, 0, len(list))
		for _, item := range list {
			s, isStr := item.(string)
			if !isStr {
				return u, fmt.Errorf("_public_tokens must be a list of share URLs or tokens")
			}
			toks = append(toks, s)
		}
		u.PublicTokens = &toks
		delete(raw, "_public_tokens")
	}
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
			"factors":              policy.Factors,
			// The stored default named the removed "password" factor and
			// was normalised (shown as a note until saved).
			"legacy_password": s.Hub.DefaultPolicyLegacy(),
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
		changed, err := s.Hub.SetDefaultPolicy(*req.DefaultAuthPolicy)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		if !changed {
			writeJSON(w, map[string]string{"status": "unchanged"})
			return
		}
		writeJSON(w, map[string]string{"status": "saved"})
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
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

// handleTemplateCompose: GET returns the three compose layers (template
// compose.yml and Hub override read-only, the custom override editable);
// PUT {user_override} validates and stores the custom override ("" removes
// it) — it applies on the next restart. Saves are audited
// (app.compose_override), never with the content (it may hold env values).
func (s *Server) handleTemplateCompose(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r, "/api/templates/compose/")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, err := s.Hub.ComposeFiles(id)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, v)
	case http.MethodPut:
		var req struct {
			UserOverride *string `json:"user_override"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.UserOverride == nil {
			http.Error(w, "expected {user_override: \"…\"} (the template's compose.yml and the Hub override are read-only)", http.StatusBadRequest)
			return
		}
		restart, detail, err := s.Hub.SaveUserOverride(id, *req.UserOverride)
		if !errors.Is(err, hub.ErrNotFound) {
			s.audit(directory.AuditEntry{Actor: r.Header.Get("X-Forwarded-User"), Action: "app.compose_override", Target: id, Detail: detail}, err)
		}
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		status := "saved"
		if detail == "removed" {
			status = "removed"
		}
		writeJSON(w, map[string]interface{}{"status": status, "restart_required": restart})
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
