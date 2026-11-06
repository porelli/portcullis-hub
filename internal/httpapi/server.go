package httpapi

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

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
	return ProxySecret(s.Secret, CSRF(s.hubMux().ServeMux)), nil
}

// hubMux is the Hub listener's routes, recorded
// (TestHubListenerRegistersFolderRoutes checks the shared-folder, doctor
// and local-network routes are registered exactly once).
func (s *Server) hubMux() *recordingMux {
	mux := &recordingMux{ServeMux: http.NewServeMux()}
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/static/", s.handleStatic)

	mux.HandleFunc("/api/templates", s.handleTemplates)
	mux.HandleFunc("/api/templates/enable", s.handleEnable)
	mux.HandleFunc("/api/templates/disable", s.handleDisable)
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
	// Hub listener only (never people, contract §11.7).
	s.registerDomains(mux)
	s.registerInstances(mux)
	s.registerSettings(mux)
	s.registerFolders(mux)
	s.registerDoctor(mux)
	return mux
}

// PeopleHandler is the people listener (contract §5.1, people.<domain>,
// any signed-in user): the same chain as Handler (proxy secret → CSRF),
// but only /healthz, the people page and the directory API. No app,
// policy, drift, compose, settings, sources or template routes.
func (s *Server) PeopleHandler() (http.Handler, error) {
	if _, err := fs.Stat(s.Web, "people.html"); err != nil {
		return nil, err
	}
	mux := s.peopleMux()
	return noReferrer(ProxySecret(s.Secret, CSRF(markPeople(mux.ServeMux)))), nil
}

// noReferrer sets Referrer-Policy: no-referrer on every people-listener
// answer (C-M6): the fresh-auth popup's callback (?code=…&state=…) never
// reaches a Referer header or another host's access log.
func noReferrer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// peopleMux is the people listener's routes, recorded
// (TestPeopleListenerHasNoAppRoutes compares them with the allowlist).
func (s *Server) peopleMux() *recordingMux {
	mux := &recordingMux{ServeMux: http.NewServeMux()}
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handlePeoplePage)
	mux.HandleFunc("/static/", s.handlePeopleStatic)
	s.registerDirectory(mux)
	s.registerPeopleApps(mux)
	return mux
}

// routeMux is what route registration needs (a *http.ServeMux, or a
// recordingMux around one).
type routeMux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// recordingMux is a ServeMux that records every pattern registered.
type recordingMux struct {
	*http.ServeMux
	patterns []string
}

func (m *recordingMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, handler)
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
	// Errors that went through an op record were redacted, then clipped
	// (finishOp); anything else is clipped here for display (nothing in it
	// is redacted, so clipping can't let a redaction slip).
	http.Error(w, clipMessage(err.Error(), 2000), code)
}

// clipMessage shortens s to at most n bytes on a rune boundary.
func clipMessage(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
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

// peopleStatic are the assets people.html loads: the people listener
// serves these only (never the Hub's index.html or settings.js).
var peopleStatic = map[string]bool{"directory.js": true, "directory.css": true, "myapps.js": true}

// handlePeopleStatic serves only peopleStatic on the people listener.
func (s *Server) handlePeopleStatic(w http.ResponseWriter, r *http.Request) {
	if !peopleStatic[strings.TrimPrefix(r.URL.Path, "/static/")] {
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
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
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
	// Missing users_<id> / admin_<id> groups are created first, as the
	// signed-in admin (audited in Users & Groups).
	res, err := s.Hub.EnableAs(req.ID, requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "enabled", "id": req.ID, "groups_created": res.GroupsCreated, "warnings": res.Warnings})
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

// handleSyncSources: GET = the last sync's status (start-up, SIGHUP or
// this endpoint; null before any), POST = sync now.
func (s *Server) handleSyncSources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]interface{}{"last": s.Hub.SourceSync()})
		return
	}
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	if err := s.Hub.SyncSources(); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "synced", "last": s.Hub.SourceSync()})
}

// ── settings ─────────────────────────────────────────────

// auditSignIn records a change (or refused change) of an app's sign-in
// mode in the Hub's audit log: switching to the app's own login removes
// Portcullis from in front of it.
func (s *Server) auditSignIn(r *http.Request, id, before, want string, err error) {
	e := directory.AuditEntry{
		Action: "app.sign_in",
		Target: id,
		Detail: before + " -> " + want,
		Result: "ok",
	}
	if want == hub.SignInNative {
		e.Detail += " (app's own login only: no Portcullis sign-in)"
	}
	s.auditAs(requestActor(r), e, err)
}

// auditAs appends e to the Hub's audit log, attributed to a (Actor, Via,
// Client), with Result from err ("refused" for a 4xx StatusError).
func (s *Server) auditAs(a directory.Actor, e directory.AuditEntry, err error) {
	e.Actor, e.Via, e.Client = a.User, a.Via, a.Client
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
			s.auditAs(requestActor(r), directory.AuditEntry{Action: "app.compose_override", Target: id, Detail: detail}, err)
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
