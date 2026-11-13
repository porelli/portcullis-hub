package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/hub"
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
	// PeopleURL overrides the people page's base URL the Hub page links
	// to (Users & Groups, group names, the old #users deep links): ""
	// = https://people.<main domain>/ (the configured Domain, never the
	// browser's host). Only the harness sets it (its people listener's
	// http://127.0.0.1:<port>/).
	PeopleURL string
	// HubURL overrides the Hub's URL in the shared navigation of both
	// pages: "" = https://hub.<main domain>/. Only the harness sets it
	// (its Hub listener's http://127.0.0.1:<port>/).
	HubURL string
	Secret string // HUB_PROXY_SECRET
	// MCPSecret is HUB_MCP_GATE_SECRET (the MCP listener, MCPHandler;
	// "" = no MCP listener).
	MCPSecret string
	Web       fs.FS // contains index.html
	// Docs holds docs/*.md, the docs pages the Portcullis MCP serves as
	// resources (web.Docs; nil = none).
	Docs fs.FS
	// RedactFiles are the Hub's other file secrets (the invite and
	// domains API secrets, the LLDAP service password): every Portcullis
	// MCP result is redacted with their content (G40). A missing file is
	// skipped; an unreadable one hides the result.
	RedactFiles []string
	// RedactLiterals are secrets the Hub holds as values (the Keycloak
	// admin password from KEYCLOAK_ADMIN_PASSWORD): redacted from every
	// Portcullis MCP result too.
	RedactLiterals []string
	// mcp: the Portcullis MCP's registry, servers and redactor cache.
	mcp mcpState
	// callHook, when set (tests), records every Hub call the shared work
	// of a route and its Portcullis MCP tool makes (rec): the twin and the
	// tool must make the same call with the same arguments.
	callHook func(method string, args ...any)

	index *template.Template
	// people: people.html, parsed by PeopleHandler (the main domain
	// injected: its links into the Hub).
	people *template.Template
	// mySignIn: mysignin.html (the Sign-in page, GET /signin on the
	// people listener), parsed by PeopleHandler like people.html.
	mySignIn *template.Template
	// impStop: impersonation-stop.html (the Stop page, GET
	// /impersonation/stop on the people listener), parsed by
	// PeopleHandler.
	impStop *template.Template
	// confirmPage: confirm.html, parsed on first use (confirm.go).
	confirmOnce sync.Once
	confirmPage *template.Template
	confirmErr  error
}

// Handler returns the full handler chain: proxy secret → read-only while
// impersonated → CSRF → routes.
func (s *Server) Handler() (http.Handler, error) {
	idx, err := template.ParseFS(s.Web, "index.html")
	if err != nil {
		return nil, err
	}
	s.index = idx
	// No-referrer on every answer (G11): the confirmation page's popup
	// lands on https://hub.<d>/?code=…&state=… too.
	return noReferrer(ProxySecret(s.Secret, RefuseWhileImpersonated(CSRF(s.hubMux().ServeMux)))), nil
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
	mux.HandleFunc("GET /api/portal/apps", s.handlePortalApps)
	// The container engine (contract §11; Hub listener only).
	mux.HandleFunc("GET /api/runtime", s.handleRuntime)
	s.registerDirectory(mux)
	// Hub listener only (never people, contract §11.7).
	s.registerDomains(mux)
	s.registerInstances(mux)
	s.registerSettings(mux)
	s.registerFolders(mux)
	s.registerDoctor(mux)
	s.registerAI(mux)
	s.registerSignIn(mux)
	// Signing in as someone else: the list and the switch (§8.1).
	s.registerImpersonationAdmin(mux)
	// Confirmations of admin tools (contract §15.6, G12): the same two
	// routes as the people listener's, for this listener's confirmations.
	s.registerConfirm(mux)
	// VPN admin (contract §11; Hub listener only).
	s.registerVPN(mux)
	return mux
}

// PeopleHandler is the people listener (contract §5.1, people.<domain>,
// any signed-in user): the same chain as Handler (proxy secret → CSRF),
// but only /healthz, the people page and the directory API. No app,
// policy, drift, compose, settings, sources or template routes.
func (s *Server) PeopleHandler() (http.Handler, error) {
	pp, err := template.ParseFS(s.Web, "people.html")
	if err != nil {
		return nil, err
	}
	s.people = pp
	ms, err := template.ParseFS(s.Web, "mysignin.html")
	if err != nil {
		return nil, err
	}
	s.mySignIn = ms
	is, err := template.ParseFS(s.Web, "impersonation-stop.html")
	if err != nil {
		return nil, err
	}
	s.impStop = is
	mux := s.peopleMux()
	return noReferrer(ProxySecret(s.Secret, RefuseWhileImpersonated(CSRF(markPeople(mux.ServeMux))))), nil
}

// noReferrer sets Referrer-Policy: no-referrer on every answer of the
// people and Hub listeners (C-M6, G11): the fresh-auth popup's callback
// (?code=…&state=…) never reaches a Referer header or another host's
// access log.
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
	// The VPN page and People → person's VPN devices (contract §5.1,
	// §9.7): people listener only.
	s.registerVPNPeople(mux)
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

// rec reports a Hub call to callHook (tests; nil = nothing).
func (s *Server) rec(method string, args ...any) {
	if s.callHook != nil {
		s.callHook(method, args...)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// writeErr maps hub errors to HTTP statuses; def is used for plain errors.
// A failed lifecycle operation (*hub.OpError) is answered as JSON
// {error, op, output, hint, rolled_back}: compose's output is the cause.
func writeErr(w http.ResponseWriter, err error, def int) {
	code := errStatus(err, def)
	if rec := opRecordOf(err); rec != nil {
		writeRecordErr(w, code, rec)
		return
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
	// The engine guard's refusal: its own message, without the client's
	// request decoration ("error during connect: Get …").
	var refused *docker.RefusedError
	if errors.As(err, &refused) {
		http.Error(w, clipMessage(refused.Message(), 2000), code)
		return
	}
	// Errors that went through an op record were redacted, then clipped
	// (finishOp); anything else is clipped here for display (nothing in it
	// is redacted, so clipping can't let a redaction slip).
	http.Error(w, clipMessage(err.Error(), 2000), code)
}

// recordError is a refusal that answers an op record as its body: a
// Stop refused (409 with the current record, contract §11.7 "Stop").
type recordError struct {
	err error
	rec *hub.OpRecord
}

func (e *recordError) Error() string { return e.err.Error() }
func (e *recordError) Unwrap() error { return e.err }

// opRecordOf is the op record a refusal answers as its JSON body (nil:
// none): a busy instance's running record (*hub.BusyError, contract §11.7
// "One operation per instance"; a lock held by work with no record stays
// the plain-text busy refusal) or a refused Stop's (recordError).
func opRecordOf(err error) *hub.OpRecord {
	var re *recordError
	if errors.As(err, &re) && re.rec != nil {
		return re.rec
	}
	var be *hub.BusyError
	if errors.As(err, &be) && be.Record != nil {
		return be.Record
	}
	return nil
}

// writeRecordErr answers code with rec (redacted when it was written) as
// JSON.
func writeRecordErr(w http.ResponseWriter, code int, rec *hub.OpRecord) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSONStatus(w, code, rec)
}

// errStatus is the HTTP status writeErr answers for err: a StatusError's,
// 409 for ErrBusy, 503 for the engine guard's refusal (contract §6), else
// def.
func errStatus(err error, def int) int {
	var se *hub.StatusError
	var busy hub.ErrBusy
	switch {
	case errors.Is(err, docker.ErrEngineRefused):
		return http.StatusServiceUnavailable
	case errors.As(err, &se):
		return se.Status
	case errors.As(err, &busy):
		return http.StatusConflict
	}
	return def
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
		"PeopleURL":  s.PeopleURL,
		"HubURL":     s.HubURL,
		"PortalName": name,
		"Templates":  ts,
		"Categories": categories,
		"Sources":    s.Hub.Sources(),
		"User":       user,
		// The signed-in user is LLDAP's bootstrap admin (checkTarget
		// refuses it in every group: it can't use the apps it installs).
		"BootstrapAdmin": strings.EqualFold(user, directory.CoreAdmin),
	}); err != nil {
		log.Printf("render index: %v", err)
	}
}

// handlePeoplePage serves people.html with the main domain injected (its
// links into the Hub: https://hub.<domain>/, and the shared navigation)
// and the harness's HubURL / PeopleURL overrides; the page asks the API
// who the caller is.
func (s *Server) handlePeoplePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.people == nil {
		http.NotFound(w, r)
		return
	}
	domain := ""
	if s.Hub != nil {
		domain = s.Hub.Domain()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if err := s.people.Execute(w, map[string]any{"Domain": domain, "HubURL": s.HubURL, "PeopleURL": s.PeopleURL}); err != nil {
		log.Printf("render people page: %v", err)
	}
}

// peopleStatic are the assets people.html and the confirmation page
// load, plus the logo and favicon set: the people listener serves these
// only (never the Hub's index.html or settings.js).
var peopleStatic = map[string]bool{"directory.js": true, "impersonation.js": true, "directory.css": true, "myapps.js": true, "myai.js": true, "mysignin.js": true, "confirm.js": true, "freshauth.js": true, "freshauth-callback.js": true,
	"favicon.svg": true, "favicon.ico": true, "apple-touch-icon.png": true, "icon-192.png": true, "icon-512.png": true, "maskable-512.png": true, "site.webmanifest": true, "mark.svg": true}

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
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(path, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	case strings.HasSuffix(path, ".webmanifest"):
		w.Header().Set("Content-Type", "application/manifest+json")
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
	op, err := s.enableInstance(requestActor(r), req.ID)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeAccepted(w, op)
}

// enableInstance is the enable's work (the route and the Portcullis
// MCP's enable_instance), in the background (202, contract §11.7):
// missing users_<id> / admin_<id> groups are created first, as the admin
// (audited in Users & Groups); audited instance.enable by the Hub (an
// invalid id here).
func (s *Server) enableInstance(a directory.Actor, id string) (*hub.AsyncOp, error) {
	if !templates.ValidID(id) {
		err := &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid id")}
		s.auditOpAs(a, id, directory.AuditEntry{Action: "instance.enable", Target: id}, err, http.StatusBadRequest)
		return nil, err
	}
	s.rec("StartEnable", id)
	op, err := s.Hub.StartEnable(id, a)
	return op, defaultStatus(err, http.StatusBadRequest)
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
	op, err := s.disableInstance(requestActor(r), req.ID)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeAccepted(w, op)
}

// disableInstance is the disable's work (route and disable_instance), in
// the background (202); audited instance.disable by the Hub (an invalid
// id here).
func (s *Server) disableInstance(a directory.Actor, id string) (*hub.AsyncOp, error) {
	if !templates.ValidID(id) {
		err := &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid id")}
		s.auditOpAs(a, id, directory.AuditEntry{Action: "instance.disable", Target: id}, err, http.StatusBadRequest)
		return nil, err
	}
	s.rec("StartDisable", id)
	op, err := s.Hub.StartDisable(id, a)
	return op, defaultStatus(err, http.StatusBadRequest)
}

func (s *Server) handleTemplateRestart(w http.ResponseWriter, r *http.Request) {
	if !methodIs(w, r, http.MethodPost) {
		return
	}
	id, ok := appID(w, r, "/api/templates/restart/")
	if !ok {
		return
	}
	op, err := s.restartInstance(requestActor(r), id)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeAccepted(w, op)
}

// restartInstance is the restart's work (route and restart_instance), in
// the background (202); audited instance.restart by the Hub.
func (s *Server) restartInstance(a directory.Actor, id string) (*hub.AsyncOp, error) {
	s.rec("StartRestart", id)
	op, err := s.Hub.StartRestart(id, a)
	return op, defaultStatus(err, http.StatusInternalServerError)
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
	res, err := s.resolveDrift(requestActor(r), req.ID, req.Action)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

// resolveDrift is the drift action's work (route and resolve_drift);
// audited drift.resolve.
func (s *Server) resolveDrift(a directory.Actor, id, action string) (map[string]string, error) {
	s.rec("ResolveDrift", id, action)
	err := s.Hub.ResolveDrift(id, action)
	if templates.ValidID(id) {
		s.auditOpAs(a, id, directory.AuditEntry{Action: "drift.resolve", Target: id, Detail: clipMessage(action, 64)}, err, http.StatusInternalServerError)
	}
	if err != nil {
		return nil, err
	}
	return map[string]string{"status": "ok", "id": id, "action": action}, nil
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
	res, err := s.addSource(requestActor(r), req.Name, req.URL)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, res)
}

// addSource is the add's work (route and add_source); audited source.add.
func (s *Server) addSource(a directory.Actor, name, url string) (map[string]string, error) {
	if name == "" || url == "" {
		return nil, badArg("name and url required")
	}
	s.rec("AddSource", name, url)
	err := s.Hub.AddSource(name, url)
	s.auditOpAs(a, "", directory.AuditEntry{Action: "source.add", Target: clipMessage(name, 64), Detail: sourceURLDetail(url)}, err, http.StatusBadRequest)
	if err != nil {
		return nil, defaultStatus(err, http.StatusBadRequest)
	}
	return map[string]string{"status": "added", "name": name}, nil
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
	res, err := s.removeSource(requestActor(r), req.Name)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, res)
}

// removeSource is the removal's work (route and remove_source); audited
// source.remove.
func (s *Server) removeSource(a directory.Actor, name string) (map[string]string, error) {
	s.rec("RemoveSource", name)
	err := s.Hub.RemoveSource(name)
	s.auditOpAs(a, "", directory.AuditEntry{Action: "source.remove", Target: clipMessage(name, 64)}, err, http.StatusBadRequest)
	if err != nil {
		return nil, defaultStatus(err, http.StatusBadRequest)
	}
	return map[string]string{"status": "removed", "name": name}, nil
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
	res, err := s.syncSources(requestActor(r))
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

// syncSources is the sync's work (route and sync_sources); audited
// source.sync.
func (s *Server) syncSources(a directory.Actor) (map[string]any, error) {
	s.rec("SyncSources")
	err := s.Hub.SyncSources()
	s.auditOpAs(a, "", directory.AuditEntry{Action: "source.sync", Target: "sources"}, err, http.StatusInternalServerError)
	if err != nil {
		return nil, defaultStatus(err, http.StatusInternalServerError)
	}
	return map[string]any{"status": "synced", "last": s.Hub.SourceSync()}, nil
}

// ── settings ─────────────────────────────────────────────

// auditSignIn records a change (or refused change) of an app's sign-in
// mode in the Hub's audit log: switching to the app's own login removes
// Portcullis from in front of it.
func (s *Server) auditSignIn(r *http.Request, id, before, want string, err error) {
	s.auditSignInAs(requestActor(r), id, before, want, err)
}

// auditSignInAs is auditSignIn attributed to a.
func (s *Server) auditSignInAs(a directory.Actor, id, before, want string, err error) {
	e := directory.AuditEntry{
		Action: "app.sign_in",
		Target: id,
		Detail: before + " -> " + want,
		Result: "ok",
	}
	if want == hub.SignInNative {
		e.Detail += " (app's own login only: no Portcullis sign-in)"
	}
	s.auditAs(a, e, err)
}

// auditAs appends e to the Hub's audit log, attributed to a (Actor, Via,
// Client), with Result from err ("refused" for a 4xx StatusError or
// ErrBusy).
func (s *Server) auditAs(a directory.Actor, e directory.AuditEntry, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	s.appendAudit(a, e, errStatus(err, http.StatusInternalServerError), err, msg)
}

// auditOp audits a mutation a handler answered (ruling G57, contract
// §9.5): attributed to requestActor(r) — the MCP identity's via / client
// when r carries one —, Result from the status the answer stands for
// (def for a plain error: 4xx refused, 5xx error), the error redacted like
// instance's op records (Hub.RedactErr; "" = not an instance) and clipped.
// Handlers call it after the Hub call returned: never under Hub.mu.
// Details never hold a secret: callers pass names, never values.
func (s *Server) auditOp(r *http.Request, instance string, e directory.AuditEntry, err error, def int) {
	s.auditOpAs(requestActor(r), instance, e, err, def)
}

// auditOpAs is auditOp attributed to a (the shared work of a route and
// its Portcullis MCP tool).
func (s *Server) auditOpAs(a directory.Actor, instance string, e directory.AuditEntry, err error, def int) {
	msg := ""
	if err != nil {
		msg = clipMessage(s.Hub.RedactErr(instance, err), 600)
	}
	s.appendAudit(a, e, errStatus(err, def), err, msg)
}

func (s *Server) appendAudit(a directory.Actor, e directory.AuditEntry, status int, err error, msg string) {
	e.Actor, e.Via, e.Client = a.User, a.Via, a.Client
	e.Detail = a.AuditDetail(e.Detail)
	l := s.Audit
	if l == nil && s.Directory != nil {
		l = s.Directory.Audit
	}
	if l == nil {
		return
	}
	e.Result = "ok"
	if err != nil {
		e.Result, e.Error = "error", msg
		if status < 500 {
			e.Result = "refused"
		}
	}
	if aerr := l.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
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
	res, err := s.execInstance(r.Context(), requestActor(r), id, req.Service, req.Command)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
}

// execInstance is the exec's work (route and exec); audited
// instance.exec with the service and the exit code only: the command and
// its output may hold anything.
func (s *Server) execInstance(ctx context.Context, a directory.Actor, id, service, command string) (*hub.ExecResult, error) {
	s.rec("Exec", id, service, command)
	res, err := s.Hub.Exec(ctx, id, service, command)
	detail := "service=" + clipMessage(service, 64)
	if res != nil {
		detail += " exit=" + strconv.Itoa(res.ExitCode)
	}
	s.auditOpAs(a, id, directory.AuditEntry{Action: "instance.exec", Target: id, Detail: detail}, err, http.StatusBadGateway)
	if err != nil {
		return nil, defaultStatus(err, http.StatusBadGateway)
	}
	return res, nil
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
		res, err := s.saveUserOverride(requestActor(r), id, *req.UserOverride)
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, res)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// saveUserOverride is the custom override save's work (route and
// save_custom_override); audited app.compose_override, never with the
// content (it may hold env values).
func (s *Server) saveUserOverride(a directory.Actor, id, content string) (map[string]any, error) {
	s.rec("SaveUserOverride", id, content)
	restart, detail, err := s.Hub.SaveUserOverride(id, content)
	if !errors.Is(err, hub.ErrNotFound) {
		s.auditAs(a, directory.AuditEntry{Action: "app.compose_override", Target: id, Detail: detail}, err)
	}
	if err != nil {
		return nil, err
	}
	status := "saved"
	if detail == "removed" {
		status = "removed"
	}
	return map[string]any{"status": status, "restart_required": restart}, nil
}

// defaultStatus gives a plain error (no StatusError, no ErrBusy, no
// OpError) the status its route answers it with, so the Portcullis MCP's
// tool error carries the same status as the HTTP twin.
func defaultStatus(err error, def int) error {
	var se *hub.StatusError
	var busy hub.ErrBusy
	var oe *hub.OpError
	if err == nil || errors.As(err, &se) || errors.As(err, &busy) || errors.As(err, &oe) {
		return err
	}
	return &hub.StatusError{Status: def, Err: err}
}

// sourceURLDetail is a source URL as an audit detail. A URL with a
// scheme and host: scheme://host[:port]/path only — user info, query
// string and fragment dropped (any may carry a token); the path stays (it
// names the repository; a token placed in a path segment would show — the
// residual). Anything else gets a fixed placeholder, never text derived
// from it: "(scp-style source)" for user@host:path, else "(invalid URL)".
func sourceURLDetail(raw string) string {
	if !strings.Contains(raw, "://") {
		if strings.Contains(raw, "@") && strings.Contains(raw, ":") {
			return "(scp-style source)"
		}
		return "(invalid URL)"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "(invalid URL)"
	}
	clean := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return clipMessage(clean.String(), 300)
}
