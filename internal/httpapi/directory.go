package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// User & group management (contract §9). Every route is keyed by LLDAP
// username / group name; mutations take the actor from X-Forwarded-User
// (set by core's group-gate, trusted because of the proxy secret).

func (s *Server) registerDirectory(mux routeMux) {
	mux.HandleFunc("GET /api/directory", s.handleDirectory)
	mux.HandleFunc("GET /api/directory/audit", s.handleAudit)
	mux.HandleFunc("GET /api/directory/users/{username}/apps", s.handlePersonApps)
	mux.HandleFunc("GET /api/directory/groups/{group}/uses", s.handleGroupUses)
	mux.HandleFunc("POST /api/directory/users", s.handleCreateUser)
	mux.HandleFunc("PUT /api/directory/users/{username}", s.handleUpdateUser)
	mux.HandleFunc("DELETE /api/directory/users/{username}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/directory/users/{username}/password", s.handleSetPassword)
	mux.HandleFunc("POST /api/directory/users/{username}/invite", s.handleInvite)
	mux.HandleFunc("POST /api/directory/users/{username}/require-passkey", s.handleRequirePasskey)
	mux.HandleFunc("POST /api/directory/users/{username}/clear-actions", s.handleClearActions)
	mux.HandleFunc("POST /api/directory/users/{username}/remove-passkeys", s.handleRemovePasskeys)
	// The person's Sign-in routes (§9.7, D32).
	s.registerSignInHelp(mux)
	// Signing in as someone else: start and Stop (§9.7, part 3).
	s.registerImpersonation(mux)
	mux.HandleFunc("DELETE /api/directory/keycloak-stale/{username}", s.handleRemoveStale)
	mux.HandleFunc("POST /api/directory/groups", s.handleCreateGroup)
	mux.HandleFunc("DELETE /api/directory/groups/{group}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/directory/groups/{group}/members", s.handleAddMember)
	mux.HandleFunc("DELETE /api/directory/groups/{group}/members/{username}", s.handleRemoveMember)

	mux.HandleFunc("GET /api/directory/me", s.handleMe)
	mux.HandleFunc("POST /api/directory/fields", s.handleCreateField)
	mux.HandleFunc("PUT /api/directory/fields/{name}", s.handleUpdateField)
	mux.HandleFunc("DELETE /api/directory/fields/{name}", s.handleDeleteField)
	mux.HandleFunc("PUT /api/directory/users/{username}/details", s.handleSetDetails)
	mux.HandleFunc("POST /api/directory/rules/preview", s.handleRulePreview)
	mux.HandleFunc("PUT /api/directory/groups/{group}/rule", s.handleSetGroupRule)
	mux.HandleFunc("POST /api/directory/groups/{group}/convert-preview", s.handleConvertPreview)
	mux.HandleFunc("POST /api/directory/groups/{group}/convert", s.handleConvert)
	mux.HandleFunc("POST /api/directory/groups/{group}/exceptions", s.handleAddException)
	mux.HandleFunc("DELETE /api/directory/groups/{group}/exceptions/{username}", s.handleRemoveException)
	mux.HandleFunc("PUT /api/directory/groups/{group}/members/{username}/expiry", s.handleSetExpiry)
	mux.HandleFunc("PUT /api/directory/permissions/{perm}", s.handleSetPermission)
	mux.HandleFunc(importReviewPath, s.handleImportReview)
	mux.HandleFunc("POST /api/directory/import/apply", s.handleImportApply)
}

// actor is the username r's changes are attributed to (requestActor's
// User: X-Forwarded-User, or the MCP listener's identity).
func actor(r *http.Request) string { return requestActor(r).User }

// caller resolves the request's Caller (who, admin, delegated
// permissions) once per request; on failure it has written the response.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (*directory.Caller, bool) {
	c, err := s.Directory.CallerAs(r.Context(), requestActor(r))
	if err != nil {
		// On the people listener (any signed-in user) an unavailable
		// directory is reported generically; the detail is logged.
		var de *directory.Error
		if isPeople(r) && (!errors.As(err, &de) || de.Status >= 500) {
			log.Printf("people: resolve caller: %v", err)
			http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
			return nil, false
		}
		dirErr(w, err)
		return nil, false
	}
	return c, true
}

type peopleKey struct{}

// markPeople tags requests of the people listener.
func markPeople(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peopleKey{}, true)))
	})
}

// isPeople: the request came in on the people listener.
func isPeople(r *http.Request) bool { v, _ := r.Context().Value(peopleKey{}).(bool); return v }

// dirErr maps directory errors to statuses; never echoes secrets (the
// service never puts them in errors).
func dirErr(w http.ResponseWriter, err error) {
	var de *directory.Error
	if errors.As(err, &de) {
		http.Error(w, de.Msg, de.Status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

func (s *Server) dirReady(w http.ResponseWriter) bool {
	if s.Directory == nil {
		http.Error(w, "user management not configured", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// noStore: responses can carry a one-time password or invite link.
func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// handleDirectory: any signed-in caller. Admins get the full Overview;
// anyone else the allow-listed PeopleOverview. Without LLDAP the page only
// says why — generically on the people listener (the detail is logged).
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	if err := s.Directory.LLDAP.Available(); err != nil {
		ov, oerr := s.Directory.Overview(r.Context(), actor(r)) // Available false + Reason, no data
		if oerr != nil {
			dirErr(w, oerr)
			return
		}
		noStore(w)
		if isPeople(r) {
			log.Printf("people: directory unavailable: %v", err)
			writeJSON(w, directory.PeopleViewOf(ov))
			return
		}
		writeJSON(w, ov)
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var out interface{}
	var err error
	if c.Admin {
		out, err = s.Directory.OverviewFor(r.Context(), c)
	} else {
		out, err = s.Directory.PeopleOverview(r.Context(), c)
	}
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, out)
}

// auditShown is how many entries the audit view shows (the last 100).
const auditShown = 100

// auditItem is one item of the merged "via AI" view (?via=ai&include=
// access, contract §15.11): an audit entry or an access-log line (§15.8),
// tagged with its source.
type auditItem struct {
	Source string                `json:"source"` // "audit" or "access"
	Time   time.Time             `json:"time"`
	Entry  *directory.AuditEntry `json:"entry,omitempty"`
	Line   *hub.AccessLine       `json:"line,omitempty"`
}

// handleAudit: administrators only. The last 100 entries (of the last
// 8 MiB); ?via=ai only those made through the Portcullis MCP (§9.5),
// ?group=<g> / ?user=<u> only those for that group / person (§9.7,
// auditFilter; combinable, malformed = 400); with &include=access
// merged with the gate's access-log lines, newest first, as auditItems
// (at most 100 of each).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if !c.Admin {
		http.Error(w, "not allowed: admins only", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	via, include := q.Get("via"), q.Get("include")
	switch {
	case via != "" && via != directory.ViaAI:
		http.Error(w, `via must be "ai" or absent`, http.StatusBadRequest)
		return
	case include != "" && include != "access":
		http.Error(w, `include must be "access" or absent`, http.StatusBadRequest)
		return
	case include != "" && via == "":
		http.Error(w, "include=access needs via=ai", http.StatusBadRequest)
		return
	}
	keep, err := auditFilter(via, q.Get("group"), q.Get("user"), q.Has("group"), q.Has("user"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, err := s.Directory.RecentMatching(auditShown, directory.AuditScan, keep)
	if err != nil {
		http.Error(w, "read audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if include == "" {
		noStore(w)
		writeJSON(w, entries)
		return
	}
	lines, err := s.Hub.AccessLog(nil, auditShown)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	items := make([]auditItem, 0, len(entries)+len(lines))
	for i := range entries {
		items = append(items, auditItem{Source: "audit", Time: entries[i].Time, Entry: &entries[i]})
	}
	for i := range lines {
		items = append(items, auditItem{Source: "access", Time: lines[i].Time, Line: &lines[i]})
	}
	// Both lists are newest first; a stable sort keeps each one's order
	// among equal times.
	slices.SortStableFunc(items, func(a, b auditItem) int { return b.Time.Compare(a.Time) })
	noStore(w)
	writeJSON(w, items)
}

// auditFilter is the entries an audit view keeps (nil: all): via (""
// or "ai", checked by the caller), and group / user when given (has*):
// directory.ForGroup / ForUser, all of them at once. A malformed group
// name or username is an error (400).
func auditFilter(via, group, user string, hasGroup, hasUser bool) (func(directory.AuditEntry) bool, error) {
	var keeps []func(directory.AuditEntry) bool
	if via != "" {
		keeps = append(keeps, func(e directory.AuditEntry) bool { return e.Via == via })
	}
	if hasGroup {
		if !lldap.ValidGroupName(group) {
			return nil, errors.New("group is not a valid group name")
		}
		keeps = append(keeps, directory.ForGroup(group))
	}
	if hasUser {
		if !lldap.ValidUsername(strings.ToLower(user)) {
			return nil, errors.New("user is not a valid username")
		}
		keeps = append(keeps, directory.ForUser(user))
	}
	if len(keeps) == 0 {
		return nil, nil
	}
	return func(e directory.AuditEntry) bool {
		for _, k := range keeps {
			if !k(e) {
				return false
			}
		}
		return true
	}, nil
}

// peopleReads is what the two admin reads of the people & groups pages
// need from the Hub (contract §9.7).
type peopleReads interface {
	PersonApps(ctx context.Context, user string) (*hub.PersonAppsView, error)
	GroupUses(ctx context.Context, group string) (*hub.GroupUsesView, error)
}

// peopleReads is the Hub's (nil: no Hub, the routes answer 503).
func (s *Server) peopleReads() peopleReads {
	if s.Hub == nil {
		return nil
	}
	return s.Hub
}

// adminRead resolves the caller of an admin-only read: 401 without an
// identity, 403 for anyone but an administrator (delegates included), 503 while the directory or
// the Hub is unavailable; on false it has written the answer.
func (s *Server) adminRead(w http.ResponseWriter, r *http.Request) (*directory.Caller, peopleReads, bool) {
	if !s.dirReady(w) {
		return nil, nil, false
	}
	if requestActor(r).User == "" {
		http.Error(w, "no signed-in user (X-Forwarded-User)", http.StatusUnauthorized)
		return nil, nil, false
	}
	c, err := s.Directory.CallerAs(r.Context(), requestActor(r))
	if err != nil {
		var de *directory.Error
		if errors.As(err, &de) && de.Status < 500 {
			http.Error(w, de.Msg, de.Status)
			return nil, nil, false
		}
		log.Printf("directory: resolve caller: %v", err)
		http.Error(w, directory.GenericUnavailable, http.StatusServiceUnavailable)
		return nil, nil, false
	}
	if !c.Admin {
		http.Error(w, "not allowed: admins only", http.StatusForbidden)
		return nil, nil, false
	}
	reads := s.peopleReads()
	if reads == nil {
		http.Error(w, "the Hub is not available", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	return c, reads, true
}

// personApps is GET /api/directory/users/{u}/apps' work (and
// get_person_apps'): the username checked (400), then Hub.PersonApps.
func personApps(ctx context.Context, reads peopleReads, user string) (*hub.PersonAppsView, error) {
	if u := strings.ToLower(user); !lldap.ValidUsername(u) {
		return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("not a valid username")}
	}
	return reads.PersonApps(ctx, user)
}

// handlePersonApps: administrators only (contract §9.7).
func (s *Server) handlePersonApps(w http.ResponseWriter, r *http.Request) {
	_, reads, ok := s.adminRead(w, r)
	if !ok {
		return
	}
	v, err := personApps(r.Context(), reads, r.PathValue("username"))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// handleGroupUses: administrators only (contract §9.7).
func (s *Server) handleGroupUses(w http.ResponseWriter, r *http.Request) {
	_, reads, ok := s.adminRead(w, r)
	if !ok {
		return
	}
	v, err := reads.GroupUses(r.Context(), r.PathValue("group"))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req directory.CreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.createUser(r.Context(), c, req)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Email       *string `json:"email"`
		DisplayName *string `json:"display_name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.updateUser(r.Context(), c, r.PathValue("username"), req.Email, req.DisplayName); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "saved"})
}

type confirmBody struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req confirmBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.deleteUser(r.Context(), c, r.PathValue("username"), req.Confirm)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, res)
}

// handleRemoveStale deletes the Keycloak copy of a user LLDAP no longer has.
func (s *Server) handleRemoveStale(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req confirmBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.removeStale(r.Context(), c, r.PathValue("username"), req.Confirm); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "removed"})
}

// removeStale is the stale Keycloak record's removal (route and
// remove_stale_keycloak_user; confirm = the username typed); audited
// keycloak.remove_stale by Users & Groups.
func (s *Server) removeStale(ctx context.Context, c *directory.Caller, username, confirm string) error {
	s.rec("RemoveStaleKeycloakUser", username, confirm)
	return s.Directory.RemoveStaleKeycloakUser(ctx, c, username, confirm)
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Generate bool   `json:"generate"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"` // required for another administrator
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.Directory.SetPassword(r.Context(), c, r.PathValue("username"), req.Password, req.Generate, req.Confirm)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

func (s *Server) handleInvite(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.sendInvite(r.Context(), c, r.PathValue("username"))
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

func (s *Server) handleRequirePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.requirePasskey(r.Context(), c, r.PathValue("username")); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "saved"})
}

func (s *Server) handleClearActions(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.clearActions(r.Context(), c, r.PathValue("username")); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "saved"})
}

func (s *Server) handleRemovePasskeys(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
		Invite  bool   `json:"invite"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.removePasskeys(r.Context(), c, r.PathValue("username"), req.Confirm, req.Invite)
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, res)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.createGroup(r.Context(), c, req.Name)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "created", "warnings": res.Warnings})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req confirmBody
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, err := s.deleteGroup(r.Context(), c, r.PathValue("group"), req.Confirm)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "deleted", "warnings": res.Warnings})
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	// Strict (§9.7): a rule group's reason or an end misspelt must not
	// be dropped silently.
	var req struct {
		Username string     `json:"username"`
		Reason   string     `json:"reason"`
		Until    *time.Time `json:"until"`
	}
	if !decodeStrict(w, r, &req, `{"username": "<user>", "reason"?: "<text>", "until"?: "<RFC 3339>"}`) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	st, err := s.addMember(r.Context(), c, r.PathValue("group"), directory.MemberAdd{Username: req.Username, Reason: req.Reason, Until: req.Until})
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, st.with(map[string]any{"status": "added"}))
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req struct{}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	res, st, err := s.removeMember(r.Context(), c, r.PathValue("group"), r.PathValue("username"))
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, st.with(map[string]any{"status": "removed", "warnings": res.Warnings}))
}

// handlePortalApps serves the landing portal's app list (contract §10),
// the same document the Hub writes to portal-apps.json.
func (s *Server) handlePortalApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.Portal())
}

// ── shared route / tool work (plan 4 Task 18) ───────────
//
// The directory call of each /api/directory mutation, shared by its
// handler and its Portcullis MCP tool (mcptools_directory.go): the same
// Service method with the same arguments (no HTTP loopback, no logic of
// its own), reported to rec for the parity test — never a password.

// settled is what Settle reports (contract §9.7): merged into the
// answer of every membership, exception, rule, convert and expiry
// mutation, and of a create with groups.
type settled struct {
	Applied bool   `json:"applied"`
	Why     string `json:"why,omitempty"`
}

// whyNotAdmin is the only why a non-admin caller (a delegate creating a
// person into groups) is given: the evaluator's reasons may name other
// people, groups or the setup.
const whyNotAdmin = "saved, not applied yet: it applies at the next directory sync"

// settle runs the evaluator after a successful mutation of groups (never
// after a refused one: callers return before it); only those groups'
// problems reach why, and only an admin sees them.
func (s *Server) settle(ctx context.Context, c *directory.Caller, groups ...string) *settled {
	s.rec("Settle", groups)
	applied, why := s.Directory.Settle(ctx, groups...)
	return settledFor(c, applied, why)
}

func settledFor(c *directory.Caller, applied bool, why string) *settled {
	if why != "" && (c == nil || !c.Admin) {
		why = whyNotAdmin
	}
	return &settled{Applied: applied, Why: why}
}

// with merges st's applied / why into an answer.
func (st *settled) with(m map[string]any) map[string]any {
	m["applied"] = st.Applied
	if st.Why != "" {
		m["why"] = st.Why
	}
	return m
}

// createdUser is CreateUser's answer, applied / why added when the
// person was put in groups.
type createdUser struct {
	*directory.Result
	*settled
}

func (s *Server) createUser(ctx context.Context, c *directory.Caller, req directory.CreateRequest) (createdUser, error) {
	s.rec("CreateUser", req.Username, req.Email, req.DisplayName, req.Groups, req.Reasons, req.Onboarding, req.Generate, req.RequirePasskey)
	res, err := s.Directory.CreateUser(ctx, c, req)
	if err != nil {
		return createdUser{}, err
	}
	out := createdUser{Result: res}
	if len(req.Groups) > 0 {
		out.settled = s.settle(ctx, c, req.Groups...)
	}
	return out, nil
}

func (s *Server) updateUser(ctx context.Context, c *directory.Caller, username string, email, displayName *string) error {
	s.rec("UpdateUser", username, email, displayName)
	return s.Directory.UpdateUser(ctx, c, username, email, displayName)
}

func (s *Server) deleteUser(ctx context.Context, c *directory.Caller, username, confirm string) (*directory.Result, error) {
	s.rec("DeleteUser", username, confirm)
	return s.Directory.DeleteUser(ctx, c, username, confirm)
}

func (s *Server) sendInvite(ctx context.Context, c *directory.Caller, username string) (*directory.Result, error) {
	s.rec("SendInvite", username)
	return s.Directory.SendInvite(ctx, c, username)
}

func (s *Server) requirePasskey(ctx context.Context, c *directory.Caller, username string) error {
	s.rec("RequirePasskey", username)
	return s.Directory.RequirePasskey(ctx, c, username)
}

func (s *Server) clearActions(ctx context.Context, c *directory.Caller, username string) error {
	s.rec("ClearActions", username)
	return s.Directory.ClearActions(ctx, c, username)
}

func (s *Server) removePasskeys(ctx context.Context, c *directory.Caller, username, confirm string, withInvite bool) (*directory.Result, error) {
	s.rec("RemovePasskeys", username, confirm, withInvite)
	return s.Directory.RemovePasskeys(ctx, c, username, confirm, withInvite)
}

func (s *Server) createGroup(ctx context.Context, c *directory.Caller, name string) (*directory.Result, error) {
	s.rec("CreateGroup", name)
	return s.Directory.CreateGroup(ctx, c, name)
}

func (s *Server) deleteGroup(ctx context.Context, c *directory.Caller, name, confirm string) (*directory.Result, error) {
	s.rec("DeleteGroup", name, confirm)
	return s.Directory.DeleteGroup(ctx, c, name, confirm)
}

func (s *Server) addMember(ctx context.Context, c *directory.Caller, group string, m directory.MemberAdd) (*settled, error) {
	s.rec("AddMember", group, m)
	if err := s.Directory.AddMember(ctx, c, group, m); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) removeMember(ctx context.Context, c *directory.Caller, group, username string) (*directory.Result, *settled, error) {
	s.rec("RemoveMember", group, username)
	res, err := s.Directory.RemoveMember(ctx, c, group, username)
	if err != nil {
		return nil, nil, err
	}
	return res, s.settle(ctx, c, group), nil
}

func (s *Server) createField(ctx context.Context, c *directory.Caller, f directory.Field) error {
	s.rec("CreateField", f)
	return s.Directory.CreateField(ctx, c, f)
}

func (s *Server) patchField(ctx context.Context, c *directory.Caller, name string, p directory.FieldPatch) (*directory.Field, error) {
	s.rec("PatchField", name, p)
	return s.Directory.PatchField(ctx, c, name, p)
}

func (s *Server) deleteField(ctx context.Context, c *directory.Caller, name, confirm string) error {
	s.rec("DeleteField", name, confirm)
	return s.Directory.DeleteField(ctx, c, name, confirm)
}

func (s *Server) setDetails(ctx context.Context, c *directory.Caller, username string, attrs map[string][]string) error {
	s.rec("SetDetails", username, attrs)
	return s.Directory.SetDetails(ctx, c, username, attrs)
}

func (s *Server) setGroupRule(ctx context.Context, c *directory.Caller, group string, rule *rules.Expr) (*settled, error) {
	s.rec("SetGroupRule", group, rule)
	if err := s.Directory.SetGroupRule(ctx, c, group, rule); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) convertGroup(ctx context.Context, c *directory.Caller, group string, rule *rules.Expr, keep []string, reviewed *directory.ConvertPreview) (*settled, error) {
	s.rec("ConvertApplyReviewed", group, rule, keep, reviewed)
	if err := s.Directory.ConvertApplyReviewed(ctx, c, group, rule, keep, reviewed); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) addException(ctx context.Context, c *directory.Caller, group string, ex directory.Exception) (*settled, error) {
	s.rec("AddException", group, ex)
	if err := s.Directory.AddException(ctx, c, group, ex); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) removeException(ctx context.Context, c *directory.Caller, group, username string) (*settled, error) {
	s.rec("RemoveException", group, username)
	if err := s.Directory.RemoveException(ctx, c, group, username); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) setMemberExpiry(ctx context.Context, c *directory.Caller, group, username string, until *time.Time) (*settled, error) {
	s.rec("SetMemberExpiry", group, username, until)
	if err := s.Directory.SetMemberExpiry(ctx, c, group, username, until); err != nil {
		return nil, err
	}
	return s.settle(ctx, c, group), nil
}

func (s *Server) setPermission(ctx context.Context, c *directory.Caller, perm, group string) error {
	s.rec("SetPermission", perm, group)
	return s.Directory.SetPermission(ctx, c, perm, group)
}

func (s *Server) importApply(ctx context.Context, c *directory.Caller, req directory.ApplyRequest) (*directory.ApplyResult, error) {
	s.rec("ImportApply", req)
	return s.Directory.ImportApply(ctx, c, req)
}
