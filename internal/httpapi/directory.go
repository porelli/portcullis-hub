package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

// User & group management (contract §9). Every route is keyed by LLDAP
// username / group name; mutations take the actor from X-Forwarded-User
// (set by core's group-gate, trusted because of the proxy secret).

func (s *Server) registerDirectory(mux routeMux) {
	mux.HandleFunc("GET /api/directory", s.handleDirectory)
	mux.HandleFunc("GET /api/directory/audit", s.handleAudit)
	mux.HandleFunc("POST /api/directory/users", s.handleCreateUser)
	mux.HandleFunc("PUT /api/directory/users/{username}", s.handleUpdateUser)
	mux.HandleFunc("DELETE /api/directory/users/{username}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/directory/users/{username}/password", s.handleSetPassword)
	mux.HandleFunc("POST /api/directory/users/{username}/invite", s.handleInvite)
	mux.HandleFunc("POST /api/directory/users/{username}/require-passkey", s.handleRequirePasskey)
	mux.HandleFunc("POST /api/directory/users/{username}/clear-actions", s.handleClearActions)
	mux.HandleFunc("POST /api/directory/users/{username}/remove-passkeys", s.handleRemovePasskeys)
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

// handleAudit: administrators only.
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
	entries, err := s.Directory.Recent(100)
	if err != nil {
		http.Error(w, "read audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	noStore(w)
	writeJSON(w, entries)
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
	var req struct {
		Username string `json:"username"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.addMember(r.Context(), c, r.PathValue("group"), req.Username); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "added"})
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
	res, err := s.removeMember(r.Context(), c, r.PathValue("group"), r.PathValue("username"))
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "removed", "warnings": res.Warnings})
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

func (s *Server) createUser(ctx context.Context, c *directory.Caller, req directory.CreateRequest) (*directory.Result, error) {
	s.rec("CreateUser", req.Username, req.Email, req.DisplayName, req.Groups, req.Onboarding, req.Generate, req.RequirePasskey)
	return s.Directory.CreateUser(ctx, c, req)
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

func (s *Server) addMember(ctx context.Context, c *directory.Caller, group, username string) error {
	s.rec("AddMember", group, username)
	return s.Directory.AddMember(ctx, c, group, username)
}

func (s *Server) removeMember(ctx context.Context, c *directory.Caller, group, username string) (*directory.Result, error) {
	s.rec("RemoveMember", group, username)
	return s.Directory.RemoveMember(ctx, c, group, username)
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

func (s *Server) setGroupRule(ctx context.Context, c *directory.Caller, group string, rule *rules.Expr) error {
	s.rec("SetGroupRule", group, rule)
	return s.Directory.SetGroupRule(ctx, c, group, rule)
}

func (s *Server) convertGroup(ctx context.Context, c *directory.Caller, group string, rule *rules.Expr, keep []string, reviewed *directory.ConvertPreview) error {
	s.rec("ConvertApplyReviewed", group, rule, keep, reviewed)
	return s.Directory.ConvertApplyReviewed(ctx, c, group, rule, keep, reviewed)
}

func (s *Server) addException(ctx context.Context, c *directory.Caller, group string, ex directory.Exception) error {
	s.rec("AddException", group, ex)
	return s.Directory.AddException(ctx, c, group, ex)
}

func (s *Server) removeException(ctx context.Context, c *directory.Caller, group, username string) error {
	s.rec("RemoveException", group, username)
	return s.Directory.RemoveException(ctx, c, group, username)
}

func (s *Server) setMemberExpiry(ctx context.Context, c *directory.Caller, group, username string, until *time.Time) error {
	s.rec("SetMemberExpiry", group, username, until)
	return s.Directory.SetMemberExpiry(ctx, c, group, username, until)
}

func (s *Server) setPermission(ctx context.Context, c *directory.Caller, perm, group string) error {
	s.rec("SetPermission", perm, group)
	return s.Directory.SetPermission(ctx, c, perm, group)
}

func (s *Server) importApply(ctx context.Context, c *directory.Caller, req directory.ApplyRequest) (*directory.ApplyResult, error) {
	s.rec("ImportApply", req)
	return s.Directory.ImportApply(ctx, c, req)
}
