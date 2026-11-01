package httpapi

import (
	"errors"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
)

// User & group management (contract §9). Every route is keyed by LLDAP
// username / group name; mutations take the actor from X-Forwarded-User
// (set by core's group-gate, trusted because of the proxy secret).

func (s *Server) registerDirectory(mux *http.ServeMux) {
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
	mux.HandleFunc("POST /api/directory/groups", s.handleCreateGroup)
	mux.HandleFunc("DELETE /api/directory/groups/{group}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/directory/groups/{group}/members", s.handleAddMember)
	mux.HandleFunc("DELETE /api/directory/groups/{group}/members/{username}", s.handleRemoveMember)
	mux.HandleFunc("GET /api/portal/apps", s.handlePortalApps)
}

func actor(r *http.Request) string { return r.Header.Get("X-Forwarded-User") }

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

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	ov, err := s.Directory.Overview(r.Context(), actor(r))
	if err != nil {
		dirErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, ov)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
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
	res, err := s.Directory.CreateUser(r.Context(), actor(r), req)
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
	if err := s.Directory.UpdateUser(r.Context(), actor(r), r.PathValue("username"), req.Email, req.DisplayName); err != nil {
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
	res, err := s.Directory.DeleteUser(r.Context(), actor(r), r.PathValue("username"), req.Confirm)
	if err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, res)
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
	res, err := s.Directory.SetPassword(r.Context(), actor(r), r.PathValue("username"), req.Password, req.Generate, req.Confirm)
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
	res, err := s.Directory.SendInvite(r.Context(), actor(r), r.PathValue("username"))
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
	if err := s.Directory.RequirePasskey(r.Context(), actor(r), r.PathValue("username")); err != nil {
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
	if err := s.Directory.ClearActions(r.Context(), actor(r), r.PathValue("username")); err != nil {
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
	res, err := s.Directory.RemovePasskeys(r.Context(), actor(r), r.PathValue("username"), req.Confirm, req.Invite)
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
	if err := s.Directory.CreateGroup(r.Context(), actor(r), req.Name); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "created"})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.dirReady(w) {
		return
	}
	var req confirmBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Directory.DeleteGroup(r.Context(), actor(r), r.PathValue("group"), req.Confirm); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "deleted"})
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
	if err := s.Directory.AddMember(r.Context(), actor(r), r.PathValue("group"), req.Username); err != nil {
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
	if err := s.Directory.RemoveMember(r.Context(), actor(r), r.PathValue("group"), r.PathValue("username")); err != nil {
		dirErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "removed"})
}

// handlePortalApps serves the landing portal's app list (contract §10),
// the same document the Hub writes to portal-apps.json.
func (s *Server) handlePortalApps(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.Portal())
}
