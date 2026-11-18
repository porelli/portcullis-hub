package httpapi

// SSH access on people.<d> (spec §9.11): the person's card, People →
// person for administrators and sign_in_help holders, and the ssh_access
// holders' delegated grants.

import (
	"errors"
	"net/http"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
)

// peopleSSHRoutes are the people listener's SSH routes.
var peopleSSHRoutes = []string{
	"GET /api/me/ssh",
	"POST /api/me/ssh/revoke-all",
	"GET /api/directory/users/{u}/ssh",
	"POST /api/directory/users/{u}/ssh/revoke-all",
	"GET /api/ssh/delegated/grants",
	"POST /api/ssh/delegated/grants",
	"PUT /api/ssh/delegated/grants/{id}",
	"DELETE /api/ssh/delegated/grants/{id}",
	"POST /api/ssh/delegated/grants/preview",
	"GET /api/ssh/delegated/hostgroups/{id}/access",
}

func (s *Server) registerSSHPeople(mux *recordingMux) {
	h := map[string]http.HandlerFunc{
		"GET /api/me/ssh":                               s.handleMySSH,
		"POST /api/me/ssh/revoke-all":                   s.handleMySSHRevokeAll,
		"GET /api/directory/users/{u}/ssh":              s.handlePersonSSH,
		"POST /api/directory/users/{u}/ssh/revoke-all":  s.handlePersonSSHRevokeAll,
		"GET /api/ssh/delegated/grants":                 s.sshDelegate(s.handleSSHGrants(true)),
		"POST /api/ssh/delegated/grants":                s.sshDelegate(s.handleSSHSaveGrant),
		"PUT /api/ssh/delegated/grants/{id}":            s.sshDelegate(s.handleSSHSaveGrant),
		"DELETE /api/ssh/delegated/grants/{id}":         s.sshDelegate(s.handleSSHDeleteGrant),
		"POST /api/ssh/delegated/grants/preview":        s.sshDelegate(s.handleSSHPreviewGrant),
		"GET /api/ssh/delegated/hostgroups/{id}/access": s.sshDelegate(s.handleDelegatedAccess),
	}
	for _, p := range peopleSSHRoutes {
		mux.HandleFunc(p, h[p])
	}
}

func (s *Server) handleMySSH(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.PersonSSHAccess(user))
}

func (s *Server) handleMySSHRevokeAll(w http.ResponseWriter, r *http.Request) {
	user, ok := mySignInUser(w, r)
	if !ok {
		return
	}
	n, err := s.Hub.RevokeAllSSH(requestActor(r), user, "I lost a device")
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"revoked": n})
}

// sshHelper: an administrator, or a sign_in_help holder who may target u
// (directory.CheckHelp: never an administrator, a protected account or a
// permission-group member — administrators' certificates are revocable
// by administrators only).
func (s *Server) sshHelper(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.dirReady(w) {
		return "", false
	}
	c, ok := s.caller(w, r)
	if !ok {
		return "", false
	}
	u := r.PathValue("u")
	if !cliapi.ValidUsername(u) {
		http.Error(w, "not a username", http.StatusBadRequest)
		return "", false
	}
	if !c.Admin {
		if err := s.Directory.CheckHelp(r.Context(), c, u); err != nil {
			dirErr(w, err)
			return "", false
		}
	}
	return u, true
}

func (s *Server) handlePersonSSH(w http.ResponseWriter, r *http.Request) {
	u, ok := s.sshHelper(w, r)
	if !ok {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.PersonSSHAccess(u))
}

func (s *Server) handlePersonSSHRevokeAll(w http.ResponseWriter, r *http.Request) {
	u, ok := s.sshHelper(w, r)
	if !ok {
		return
	}
	n, err := s.Hub.RevokeAllSSH(requestActor(r), u, "revoked by "+actor(r))
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, map[string]any{"revoked": n})
}

// sshDelegate: an ssh_access holder (or an administrator).
func (s *Server) sshDelegate(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.dirReady(w) {
			return
		}
		c, ok := s.caller(w, r)
		if !ok {
			return
		}
		if !c.Admin && !c.Perms[directory.PermSSHAccess] {
			http.Error(w, "not allowed: needs ssh_access", http.StatusForbidden)
			return
		}
		noStore(w)
		fn(w, r)
	}
}

func (s *Server) handleDelegatedAccess(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	delegable := false
	for _, g := range s.Hub.SSHHostGroups() {
		if g.ID == id {
			delegable = g.Delegable
		}
	}
	if !delegable {
		http.Error(w, "not allowed: that host group isn't delegable", http.StatusForbidden)
		return
	}
	rows, err := s.Hub.SSHAccess("hostgroup", id, r.URL.Query().Get("root") == "1")
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"rows": rows})
}

// dirErrStatus is a directory error's status (0 = not one).
func dirErrStatus(err error) int {
	var de *directory.Error
	if errors.As(err, &de) {
		return de.Status
	}
	return 0
}

// cliapiDecode is cliapi's strict decoding for the admin bodies.
func cliapiDecode(r *http.Request, v any) error {
	return cliapi.DecodeStrict(r.Body, maxBodyBytes, v)
}
