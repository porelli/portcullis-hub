package httpapi

// Hub → SSH access (contract §18, spec §9.11): the admin routes on the
// Hub listener. Every mutation is audited by the Hub with its action.

import (
	"context"
	"errors"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

func (s *Server) registerSSHAdmin(mux *recordingMux) {
	mux.HandleFunc("GET /api/ssh/settings", s.sshAdmin(s.handleSSHSettings))
	mux.HandleFunc("PUT /api/ssh/settings", s.sshAdmin(s.handleSSHSetSettings))
	mux.HandleFunc("GET /api/ssh/hostgroups", s.sshAdmin(s.handleSSHHostGroups))
	mux.HandleFunc("POST /api/ssh/hostgroups", s.sshAdmin(s.handleSSHSaveHostGroup(true)))
	mux.HandleFunc("PUT /api/ssh/hostgroups/{id}", s.sshAdmin(s.handleSSHSaveHostGroup(false)))
	mux.HandleFunc("DELETE /api/ssh/hostgroups/{id}", s.sshAdmin(s.handleSSHDeleteHostGroup))
	mux.HandleFunc("GET /api/ssh/hostgroups/{id}/access", s.sshAdmin(s.handleSSHAccess("hostgroup")))
	mux.HandleFunc("GET /api/ssh/hosts", s.sshAdmin(s.handleSSHHosts))
	mux.HandleFunc("POST /api/ssh/hosts", s.sshAdmin(s.handleSSHCreateHost))
	mux.HandleFunc("PUT /api/ssh/hosts/{id}", s.sshAdmin(s.handleSSHUpdateHost))
	mux.HandleFunc("DELETE /api/ssh/hosts/{id}", s.sshAdmin(s.handleSSHRemoveHost))
	mux.HandleFunc("POST /api/ssh/hosts/{id}/code", s.sshAdmin(s.handleSSHNewCode))
	mux.HandleFunc("POST /api/ssh/hosts/{id}/accounts/{name}/remove", s.sshAdmin(s.handleSSHRemoveAccount))
	mux.HandleFunc("GET /api/ssh/hosts/{id}/access", s.sshAdmin(s.handleSSHAccess("host")))
	mux.HandleFunc("GET /api/ssh/people/{u}/access", s.sshAdmin(s.handleSSHAccess("person")))
	mux.HandleFunc("GET /api/ssh/grants", s.sshAdmin(s.handleSSHGrants(false)))
	mux.HandleFunc("POST /api/ssh/grants", s.sshAdmin(s.handleSSHSaveGrant))
	mux.HandleFunc("PUT /api/ssh/grants/{id}", s.sshAdmin(s.handleSSHSaveGrant))
	mux.HandleFunc("DELETE /api/ssh/grants/{id}", s.sshAdmin(s.handleSSHDeleteGrant))
	mux.HandleFunc("POST /api/ssh/grants/preview", s.sshAdmin(s.handleSSHPreviewGrant))
	mux.HandleFunc("GET /api/ssh/certificates", s.sshAdmin(s.handleSSHCertificates))
	mux.HandleFunc("POST /api/ssh/certificates/revoke", s.sshAdmin(s.handleSSHRevoke))
	mux.HandleFunc("POST /api/ssh/host-certificates", s.sshAdmin(s.handleSSHSignHostKey))
}

// sshAdmin: administrators only, answers no-store.
func (s *Server) sshAdmin(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.signInAdmin(w, r) {
			return
		}
		noStore(w)
		fn(w, r)
	}
}

// proofBody is the fresh sign-in part of a body.
type proofBody struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

func (p proofBody) proof() freshauth.Proof {
	return freshauth.Proof{Code: p.Code, CodeVerifier: p.CodeVerifier, Nonce: p.Nonce}
}

// proofOrNil is the proof, or nil when the body carries none.
func (p proofBody) proofOrNil() *freshauth.Proof {
	if p.Code == "" {
		return nil
	}
	pp := p.proof()
	return &pp
}

func (s *Server) handleSSHSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.SSHSettings())
}

func (s *Server) handleSSHSetSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled         bool `json:"enabled"`
		DefaultTTLHours int  `json:"default_ttl_hours"`
		proofBody
	}
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	if err := s.Hub.SetSSHSettings(r.Context(), requestActor(r), b.Enabled, b.DefaultTTLHours, b.proofOrNil()); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.Hub.SSHSettings())
}

func (s *Server) handleSSHHostGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"host_groups": s.Hub.SSHHostGroups()})
}

type hostGroupBody struct {
	ID string `json:"id"`
	state.SSHHostGroup
	HostCerts *bool `json:"host_certs"`
	proofBody
}

func (s *Server) handleSSHSaveHostGroup(create bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b hostGroupBody
		if !decodeStrictJSON(w, r, &b) {
			return
		}
		id := b.ID
		if !create {
			id = r.PathValue("id")
		}
		g := b.SSHHostGroup
		if b.HostCerts != nil {
			g.NoHostCerts = !*b.HostCerts
		}
		if err := s.Hub.SaveHostGroup(r.Context(), requestActor(r), id, g, create, b.proofOrNil()); err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleSSHDeleteHostGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.Hub.DeleteHostGroup(requestActor(r), r.PathValue("id")); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSSHAccess(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if kind == "person" {
			id = r.PathValue("u")
		}
		rows, err := s.Hub.SSHAccess(kind, id, r.URL.Query().Get("root") == "1")
		if err != nil {
			writeErr(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"rows": rows})
	}
}

func (s *Server) handleSSHHosts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"hosts": s.Hub.SSHHosts()})
}

func (s *Server) handleSSHCreateHost(w http.ResponseWriter, r *http.Request) {
	var b struct {
		hub.HostInput
		proofBody
	}
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	code, err := s.Hub.CreateHost(r.Context(), requestActor(r), b.HostInput, b.proof())
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	// The code is shown once: never logged, never stored, never in a URL.
	writeJSON(w, map[string]any{"id": b.ID, "code": code})
}

func (s *Server) handleSSHUpdateHost(w http.ResponseWriter, r *http.Request) {
	var b struct {
		hub.HostInput
		proofBody
	}
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	if err := s.Hub.UpdateHost(r.Context(), requestActor(r), r.PathValue("id"), b.HostInput, b.proofOrNil()); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSSHRemoveHost(w http.ResponseWriter, r *http.Request) {
	var b proofBody
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	if err := s.Hub.RemoveHost(r.Context(), requestActor(r), r.PathValue("id"), b.proof()); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSSHNewCode(w http.ResponseWriter, r *http.Request) {
	var b proofBody
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	code, err := s.Hub.NewEnrolCode(r.Context(), requestActor(r), r.PathValue("id"), b.proof())
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": r.PathValue("id"), "code": code})
}

func (s *Server) handleSSHRemoveAccount(w http.ResponseWriter, r *http.Request) {
	if err := s.Hub.RemoveSSHAccount(requestActor(r), r.PathValue("id"), r.PathValue("name")); err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSSHGrants(delegated bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"grants": s.Hub.SSHGrants(delegated)})
	}
}

type grantBody struct {
	state.SSHGrant
	Confirm string `json:"confirm"`
	proofBody
}

func (s *Server) handleSSHSaveGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var b grantBody
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	if id := r.PathValue("id"); id != "" {
		b.SSHGrant.ID = id
	} else {
		b.SSHGrant.ID = ""
	}
	g, err := s.saveSSHGrant(r.Context(), c, b.SSHGrant, b.Confirm, b.proofOrNil())
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	writeJSON(w, g)
}

func (s *Server) handleSSHDeleteGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	if err := s.Hub.DeleteGrant(r.Context(), c, r.PathValue("id")); err != nil {
		writeAnyErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSSHPreviewGrant(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	var g state.SSHGrant
	if !decodeStrictJSON(w, r, &g) {
		return
	}
	rows, err := s.Hub.PreviewGrant(r.Context(), c, g)
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"rows": rows})
}

func (s *Server) handleSSHCertificates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.SSHCertificates(r.URL.Query().Get("user")))
}

func (s *Server) handleSSHRevoke(w http.ResponseWriter, r *http.Request) {
	var b struct {
		User         string   `json:"user"`
		Fingerprints []string `json:"fingerprints"`
	}
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	n, err := s.revokeSSH(r.Context(), requestActor(r), b.User, b.Fingerprints)
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"revoked": n})
}

func (s *Server) handleSSHSignHostKey(w http.ResponseWriter, r *http.Request) {
	var b struct {
		hub.HostKeyRequest
		proofBody
	}
	if !decodeStrictJSON(w, r, &b) {
		return
	}
	ans, err := s.Hub.SignHostKey(r.Context(), requestActor(r), b.HostKeyRequest, b.proof())
	if err != nil {
		writeAnyErr(w, err)
		return
	}
	writeJSON(w, ans)
}

// writeAnyErr answers a Hub or directory error with its status and
// text: a refusal's fixed text; a 5xx with a generic text (the cause
// stays in the Hub's log and audit).
func writeAnyErr(w http.ResponseWriter, err error) {
	code, text := http.StatusInternalServerError, ""
	var se *hub.StatusError
	switch {
	case dirErrStatus(err) != 0:
		code, text = dirErrStatus(err), err.Error()
	case errors.As(err, &se):
		code, text = se.Status, se.Error()
	default:
		code, text = hub.SSHErrorStatus(err)
	}
	if code >= 500 {
		text = "SSH access can't do that right now"
	}
	http.Error(w, text, code)
}

// decodeStrictJSON is decodeJSON with unknown fields refused.
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := cliapiDecode(r, v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// saveSSHGrant is POST|PUT /api/ssh/grants and set_ssh_grant.
func (s *Server) saveSSHGrant(ctx context.Context, c *directory.Caller, g state.SSHGrant, confirm string, p *freshauth.Proof) (*state.SSHGrant, error) {
	if g.Sudo == "" {
		g.Sudo = state.SudoNone
	}
	s.rec("SaveGrant", g.ID, g.Group, g.HostGroup, g.Accounts, g.Sudo, g.TTLHours, g.PortForwarding, g.AgentForwarding)
	return s.Hub.SaveGrant(ctx, c, g, confirm, p)
}

// revokeSSH is POST /api/ssh/certificates/revoke and
// revoke_ssh_certificates: the listed fingerprints, or (none listed) every
// unexpired certificate of user.
func (s *Server) revokeSSH(ctx context.Context, a directory.Actor, user string, fps []string) (int, error) {
	s.rec("RevokeSSH", user, fps)
	if len(fps) == 0 {
		if user == "" {
			return 0, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("name a person or fingerprints")}
		}
		return s.Hub.RevokeAllSSH(a, user, "revoked by "+a.User)
	}
	return s.Hub.RevokeSSHCertificates(a, fps, "revoked by "+a.User)
}
