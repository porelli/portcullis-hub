package httpapi

import (
	"net/http"
)

// The HA page (contract §20.1 "The HA page"): Settings → High
// availability, Hub listener, administrators, Kubernetes only (409 "high
// availability needs Kubernetes" elsewhere: Docker and Podman don't
// change). Read-only: GET /api/ha is the checklist, the live state and
// the command. Turning HA on is CLI-only (`./portcullis ha enable`, D5):
// there is no enable route, so POST /api/ha/enable is a 404. MCP tool
// ha_status (R); the CLI twin is GET /host/ha (hostctl.go).

func (s *Server) registerHA(mux routeMux) {
	mux.HandleFunc("GET /api/ha", s.handleHA)
}

func (s *Server) handleHA(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	v, err := s.Hub.HA(r.Context())
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, v)
}
