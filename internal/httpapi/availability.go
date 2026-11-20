package httpapi

import (
	"net/http"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// Instance availability (contract §20.6): Hub listener, administrators
// (the instance-settings rule), Kubernetes only (409 "availability needs
// Kubernetes" before the body is read). The GET has its MCP tool
// instance_availability_get (R); the PUT has none and refuses an MCP or
// AI actor (raising an instance's priority stays an admin's action in
// the Hub: availabilityNoToolRoutes).

func (s *Server) registerAvailability(mux routeMux) {
	mux.HandleFunc("GET /api/instances/{id}/availability", s.handleInstanceAvailability)
	mux.HandleFunc("PUT /api/instances/{id}/availability", s.handleSetInstanceAvailability)
}

// availabilityBody is the PUT's body (strict: an unknown key is a 400).
type availabilityBody struct {
	Priority       string        `json:"priority"`
	RunsOn         *state.RunsOn `json:"runs_on"`
	ConfirmNMinus1 bool          `json:"confirm_n_minus_1"`
}

const availabilityUsage = `{"priority": "critical|high|normal|low", "runs_on": {"mode": "anywhere|prefer|only", "class"?, "site"?, "nodes"?: [...]}, "confirm_n_minus_1"?: true}`

func (s *Server) handleInstanceAvailability(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	v, err := s.Hub.InstanceAvailability(r.Context(), id)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, v)
}

func (s *Server) handleSetInstanceAvailability(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	noStore(w)
	if requestActor(r).Via != "" {
		http.Error(w, "not allowed: an instance's availability is changed in the Hub only, never through MCP or AI", http.StatusForbidden)
		return
	}
	if err := s.Hub.AvailabilityOn(); err != nil {
		writeErr(w, err, http.StatusConflict)
		return
	}
	var b availabilityBody
	if !decodeStrict(w, r, &b, availabilityUsage) {
		return
	}
	a := state.Availability{Priority: b.Priority}
	if b.RunsOn != nil {
		a.RunsOn = *b.RunsOn
	}
	s.rec("SetAvailability", id, a, b.ConfirmNMinus1)
	v, err := s.Hub.SetAvailability(r.Context(), id, a, b.ConfirmNMinus1, requestActor(r))
	if err != nil {
		if n1 := hub.ErrorsAsN1(err); n1 != nil {
			writeJSONStatus(w, http.StatusConflict, map[string]any{"error": n1.Msg, "n_minus_1": n1.Results})
			return
		}
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, v)
}
