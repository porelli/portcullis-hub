package httpapi

import (
	"context"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// Instance availability (contract §20.6): Hub listener, administrators
// (the instance-settings rule), Kubernetes only (409 "availability needs
// Kubernetes" whatever the body). The GET's MCP tool is
// instance_availability_get (R), the PUT's set_instance_availability (W;
// with confirm_n_minus_1 it asks the person in the browser, and an AI
// never overrides a red or unknown N−1 result: the Hub's rule).

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
	// Off Kubernetes any body is the 409 (a valid one goes the tool's
	// way, through the Hub, which answers it too).
	var b availabilityBody
	ok = strictBody(w, r, &b)
	if err := s.Hub.AvailabilityOn(); err != nil && !ok {
		writeErr(w, err, http.StatusConflict)
		return
	}
	if !ok {
		http.Error(w, "body must be "+availabilityUsage, http.StatusBadRequest)
		return
	}
	a := state.Availability{Priority: b.Priority}
	if b.RunsOn != nil {
		a.RunsOn = *b.RunsOn
	}
	v, err := s.setAvailability(r.Context(), requestActor(r), id, a, b.ConfirmNMinus1)
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

// setAvailability is the change's work (route and
// set_instance_availability).
func (s *Server) setAvailability(ctx context.Context, actor directory.Actor, id string, a state.Availability, confirm bool) (*hub.AvailabilityView, error) {
	s.rec("SetAvailability", id, a, confirm)
	return s.Hub.SetAvailability(ctx, id, a, confirm, actor)
}
