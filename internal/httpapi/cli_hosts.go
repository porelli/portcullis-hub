package httpapi

// The managed-host routes of the CLI listener (contract §18.11).

import (
	"io"
	"net/http"
	"strconv"

	"github.com/portcullis/hub/internal/cliapi"
)

func (s *Server) registerCLIHosts(mux *recordingMux) {
	mux.HandleFunc("POST /api/cli/v1/hosts/enrol/challenge", s.handleEnrolChallenge)
	mux.HandleFunc("POST /api/cli/v1/hosts/enrol", s.handleEnrol)
	mux.HandleFunc("GET /api/cli/v1/hosts/bundle", s.handleHostBundle)
	mux.HandleFunc("POST /api/cli/v1/hosts/report", s.handleHostReport)
}

func (s *Server) handleEnrolChallenge(w http.ResponseWriter, r *http.Request) {
	var req cliapi.EnrolChallengeRequest
	if !cliDecode(w, r, cliapi.MaxSmallRequest, &req) {
		return
	}
	ch, err := s.Hub.EnrolChallenge(req.HostID)
	if err != nil {
		cliHubError(w, err)
		return
	}
	cliJSON(w, http.StatusOK, cliapi.EnrolChallenge{Challenge: ch})
}

func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) {
	var req cliapi.EnrolRequest
	if !cliDecode(w, r, cliapi.MaxEnrolRequest, &req) {
		return
	}
	b, err := s.Hub.Enrol(r.Context(), req, cliAddr(r))
	if err != nil {
		cliHubError(w, err)
		return
	}
	cliJSON(w, http.StatusOK, b)
}

// signedBody reads at most max bytes and checks the host signature over
// them; it answers the error itself and returns ok false.
func (s *Server) signedBody(w http.ResponseWriter, r *http.Request, max int64) (string, []byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		cliError(w, http.StatusBadRequest, "malformed request")
		return "", nil, false
	}
	if int64(len(body)) > max {
		cliError(w, http.StatusRequestEntityTooLarge, "request too large")
		return "", nil, false
	}
	id, err := s.Hub.VerifyHostRequest(r, body)
	if err != nil {
		cliHubError(w, err)
		return "", nil, false
	}
	return id, body, true
}

func (s *Server) handleHostBundle(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.signedBody(w, r, 0)
	if !ok {
		return
	}
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil || since < 0 || len(r.URL.Query()) != 1 {
		cliError(w, http.StatusBadRequest, "since must be a serial")
		return
	}
	b, err := s.Hub.HostBundle(r.Context(), id, since)
	if err != nil {
		cliHubError(w, err)
		return
	}
	if b == nil {
		cliHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cliJSON(w, http.StatusOK, b)
}

func (s *Server) handleHostReport(w http.ResponseWriter, r *http.Request) {
	id, body, ok := s.signedBody(w, r, cliapi.MaxReport)
	if !ok {
		return
	}
	var rep cliapi.Report
	if err := cliapi.UnmarshalStrict(body, &rep); err != nil {
		cliError(w, http.StatusBadRequest, "malformed report")
		return
	}
	if err := s.Hub.HostReport(r.Context(), id, rep); err != nil {
		cliHubError(w, err)
		return
	}
	cliHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}
