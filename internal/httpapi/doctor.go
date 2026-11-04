package httpapi

import (
	"net/http"
	"regexp"
)

// The doctor (contract §14.5–14.6, §14.8, Task 13): Hub listener only,
// admins only (folderAdmin) — previews and both fix routes included —,
// strict bodies (decodeAPI), errors as {"error"} (writeAPIErr).

func (s *Server) registerDoctor(mux routeMux) {
	mux.HandleFunc("GET /api/doctor", s.handleDoctor)
	mux.HandleFunc("POST /api/doctor/scan", s.handleDoctorScan)
	mux.HandleFunc("GET /api/doctor/op", s.handleDoctorOp)
	mux.HandleFunc("POST /api/doctor/findings/{fp}/preview", s.handleFixPreview)
	mux.HandleFunc("POST /api/doctor/findings/{fp}/apply", s.handleFixApply)
	mux.HandleFunc("POST /api/doctor/findings/{fp}/mute", s.handleMute)
	mux.HandleFunc("DELETE /api/doctor/findings/{fp}/mute", s.handleUnmute)
}

const (
	fixPreviewUsage = `{"params": {"<name>": "<value>"}} (params: "fix" picks one of the finding's fixes; rebind_port takes "address", manage_as_folder "name" and "id")`
	fixApplyUsage   = `{"plan_hash": "<hash>", "params": {"<name>": "<value>"}}`
	muteUsage       = `{"reason": "<why, at most 200 characters>"}`
)

// fpRe is a finding's fingerprint (doctor.Fingerprint: 16 hex).
var fpRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// findingFP reads the {fp} path value: anything else is no finding (404).
func findingFP(w http.ResponseWriter, r *http.Request) (string, bool) {
	fp := r.PathValue("fp")
	if !fpRe.MatchString(fp) {
		writeJSONError(w, http.StatusNotFound, "no such finding")
		return "", false
	}
	return fp, true
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	rep, err := s.Hub.Doctor(r.Context())
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, rep)
}

// handleDoctorScan starts the disk checks (202, polled at
// /api/doctor/op); the body is ignored.
func (s *Server) handleDoctorScan(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	op, err := s.Hub.StartDoctorScan(actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeOpAccepted(w, op)
}

func (s *Server) handleDoctorOp(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	s.writeOpRecord(w, "_doctor", "the doctor")
}

func (s *Server) handleFixPreview(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	fp, ok := findingFP(w, r)
	if !ok {
		return
	}
	var b struct {
		Params map[string]string `json:"params"`
	}
	if !decodeAPI(w, r, &b, fixPreviewUsage) {
		return
	}
	p, err := s.Hub.PreviewFix(r.Context(), fp, b.Params)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, p)
}

// handleFixApply → 202 {op_id, op, instance, poll}: a folder fix polls
// the folder's record, a rebind the instance's.
func (s *Server) handleFixApply(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	fp, ok := findingFP(w, r)
	if !ok {
		return
	}
	var b struct {
		PlanHash *string           `json:"plan_hash"`
		Params   map[string]string `json:"params"`
	}
	if !decodeAPI(w, r, &b, fixApplyUsage) {
		return
	}
	if b.PlanHash == nil {
		writeJSONError(w, http.StatusBadRequest, "body must be "+fixApplyUsage)
		return
	}
	op, err := s.Hub.ApplyFix(r.Context(), fp, b.Params, *b.PlanHash, actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeOpAccepted(w, op)
}

func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	fp, ok := findingFP(w, r)
	if !ok {
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decodeAPI(w, r, &b, muteUsage) {
		return
	}
	if err := s.Hub.MuteFinding(r.Context(), fp, b.Reason, actor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUnmute(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	fp, ok := findingFP(w, r)
	if !ok {
		return
	}
	if err := s.Hub.UnmuteFinding(fp, actor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
