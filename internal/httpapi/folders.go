package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/settings"
)

// Shared folders and local networks (contract §14.8, Task 13): Hub
// listener only (never people), admins only (folderAdmin: no
// X-Forwarded-User 401, delegates 403, no Users & Groups 503),
// proxy-secret + CSRF like every route. Bodies are strict JSON
// (decodeStrict: DisallowUnknownFields, trailing data refused, 64 KiB, a
// fixed usage message — never the decoder's error). Errors answer
// {"error"} (writeAPIErr) with the Hub's status: 400 bad input, 404
// unknown folder or snapshot, 409 refused / busy / "the setup changed
// since the preview", 503 the Hub's own image not found, 507 no space.

func (s *Server) registerFolders(mux routeMux) {
	mux.HandleFunc("GET /api/folders", s.handleFolders)
	mux.HandleFunc("POST /api/folders", s.handleCreateFolder)
	mux.HandleFunc("PUT /api/folders/{id}", s.handleUpdateFolder)
	mux.HandleFunc("DELETE /api/folders/{id}", s.handleDeleteFolder)
	mux.HandleFunc("POST /api/folders/check", s.handleCheckFolderPath)
	mux.HandleFunc("POST /api/folders/{id}/assign/preview", s.handleAssignPreview)
	mux.HandleFunc("POST /api/folders/{id}/assign/apply", s.handleAssignApply)
	mux.HandleFunc("POST /api/folders/{id}/undo/preview", s.handleUndoPreview)
	mux.HandleFunc("POST /api/folders/{id}/undo/apply", s.handleUndoApply)
	mux.HandleFunc("GET /api/folders/{id}/op", s.handleFolderOp)
	mux.HandleFunc("GET /api/settings/local-networks", s.handleLocalNetworks)
	mux.HandleFunc("PUT /api/settings/local-networks", s.handleSetLocalNetworks)
}

// Usage texts of the bodies (a 400 answers "body must be " + usage).
const (
	folderCreateUsage = `{"id": "<folder id>", "name": "<name>", "path": "<host path>", "description": "<text>", "gid": <number> (optional), "create": true | false}`
	folderUpdateUsage = `{"name": "<name>", "path": "<host path>", "description": "<text>"}`
	folderCheckUsage  = `{"path": "<host path>", "create": true | false}`
	assignUsage       = `{"uses": [{"instance": "<id>", "key": "<option>", "subpath": "<relative path>", "write": true | false}]}`
	assignApplyUsage  = `{"plan_hash": "<hash>", "uses": [{"instance": "<id>", "key": "<option>", "subpath": "<relative path>", "write": true | false}]}`
	undoApplyUsage    = `{"plan_hash": "<hash>"}`
	localNetsUsage    = `{"networks": ["<cidr>", ...] | null}`
)

// folderAdmin: a signed-in admin (no user 401; then adminOnly: no Users
// & Groups 503, anyone else 403).
func (s *Server) folderAdmin(w http.ResponseWriter, r *http.Request) bool {
	if actor(r) == "" {
		writeJSONError(w, http.StatusUnauthorized, "no signed-in user (X-Forwarded-User)")
		return false
	}
	return s.adminOnly(w, r)
}

// folderID reads the {id} path value (settings.FolderIDRe; else 400).
func folderID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !settings.FolderIDRe.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "invalid shared folder id")
		return "", false
	}
	return id, true
}

// writeJSONError answers {"error": msg} with code.
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSONStatus(w, code, map[string]string{"error": msg})
}

// writeAPIErr maps a Hub error to its status (StatusError, ErrBusy 409,
// else 500) as {"error"}; a failed operation (*hub.OpError) is
// {error, op, output, hint, rolled_back} like writeErr's. Hub messages
// carry ids, paths and counts, never secrets (op records are redacted
// before they are clipped); clipped for display.
func writeAPIErr(w http.ResponseWriter, err error) {
	var oe *hub.OpError
	if errors.As(err, &oe) {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	code := http.StatusInternalServerError
	var se *hub.StatusError
	var busy hub.ErrBusy
	switch {
	case errors.As(err, &se):
		code = se.Status
	case errors.As(err, &busy):
		code = http.StatusConflict
	}
	msg := err.Error()
	if errors.Is(err, hub.ErrNotFound) && msg == hub.ErrNotFound.Error() {
		msg = "no such shared folder, finding or snapshot"
	}
	writeJSONError(w, code, clipMessage(msg, 2000))
}

// writeOpAccepted answers an operation the Hub runs in the background
// (contract §14.8, §11.7): 202 {op_id, op, instance, poll} — instance is
// the op key; a folder's (_folder.<id>) also names the folder and is
// polled at /api/folders/<id>/op, the doctor's (_doctor) at
// /api/doctor/op, anything else (a rebind) at the instance's record.
func writeOpAccepted(w http.ResponseWriter, op *hub.AsyncOp) {
	body := map[string]string{"op_id": op.OpID, "op": op.Op, "instance": op.Instance}
	switch fid, isFolder := strings.CutPrefix(op.Instance, "_folder."); {
	case isFolder:
		body["folder"] = fid
		body["poll"] = "/api/folders/" + fid + "/op"
	case op.Instance == "_doctor":
		body["poll"] = "/api/doctor/op"
	default:
		body["poll"] = "/api/instances/" + op.Instance + "/op"
	}
	noStore(w)
	writeJSONStatus(w, http.StatusAccepted, body)
}

// writeOpRecord answers the op record under key (404 when none).
func (s *Server) writeOpRecord(w http.ResponseWriter, key, what string) {
	noStore(w)
	rec := s.Hub.LastOp(key)
	if rec == nil {
		writeJSONError(w, http.StatusNotFound, "no operation recorded for "+what)
		return
	}
	writeJSON(w, rec)
}

// ── definitions ──────────────────────────────────────────

func (s *Server) handleFolders(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	fs := s.Hub.Folders()
	if fs == nil {
		fs = []hub.FolderView{}
	}
	noStore(w)
	writeJSON(w, map[string]any{"folders": fs})
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var in hub.FolderInput
	if !decodeAPI(w, r, &in, folderCreateUsage) {
		return
	}
	view, warns, err := s.Hub.CreateFolder(r.Context(), in, actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	if warns == nil {
		warns = []string{}
	}
	writeJSONStatus(w, http.StatusCreated, map[string]any{"folder": view, "warnings": warns})
}

func (s *Server) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	var b struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Description string `json:"description"`
	}
	if !decodeAPI(w, r, &b, folderUpdateUsage) {
		return
	}
	view, err := s.Hub.UpdateFolder(r.Context(), id, hub.FolderInput{Name: b.Name, Path: b.Path, Description: b.Description}, actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"folder": view})
}

func (s *Server) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	if err := s.Hub.DeleteFolder(id, actor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCheckFolderPath(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		Path   string `json:"path"`
		Create bool   `json:"create"`
	}
	if !decodeAPI(w, r, &b, folderCheckUsage) {
		return
	}
	pc, err := s.Hub.CheckFolderPath(r.Context(), b.Path, b.Create)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, pc)
}

// ── assignment and undo ──────────────────────────────────

// readUses decodes an assignment body; uses is required (the full desired
// set: [] removes every use, a missing list is a 400, never "remove all").
func readUses(w http.ResponseWriter, r *http.Request, withHash bool) (hub.AssignRequest, string, bool) {
	var b struct {
		PlanHash *string          `json:"plan_hash"`
		Uses     *[]hub.FolderUse `json:"uses"`
	}
	usage := assignUsage
	if withHash {
		usage = assignApplyUsage
	}
	if !decodeAPI(w, r, &b, usage) {
		return hub.AssignRequest{}, "", false
	}
	if b.Uses == nil || (withHash != (b.PlanHash != nil)) {
		writeJSONError(w, http.StatusBadRequest, "body must be "+usage)
		return hub.AssignRequest{}, "", false
	}
	hash := ""
	if b.PlanHash != nil {
		hash = *b.PlanHash
	}
	return hub.AssignRequest{Uses: *b.Uses}, hash, true
}

func (s *Server) handleAssignPreview(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	req, _, ok := readUses(w, r, false)
	if !ok {
		return
	}
	p, err := s.Hub.PreviewAssign(r.Context(), id, req)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, p)
}

func (s *Server) handleAssignApply(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	req, hash, ok := readUses(w, r, true)
	if !ok {
		return
	}
	op, err := s.Hub.StartAssign(id, req, hash, actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeOpAccepted(w, op)
}

// handleUndoPreview: the undo of the folder's last fix (404 without an
// apply snapshot); the body is ignored.
func (s *Server) handleUndoPreview(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	p, err := s.Hub.PreviewUndo(r.Context(), id)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	noStore(w)
	writeJSON(w, p)
}

func (s *Server) handleUndoApply(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	var b struct {
		PlanHash *string `json:"plan_hash"`
	}
	if !decodeAPI(w, r, &b, undoApplyUsage) {
		return
	}
	if b.PlanHash == nil {
		writeJSONError(w, http.StatusBadRequest, "body must be "+undoApplyUsage)
		return
	}
	op, err := s.Hub.StartUndo(id, *b.PlanHash, actor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeOpAccepted(w, op)
}

// handleFolderOp is the folder's op record (_folder.<id>): poll it until
// running is false and op_id is the request's.
func (s *Server) handleFolderOp(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	id, ok := folderID(w, r)
	if !ok {
		return
	}
	s.writeOpRecord(w, "_folder."+id, "shared folder "+id)
}

// ── local networks ───────────────────────────────────────

func (s *Server) writeLocalNetworks(w http.ResponseWriter) {
	cidrs, isDefault := s.Hub.LocalNetworksView()
	if cidrs == nil {
		cidrs = []string{}
	}
	noStore(w)
	writeJSON(w, map[string]any{"networks": cidrs, "default": isDefault})
}

func (s *Server) handleLocalNetworks(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	s.writeLocalNetworks(w)
}

// handleSetLocalNetworks: {"networks": [...]} stores the list ([] =
// loopback only), {"networks": null} goes back to the defaults; the
// field is required.
func (s *Server) handleSetLocalNetworks(w http.ResponseWriter, r *http.Request) {
	if !s.folderAdmin(w, r) {
		return
	}
	var b struct {
		Networks json.RawMessage `json:"networks"`
	}
	if !decodeAPI(w, r, &b, localNetsUsage) {
		return
	}
	var cidrs []string
	if len(b.Networks) == 0 || json.Unmarshal(b.Networks, &cidrs) != nil {
		writeJSONError(w, http.StatusBadRequest, "body must be "+localNetsUsage)
		return
	}
	if string(b.Networks) != "null" && cidrs == nil {
		cidrs = []string{}
	}
	if err := s.Hub.SetLocalNetworks(cidrs, actor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	s.writeLocalNetworks(w)
}

// decodeAPI is decodeStrict (64 KiB, unknown fields and trailing data
// refused, never the decoder's error) answering {"error": "body must be
// <usage>"}.
func decodeAPI(w http.ResponseWriter, r *http.Request, v any, usage string) bool {
	if !strictBody(w, r, v) {
		writeJSONError(w, http.StatusBadRequest, "body must be "+usage)
		return false
	}
	return true
}
