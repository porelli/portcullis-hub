package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/templates"
)

// App instances, backups and restore (contract §11.7): Hub listener only
// (never people), admins only (lldap_admin; delegates 403), proxy-secret +
// CSRF like every route, audited in the Hub with the X-Forwarded-User actor
// (instance.create|update|delete|backup|restore).

func (s *Server) registerInstances(mux routeMux) {
	mux.HandleFunc("GET /api/instances", s.handleInstances)
	mux.HandleFunc("POST /api/instances", s.handleCreateInstance)
	mux.HandleFunc("GET /api/instances/defaults", s.handleInstanceDefaults)
	mux.HandleFunc("PUT /api/instances/{id}/hosts", s.handleInstanceHosts)
	mux.HandleFunc("DELETE /api/instances/{id}", s.handleDeleteInstance)
	mux.HandleFunc("GET /api/backups", s.handleBackups)
	mux.HandleFunc("GET /api/instances/{id}/backups", s.handleBackups)
	mux.HandleFunc("POST /api/instances/{id}/backups", s.handleBackupInstance)
	mux.HandleFunc("POST /api/instances/{id}/restore", s.handleRestoreInstance)
	mux.HandleFunc("POST /api/instances/restore", s.handleRestoreAs)
	mux.HandleFunc("GET /api/instances/{id}/op", s.handleInstanceOp)
	mux.HandleFunc("POST /api/instances/{id}/op/stop", s.handleStopOp)
	mux.HandleFunc("GET /api/instances/missing-groups", s.handleMissingGroups)
	mux.HandleFunc("POST /api/instances/missing-groups", s.handleCreateMissingGroups)
	mux.HandleFunc("GET /api/keycloak/user-sweep", s.handleUserSweep)
	mux.HandleFunc("POST /api/keycloak/user-sweep/resume", s.handleResumeUserSweep)
	// Admin credential routes (Task 12, plan 3).
	mux.HandleFunc("GET /api/instances/{id}/credentials", s.handleAdminCredentials)
	mux.HandleFunc("DELETE /api/instances/{id}/credentials/{key}/{user}", s.handleAdminRevokeCredential)
}

// handleUserSweep: the guarded stale-record cleanup's status (banner).
func (s *Server) handleUserSweep(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.UserSweep())
}

// handleResumeUserSweep resumes a paused cleanup ({"confirm": "resume"}),
// as the signed-in admin; audited.
func (s *Server) handleResumeUserSweep(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Confirm string `json:"confirm"`
	}
	if !decodeStrict(w, r, &b, `{"confirm": "resume"}`) {
		return
	}
	st, err := s.resumeUserSweep(r.Context(), requestActor(r), b.Confirm)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, st)
}

// resumeUserSweep is the resume's work (route and resume_user_sweep);
// audited keycloak.sweep_resume by the Hub.
func (s *Server) resumeUserSweep(ctx context.Context, a directory.Actor, confirm string) (hub.UserSweepStatus, error) {
	s.rec("ResumeUserSweep", confirm)
	st, err := s.Hub.ResumeUserSweep(ctx, a, confirm)
	return st, defaultStatus(err, http.StatusBadRequest)
}

// handleMissingGroups lists the enabled instances whose access / admin
// groups are missing in LLDAP (the Apps page banner).
func (s *Server) handleMissingGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Hub.MissingGroups(r.Context()))
}

// handleCreateMissingGroups creates them as the signed-in admin ({"ids":
// [...]} or {} = every enabled instance), audited in Users & Groups.
func (s *Server) handleCreateMissingGroups(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if !decodeStrict(w, r, &b, `{"ids": ["<instance id>", ...]} (or {} for all)`) {
		return
	}
	res, err := s.createMissingGroups(r.Context(), requestActor(r), b.IDs)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"results": res})
}

// createMissingGroups is the banner's work (route and
// create_missing_groups).
func (s *Server) createMissingGroups(ctx context.Context, a directory.Actor, ids []string) ([]hub.CreateGroupsResult, error) {
	s.rec("CreateMissingGroups", ids)
	res, err := s.Hub.CreateMissingGroups(ctx, ids, a)
	return res, defaultStatus(err, http.StatusBadRequest)
}

// decodeStrict decodes a small JSON body into v (unknown fields refused);
// usage is the message of a 400.
func decodeStrict(w http.ResponseWriter, r *http.Request, v interface{}, usage string) bool {
	if !strictBody(w, r, v) {
		http.Error(w, "body must be "+usage, http.StatusBadRequest)
		return false
	}
	return true
}

// strictBody decodes one JSON document of at most 64 KiB into v: unknown
// fields and trailing data refused. The caller answers a failure with a
// fixed message (never the decoder's error: it may quote the body).
func strictBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && dec.Decode(&struct{}{}) == io.EOF
}

// writeJSONStatus writes v as JSON with status code.
func writeJSONStatus(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// instanceID reads the {id} path value: an instance id or a template id
// (the default instance).
func instanceID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !templates.InstanceIDRe.MatchString(id) && !templates.ValidID(id) {
		http.Error(w, "invalid instance id", http.StatusBadRequest)
		return "", false
	}
	return id, true
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, s.Hub.Instances())
}

func (s *Server) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Template string            `json:"template"`
		ID       string            `json:"id"`
		Hosts    map[string]string `json:"hosts"`
	}
	if !decodeStrict(w, r, &b, `{"template": "<template>", "id": "<instance-id>", "hosts": {"<host router>": "<hostname>", ...}}`) {
		return
	}
	op, err := s.createInstance(requestActor(r), b.Template, b.ID, b.Hosts)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeAccepted(w, op)
}

// createInstance is the create's work (route and create_instance), in
// the background (202, op create, the new id's record; its result
// "instance", the warnings the record's); audited instance.create by the
// Hub.
func (s *Server) createInstance(a directory.Actor, template, id string, hosts map[string]string) (*hub.AsyncOp, error) {
	if !templates.ValidID(template) {
		return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid template id")}
	}
	if len(hosts) == 0 {
		hosts = nil // the defaults on the main domain
	}
	s.rec("StartCreate", template, id, hosts)
	op, err := s.Hub.StartCreate(template, id, hosts, a)
	return op, defaultStatus(err, http.StatusBadGateway)
}

// handleInstanceDefaults feeds the hostname editor: a template's host
// routers (immutable ones flagged), the domains hostnames may go on, and
// the pre-filled hostnames of instance id on domain (default: the main
// domain; contract §11.3).
func (s *Server) handleInstanceDefaults(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	q := r.URL.Query()
	v, err := s.instanceDefaults(q.Get("template"), q.Get("id"), q.Get("domain"))
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	noStore(w)
	writeJSON(w, v)
}

// instanceDefaults is the hostname editor's data (route and
// instance_defaults).
func (s *Server) instanceDefaults(tid, id, domain string) (map[string]any, error) {
	domain = hub.NormalizeHost(domain)
	if !templates.ValidID(tid) {
		return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("invalid template id")}
	}
	routers, multi, legacy, ok := s.Hub.HostRouters(tid)
	if !ok {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("template not found: " + tid)}
	}
	domains := s.Hub.InstanceDomains()
	if domain != "" {
		known := false
		for _, d := range domains {
			known = known || d.Name == domain
		}
		if !known {
			return nil, &hub.StatusError{Status: http.StatusBadRequest, Err: errors.New("unknown domain: " + domain)}
		}
	}
	hosts := map[string]string{}
	if id == tid || templates.InstanceIDRe.MatchString(id) {
		hosts = s.Hub.DefaultHosts(tid, id, domain)
	}
	return map[string]any{
		"template": tid, "id": id, "domain": domain, "multi": multi, "legacy": legacy,
		"routers": routers, "domains": domains, "hosts": hosts,
	}, nil
}

func (s *Server) handleInstanceHosts(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		Hosts map[string]string `json:"hosts"`
	}
	if !decodeStrict(w, r, &b, `{"hosts": {"<host router>": "<hostname>", ...}}`) {
		return
	}
	v, err := s.setHosts(requestActor(r), id, b.Hosts)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, v)
}

// setHosts is the hostname change's work (route and set_hosts); audited
// instance.update by the Hub. Changed but no longer resolvable (e.g. a
// concurrent delete) is a 409, never a zero-value answer.
func (s *Server) setHosts(a directory.Actor, id string, hosts map[string]string) (*hub.InstanceView, error) {
	s.rec("SetHosts", id, hosts)
	if err := s.Hub.SetHosts(id, hosts, a); err != nil {
		return nil, defaultStatus(err, http.StatusBadGateway)
	}
	v, ok := s.Hub.InstanceView(id)
	if !ok {
		return nil, &hub.StatusError{Status: http.StatusConflict, Err: errors.New("hostnames changed, but instance " + id + " can no longer be listed")}
	}
	return &v, nil
}

func (s *Server) handleDeleteInstance(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		Confirm string `json:"confirm"`
	}
	if !decodeStrict(w, r, &b, `{"confirm": "<instance-id>"}`) {
		return
	}
	op, err := s.startDelete(requestActor(r), id, b.Confirm)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeAccepted(w, op)
}

// startDelete is the guarded delete's work (route and delete_instance;
// confirm = the id typed); audited instance.delete by the Hub.
func (s *Server) startDelete(a directory.Actor, id, confirm string) (*hub.AsyncOp, error) {
	s.rec("StartDelete", id, confirm)
	op, err := s.Hub.StartDelete(id, confirm, a)
	return op, defaultStatus(err, http.StatusBadGateway)
}

func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id := ""
	if r.PathValue("id") != "" {
		var ok bool
		if id, ok = instanceID(w, r); !ok {
			return
		}
	}
	list, err := s.listBackups(id)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

// listBackups is the backups list (routes, list_backups and
// list_backups_all; id "" = every instance's, deleted ones included).
func (s *Server) listBackups(id string) ([]hub.BackupEntry, error) {
	list, err := s.Hub.ListBackups(id)
	if err != nil {
		return nil, defaultStatus(err, http.StatusInternalServerError)
	}
	if list == nil {
		list = []hub.BackupEntry{}
	}
	return list, nil
}

func (s *Server) handleBackupInstance(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	op, err := s.startBackup(requestActor(r), id)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeAccepted(w, op)
}

func (s *Server) handleRestoreInstance(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		Archive string `json:"archive"`
	}
	if !decodeStrict(w, r, &b, `{"archive": "<instance-id>/<YYYYMMDDTHHMMSSZ>.tar"}`) {
		return
	}
	op, err := s.startRestore(requestActor(r), id, b.Archive)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeAccepted(w, op)
}

func (s *Server) handleRestoreAs(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Archive string            `json:"archive"`
		ID      string            `json:"id"`
		Hosts   map[string]string `json:"hosts"`
	}
	if !decodeStrict(w, r, &b, `{"archive": "<instance-id>/<YYYYMMDDTHHMMSSZ>.tar", "id": "<new instance-id>", "hosts": {"<host router>": "<hostname>"} (optional)}`) {
		return
	}
	op, err := s.startRestoreAs(requestActor(r), b.Archive, b.ID, b.Hosts)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeAccepted(w, op)
}

// startBackup, startRestore and startRestoreAs are the background
// operations' work (routes and backup_instance / restore_instance /
// restore_as); audited instance.backup|restore by the Hub.
func (s *Server) startBackup(a directory.Actor, id string) (*hub.AsyncOp, error) {
	s.rec("StartBackup", id)
	op, err := s.Hub.StartBackup(id, a)
	return op, defaultStatus(err, http.StatusInternalServerError)
}

func (s *Server) startRestore(a directory.Actor, id, archive string) (*hub.AsyncOp, error) {
	s.rec("StartRestore", id, archive)
	op, err := s.Hub.StartRestore(id, archive, a)
	return op, defaultStatus(err, http.StatusInternalServerError)
}

func (s *Server) startRestoreAs(a directory.Actor, archive, id string, hosts map[string]string) (*hub.AsyncOp, error) {
	s.rec("StartRestoreAs", archive, id, hosts)
	op, err := s.Hub.StartRestoreAs(archive, id, a, hosts)
	return op, defaultStatus(err, http.StatusInternalServerError)
}

// writeAccepted answers a long operation the Hub runs in the background
// (enable, disable, restart, an AI switch, create, backup, restore,
// delete; contract §11.7): 202 with the op id and where to poll its op
// record.
func writeAccepted(w http.ResponseWriter, op *hub.AsyncOp) {
	writeJSONStatus(w, http.StatusAccepted, acceptedBody(op))
}

// acceptedBody is a long operation's 202 body (the Portcullis MCP's
// OpStarted too).
func acceptedBody(op *hub.AsyncOp) OpStarted {
	return OpStarted{OpID: op.OpID, Op: op.Op, Instance: op.Instance, Poll: "/api/instances/" + op.Instance + "/op"}
}

// handleInstanceOp is an instance's op record (also of a deleted
// instance, or of a new id a restore creates): poll it until running is
// false and op_id is the request's.
func (s *Server) handleInstanceOp(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	noStore(w)
	rec := s.Hub.LastOp(id)
	if rec == nil {
		http.Error(w, "no operation recorded for "+id, http.StatusNotFound)
		return
	}
	writeJSON(w, rec)
}

// stopOpIDRe is an operation id (hub.newOpID: 16 lowercase hex digits).
var stopOpIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// handleStopOp stops the instance's operation and undoes what it did
// (contract §11.7 "Stop"; body {"op_id": "<16 hex>"} — only that
// operation, another one now is 409 "the operation changed" with the
// current record, nothing stopped; {} — whatever runs, for API callers):
// 202 with the record (stopping); 409 with the record when nothing
// runs, past the point of no return or already stopping; 404 for an
// unknown instance or no record. Audited <op>.stop by the Hub.
func (s *Server) handleStopOp(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		OpID *string `json:"op_id"`
	}
	const usage = `{} or {"op_id": "<16 hex>"}`
	if !decodeStrict(w, r, &b, usage) {
		return
	}
	expected := ""
	if b.OpID != nil {
		if !stopOpIDRe.MatchString(*b.OpID) {
			http.Error(w, "body must be "+usage, http.StatusBadRequest)
			return
		}
		expected = *b.OpID
	}
	rec, err := s.stopOp(requestActor(r), id, expected)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, rec)
}

// stopOp is the Stop's work (route and stop_op): expectedOpID "" stops
// whatever runs (the route), else only that operation (stop_op: the one
// its class and confirmation were for; another is 409 "the operation
// changed", judged by the Hub under the operation's lock). A 409 refusal
// carries the current record (recordError: the body / the tool error's
// JSON).
func (s *Server) stopOp(a directory.Actor, id, expectedOpID string) (*hub.OpRecord, error) {
	s.rec("StopOp", id)
	rec, err := s.Hub.StopOpExpect(id, a, expectedOpID)
	if err != nil {
		if rec != nil && errStatus(err, http.StatusInternalServerError) == http.StatusConflict {
			return nil, &recordError{err: err, rec: rec}
		}
		return nil, defaultStatus(err, http.StatusInternalServerError)
	}
	return rec, nil
}
