package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

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
	mux.HandleFunc("GET /api/instances/missing-groups", s.handleMissingGroups)
	mux.HandleFunc("POST /api/instances/missing-groups", s.handleCreateMissingGroups)
	mux.HandleFunc("GET /api/keycloak/user-sweep", s.handleUserSweep)
	mux.HandleFunc("POST /api/keycloak/user-sweep/resume", s.handleResumeUserSweep)
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
	st, err := s.Hub.ResumeUserSweep(r.Context(), actor(r), b.Confirm)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, st)
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
	res, err := s.Hub.CreateMissingGroups(r.Context(), b.IDs, actor(r))
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"results": res})
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
	if !templates.ValidID(b.Template) {
		http.Error(w, "invalid template id", http.StatusBadRequest)
		return
	}
	if len(b.Hosts) == 0 {
		b.Hosts = nil // the defaults on the main domain
	}
	res, err := s.Hub.CreateInstanceAs(b.Template, b.ID, b.Hosts, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSONStatus(w, http.StatusCreated, res)
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
	tid, id, domain := q.Get("template"), q.Get("id"), hub.NormalizeHost(q.Get("domain"))
	if !templates.ValidID(tid) {
		http.Error(w, "invalid template id", http.StatusBadRequest)
		return
	}
	routers, multi, legacy, ok := s.Hub.HostRouters(tid)
	if !ok {
		http.Error(w, "template not found: "+tid, http.StatusNotFound)
		return
	}
	domains := s.Hub.InstanceDomains()
	if domain != "" {
		known := false
		for _, d := range domains {
			known = known || d.Name == domain
		}
		if !known {
			http.Error(w, "unknown domain: "+domain, http.StatusBadRequest)
			return
		}
	}
	hosts := map[string]string{}
	if id == tid || templates.InstanceIDRe.MatchString(id) {
		hosts = s.Hub.DefaultHosts(tid, id, domain)
	}
	noStore(w)
	writeJSON(w, map[string]interface{}{
		"template": tid, "id": id, "domain": domain, "multi": multi, "legacy": legacy,
		"routers": routers, "domains": domains, "hosts": hosts,
	})
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
	err := s.Hub.SetHosts(id, b.Hosts, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	v, ok := s.Hub.InstanceView(id)
	if !ok {
		// Changed but no longer resolvable (e.g. a concurrent delete):
		// never a zero-value 200.
		http.Error(w, "hostnames changed, but instance "+id+" can no longer be listed", http.StatusConflict)
		return
	}
	writeJSON(w, v)
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
	op, err := s.Hub.StartDelete(id, b.Confirm, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeAccepted(w, op)
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
	list, err := s.Hub.ListBackups(id)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []hub.BackupEntry{}
	}
	writeJSON(w, list)
}

func (s *Server) handleBackupInstance(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	op, err := s.Hub.StartBackup(id, actor(r))
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
	op, err := s.Hub.StartRestore(id, b.Archive, actor(r))
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
	op, err := s.Hub.StartRestoreAs(b.Archive, b.ID, actor(r), b.Hosts)
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeAccepted(w, op)
}

// writeAccepted answers a long operation the Hub runs in the background
// (backup, restore, delete; contract §11.7): 202 with the op id and where
// to poll its op record.
func writeAccepted(w http.ResponseWriter, op *hub.AsyncOp) {
	writeJSONStatus(w, http.StatusAccepted, map[string]string{
		"op_id": op.OpID, "op": op.Op, "instance": op.Instance,
		"poll": "/api/instances/" + op.Instance + "/op",
	})
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
