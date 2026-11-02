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

func (s *Server) registerInstances(mux *http.ServeMux) {
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
}

// decodeStrict decodes a small JSON body into v (unknown fields refused);
// usage is the message of a 400.
func decodeStrict(w http.ResponseWriter, r *http.Request, v interface{}, usage string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "body must be "+usage, http.StatusBadRequest)
		return false
	}
	return true
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
	res, err := s.Hub.DeleteInstance(id, b.Confirm, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, res)
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
	entry, err := s.Hub.BackupInstance(id, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusCreated, entry)
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
	res, err := s.Hub.RestoreInstance(id, b.Archive, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleRestoreAs(w http.ResponseWriter, r *http.Request) {
	if !s.adminOnly(w, r) {
		return
	}
	var b struct {
		Archive string `json:"archive"`
		ID      string `json:"id"`
	}
	if !decodeStrict(w, r, &b, `{"archive": "<instance-id>/<YYYYMMDDTHHMMSSZ>.tar", "id": "<new instance-id>"}`) {
		return
	}
	res, err := s.Hub.RestoreInstanceAs(b.Archive, b.ID, actor(r))
	noStore(w)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusCreated, res)
}
