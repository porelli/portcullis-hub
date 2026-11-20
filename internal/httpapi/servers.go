package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// The Servers API (contract §17.3, Task 12; Hub listener, administrators
// only, behind the proxy-secret and CSRF guards; bodies strict JSON).
// Routes marked † in the contract also need a fresh sign-in on the Hub
// listener (the proof's code, code_verifier and nonce in the body):
// adding, revoking and removing a server, undoing a move, removing a
// move's leftover and lifting a worker's quarantine. Every answer is
// no-store; none ever carries a join code (but the add's own answer), a
// key, a secret or a serial.

func (s *Server) registerServers(mux routeMux) {
	mux.HandleFunc("GET /api/servers", s.handleServers)
	mux.HandleFunc("POST /api/servers", s.handleAddServer)
	mux.HandleFunc("GET /api/servers/{id}", s.handleServer)
	mux.HandleFunc("DELETE /api/servers/{id}", s.handleRemoveServer)
	mux.HandleFunc("GET /api/servers/{id}/op", s.handleServerOp)
	mux.HandleFunc("POST /api/servers/{id}/op/stop", s.handleStopServerOp)
	mux.HandleFunc("PUT /api/servers/{id}/settings", s.handleServerSettings)
	mux.HandleFunc("PUT /api/servers/primary/settings", s.handleServerSettings)
	mux.HandleFunc("POST /api/servers/{id}/revoke", s.handleRevokeServer)
	mux.HandleFunc("POST /api/instances/{id}/move", s.handleMoveInstance)
	mux.HandleFunc("POST /api/instances/{id}/move/undo", s.handleUndoMove)
	mux.HandleFunc("DELETE /api/instances/{id}/move-leftover", s.handleRemoveMoveLeftover)
	mux.HandleFunc("POST /api/instances/{id}/quarantine/lift", s.handleLiftQuarantine)
}

// freshBody is a † route's fresh sign-in proof.
type freshBody struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce"`
}

func (b freshBody) proof() freshauth.Proof {
	return freshauth.Proof{Code: b.Code, CodeVerifier: b.CodeVerifier, Nonce: b.Nonce}
}

const freshUsage = `"code": "...", "code_verifier": "...", "nonce": "..."`

// fresh checks a † route's proof (audited as action on target when
// refused); false when it answered.
func (s *Server) fresh(w http.ResponseWriter, r *http.Request, action, target string, b freshBody) bool {
	if err := s.Hub.CheckAdminFresh(r.Context(), requestActor(r), action, target, b.proof()); err != nil {
		noStore(w)
		writeAPIErr(w, err)
		return false
	}
	return true
}

// serverIDOf is the path's server id: a valid worker id (primaryOK: or
// "primary"), else 400.
func serverIDOf(w http.ResponseWriter, r *http.Request, primaryOK bool) (string, bool) {
	id := r.PathValue("id")
	if id == "" && primaryOK {
		id = servers.PrimaryID // PUT /api/servers/primary/settings
	}
	if id == servers.PrimaryID && primaryOK {
		return id, true
	}
	if servers.ValidID(id) != nil {
		http.Error(w, "invalid server id", http.StatusBadRequest)
		return "", false
	}
	return id, true
}

// serversPage is GET /api/servers: every server (the primary first) and
// the Hub listener's fresh sign-in parameters for the † actions.
type serversPage struct {
	Servers   []hub.ServerView         `json:"servers"`
	FreshAuth *freshauth.AuthorizeInfo `json:"fresh_auth"`
	// AddKind is what Add server adds here: "cluster-node" on Kubernetes
	// (R9), else "worker".
	AddKind string `json:"add_kind"`
}

func (s *Server) addKind() string {
	if s.Hub.ClusterNodesMode() {
		return state.KindClusterNode
	}
	return state.KindWorker
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	noStore(w)
	writeJSON(w, serversPage{Servers: s.listServers(r.Context()), FreshAuth: s.Hub.AdminFreshAuthInfo(), AddKind: s.addKind()})
}

// listServers is the list's work (route and list_servers).
func (s *Server) listServers(ctx context.Context) []hub.ServerView {
	s.rec("Servers")
	return s.Hub.Servers(ctx)
}

func (s *Server) handleServer(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, true)
	if !ok {
		return
	}
	d, err := s.serverDetail(r.Context(), id)
	noStore(w)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, d)
}

// serverDetail is one server's work (route and get_server).
func (s *Server) serverDetail(ctx context.Context, id string) (*hub.ServerDetail, error) {
	s.rec("ServerDetail", id)
	return s.Hub.ServerDetailOf(ctx, id)
}

// addClusterNode is POST /api/servers with kind cluster-node (fresh
// sign-in, audited server.add; never over MCP).
func (s *Server) addClusterNode(w http.ResponseWriter, r *http.Request, b addServerBody) {
	if err := hub.CheckClusterNodeInput(b.clusterRequest()); err != nil {
		writeAPIErr(w, err)
		return
	}
	if !s.fresh(w, r, "server.add", b.ID, b.freshBody) {
		return
	}
	s.rec("AddClusterNode", b.ID, b.Name)
	out, code, err := s.Hub.AddClusterNode(r.Context(), requestActor(r), b.clusterRequest())
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, addedClusterNode{Code: code.Reveal(), ClusterNodeAdded: out})
}

// addedServer is POST /api/servers' 201: the code once, its expiry and
// the enrolment op to poll.
type addedServer struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	OpID      string    `json:"op_id"`
	Op        string    `json:"op"`
	Poll      string    `json:"poll"`
}

// addedClusterNode is POST /api/servers' 201 for a cluster node (contract
// §20.1): §17.3's answer plus the role, the warnings, the server
// sentence and the one-liner.
type addedClusterNode struct {
	Code string `json:"code"`
	hub.ClusterNodeAdded
}

// addServerBody is POST /api/servers (kind: "worker" by default;
// "cluster-node" with its role, class, site and labels, each optional).
type addServerBody struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Role    string `json:"role"`
	Class   string `json:"class"`
	Site    string `json:"site"`
	Ingress *bool  `json:"ingress"`
	Storage *bool  `json:"storage"`
	freshBody
}

const addServerUsage = `{"id": "<server id>", "name": "<name>", "kind"?: "worker"|"cluster-node", "role"?: "server"|"agent", "class"?: "small"|"home"|"cloud", "site"?, "ingress"?: bool, "storage"?: bool, ` + freshUsage + `}`

func (b addServerBody) clusterRequest() hub.AddClusterNodeRequest {
	return hub.AddClusterNodeRequest{ID: b.ID, Name: b.Name, Role: b.Role, Class: b.Class, Site: b.Site, Ingress: b.Ingress, Storage: b.Storage}
}

func (s *Server) handleAddServer(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	var b addServerBody
	if !decodeStrict(w, r, &b, addServerUsage) {
		return
	}
	noStore(w)
	switch b.Kind {
	case "", state.KindWorker:
		if b.Role != "" || b.Class != "" || b.Site != "" || b.Ingress != nil || b.Storage != nil {
			http.Error(w, "role, class, site, ingress and storage are a cluster node's (kind cluster-node)", http.StatusBadRequest)
			return
		}
		if s.Hub.ClusterNodesMode() {
			// R9, before the proof is spent (review M2).
			writeAPIErr(w, hub.ErrWorkersOnKube())
			return
		}
	case state.KindClusterNode:
		if !s.Hub.ClusterNodesMode() {
			writeAPIErr(w, hub.ErrClusterOnDocker())
			return
		}
		s.addClusterNode(w, r, b)
		return
	default:
		http.Error(w, "kind must be worker or cluster-node", http.StatusBadRequest)
		return
	}
	// Cheap checks first: a bad id never spends the proof, and only a
	// valid id is ever an audit target (L4).
	if err := hub.CheckServerInput(b.ID, b.Name); err != nil {
		writeAPIErr(w, err)
		return
	}
	if !s.fresh(w, r, "server.add", b.ID, b.freshBody) {
		return
	}
	s.rec("AddServer", b.ID, b.Name)
	code, exp, opID, err := s.Hub.AddServerOp(r.Context(), requestActor(r), b.ID, b.Name)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, addedServer{Code: code, ExpiresAt: exp, OpID: opID, Op: hub.OpServerEnrol,
		Poll: "/api/servers/" + b.ID + "/op?op_id=" + opID})
}

func (s *Server) handleServerOp(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, false)
	if !ok {
		return
	}
	noStore(w)
	opID := ""
	if q, asked := r.URL.Query()["op_id"]; asked {
		if len(q) != 1 || !stopOpIDRe.MatchString(q[0]) {
			http.Error(w, "op_id must be 16 lowercase hex digits, once", http.StatusBadRequest)
			return
		}
		opID = q[0]
	}
	rec := s.Hub.ServerOp(id, opID)
	if rec == nil {
		http.Error(w, "no enrolment recorded for "+id, http.StatusNotFound)
		return
	}
	writeJSON(w, rec)
}

func (s *Server) handleStopServerOp(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, false)
	if !ok {
		return
	}
	var b struct {
		OpID json.RawMessage `json:"op_id"`
	}
	const usage = `{} or {"op_id": "<16 hex>"}`
	if !decodeStrict(w, r, &b, usage) {
		return
	}
	expected := ""
	if b.OpID != nil {
		if len(b.OpID) == 0 || b.OpID[0] != '"' || json.Unmarshal(b.OpID, &expected) != nil || !stopOpIDRe.MatchString(expected) {
			http.Error(w, "body must be "+usage, http.StatusBadRequest)
			return
		}
	}
	noStore(w)
	s.rec("StopServerEnrol", id, expected)
	if err := s.Hub.StopServerEnrol(id, requestActor(r), expected); err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "stopping", "server": id})
}

// serverSettingsBody is PUT …/settings. local_networks: a list, or null for
// the defaults (absent = unchanged).
type serverSettingsBody struct {
	Name           *string               `json:"name"`
	LocalNetworks  json.RawMessage       `json:"local_networks"`
	BackupSchedule *state.BackupSchedule `json:"backup_schedule"`
}

func (s *Server) handleServerSettings(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, true)
	if !ok {
		return
	}
	const usage = `{"name": "<name>", "local_networks": ["<cidr>", …] | null, "backup_schedule": {"mode": "off|daily|weekly", "hour": 0-23, "weekday": 0-6}} (each optional)`
	var b serverSettingsBody
	if !decodeStrict(w, r, &b, usage) {
		return
	}
	in := hub.ServerSettings{Name: b.Name, BackupSchedule: b.BackupSchedule}
	if b.LocalNetworks != nil {
		if string(b.LocalNetworks) == "null" {
			in.LocalNetworksDefault = true
		} else {
			var list []string
			if json.Unmarshal(b.LocalNetworks, &list) != nil || list == nil {
				http.Error(w, "body must be "+usage, http.StatusBadRequest)
				return
			}
			in.LocalNetworks = &list
		}
	}
	noStore(w)
	if err := s.setServerSettings(r.Context(), requestActor(r), id, in); err != nil {
		writeAPIErr(w, err)
		return
	}
	d, err := s.serverDetail(r.Context(), id)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, d)
}

// setServerSettings is the settings' work (route and set_backup_schedule).
func (s *Server) setServerSettings(ctx context.Context, a directory.Actor, id string, in hub.ServerSettings) error {
	s.rec("SetServerSettings", id)
	return s.Hub.SetServerSettings(ctx, a, id, in)
}

// serverConfirmBody is a typed-id † route's body.
type serverConfirmBody struct {
	Confirm string `json:"confirm"`
	freshBody
}

const serverConfirmUsage = `{"confirm": "<id>", ` + freshUsage + `}`

func (s *Server) handleRevokeServer(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, false)
	if !ok {
		return
	}
	var b serverConfirmBody
	if !decodeStrict(w, r, &b, serverConfirmUsage) {
		return
	}
	noStore(w)
	if b.Confirm != id {
		http.Error(w, "type the server id ("+id+") to confirm the revocation", http.StatusBadRequest)
		return
	}
	if !s.fresh(w, r, "server.revoked", id, b.freshBody) {
		return
	}
	if s.Hub.ClusterNodesMode() {
		s.rec("RevokeClusterNode", id)
		_, parked, err := s.Hub.RemoveClusterNode(r.Context(), requestActor(r), id, b.Confirm, nodeadm.Revoke)
		if err != nil {
			writeAPIErr(w, err)
			return
		}
		writeRevoked(w, id, parked)
		return
	}
	s.rec("RevokeServer", id)
	if err := s.Hub.RevokeServer(r.Context(), requestActor(r), id); err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "revoked", "server": id})
}

func (s *Server) handleRemoveServer(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := serverIDOf(w, r, false)
	if !ok {
		return
	}
	var b serverConfirmBody
	if !decodeStrict(w, r, &b, serverConfirmUsage) {
		return
	}
	noStore(w)
	if b.Confirm != id {
		http.Error(w, "type the server id ("+id+") to confirm the removal", http.StatusBadRequest)
		return
	}
	if !s.fresh(w, r, "server.removed", id, b.freshBody) {
		return
	}
	if s.Hub.ClusterNodesMode() {
		s.rec("RemoveClusterNode", id)
		op, _, err := s.Hub.RemoveClusterNode(r.Context(), requestActor(r), id, b.Confirm, nodeadm.Cooperative)
		if err != nil {
			writeAPIErr(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, map[string]string{"status": "removing", "server": id, "op_id": op.OpID, "op": op.Op,
			"poll": "/api/servers/" + id + "/op?op_id=" + op.OpID})
		return
	}
	s.rec("RemoveServer", id)
	if err := s.Hub.RemoveServer(r.Context(), requestActor(r), id); err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "removed", "server": id})
}

func (s *Server) handleMoveInstance(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b struct {
		Server *string `json:"server"`
	}
	if !decodeStrict(w, r, &b, `{"server": "<server id>" ("" = the primary)}`) {
		return
	}
	noStore(w)
	if b.Server == nil {
		http.Error(w, `body must be {"server": "<server id>" ("" = the primary)}`, http.StatusBadRequest)
		return
	}
	op, err := s.startMove(requestActor(r), id, *b.Server)
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeAccepted(w, op)
}

// startMove is the move's work (route and move_instance).
func (s *Server) startMove(a directory.Actor, id, server string) (*hub.AsyncOp, error) {
	s.rec("StartMove", id, server)
	return s.Hub.StartMove(id, server, a)
}

func (s *Server) handleUndoMove(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b serverConfirmBody
	if !decodeStrict(w, r, &b, serverConfirmUsage) {
		return
	}
	noStore(w)
	if b.Confirm != id {
		http.Error(w, "type the instance id ("+id+") to confirm: changes since the move are lost", http.StatusBadRequest)
		return
	}
	if !s.fresh(w, r, "instance.move_undo", id, b.freshBody) {
		return
	}
	s.rec("StartUndoMove", id, b.Confirm)
	op, err := s.Hub.StartUndoMove(id, b.Confirm, requestActor(r))
	if err != nil {
		writeAPIErr(w, err)
		return
	}
	writeAccepted(w, op)
}

func (s *Server) handleRemoveMoveLeftover(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b serverConfirmBody
	if !decodeStrict(w, r, &b, serverConfirmUsage) {
		return
	}
	noStore(w)
	if b.Confirm != id {
		http.Error(w, "type the instance id ("+id+") to confirm", http.StatusBadRequest)
		return
	}
	if !s.fresh(w, r, "instance.move_leftover_removed", id, b.freshBody) {
		return
	}
	s.rec("RemoveMoveLeftover", id, b.Confirm)
	if err := s.Hub.RemoveMoveLeftover(r.Context(), id, b.Confirm, requestActor(r)); err != nil {
		writeAPIErr(w, err)
		return
	}
	v, ok := s.Hub.InstanceView(id)
	if !ok {
		http.Error(w, "instance not found: "+id, http.StatusNotFound)
		return
	}
	writeJSON(w, v)
}

func (s *Server) handleLiftQuarantine(w http.ResponseWriter, r *http.Request) {
	noStore(w) // every answer, refusals included (I5)
	if !s.adminOnly(w, r) {
		return
	}
	id, ok := instanceID(w, r)
	if !ok {
		return
	}
	var b freshBody
	if !decodeStrict(w, r, &b, `{`+freshUsage+`}`) {
		return
	}
	noStore(w)
	if !s.fresh(w, r, "server.quarantine_lift", id, b) {
		return
	}
	s.rec("LiftQuarantine", id)
	if err := s.Hub.LiftQuarantine(r.Context(), requestActor(r), id); err != nil {
		writeAPIErr(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "lifted", "instance": id})
}

// writeRevoked answers a cluster node's revocation: 200, or 202 with
// nodeadm's text when it is parked (its security steps done; the etcd
// member goes once quorum returns: review I1).
func writeRevoked(w http.ResponseWriter, id, parked string) {
	if parked == "" {
		writeJSON(w, map[string]string{"status": "revoked", "server": id})
		return
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"status": "revoked", "server": id, "parked": true, "warning": parked,
		"detail": hub.ParkedRevokeText})
}
