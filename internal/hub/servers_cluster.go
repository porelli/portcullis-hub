package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/nodeagent"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/state"
)

// Cluster nodes (contract §17 "NEW (HA)", §20.1–§20.3, ruling R9): on
// Kubernetes every server is a node of the one k3s cluster (kind
// cluster-node), added, removed and revoked through nodeadm. The Hub never
// holds a k3s token or a code's secret: nodeadm builds the join code v2
// (POST /v1/codes) and the Hub shows it once. Docker workers stay refused
// on Kubernetes and cluster nodes on Docker and Podman. The routes are
// never mirrored over MCP (serverNoToolRoutes).

const (
	// OpNodeRemove is a cluster node's cooperative removal (op key
	// _server.<id>, as the enrolment).
	OpNodeRemove = "node_remove"

	// The server_enrol steps of a cluster node (§20.1).
	StepEnrolled     = "enrolled"
	StepMeshReady    = "mesh_ready"
	StepK3sJoined    = "k3s_joined"
	StepNodeReady    = "node_ready"
	StepStorageReady = "storage_ready"
	StepClusterDone  = "done" // the step key (StepDone is the step state)

	// ServerRemoving: a cluster node's removal op runs.
	ServerRemoving = "removing"

	// ServerJoinNotice is the Add-node dialog's sentence for a server
	// (spec §6.2, contract §20.1).
	ServerJoinNotice = "Joining as a server gives this machine full control of the cluster (cluster-admin)."

	errWorkersOnKube   = "Docker workers can't join a Kubernetes cluster: add it as a cluster node"
	errClusterOnDocker = "cluster nodes need a Kubernetes primary: on Docker and Podman, add a worker"
)

// The waits of a cluster node's enrolment (nodeadm's own: mesh_pending at
// most 10 min, waiting_admission at most 30 min, §20.2).
const (
	clusterEnrolGrace = time.Minute // past the code's expiry, for nodeadm's clock
	clusterJoinWait   = 45 * time.Minute
	clusterReadyWait  = 10 * time.Minute
	clusterCallWait   = 30 * time.Second
)

// NodeadmAPI is nodeadm's internal API as the Hub uses it
// (*nodeadm.Client; tests substitute it).
type NodeadmAPI interface {
	IssueCode(ctx context.Context, r nodeadm.CodeRequest) (nodeadm.CodeAnswer, error)
	Cluster(ctx context.Context) (nodeadm.Snapshot, error)
	SetLabels(ctx context.Context, id string, l nodeadm.Labels) error
	Cordon(ctx context.Context, id string) error
	Uncordon(ctx context.Context, id string) error
	Drain(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, mode nodeadm.RemoveMode) error
}

// NodeagentAPI is the part of a node's nodeagent the removal uses.
type NodeagentAPI interface {
	Uninstall(ctx context.Context) error
}

// clusterNodes is the Hub's cluster-node wiring.
type clusterNodes struct {
	mu sync.Mutex
	// api replaces the nodeadm client (SetNodeadm: tests).
	api NodeadmAPI
	// real is the client built from the control certificate; realCert the
	// certificate it was built with (a renewal rebuilds it).
	real     *nodeadm.Client
	realCert []byte
	// agentFor replaces the nodeagent client (tests).
	agentFor func(id, meshIP string) NodeagentAPI
	// The mesh (Task 10 fills them): the bootstrap peer plan of a new
	// node, whether its plan is applied (mesh_ready), and its peer out of
	// every plan.
	meshPlan   func(ctx context.Context, id, site string, snap nodeadm.Snapshot) (nodeadm.MeshPlan, error)
	meshReady  func(ctx context.Context, id string) (bool, error)
	meshRemove func(ctx context.Context, id string) error
	// poll is how often the enrolment reads the snapshot (0: 5 s).
	poll time.Duration
	// adding: adds between their entry and their op (the settle tick
	// leaves them alone).
	adding map[string]bool
}

func (h *Hub) markAdding(id string, on bool) {
	h.cl.mu.Lock()
	defer h.cl.mu.Unlock()
	if h.cl.adding == nil {
		h.cl.adding = map[string]bool{}
	}
	if on {
		h.cl.adding[id] = true
	} else {
		delete(h.cl.adding, id)
	}
}

func (h *Hub) isAdding(id string) bool {
	h.cl.mu.Lock()
	defer h.cl.mu.Unlock()
	return h.cl.adding[id]
}

// SetNodeadm replaces the nodeadm client (tests; nil: the real one).
func (h *Hub) SetNodeadm(api NodeadmAPI) {
	h.cl.mu.Lock()
	h.cl.api = api
	h.cl.mu.Unlock()
}

// ClusterNodesMode: Servers manages cluster nodes (a Kubernetes primary,
// R9), not Docker workers.
func (h *Hub) ClusterNodesMode() bool { return h.kubeOn() }

// clusterNodesOn: cluster nodes can be managed now (a Kubernetes primary
// with nodeadm configured); serversOn stays the Docker link's (T8).
func (h *Hub) clusterNodesOn() error {
	if !h.kubeOn() {
		return statusErr(http.StatusConflict, errClusterOnDocker)
	}
	h.cl.mu.Lock()
	api := h.cl.api
	h.cl.mu.Unlock()
	if api == nil && h.cfg.NodeadmURL == "" {
		return statusErr(http.StatusServiceUnavailable, "cluster nodes are off: nodeadm isn't configured (HUB_NODEADM_URL)")
	}
	return nil
}

// nodeadmAPI is the nodeadm client: the substitute, else one over TLS 1.3
// with the hub.control certificate, verifying nodeadm's node-nodeadm
// certificate (SAN nodeadm.portcullis-nodeadm.svc) against the pki_node CA.
func (h *Hub) nodeadmAPI(ctx context.Context) (NodeadmAPI, error) {
	if err := h.clusterNodesOn(); err != nil {
		return nil, err
	}
	h.cl.mu.Lock()
	api := h.cl.api
	h.cl.mu.Unlock()
	if api != nil {
		return api, nil
	}
	cert, ca, err := h.controlCert(ctx)
	if err != nil {
		return nil, err
	}
	h.cl.mu.Lock()
	defer h.cl.mu.Unlock()
	if h.cl.real == nil || len(cert.Certificate) == 0 || string(h.cl.realCert) != string(cert.Certificate[0]) {
		h.cl.real = &nodeadm.Client{BaseURL: h.cfg.NodeadmURL, TLS: pkiNodeTLS(cert, ca, nodeadm.ServerName)}
		if len(cert.Certificate) > 0 {
			h.cl.realCert = cert.Certificate[0]
		}
	}
	return h.cl.real, nil
}

// pkiNodeTLS: TLS 1.3, the control certificate as the client
// certificate, the pki_node CA as the only root, name the server's SAN.
func pkiNodeTLS(cert tls.Certificate, ca *x509.Certificate, name string) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	c := cert
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: name,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }}
}

// nodeagentAPI is node id's nodeagent at its mesh address.
func (h *Hub) nodeagentAPI(ctx context.Context, id, meshIP string) (NodeagentAPI, error) {
	h.cl.mu.Lock()
	f := h.cl.agentFor
	h.cl.mu.Unlock()
	if f != nil {
		return f(id, meshIP), nil
	}
	if !servers.MeshAddrOK(meshIP) {
		return nil, fmt.Errorf("node %s has no mesh address", id)
	}
	cert, ca, err := h.controlCert(ctx)
	if err != nil {
		return nil, err
	}
	return &nodeagent.Client{BaseURL: fmt.Sprintf("https://%s:%d", meshIP, nodeagent.Port), TLS: pkiNodeTLS(cert, ca, nodeagent.ServerName(id))}, nil
}

func (h *Hub) meshPlanFor(ctx context.Context, id, site string, snap nodeadm.Snapshot) (nodeadm.MeshPlan, error) {
	if f := h.cl.meshPlan; f != nil {
		return f(ctx, id, site, snap)
	}
	// Until the mesh planner (Task 10): no bootstrap peers.
	return nodeadm.MeshPlan{Peers: []nodeadm.MeshPeer{}, Forward: false}, nil
}

func (h *Hub) meshReady(ctx context.Context, id string) (bool, error) {
	if f := h.cl.meshReady; f != nil {
		return f(ctx, id)
	}
	return true, nil // Task 10 fills it (pre-flight P17)
}

func (h *Hub) meshRemovePeer(ctx context.Context, id string) error {
	if f := h.cl.meshRemove; f != nil {
		return f(ctx, id)
	}
	return nil
}

// nodeadmErr is a nodeadm refusal as the Hub answers it: its status (a 4xx
// or 503; anything else 502) and its text.
func nodeadmErr(err error) error {
	var ae *nodeadm.APIError
	if errors.As(err, &ae) {
		code := ae.Status
		if code < 400 || (code >= 500 && code != http.StatusServiceUnavailable) {
			code = http.StatusBadGateway
		}
		return statusErr(code, "%s", ae.Error())
	}
	var se *StatusError
	if errors.As(err, &se) {
		return err
	}
	return statusErr(http.StatusBadGateway, "nodeadm doesn't answer: %s", clipRunes(err.Error(), 200))
}

// AddClusterNodeRequest is POST /api/servers with kind cluster-node: role
// and class default to the suggestion, site to main, ingress to a cloud
// node and storage to a non-small node at main.
type AddClusterNodeRequest struct {
	ID, Name          string
	Role, Class, Site string
	Ingress, Storage  *bool
}

// ClusterNodeAdded is the add's answer (the code apart): the enrolment
// op, the node's role, class, site and labels, the suggestion's warnings,
// the server sentence and the one-liner to run on the machine.
type ClusterNodeAdded struct {
	OpID      string    `json:"op_id"`
	Op        string    `json:"op"`
	Poll      string    `json:"poll"`
	ExpiresAt time.Time `json:"expires_at"`
	Role      string    `json:"role"`
	Class     string    `json:"class"`
	Site      string    `json:"site"`
	Ingress   bool      `json:"ingress"`
	Storage   bool      `json:"storage"`
	Warnings  []string  `json:"warnings"`
	Notice    string    `json:"notice,omitempty"`
	Command   string    `json:"command"`
}

// JoinCommand is the one-liner a new node runs (ruling C6: the code is
// never on its command line; join.sh reads it from /dev/tty).
func (h *Hub) JoinCommand() string {
	return "curl -fsSL https://" + h.cfg.Domain + "/node/join.sh | sudo sh"
}

// CheckClusterNodeInput is an add's cheap checks (400), before a fresh
// sign-in proof is spent.
func CheckClusterNodeInput(r AddClusterNodeRequest) error {
	if err := CheckServerInput(r.ID, r.Name); err != nil {
		return err
	}
	switch {
	case r.Role != "" && r.Role != "server" && r.Role != "agent":
		return statusErr(http.StatusBadRequest, "role must be server or agent")
	case r.Class != "" && !servers.ValidClass(r.Class):
		return statusErr(http.StatusBadRequest, "class must be small, home or cloud")
	case r.Site != "" && !servers.ValidSite(r.Site):
		return statusErr(http.StatusBadRequest, "site must match ^[a-z][a-z0-9-]{0,30}$")
	case r.Storage != nil && *r.Storage && r.Site != "" && r.Site != servers.PrimarySite:
		return statusErr(http.StatusBadRequest, "storage nodes must be at the primary site (main) in this version")
	}
	return nil
}

// clusterSuggestInput: the snapshot's nodes plus the Hub's own nodes not
// in it yet (an enrolment in progress counts as a healthy node of its
// role, so two adds don't both take the third server).
func (h *Hub) clusterSuggestInput(snap nodeadm.Snapshot) []servers.ClusterNode {
	seen := map[string]bool{}
	var out []servers.ClusterNode
	for _, n := range snap.Nodes {
		seen[n.Name] = true
		site := n.Labels[nodeadm.LabelSite]
		if site == "" {
			site = servers.PrimarySite
		}
		out = append(out, servers.ClusterNode{ID: n.Name, Site: site, Role: n.Role, Healthy: n.Ready})
	}
	for _, e := range snap.Enrolling {
		if !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, servers.ClusterNode{ID: e.ID, Site: e.Site, Role: e.Role, Healthy: true})
		}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, s := range h.st.Servers {
		if s.ClusterNode() && !seen[id] && s.State == ServerEnrolling {
			out = append(out, servers.ClusterNode{ID: id, Site: s.Site, Role: s.Role, Healthy: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// allocMeshIP: the lowest free host address of 10.215.0.0/24 (.1–.254)
// that no node, enrolling node or listed server holds. Caller holds mu.
func (h *Hub) allocMeshIPLocked(snap nodeadm.Snapshot) (string, error) {
	used := map[string]bool{}
	for _, n := range snap.Nodes {
		used[n.Addresses.Mesh] = true
	}
	for _, e := range snap.Enrolling {
		used[e.MeshIP] = true
	}
	for _, s := range h.st.Servers {
		if s.MeshIP != "" {
			used[s.MeshIP] = true
		}
	}
	for i := 1; i <= 254; i++ {
		a := netip.AddrFrom4([4]byte{10, 215, 0, byte(i)}).String()
		if !used[a] {
			return a, nil
		}
	}
	return "", statusErr(http.StatusConflict, "the node mesh 10.215.0.0/24 has no free address")
}

// AddClusterNode adds a cluster node (§20.1): the role suggestion, a mesh
// address, the code from nodeadm (shown once: in no state field, op
// record, log line or audit entry), the audit server.add and the
// server_enrol op. Refused on Docker and Podman.
func (h *Hub) AddClusterNode(ctx context.Context, actor directory.Actor, r AddClusterNodeRequest) (out ClusterNodeAdded, code string, err error) {
	defer func() {
		if err != nil {
			h.auditOp(actor, "server.add", r.ID, "kind cluster-node", err)
		}
	}()
	if actor.User == "" {
		return out, "", statusErr(http.StatusUnauthorized, "no acting user")
	}
	if err := CheckClusterNodeInput(r); err != nil {
		return out, "", err
	}
	name, _ := validServerName(r.ID, r.Name)
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return out, "", err
	}
	snap, err := api.Cluster(ctx)
	if err != nil {
		return out, "", nodeadmErr(err)
	}
	if snap.Node(r.ID) != nil || snap.EnrollingNode(r.ID) != nil {
		return out, "", statusErr(http.StatusConflict, "server %s exists", r.ID)
	}
	site := r.Site
	if site == "" {
		site = servers.PrimarySite
	}
	role, warnings, err := servers.SuggestRole(h.clusterSuggestInput(snap), servers.NewNode{Site: site, Override: r.Role})
	if err != nil {
		return out, "", statusErr(http.StatusConflict, "%v", err)
	}
	class := r.Class
	if class == "" {
		class = "home" // the machine is unknown before it joins: the admin confirms or changes it
	}
	ingress, storage := class == "cloud", class != "small" && site == servers.PrimarySite
	if r.Ingress != nil {
		ingress = *r.Ingress
	}
	if r.Storage != nil {
		storage = *r.Storage
	}
	now := h.now().UTC()

	h.mu.Lock()
	if _, ok := h.st.Servers[r.ID]; ok {
		h.mu.Unlock()
		return out, "", statusErr(http.StatusConflict, "server %s exists", r.ID)
	}
	meshIP, err := h.allocMeshIPLocked(snap)
	if err != nil {
		h.mu.Unlock()
		return out, "", err
	}
	if h.st.Servers == nil {
		h.st.Servers = map[string]state.Server{}
	}
	h.markAdding(r.ID, true)
	defer h.markAdding(r.ID, false)
	h.st.Servers[r.ID] = state.Server{Kind: state.KindClusterNode, Name: name, State: ServerEnrolling, Role: role, Class: class, Site: site,
		MeshIP: meshIP, Labels: &state.NodeLabels{Ingress: ingress, Storage: storage}, BackupSchedule: state.BackupSchedule{Mode: "off"},
		Enrol: &state.Enrol{IssuedAt: now, ExpiresAt: now.Add(JoinCodeTTL), Step: StepEnrolled}}
	h.saveLocked()
	h.mu.Unlock()
	forget := func() {
		h.mu.Lock()
		if s, ok := h.st.Servers[r.ID]; ok && s.ClusterNode() {
			delete(h.st.Servers, r.ID)
			h.saveLocked()
		}
		h.mu.Unlock()
	}

	plan, err := h.meshPlanFor(ctx, r.ID, site, snap)
	if err != nil {
		forget()
		return out, "", statusErr(http.StatusConflict, "the node's mesh plan: %v", err)
	}
	ans, err := api.IssueCode(ctx, nodeadm.CodeRequest{ServerID: r.ID, Role: role, Class: class, Site: site, MeshIP: meshIP,
		Ingress: ingress, Storage: storage, Mesh: plan})
	if err != nil {
		forget()
		return out, "", nodeadmErr(err)
	}
	// The code must be the one asked for (a strict decode; its errors
	// never carry the code).
	jc, derr := servers.DecodeJoinCodeV2(ans.Code)
	expires, terr := time.Parse(time.RFC3339, ans.ExpiresAt)
	if derr != nil || terr != nil || jc.ServerID != r.ID || jc.Role != role || jc.Class != class || jc.Site != site || jc.MeshIP != meshIP {
		h.voidCode(r.ID)
		forget()
		why := "it doesn't match the request"
		if derr != nil {
			why = derr.Error()
		}
		return out, "", statusErr(http.StatusBadGateway, "nodeadm answered an unusable join code (%s): nothing was added", why)
	}
	h.mu.Lock()
	if s, ok := h.st.Servers[r.ID]; ok && s.Enrol != nil {
		s.Enrol.ExpiresAt = expires.UTC()
		h.st.Servers[r.ID] = s
		h.saveLocked()
	}
	h.mu.Unlock()
	h.auditOp(actor, "server.add", r.ID, fmt.Sprintf("kind cluster-node, name %q, role %s, class %s, site %s, mesh address %s, ingress %t, storage %t",
		name, role, class, site, meshIP, ingress, storage), nil)
	a, _, err := h.startOp(serverOpKey(r.ID), OpServerEnrol, actor, clusterEnrolPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		ready()
		return nil, nil, h.runClusterEnrol(ctx, r.ID, actor)
	})
	if err != nil {
		h.voidCode(r.ID)
		forget()
		return out, "", err
	}
	out = ClusterNodeAdded{OpID: a.OpID, Op: OpServerEnrol, Poll: "/api/servers/" + r.ID + "/op?op_id=" + a.OpID, ExpiresAt: expires.UTC(),
		Role: role, Class: class, Site: site, Ingress: ingress, Storage: storage, Warnings: warnings, Command: h.JoinCommand()}
	if role == "server" {
		out.Notice = ServerJoinNotice
	}
	return out, ans.Code, nil
}

func clusterEnrolPlan() []Step {
	return []Step{
		{Key: StepEnrolled, Label: "Waiting for the machine to enrol with its code"},
		{Key: StepMeshReady, Label: "Connecting it to the node mesh"},
		{Key: StepK3sJoined, Label: "Joining the cluster (k3s)"},
		{Key: StepNodeReady, Label: "Waiting for the node to be Ready"},
		{Key: StepStorageReady, Label: "Applying its labels and storage"},
		{Key: StepClusterDone, Label: "Done"},
	}
}

func (h *Hub) clusterPoll() time.Duration { return orDur(h.cl.poll, 5*time.Second) }

// cleanupCtx is a context for an undo after a Stop (the op's own is
// cancelled): its values, a bounded time.
func cleanupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
}

// voidCode voids node id's code (an unused code or an enrolled node
// without k3s: DELETE …?mode=cooperative) and its mesh peer; false when
// nodeadm couldn't be told (the entry then stays for the next tick).
func (h *Hub) voidCode(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), clusterCallWait)
	defer cancel()
	api, err := h.nodeadmAPI(ctx)
	if err == nil {
		err = api.Remove(ctx, id, nodeadm.Cooperative)
		if nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
			err = nil // nothing left there
		}
	}
	if err != nil {
		log.Printf("servers: voiding the code of %s: %v", id, err)
		return false
	}
	if err := h.meshRemovePeer(ctx, id); err != nil {
		log.Printf("servers: the mesh peer of %s: %v", id, err)
	}
	return true
}

// runClusterEnrol is a cluster node's server_enrol op: each step read
// from GET /v1/cluster (and the mesh). A Stop or a failure before
// k3s_joined voids the code (nothing is left); later it removes the node
// as a removal does.
func (h *Hub) runClusterEnrol(ctx context.Context, id string, actor directory.Actor) error {
	p := progressFrom(ctx)
	joined := false
	undo := func(step string, cause error) error {
		stopped := ctx.Err() != nil
		if !joined {
			if h.voidCode(id) {
				h.mu.Lock()
				if s, ok := h.st.Servers[id]; ok && s.ClusterNode() && s.State == ServerEnrolling {
					delete(h.st.Servers, id)
					h.saveLocked()
				}
				h.mu.Unlock()
			}
		} else {
			// A fresh context: the op's own reporter would refuse the
			// removal's commit once a Stop was accepted.
			cctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			if err := h.removeClusterNodeSteps(cctx, id, nil); err != nil {
				log.Printf("servers: removing %s after its enrolment ended: %v", id, err)
				h.setClusterState(id, ServerReady, "")
			}
			cancel()
		}
		if stopped {
			p.Undone(step)
			return ErrStopped
		}
		p.Fail(step, cause)
		h.auditOp(actor, "server.enrol_refused", id, "kind cluster-node", cause)
		return cause
	}
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return undo(StepEnrolled, err)
	}
	h.mu.RLock()
	s := h.st.Servers[id]
	h.mu.RUnlock()
	expires := h.now().Add(JoinCodeTTL)
	if s.Enrol != nil {
		expires = s.Enrol.ExpiresAt
	}
	// wait polls cond on the snapshot until it holds or deadline passes.
	wait := func(step string, deadline time.Time, why string, cond func(nodeadm.Snapshot) (bool, error)) error {
		p.Start(step)
		h.setEnrolStep(id, step)
		for {
			c, cancel := context.WithTimeout(ctx, clusterCallWait)
			snap, err := api.Cluster(c)
			cancel()
			if err == nil {
				ok, cerr := cond(snap)
				if cerr != nil {
					return cerr
				}
				if ok {
					p.Done(step)
					return nil
				}
			} else if ctx.Err() == nil {
				p.DetailThrottled(step, "nodeadm: "+clipRunes(err.Error(), 200))
			}
			if h.now().After(deadline) {
				return statusErr(http.StatusConflict, "%s", why)
			}
			if !sleepCtx(ctx, h.clusterPoll()) {
				return ctx.Err()
			}
		}
	}
	if err := wait(StepEnrolled, expires.Add(clusterEnrolGrace), "the join code expired before the machine enrolled: add the node again", func(sn nodeadm.Snapshot) (bool, error) {
		return sn.EnrollingNode(id) != nil || sn.Node(id) != nil, nil
	}); err != nil {
		return undo(StepEnrolled, err)
	}
	enrolled := h.now()
	p.Start(StepMeshReady)
	h.setEnrolStep(id, StepMeshReady)
	for {
		ok, err := h.meshReady(ctx, id)
		if err != nil {
			return undo(StepMeshReady, err)
		}
		if ok {
			p.Done(StepMeshReady)
			break
		}
		if h.now().After(enrolled.Add(clusterReadyWait)) {
			return undo(StepMeshReady, statusErr(http.StatusConflict, "the node mesh didn't reach %s within 10 minutes", id))
		}
		if !sleepCtx(ctx, h.clusterPoll()) {
			return undo(StepMeshReady, ctx.Err())
		}
	}
	if err := wait(StepK3sJoined, enrolled.Add(clusterJoinWait), "the node didn't join the cluster within 45 minutes (is params-sync running on the install host?)", func(sn nodeadm.Snapshot) (bool, error) {
		return sn.Node(id) != nil, nil
	}); err != nil {
		return undo(StepK3sJoined, err)
	}
	joined = true
	if err := wait(StepNodeReady, h.now().Add(clusterReadyWait), "the node didn't become Ready within 10 minutes", func(sn nodeadm.Snapshot) (bool, error) {
		n := sn.Node(id)
		return n != nil && n.Ready, nil
	}); err != nil {
		return undo(StepNodeReady, err)
	}
	h.mu.RLock()
	s = h.st.Servers[id]
	h.mu.RUnlock()
	want := nodeadm.Labels{Class: s.Class, Site: s.Site}
	if s.Labels != nil {
		want.Ingress, want.Storage = s.Labels.Ingress, s.Labels.Storage
	}
	relabelled := false
	if err := wait(StepStorageReady, h.now().Add(clusterReadyWait), "the node's labels weren't applied within 10 minutes", func(sn nodeadm.Snapshot) (bool, error) {
		n := sn.Node(id)
		if n == nil {
			return false, statusErr(http.StatusConflict, "node %s left the cluster during its enrolment", id)
		}
		if labelsMatch(n.Labels, want) {
			return true, nil
		}
		if !relabelled {
			relabelled = true
			c, cancel := context.WithTimeout(ctx, clusterCallWait)
			defer cancel()
			if err := api.SetLabels(c, id, want); err != nil && ctx.Err() == nil {
				return false, nodeadmErr(err)
			}
		}
		return false, nil
	}); err != nil {
		return undo(StepStorageReady, err)
	}
	p.Start(StepClusterDone)
	if !p.CloseStop() {
		return undo(StepClusterDone, ErrStopped)
	}
	h.mu.Lock()
	s, ok := h.st.Servers[id]
	if ok && s.ClusterNode() {
		s.State, s.Enrol, s.LastContact = ServerReady, nil, h.now().UTC()
		h.st.Servers[id] = s
		h.saveLocked()
	}
	h.mu.Unlock()
	p.Done(StepClusterDone)
	h.auditOp(actor, "server.enrolled", id, fmt.Sprintf("kind cluster-node, role %s, site %s", s.Role, s.Site), nil)
	return nil
}

// labelsMatch: the node carries the requested placement labels.
func labelsMatch(have map[string]string, w nodeadm.Labels) bool {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return ""
	}
	norm := func(v string) string {
		if v == "true" {
			return "true"
		}
		return ""
	}
	return have[nodeadm.LabelClass] == w.Class && have[nodeadm.LabelSite] == w.Site &&
		norm(have[nodeadm.LabelIngress]) == b(w.Ingress) && norm(have[nodeadm.LabelStorage]) == b(w.Storage)
}

func (h *Hub) setClusterState(id, st, step string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st.Servers[id]; ok && s.ClusterNode() {
		s.State = st
		if step != "" && s.Enrol != nil {
			s.Enrol.Step = step
		}
		h.st.Servers[id] = s
		h.saveLocked()
	}
}

// quorumMinimumText is nodeadm's quorum_minimum text (§20.2).
func quorumMinimumText(id string) string {
	return fmt.Sprintf("removing %s would leave fewer than 3 servers", id)
}

// RemoveClusterNode removes (mode cooperative: the op node_remove,
// cordon → drain → DELETE …?mode=cooperative → the nodeagent's k3s
// uninstall → its mesh peer out of every plan) or revokes (mode revoke:
// DELETE …?mode=revoke and the mesh peer at once) cluster node id; typed
// must be the id. A server whose removal would leave fewer than 3 healthy
// servers is refused 409 with nodeadm's text. The op is nil for a revoke.
func (h *Hub) RemoveClusterNode(ctx context.Context, actor directory.Actor, id, typed string, mode nodeadm.RemoveMode) (a *AsyncOp, err error) {
	action := "server.removed"
	if mode == nodeadm.Revoke {
		action = "server.revoked"
	}
	defer func() {
		if err != nil || mode == nodeadm.Revoke {
			h.auditOp(actor, action, id, "kind cluster-node", err)
		}
	}()
	switch {
	case actor.User == "":
		return nil, statusErr(http.StatusUnauthorized, "no acting user")
	case servers.ValidID(id) != nil:
		return nil, statusErr(http.StatusBadRequest, "invalid server id")
	case typed != id:
		return nil, statusErr(http.StatusBadRequest, "type the server id (%s) to confirm", id)
	case mode != nodeadm.Cooperative && mode != nodeadm.Revoke:
		return nil, statusErr(http.StatusBadRequest, "mode must be cooperative or revoke")
	}
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	s, listed := h.st.Servers[id]
	h.mu.RUnlock()
	if listed && !s.ClusterNode() {
		return nil, statusErr(http.StatusConflict, "server %s isn't a cluster node", id)
	}
	if listed && (s.State == ServerEnrolling || s.State == ServerRemoving) {
		return nil, statusErr(http.StatusConflict, "server %s is %s: stop its operation first (a Stop of an enrolment voids its code)", id, s.State)
	}
	snap, err := api.Cluster(ctx)
	if err != nil {
		return nil, nodeadmErr(err)
	}
	n := snap.Node(id)
	if n == nil && !listed {
		return nil, statusErr(http.StatusNotFound, "server %s not found", id)
	}
	meshIP := s.MeshIP
	if n != nil && n.Addresses.Mesh != "" {
		meshIP = n.Addresses.Mesh
	}
	if mode == nodeadm.Revoke {
		if err := api.Remove(ctx, id, nodeadm.Revoke); err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
			return nil, nodeadmErr(err)
		}
		if err := h.meshRemovePeer(ctx, id); err != nil {
			log.Printf("servers: the mesh peer of %s: %v", id, err)
		}
		h.dropClusterNode(id)
		return nil, nil
	}
	if n != nil && n.Role == "server" && n.Ready {
		healthy := 0
		for _, o := range snap.Nodes {
			if o.Role == "server" && o.Ready {
				healthy++
			}
		}
		if healthy <= 3 {
			return nil, statusErr(http.StatusConflict, "%s", quorumMinimumText(id))
		}
	}
	prev := s.State
	a, _, err = h.startOp(serverOpKey(id), OpNodeRemove, actor, removePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		if listed {
			h.setClusterState(id, ServerRemoving, "")
		}
		ready()
		err := h.removeClusterNodeSteps(ctx, id, &meshIP)
		if err != nil && listed {
			if _, still := h.serverEntry(id); still {
				h.setClusterState(id, nonEmpty(prev, ServerReady), "")
			}
		}
		h.auditOp(actor, "server.removed", id, "kind cluster-node", err)
		return nil, nil, err
	})
	return a, err
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (h *Hub) serverEntry(id string) (state.Server, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.st.Servers[id]
	return s, ok
}

func removePlan() []Step {
	return []Step{
		{Key: "cordon", Label: "Cordoning the node"},
		{Key: "drain", Label: "Draining it (disruption budgets respected)"},
		{Key: "remove", Label: "Removing it from the cluster"},
		{Key: "uninstall", Label: "Uninstalling k3s on the machine"},
		{Key: "mesh", Label: "Removing it from the node mesh"},
	}
}

// removeClusterNodeSteps is the cooperative removal. meshIP nil: read
// from the entry. Before the DELETE a Stop or a refusal uncordons the
// node and leaves it in the cluster; the DELETE is the commit.
func (h *Hub) removeClusterNodeSteps(ctx context.Context, id string, meshIP *string) error {
	p := progressFrom(ctx)
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return err
	}
	ip := ""
	if meshIP != nil {
		ip = *meshIP
	} else if s, ok := h.serverEntry(id); ok {
		ip = s.MeshIP
	}
	back := func(step string, cause error) error {
		c, cancel := cleanupCtx(ctx)
		if err := api.Uncordon(c, id); err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
			log.Printf("servers: uncordoning %s: %v", id, err)
		}
		cancel()
		if ctx.Err() != nil {
			p.Undone(step)
			return ErrStopped
		}
		cause = nodeadmErr(cause)
		p.Fail(step, cause)
		return cause
	}
	p.Start("cordon")
	if err := api.Cordon(ctx, id); err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
		return back("cordon", err)
	}
	p.Done("cordon")
	p.Start("drain")
	if err := api.Drain(ctx, id); err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
		return back("drain", err)
	}
	p.Done("drain")
	p.Start("remove")
	if !p.CloseStop() {
		return back("remove", ErrStopped)
	}
	if err := api.Remove(context.WithoutCancel(ctx), id, nodeadm.Cooperative); err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
		c, cancel := cleanupCtx(ctx)
		api.Uncordon(c, id)
		cancel()
		err = nodeadmErr(err)
		p.Fail("remove", err)
		return err
	}
	p.Done("remove")
	p.Start("uninstall")
	if ag, err := h.nodeagentAPI(ctx, id, ip); err != nil {
		p.Warn(fmt.Sprintf("k3s wasn't uninstalled on %s (%v): run k3s-uninstall.sh there", id, clipRunes(err.Error(), 160)))
	} else if err := ag.Uninstall(context.WithoutCancel(ctx)); err != nil {
		p.Warn(fmt.Sprintf("k3s wasn't uninstalled on %s (%v): run k3s-uninstall.sh there", id, clipRunes(err.Error(), 160)))
	}
	p.Done("uninstall")
	p.Start("mesh")
	if err := h.meshRemovePeer(context.WithoutCancel(ctx), id); err != nil {
		p.Warn(fmt.Sprintf("the mesh peer of %s: %v", id, clipRunes(err.Error(), 160)))
	}
	p.Done("mesh")
	h.dropClusterNode(id)
	return nil
}

// dropClusterNode removes node id's entry (gone from the cluster).
func (h *Hub) dropClusterNode(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st.Servers[id]; ok && s.ClusterNode() {
		delete(h.st.Servers, id)
		h.saveLocked()
	}
}

// settleClusterNodes: an enrolment or removal a Hub restart interrupted
// ends as a Stop at its step would (§17.5): before k3s_joined the code is
// voided and the entry goes; from it on the node is removed (the op
// node_remove). An entry whose void nodeadm didn't take is retried at the
// next tick.
func (h *Hub) settleClusterNodes(ctx context.Context) {
	h.mu.RLock()
	var void, remove, back []string
	for id, s := range h.st.Servers {
		if !s.ClusterNode() {
			continue
		}
		if h.opRunOf(serverOpKey(id)) || h.isAdding(id) {
			continue
		}
		switch s.State {
		case ServerEnrolling:
			step := ""
			if s.Enrol != nil {
				step = s.Enrol.Step
			}
			if step == "" || step == StepEnrolled || step == StepMeshReady || step == StepK3sJoined {
				void = append(void, id)
			} else {
				remove = append(remove, id)
			}
		case ServerRemoving:
			back = append(back, id)
		}
	}
	h.mu.RUnlock()
	for _, id := range void {
		if h.voidCode(id) {
			h.mu.Lock()
			if s, ok := h.st.Servers[id]; ok && s.ClusterNode() && s.State == ServerEnrolling {
				delete(h.st.Servers, id)
				h.saveLocked()
			}
			h.mu.Unlock()
			log.Printf("servers: the enrolment of %s was interrupted before it joined the cluster: its code is void", id)
			h.auditOp(directory.Actor{}, "server.enrol_refused", id, "kind cluster-node", statusErr(http.StatusConflict, "the Hub restarted during the enrolment"))
		}
	}
	for _, id := range append(remove, back...) {
		h.setClusterState(id, ServerReady, "")
		if _, err := h.RemoveClusterNode(ctx, directory.Human("hub"), id, id, nodeadm.Cooperative); err != nil {
			log.Printf("servers: removing %s after an interrupted operation: %v", id, err)
		}
	}
}

// opRunOf: an operation runs under key.
func (h *Hub) opRunOf(key string) bool {
	h.opRunsMu.Lock()
	defer h.opRunsMu.Unlock()
	return h.opRuns[key] != nil
}

// runClusterNodes is RunServers on Kubernetes: the interrupted
// operations settled at start and retried every tick.
func (h *Hub) runClusterNodes(ctx context.Context, every time.Duration) {
	if h.clusterNodesOn() != nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.settleClusterNodes(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// clusterViewFields fills a cluster node's view fields.
func clusterViewFields(v *ServerView, s state.Server) {
	if !s.ClusterNode() {
		return
	}
	v.Kind, v.Role, v.Class, v.Site, v.MeshIP = s.Kind, s.Role, s.Class, s.Site, s.MeshIP
	if s.Labels != nil {
		v.Ingress, v.Storage = s.Labels.Ingress, s.Labels.Storage
	}
	v.Runtime = "kubernetes"
}
