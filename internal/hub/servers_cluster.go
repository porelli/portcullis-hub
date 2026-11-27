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
	"strings"
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

// NodeagentAPI is the part of a node's nodeagent the Hub uses: the k3s
// uninstall of a removal, the health read (its pcmesh key), the mesh
// peer plan, the round trips over pcmesh and the host checks
// (*nodeagent.Client; tests substitute it).
type NodeagentAPI interface {
	Uninstall(ctx context.Context) error
	Health(ctx context.Context) (nodeagent.Health, error)
	PutMeshPeers(ctx context.Context, p nodeagent.MeshPlan) error
	RTT(ctx context.Context) (map[string]int, error)
	Checks(ctx context.Context) (nodeagent.Checks, error)
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
	// The mesh hooks' substitutes (tests; nil: servers_mesh.go): the
	// bootstrap peer plan of a new node, whether its plan is applied
	// (mesh_ready), and its peer out of every plan.
	meshPlan   func(ctx context.Context, id, site string, snap nodeadm.Snapshot) (nodeadm.MeshPlan, error)
	meshReady  func(ctx context.Context, id string) (bool, error)
	meshRemove func(ctx context.Context, id string) error
	// ms is the mesh's push state (servers_mesh.go).
	ms meshState
	// rtt: the nodes' last round trips over pcmesh (sites.go).
	rtt meshRTT
	// wd: the nodes' last watchdog host check, read with the round trips
	// while HA is off (sites.go: the checklist's watchdog before fencing).
	wd hostWatchdog
	// poll is how often the enrolment reads the snapshot (0: 5 s).
	poll time.Duration
	// adding: adds between their entry and their op (the settle tick
	// leaves them alone).
	adding map[string]bool
	// last is the last snapshot read (the list shows the nodes the Hub
	// didn't add: the ones of init).
	last *nodeadm.Snapshot
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

// SetNodeagents replaces the nodeagent clients (tests; nil: the real
// ones over pcmesh).
func (h *Hub) SetNodeagents(f func(id, meshIP string) NodeagentAPI) {
	h.cl.mu.Lock()
	h.cl.agentFor = f
	h.cl.mu.Unlock()
}

// ErrWorkersOnKube / ErrClusterOnDocker are the R9 refusals (409), for
// the routes' checks before a proof is spent.
func ErrWorkersOnKube() error   { return statusErr(http.StatusConflict, errWorkersOnKube) }
func ErrClusterOnDocker() error { return statusErr(http.StatusConflict, errClusterOnDocker) }

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
	s, _ := h.serverEntry(id)
	return h.bootstrapMeshPlan(ctx, id, site, s.MeshIP, snap)
}

func (h *Hub) meshReady(ctx context.Context, id string) (bool, error) {
	if f := h.cl.meshReady; f != nil {
		return f(ctx, id)
	}
	return h.meshReadyOf(ctx, id)
}

func (h *Hub) meshRemovePeer(ctx context.Context, id string) error {
	if f := h.cl.meshRemove; f != nil {
		return f(ctx, id)
	}
	return h.meshRemove(ctx, id)
}

// nodeadmErr is a nodeadm refusal as the Hub answers it: its status (a 4xx
// or 503; anything else 502) and its text.
func nodeadmErr(err error) error {
	var ae *nodeadm.APIError
	if errors.As(err, &ae) {
		code := ae.Status
		switch {
		case code == http.StatusForbidden:
			// Never a 403: on the † routes it means "a fresh sign-in is
			// required".
			return statusErr(http.StatusBadGateway, "nodeadm refused the Hub's certificate")
		case code == http.StatusServiceUnavailable:
			// Not the Hub's own "standing by".
			return statusErr(code, "nodeadm: %s", ae.Error())
		case code < 400 || code >= 500:
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
	// PublicEndpoint is the node's forwarded public UDP endpoint
	// ("<ip:port>", optional): a NATed node at a site of its own reaches
	// the other sites through it (contract §20.11).
	PublicEndpoint string
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
	if r.PublicEndpoint != "" {
		if _, ok := parseEndpoint(r.PublicEndpoint); !ok || len(r.PublicEndpoint) > 21 {
			return statusErr(http.StatusBadRequest, "public_endpoint must be an IPv4 address and port (<ip>:<port>)")
		}
	}
	return nil
}

// clusterSuggestInputLocked: the snapshot's nodes plus the Hub's own nodes not
// in it yet (an enrolment in progress counts as a healthy node of its
// role, so two adds don't both take the third server). Caller holds mu.
func (h *Hub) clusterSuggestInputLocked(snap nodeadm.Snapshot) []servers.ClusterNode {
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
	for id, s := range h.st.Servers {
		if s.ClusterNode() && !seen[id] && s.State == ServerEnrolling {
			out = append(out, servers.ClusterNode{ID: id, Site: s.Site, Role: s.Role, Healthy: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// allocMeshIP: the lowest free host address of 10.215.0.0/24 (.1–.254)
// that no node, enrolling node or listed server holds, nor a removed node
// whose record nodeadm still keeps (its code issue refuses that address
// until the admission params let it go). Caller holds mu.
func (h *Hub) allocMeshIPLocked(snap nodeadm.Snapshot) (string, error) {
	used := map[string]bool{}
	for _, n := range snap.Nodes {
		used[n.Addresses.Mesh] = true
	}
	for _, e := range snap.Enrolling {
		used[e.MeshIP] = true
	}
	for _, a := range snap.ReservedMeshIPs {
		used[a] = true
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
func (h *Hub) AddClusterNode(ctx context.Context, actor directory.Actor, r AddClusterNodeRequest) (out ClusterNodeAdded, code servers.JoinCodeSecret, err error) {
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
	snap, err := h.clusterSnapshot(ctx, api)
	if err != nil {
		return out, "", nodeadmErr(err)
	}
	if snap.Node(r.ID) != nil || snap.EnrollingNode(r.ID) != nil {
		return out, "", statusErr(http.StatusConflict, "server %s exists", r.ID)
	}
	// The pinned pki_node CA: the code's ca_sha256 must name it (M8).
	_, ca, err := h.controlCert(ctx)
	if err != nil {
		return out, "", err
	}
	site := r.Site
	if site == "" {
		site = servers.PrimarySite
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
	forward := ""
	if r.PublicEndpoint != "" {
		// The front door's rule for a public endpoint (never a private,
		// special-purpose or cluster address): checked before anything is
		// recorded.
		ap, _ := parseEndpoint(r.PublicEndpoint)
		h.cl.ms.mu.Lock()
		allowDoc := h.cl.ms.allowDoc
		h.cl.ms.mu.Unlock()
		if err := publicEndpointOK(ap, allowDoc, h.meshExcluded()); err != nil {
			return out, "", statusErr(http.StatusBadRequest, "public_endpoint: %v", err)
		}
		forward = ap.String()
	}
	now := h.now().UTC()

	h.mu.Lock()
	if _, ok := h.st.Servers[r.ID]; ok {
		h.mu.Unlock()
		return out, "", statusErr(http.StatusConflict, "server %s exists", r.ID)
	}
	// Task 30 fix round 2 (nit 1): an endpoint another node already has,
	// forwarded or reported, is a likely typo (its handshake would never
	// confirm it here): refused, naming that node.
	if other := h.endpointHolderLocked(forward, r.ID); other != "" {
		h.mu.Unlock()
		return out, "", statusErr(http.StatusConflict, "public_endpoint %s is already %s's", forward, other)
	}
	// Under mu with the entry's save: two adds never both take the third
	// server or pass the cap.
	role, warnings, err := servers.SuggestRole(h.clusterSuggestInputLocked(snap), servers.NewNode{Site: site, Override: r.Role})
	if err != nil {
		h.mu.Unlock()
		return out, "", statusErr(http.StatusConflict, "%v", err)
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
		MeshIP: meshIP, MeshForward: forward, Labels: &state.NodeLabels{Ingress: ingress, Storage: storage}, BackupSchedule: state.BackupSchedule{Mode: "off"},
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
		var se *StatusError
		if errors.As(err, &se) {
			return out, "", err // the §20.11 refusal, verbatim
		}
		return out, "", statusErr(http.StatusConflict, "the node's mesh plan: %v", err)
	}
	ans, err := api.IssueCode(ctx, nodeadm.CodeRequest{ServerID: r.ID, Role: role, Class: class, Site: site, MeshIP: meshIP,
		Ingress: ingress, Storage: storage, Mesh: plan, PublicEndpoint: forward})
	if err != nil {
		forget()
		return out, "", nodeadmErr(err)
	}
	// The code must be the one asked for (a strict decode; its errors
	// never carry the code).
	jc, derr := servers.DecodeJoinCodeV2(ans.Code.Reveal())
	expires, terr := time.Parse(time.RFC3339, ans.ExpiresAt)
	if derr != nil || terr != nil || jc.ServerID != r.ID || jc.Role != role || jc.Class != class || jc.Site != site || jc.MeshIP != meshIP ||
		jc.CASHA256 != caSHA256(ca) || jc.Endpoint != "https://"+h.cfg.Domain+"/node" {
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
	a, _, err := h.startOp(serverOpKey(r.ID), OpServerEnrol, actor, clusterEnrolPlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		// Audited ok only once the op is sure to start (ready can't fail).
		detail := fmt.Sprintf("kind cluster-node, name %q, role %s, class %s, site %s, mesh address %s, ingress %t, storage %t",
			name, role, class, site, meshIP, ingress, storage)
		if forward != "" {
			detail += ", forwarded endpoint " + forward
		}
		h.auditOp(actor, "server.add", r.ID, detail, nil)
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

// clusterSnapshot reads GET /v1/cluster and keeps it as the last
// snapshot (the list's nodes from init, M5).
func (h *Hub) clusterSnapshot(ctx context.Context, api NodeadmAPI) (nodeadm.Snapshot, error) {
	snap, err := api.Cluster(ctx)
	if err == nil {
		h.cl.mu.Lock()
		h.cl.last = &snap
		h.cl.mu.Unlock()
	}
	return snap, err
}

// lastSnapshot is the last snapshot read (nil: none yet).
func (h *Hub) lastSnapshot() *nodeadm.Snapshot {
	h.cl.mu.Lock()
	defer h.cl.mu.Unlock()
	return h.cl.last
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
	undo := func(step string, cause error) error {
		stopped := ctx.Err() != nil
		// Never only a void once the node may have joined (I2): the
		// snapshot decides, read now.
		h.endClusterEnrol(id, actor, nil)
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
	// The RTT limits (P23): after mesh_ready, before k3s_joined; a refusal
	// ends the enrolment as a revoke (its peer out of every plan), even
	// if nodeadm released its material meanwhile.
	rttOK, rttSince := false, h.now()
	if err := wait(StepK3sJoined, enrolled.Add(clusterJoinWait), "the node didn't join the cluster within 45 minutes (is params-sync running on the install host?)", func(sn nodeadm.Snapshot) (bool, error) {
		if !rttOK {
			ok, err := h.joinRTT(ctx, id, s.Role, s.MeshIP, sn, rttSince, p)
			if err != nil || !ok {
				return false, err
			}
			rttOK = true
		}
		return sn.Node(id) != nil, nil
	}); err != nil {
		return undo(StepK3sJoined, err)
	}
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
// servers is refused 409 with nodeadm's text. The op is nil for a revoke;
// parked is nodeadm's text when the revocation is parked (its security
// steps done, the node's etcd member waiting for quorum: accepted, the
// entry kept revoked until the cluster no longer lists the node).
func (h *Hub) RemoveClusterNode(ctx context.Context, actor directory.Actor, id, typed string, mode nodeadm.RemoveMode) (a *AsyncOp, parked string, err error) {
	action := "server.removed"
	if mode == nodeadm.Revoke {
		action = "server.revoked"
	}
	defer func() {
		if err != nil || mode == nodeadm.Revoke {
			detail := "kind cluster-node"
			if parked != "" {
				detail += ", parked: " + parked
			}
			h.auditOp(actor, action, id, detail, err)
		}
	}()
	switch {
	case actor.User == "":
		return nil, "", statusErr(http.StatusUnauthorized, "no acting user")
	case servers.ValidID(id) != nil:
		return nil, "", statusErr(http.StatusBadRequest, "invalid server id")
	case typed != id:
		return nil, "", statusErr(http.StatusBadRequest, "type the server id (%s) to confirm", id)
	case mode != nodeadm.Cooperative && mode != nodeadm.Revoke:
		return nil, "", statusErr(http.StatusBadRequest, "mode must be cooperative or revoke")
	}
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return nil, "", err
	}
	h.mu.RLock()
	s, listed := h.st.Servers[id]
	h.mu.RUnlock()
	if listed && !s.ClusterNode() {
		return nil, "", statusErr(http.StatusConflict, "server %s isn't a cluster node", id)
	}
	if listed && (s.State == ServerEnrolling || s.State == ServerRemoving) {
		return nil, "", statusErr(http.StatusConflict, "server %s is %s: stop its operation first (a Stop after enrolment revokes the node)", id, s.State)
	}
	if listed && s.State == ServerRevoked && mode == nodeadm.Cooperative {
		return nil, "", statusErr(http.StatusConflict, "server %s is revoked: its removal finishes once quorum returns", id)
	}
	snap, err := h.clusterSnapshot(ctx, api)
	if err != nil {
		return nil, "", nodeadmErr(err)
	}
	n := snap.Node(id)
	if n == nil && !listed {
		return nil, "", statusErr(http.StatusNotFound, "server %s not found", id)
	}
	meshIP := s.MeshIP
	if n != nil && n.Addresses.Mesh != "" {
		meshIP = n.Addresses.Mesh
	}
	if mode == nodeadm.Revoke {
		// Revoke now (a lost node): no uninstall (the machine is gone or
		// not trusted); the entry kept revoked and watched (settleRevoked).
		// Never on the caller's context alone (Task 30 fix round 1): the
		// CLI's exec into this pod breaks while the servers restart for
		// the token rotation, and a cancelled call recorded nothing, so the
		// node stayed listed ready while nodeadm finished the revocation.
		// Bounded like settleRevoked's.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Minute)
		defer cancel()
		parked, _, err := h.revokeNode(rctx, api, id, n, meshIP, false)
		if err != nil {
			return nil, "", nodeadmErr(err)
		}
		return nil, parked, nil
	}
	if n != nil && n.Role == "server" && n.Ready {
		healthy := 0
		for _, o := range snap.Nodes {
			if o.Role == "server" && o.Ready {
				healthy++
			}
		}
		if healthy <= 3 {
			return nil, "", statusErr(http.StatusConflict, "%s", quorumMinimumText(id))
		}
	}
	prev := s.State
	a, _, err = h.startOp(serverOpKey(id), OpNodeRemove, actor, removePlan(), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		// Recorded removing (an init node gets its entry now), so a Hub
		// restart can settle it.
		h.keepClusterNode(id, n, ServerRemoving, "")
		ready()
		err := h.removeClusterNodeSteps(ctx, id, &meshIP)
		if err != nil {
			if _, still := h.serverEntry(id); still {
				h.setClusterState(id, nonEmpty(prev, ServerReady), "")
			}
		}
		h.auditOp(actor, "server.removed", id, "kind cluster-node", err)
		return nil, nil, err
	})
	return a, "", err
}

// ParkedRevokeText is a parked revocation's line in the list (I1).
const ParkedRevokeText = "revoked; waiting for quorum to remove its etcd member"

// keepClusterNode puts node id in state st (an init node, listed only by
// the snapshot, gets its entry from n); parked is a parked revocation's
// nodeadm text.
func (h *Hub) keepClusterNode(id string, n *nodeadm.Node, st, parked string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.st.Servers[id]
	if !ok {
		if n == nil {
			return
		}
		s = state.Server{Kind: state.KindClusterNode, Name: id, Role: n.Role, Class: n.Labels[nodeadm.LabelClass], Site: n.Labels[nodeadm.LabelSite],
			MeshIP: n.Addresses.Mesh, BackupSchedule: state.BackupSchedule{Mode: "off"},
			Labels: &state.NodeLabels{Ingress: n.Labels[nodeadm.LabelIngress] == "true", Storage: n.Labels[nodeadm.LabelStorage] == "true"}}
	}
	if !s.ClusterNode() {
		return
	}
	s.State, s.Enrol = st, nil
	s.RevokeParked = parked
	if h.st.Servers == nil {
		h.st.Servers = map[string]state.Server{}
	}
	h.st.Servers[id] = s
	h.saveLocked()
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
	if s, ok := h.st.Servers[id]; ok && s.ClusterNode() {
		delete(h.st.Servers, id)
		h.saveLocked()
	}
	h.mu.Unlock()
	h.forgetCached(id)
}

// endClusterEnrol ends node id's enrolment (a Stop, a failure, a Hub
// restart), failing closed (security review round 3): once the machine
// enrolled or may have — nodeadm lists it enrolling or as a Node, or the
// op saw it — its code may have been used and its k3s material released,
// so it is revoked (revokeNode: nodeadm's revoke, the nodeagent's
// uninstall best effort, the entry kept revoked and watched). Only a code
// a snapshot read just now reports unused is voided, and that entry is
// watched too (a Node registering within NodeGoneWait is revoked). false:
// nodeadm couldn't be asked (the entry stays enrolling; the next tick
// retries).
func (h *Hub) endClusterEnrol(id string, actor directory.Actor, _ *nodeadm.Snapshot) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return false
	}
	// Always a fresh read, right before the decision.
	c, ccancel := context.WithTimeout(ctx, clusterCallWait)
	snap, err := h.clusterSnapshot(c, api)
	ccancel()
	if err != nil {
		log.Printf("servers: ending the enrolment of %s: the snapshot: %v (retried at the next tick)", id, err)
		return false
	}
	s, _ := h.serverEntry(id)
	step := ""
	if s.Enrol != nil {
		step = s.Enrol.Step
	}
	n := snap.Node(id)
	meshIP := s.MeshIP
	if n != nil && n.Addresses.Mesh != "" {
		meshIP = n.Addresses.Mesh
	}
	if n != nil || snap.EnrollingNode(id) != nil || (step != "" && step != StepEnrolled) {
		parked, _, err := h.revokeNode(ctx, api, id, n, meshIP, true)
		if err != nil {
			log.Printf("servers: revoking %s after its enrolment ended: %v (retried at the next tick)", id, err)
			return false
		}
		detail := "kind cluster-node, after its enrolment ended (its k3s material may have been released)"
		if parked != "" {
			detail += ", parked: " + parked
		}
		h.auditOp(actor, "server.revoked", id, detail, nil)
		return true
	}
	if !h.voidCode(id) {
		return false
	}
	h.markRevoked(id, nil, revokeMark{void: true, confirmed: true})
	return true
}

// NodeGoneWait is how long a revoked entry stays once its revocation is
// confirmed and the cluster lists no Node of its name (a machine still
// finishing its join would register meanwhile).
const NodeGoneWait = 10 * time.Minute

// VoidedText is a voided enrolment's line in the list while it is watched.
const VoidedText = "cancelled: its join code is void (watched for 10 minutes)"

// revokeMark is how a revoked entry is recorded.
type revokeMark struct {
	parked    string // nodeadm's text of a parked (or background) revocation
	confirmed bool   // nodeadm answered done (204) or parked with its security steps done
	void      bool   // only the code was voided (it was never used)
}

// revokeNode is nodeadm's revoke of node id (DELETE ?mode=revoke: the
// node marked removed, its certificate revoked, its tokens deleted, the
// server and agent tokens rotated, the Node deleted; never a cordon, a
// drain or an uncordon: nodeadm owns the node from here), the mesh peer at
// once, the nodeagent's k3s uninstall when uninstall (best effort, its TLS
// pinned by id), and the entry kept revoked and watched. A 409 parked
// (security steps done) is confirmed; a 503 "goes on in the background"
// and unknown_node are accepted but unconfirmed: settleRevoked asks again
// each tick. Any other refusal is err (nothing recorded).
func (h *Hub) revokeNode(ctx context.Context, api NodeadmAPI, id string, n *nodeadm.Node, meshIP string, uninstall bool) (parked string, confirmed bool, err error) {
	parked, confirmed, err = revokeAnswer(api.Remove(ctx, id, nodeadm.Revoke))
	if err != nil {
		return "", false, err
	}
	if err := h.meshRemovePeer(ctx, id); err != nil {
		log.Printf("servers: the mesh peer of %s: %v", id, err)
	}
	if uninstall {
		if ag, err := h.nodeagentAPI(ctx, id, meshIP); err == nil {
			c, cancel := context.WithTimeout(ctx, clusterCallWait)
			if err := ag.Uninstall(c); err != nil {
				log.Printf("servers: k3s wasn't uninstalled on %s (%v): the node stays watched", id, err)
			}
			cancel()
		}
	}
	h.markRevoked(id, n, revokeMark{parked: parked, confirmed: confirmed})
	return parked, confirmed, nil
}

// revokeAnswer classifies nodeadm's answer to a revoke.
func revokeAnswer(err error) (parked string, confirmed bool, _ error) {
	var ae *nodeadm.APIError
	switch {
	case err == nil:
		return "", true, nil
	case nodeadm.IsKind(err, nodeadm.KindUnknownNode):
		return "", false, nil // no proof it finished: asked again
	case errors.As(err, &ae) && ae.Status == http.StatusConflict && ae.Kind == nodeadm.KindQuorumMinimum:
		return ae.Text, true, nil // parked: its security steps are done
	case errors.As(err, &ae) && ae.Status == http.StatusServiceUnavailable && strings.Contains(ae.Text, "goes on in the background"):
		return ae.Text, false, nil
	}
	return "", false, err
}

// markRevoked records node id revoked and watched (an init node gets its
// entry from n).
func (h *Hub) markRevoked(id string, n *nodeadm.Node, m revokeMark) {
	h.keepClusterNode(id, n, ServerRevoked, m.parked)
	h.mu.Lock()
	if s, ok := h.st.Servers[id]; ok && s.ClusterNode() {
		s.RevokeWatch, s.RevokeConfirmed, s.RevokeVoidOnly = true, m.confirmed, m.void
		h.st.Servers[id] = s
		h.saveLocked()
	}
	h.mu.Unlock()
	h.forgetCached(id)
}

// forgetCached takes node id out of the cached snapshot (re-review N2):
// a node just revoked or removed is never listed again as an init node.
func (h *Hub) forgetCached(id string) {
	h.cl.mu.Lock()
	defer h.cl.mu.Unlock()
	if h.cl.last == nil {
		return
	}
	c := *h.cl.last
	c.Nodes = nil
	for _, n := range h.cl.last.Nodes {
		if n.Name != id {
			c.Nodes = append(c.Nodes, n)
		}
	}
	h.cl.last = &c
}

// settleClusterNodes runs at start and every tick (one snapshot):
//   - an enrolment a Hub restart interrupted ends as a Stop would
//     (endClusterEnrol: a listed node removed, else its code voided);
//   - an interrupted removal is a Stop too: before its DELETE (the node
//     still listed) it is uncordoned and back to ready; after it (no
//     longer listed) the uninstall and the mesh peer are finished;
//   - a parked revocation's entry goes once the cluster no longer lists
//     the node.
func (h *Hub) settleClusterNodes(ctx context.Context) {
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return
	}
	c, cancel := context.WithTimeout(ctx, clusterCallWait)
	snap, err := h.clusterSnapshot(c, api)
	cancel()
	if err != nil {
		log.Printf("servers: the cluster snapshot: %v", err)
		return
	}
	type pending struct{ id, state, mesh string }
	var todo []pending
	h.mu.RLock()
	for id, s := range h.st.Servers {
		if !s.ClusterNode() || h.opRunOf(serverOpKey(id)) || h.isAdding(id) {
			continue
		}
		if s.State == ServerEnrolling || s.State == ServerRemoving || s.State == ServerRevoked {
			todo = append(todo, pending{id, s.State, s.MeshIP})
		}
	}
	h.mu.RUnlock()
	sort.Slice(todo, func(i, j int) bool { return todo[i].id < todo[j].id })
	hubActor := directory.Human("hub")
	for _, t := range todo {
		n := snap.Node(t.id)
		switch t.state {
		case ServerEnrolling:
			if h.endClusterEnrol(t.id, hubActor, &snap) {
				log.Printf("servers: the enrolment of %s was interrupted by a Hub stop: ended as a Stop", t.id)
				h.auditOp(hubActor, "server.enrol_refused", t.id, "kind cluster-node", statusErr(http.StatusConflict, "the Hub restarted during the enrolment"))
			}
		case ServerRemoving:
			if n != nil {
				c, cancel := cleanupCtx(ctx)
				err := api.Uncordon(c, t.id)
				cancel()
				if err != nil && !nodeadm.IsKind(err, nodeadm.KindUnknownNode) {
					log.Printf("servers: uncordoning %s after an interrupted removal: %v (retried at the next tick)", t.id, err)
					continue
				}
				h.setClusterState(t.id, ServerReady, "")
				log.Printf("servers: the removal of %s was interrupted by a Hub stop: uncordoned, remove it again", t.id)
				h.auditOp(hubActor, "server.removed", t.id, "kind cluster-node", statusErr(http.StatusConflict, "the Hub restarted during the removal: the node was uncordoned; remove it again"))
				continue
			}
			// Its DELETE had committed: finish the machine and the mesh.
			c, cancel := cleanupCtx(ctx)
			if ag, err := h.nodeagentAPI(c, t.id, t.mesh); err == nil {
				if err := ag.Uninstall(c); err != nil {
					log.Printf("servers: k3s wasn't uninstalled on %s: %v (run k3s-uninstall.sh there)", t.id, err)
				}
			}
			if err := h.meshRemovePeer(c, t.id); err != nil {
				log.Printf("servers: the mesh peer of %s: %v", t.id, err)
			}
			cancel()
			h.dropClusterNode(t.id)
			h.auditOp(hubActor, "server.removed", t.id, "kind cluster-node, finished after a Hub restart", nil)
		case ServerRevoked:
			h.settleRevoked(ctx, api, t.id, n)
		}
	}
	// A node that missed its mesh plan (or whose plan changed: a join, a
	// removal, an endpoint) gets it now.
	h.meshTick(ctx, snap)
	// The round trips (the gauge, mesh_rtt_high, the sites view).
	h.startCollectRTT(ctx, snap)
}

// settleRevoked watches a revoked entry (security review round 3):
//   - an unconfirmed revocation (503 background, unknown_node) is asked
//     again (nodeadm's revoke is a resumable op);
//   - while the cluster lists its Node, a revocation that isn't parked is
//     asked again (nodeadm deletes the Node again) — a voided code whose
//     machine registered after all is revoked; never a cordon, a drain or
//     an uncordon;
//   - the entry goes only once its revocation is confirmed AND no Node of
//     its name was listed for NodeGoneWait (time alone is never enough).
func (h *Hub) settleRevoked(ctx context.Context, api NodeadmAPI, id string, n *nodeadm.Node) {
	s, ok := h.serverEntry(id)
	if !ok {
		return
	}
	now := h.now().UTC()
	hubActor := directory.Human("hub")
	again := !s.RevokeConfirmed || (n != nil && s.RevokeParked == "")
	if again {
		c, cancel := context.WithTimeout(ctx, 20*time.Minute)
		if n != nil {
			log.Printf("servers: %s is listed after its revocation (its kubelet still runs): revoking it again", id)
		}
		mesh := s.MeshIP
		if n != nil && n.Addresses.Mesh != "" {
			mesh = n.Addresses.Mesh
		}
		// A voided code whose machine registered: its material was out.
		uninstall := s.RevokeVoidOnly && n != nil
		parked, confirmed, err := h.revokeNode(c, api, id, n, mesh, uninstall)
		cancel()
		if err != nil {
			log.Printf("servers: revoking %s again: %v (retried at the next tick)", id, err)
		} else {
			detail := "kind cluster-node, revoked again"
			if n != nil {
				detail = "kind cluster-node, listed again after its revocation"
			}
			if parked != "" {
				detail += ", parked: " + parked
			}
			if n != nil || !s.RevokeConfirmed && confirmed {
				h.auditOp(hubActor, "server.revoked", id, detail, nil)
			}
		}
		s, _ = h.serverEntry(id)
	}
	if n != nil {
		if !s.NodeGoneSince.IsZero() {
			h.setNodeGone(id, time.Time{})
		}
		return
	}
	switch {
	case s.NodeGoneSince.IsZero():
		h.setNodeGone(id, now)
	case s.RevokeConfirmed && now.Sub(s.NodeGoneSince) >= NodeGoneWait:
		h.dropClusterNode(id) // confirmed, and no Node for 10 min
	}
}

func (h *Hub) setNodeGone(id string, t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st.Servers[id]; ok && s.ClusterNode() {
		s.NodeGoneSince = t
		h.st.Servers[id] = s
		h.saveLocked()
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
	v.RevokeConfirmed = s.State == ServerRevoked && s.RevokeConfirmed
	switch {
	case s.State == ServerRevoked && s.RevokeVoidOnly:
		v.Error = VoidedText
	case s.State == ServerRevoked && s.RevokeParked != "":
		v.Error = ParkedRevokeText
	}
}

// initNodeViewsLocked are the views of the cluster's nodes the Hub has no
// entry for (the nodes of init), from the last snapshot (review M5), by
// name. Caller holds mu.
func (h *Hub) initNodeViewsLocked() []ServerView {
	if !h.kubeOn() {
		return nil
	}
	snap := h.lastSnapshot()
	if snap == nil {
		return nil
	}
	var out []ServerView
	for _, n := range snap.Nodes {
		if _, ok := h.st.Servers[n.Name]; ok || servers.ValidID(n.Name) != nil {
			continue
		}
		st := ServerReady
		if !n.Ready {
			st = ServerOffline
		}
		site := n.Labels[nodeadm.LabelSite]
		if site == "" {
			site = servers.PrimarySite
		}
		out = append(out, ServerView{ID: n.Name, Name: n.Name, State: st, Runtime: "kubernetes", Instances: []string{}, Kind: state.KindClusterNode,
			Role: n.Role, Class: n.Labels[nodeadm.LabelClass], Site: site, MeshIP: n.Addresses.Mesh,
			Ingress: n.Labels[nodeadm.LabelIngress] == "true", Storage: n.Labels[nodeadm.LabelStorage] == "true"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// endpointHolderLocked: the other server whose forwarded or reported
// public endpoint is ep ("" when none, or ep is ""). h.mu held.
func (h *Hub) endpointHolderLocked(ep, self string) string {
	if ep == "" {
		return ""
	}
	ids := make([]string, 0, len(h.st.Servers))
	for id := range h.st.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := h.st.Servers[id]
		if id != self && (s.MeshForward == ep || s.MeshPublic == ep) {
			return id
		}
	}
	return ""
}
