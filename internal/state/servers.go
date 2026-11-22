package state

import "time"

// Server is one worker server (contract §17.3). The primary is never
// listed here (it is the local engine).
type Server struct {
	Name     string `json:"name" yaml:"name"`
	TunnelIP string `json:"tunnel_ip" yaml:"tunnel_ip"`
	// WGPublicKey is the peer key link.json carries: the bootstrap key's
	// while enrolling, the agent's own once enrolled.
	WGPublicKey string `json:"wg_public_key" yaml:"wg_public_key"`
	// CertSerial / SPKI pin the worker's node certificate (serial as
	// Vault writes it; SPKI the sha256 hex of its SubjectPublicKeyInfo).
	CertSerial string `json:"cert_serial,omitempty" yaml:"cert_serial,omitempty"`
	SPKI       string `json:"spki,omitempty" yaml:"spki,omitempty"`
	// State is enrolling, ready, offline or revoked.
	State          string         `json:"state" yaml:"state"`
	LocalNetworks  *[]string      `json:"local_networks,omitempty" yaml:"local_networks,omitempty"`
	BackupSchedule BackupSchedule `json:"backup_schedule" yaml:"backup_schedule"`
	CertNotAfter   time.Time      `json:"cert_not_after,omitempty" yaml:"cert_not_after,omitempty"`
	LastContact    time.Time      `json:"last_contact,omitempty" yaml:"last_contact,omitempty"`
	AgentVersion   string         `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`
	// Enrol exists only while enrolling (no secret: its sha256).
	Enrol *Enrol `json:"enrol,omitempty" yaml:"enrol,omitempty"`
	// QuarantinedUntil: a revoked server's tunnel address is free again
	// after it.
	QuarantinedUntil time.Time `json:"quarantined_until,omitempty" yaml:"quarantined_until,omitempty"`
	// Revoke is the revocation's progress (each step retried until done).
	Revoke *RevokeSteps `json:"revoke,omitempty" yaml:"revoke,omitempty"`
	// Kind is "" or "worker" (a Docker or Podman worker, contract §17) or
	// "cluster-node" (a node of the Kubernetes cluster, §20.1, added
	// through nodeadm; no tunnel, agent or pins). A cluster node keeps its
	// role, class, site, mesh address and labels here.
	Kind   string      `json:"kind,omitempty" yaml:"kind,omitempty"`
	Role   string      `json:"role,omitempty" yaml:"role,omitempty"`
	Class  string      `json:"class,omitempty" yaml:"class,omitempty"`
	Site   string      `json:"site,omitempty" yaml:"site,omitempty"`
	MeshIP string      `json:"mesh_ip,omitempty" yaml:"mesh_ip,omitempty"`
	Labels *NodeLabels `json:"labels,omitempty" yaml:"labels,omitempty"`
	// MeshPub, MeshLAN and MeshPublic are the node's pcmesh report at
	// enrolment (its WireGuard key, its LAN and public "<ip:port>"; "":
	// none), kept from nodeadm's enrolling entry for the peer plan
	// (contract §20.11) once the node is a Kubernetes Node.
	MeshPub    string `json:"mesh_pub,omitempty" yaml:"mesh_pub,omitempty"`
	MeshLAN    string `json:"mesh_lan,omitempty" yaml:"mesh_lan,omitempty"`
	MeshPublic string `json:"mesh_public,omitempty" yaml:"mesh_public,omitempty"`
	// MeshKeyAt is when MeshPub was first recorded (of two nodes sharing
	// a key, the later one is left out of the plan; zero: a node of init,
	// the earliest).
	MeshKeyAt time.Time `json:"mesh_key_at,omitempty" yaml:"mesh_key_at,omitempty"`
	// MeshPlanPushedAt: when the node's own plan first reached its
	// nodeagent; from then on its key and endpoints are frozen.
	MeshPlanPushedAt time.Time `json:"mesh_plan_pushed_at,omitempty" yaml:"mesh_plan_pushed_at,omitempty"`
	// RevokeParked is nodeadm's text of a parked revocation (its security
	// steps done, the etcd member removed once quorum returns): the entry
	// stays revoked until the cluster no longer lists the node.
	RevokeParked string `json:"revoke_parked,omitempty" yaml:"revoke_parked,omitempty"`
	// RevokeWatch: an enrolment revoked because its machine may hold its
	// k3s material; a Node that registers is removed for good.
	// NodeGoneSince: since when the cluster lists no Node of the revoked
	// entry's name (the entry goes 10 min later).
	// RevokeConfirmed: nodeadm answered the revoke done (204) or parked
	// with its security steps done; RevokeVoidOnly: only an unused code
	// was voided (a Node registering later is revoked).
	RevokeWatch     bool      `json:"revoke_watch,omitempty" yaml:"revoke_watch,omitempty"`
	RevokeConfirmed bool      `json:"revoke_confirmed,omitempty" yaml:"revoke_confirmed,omitempty"`
	RevokeVoidOnly  bool      `json:"revoke_void_only,omitempty" yaml:"revoke_void_only,omitempty"`
	NodeGoneSince   time.Time `json:"node_gone_since,omitempty" yaml:"node_gone_since,omitempty"`
}

// The server kinds.
const (
	KindWorker      = "worker"
	KindClusterNode = "cluster-node"
)

// ClusterNode: s is a node of the Kubernetes cluster.
func (s Server) ClusterNode() bool { return s.Kind == KindClusterNode }

// NodeLabels are a cluster node's boolean placement labels (contract
// §20.1: portcullis.io/ingress, portcullis.io/storage).
type NodeLabels struct {
	Ingress bool `json:"ingress" yaml:"ingress"`
	Storage bool `json:"storage" yaml:"storage"`
}

// Enrol is an enrolment in progress: the join code secret's sha256, the
// bootstrap public key, when the code expires, whether it was used, and
// how far it got (join, handshake, verify).
type Enrol struct {
	SecretSHA256 string    `json:"secret_sha256" yaml:"secret_sha256"`
	BootstrapPub string    `json:"bootstrap_pub" yaml:"bootstrap_pub"`
	IssuedAt     time.Time `json:"issued_at" yaml:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at" yaml:"expires_at"`
	Used         bool      `json:"used,omitempty" yaml:"used,omitempty"`
	Step         string    `json:"step,omitempty" yaml:"step,omitempty"`
}

// RevokeSteps records which revocation steps are done (spec §6). The
// certificates to revoke (step 2) are AppState.OwedSerials.
type RevokeSteps struct {
	At         time.Time `json:"at" yaml:"at"`
	RelaysDone bool      `json:"relays_done,omitempty" yaml:"relays_done,omitempty"`
	Rotated    bool      `json:"rotated,omitempty" yaml:"rotated,omitempty"`
	// Remove: a removal (the entry goes once every step is done).
	Remove bool `json:"remove,omitempty" yaml:"remove,omitempty"`
}

// BackupSchedule is a server's scheduled backups (contract §11.5):
// off, daily or weekly at Hour (0–23), Weekday 0–6 (weekly; 0 = Sunday).
type BackupSchedule struct {
	Mode    string `json:"mode" yaml:"mode"`
	Hour    int    `json:"hour" yaml:"hour"`
	Weekday int    `json:"weekday" yaml:"weekday"`
}

// OwedBundle is a worker bundle to remove: the server, the instance and
// since when.
type OwedBundle struct {
	Server   string    `json:"server" yaml:"server"`
	Instance string    `json:"instance" yaml:"instance"`
	Since    time.Time `json:"since" yaml:"since"`
}

// OwedSerial is a node certificate serial that must be revoked on
// pki_node: one signed but not (yet) pinned — recorded before the
// certificate leaves the Hub — or a revoked server's pinned one. It
// stays until it is pinned or revoked, whether or not its server still
// exists.
type OwedSerial struct {
	Server string    `json:"server" yaml:"server"`
	Serial string    `json:"serial" yaml:"serial"`
	Since  time.Time `json:"since" yaml:"since"`
}

// MeshNode is the Hub's record of a node's place in the pcmesh peer plan
// (contract §20.11), persisted so a Hub restart plans with what it knew:
// for a node of init (no Server entry) its key, mesh address and site,
// pinned at first sight; for every node the state of its public endpoint
// (offered until a peer at another site holds a handshake from it, then
// reachable, or unreachable after 2 min without one) and whether it was
// taken out of every plan.
type MeshNode struct {
	Pub    string `json:"pub,omitempty" yaml:"pub,omitempty"`
	MeshIP string `json:"mesh_ip,omitempty" yaml:"mesh_ip,omitempty"`
	Site   string `json:"site,omitempty" yaml:"site,omitempty"`
	// Ingress: a node of init is an ingress node (its Node's
	// portcullis.io/ingress label, pinned with its site at first sight:
	// never re-read from a later Node, core Task 11 parked → Task 30).
	Ingress   bool      `json:"ingress,omitempty" yaml:"ingress,omitempty"`
	Public    string    `json:"public,omitempty" yaml:"public,omitempty"`
	Reach     string    `json:"reach,omitempty" yaml:"reach,omitempty"`
	OfferedAt time.Time `json:"offered_at,omitempty" yaml:"offered_at,omitempty"`
	// CheckedAt: the last handshake that confirmed a reachable endpoint,
	// or when it was found unreachable.
	CheckedAt time.Time `json:"checked_at,omitempty" yaml:"checked_at,omitempty"`
	// Changes: when Public changed lately (the last 10 min); HoldUntil: a
	// flapping endpoint (more than 3 changes in 10 min) is unreachable
	// until then.
	Changes   []time.Time `json:"changes,omitempty" yaml:"changes,omitempty"`
	HoldUntil time.Time   `json:"hold_until,omitempty" yaml:"hold_until,omitempty"`
	Removed   bool        `json:"removed,omitempty" yaml:"removed,omitempty"`
	// Applied is the hash of the plan the node's nodeagent last took from
	// a Hub (a record only: a new leader pushes every plan again and never
	// counts it as proof; cleared once the node is out of the plan).
	Applied string `json:"applied,omitempty" yaml:"applied,omitempty"`
}

// The public endpoint states of a MeshNode.
const (
	ReachOffered     = "offered"
	ReachReachable   = "reachable"
	ReachUnreachable = "unreachable"
)
