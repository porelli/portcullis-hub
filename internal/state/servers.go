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
	// RevokeParked is nodeadm's text of a parked revocation (its security
	// steps done, the etcd member removed once quorum returns): the entry
	// stays revoked until the cluster no longer lists the node.
	RevokeParked string `json:"revoke_parked,omitempty" yaml:"revoke_parked,omitempty"`
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
