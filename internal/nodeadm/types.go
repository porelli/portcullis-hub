// Package nodeadm is the Hub's client of core's nodeadm internal API
// (contract §20.2): join codes for cluster nodes, the cluster snapshot,
// node labels, cordon / uncordon / drain and removal. The wire shapes are
// nodeadm's own (core nodeadm/types.go), decoded strictly both ways;
// vectors nodeadm_api_vectors.json (a byte copy of core's).
package nodeadm

import (
	"encoding/json"
	"log/slog"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/servers"
)

// MeshPeer is one peer of a mesh plan (§20.4 PUT /v1/mesh/peers).
type MeshPeer struct {
	ID         string                      `json:"id"`
	Pub        string                      `json:"pub"`
	Endpoint   jsonstrict.Nullable[string] `json:"endpoint"`
	AllowedIPs []string                    `json:"allowed_ips"`
	Keepalive  int                         `json:"keepalive"`
}

// MeshPlan is a node's peer plan; a code carries the bootstrap one.
type MeshPlan struct {
	Peers   []MeshPeer `json:"peers"`
	Forward bool       `json:"forward"`
}

// MeshReport is what a node reported of itself at enrolment.
type MeshReport struct {
	Pub    string                      `json:"pub"`
	LAN    jsonstrict.Nullable[string] `json:"lan"`
	Public jsonstrict.Nullable[string] `json:"public"`
}

// CodeRequest is POST /v1/codes.
type CodeRequest struct {
	ServerID string   `json:"server_id"`
	Role     string   `json:"role"`
	Class    string   `json:"class"`
	Site     string   `json:"site"`
	MeshIP   string   `json:"mesh_ip"`
	Ingress  bool     `json:"ingress"`
	Storage  bool     `json:"storage"`
	Mesh     MeshPlan `json:"mesh"`
}

// CodeAnswer is POST /v1/codes' 201. Code is a secret (the join code
// v2): String, GoString, MarshalJSON and LogValue redact it (the code's
// own type redacts it too).
type CodeAnswer struct {
	Code      servers.JoinCodeSecret `json:"code"`
	ExpiresAt string                 `json:"expires_at"`
}

// String redacts the code.
func (a CodeAnswer) String() string {
	return "code answer {code:<redacted> expires_at:" + a.ExpiresAt + "}"
}

// GoString redacts the code.
func (a CodeAnswer) GoString() string { return a.String() }

// MarshalJSON redacts the code.
func (a CodeAnswer) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"code": "<redacted>", "expires_at": a.ExpiresAt})
}

// LogValue redacts the code (log/slog).
func (a CodeAnswer) LogValue() slog.Value { return slog.StringValue(a.String()) }

// Labels is PUT /v1/nodes/{id}/labels (all four: a full replacement).
type Labels struct {
	Class   string `json:"class"`
	Site    string `json:"site"`
	Ingress bool   `json:"ingress"`
	Storage bool   `json:"storage"`
}

// RemoveMode is DELETE /v1/nodes/{id}'s mode.
type RemoveMode string

const (
	// Cooperative drains, evicts Longhorn's replicas, removes the etcd
	// member and the node object and revokes the certificate.
	Cooperative RemoveMode = "cooperative"
	// Revoke is for a lost node: never refused for a minimum; the k3s
	// tokens are rotated.
	Revoke RemoveMode = "revoke"
)

// Resources are CPU (millicores) and memory (bytes).
type Resources struct {
	CPUm     int64 `json:"cpu_m"`
	MemBytes int64 `json:"mem_bytes"`
}

// Voters is one quorum's members and healthy members.
type Voters struct {
	Voters  int `json:"voters"`
	Healthy int `json:"healthy"`
}

// Taint is a node taint.
type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Effect string `json:"effect"`
}

// NodeAddresses are a node's mesh, LAN and public addresses.
type NodeAddresses struct {
	Mesh   string   `json:"mesh"`
	LAN    []string `json:"lan"`
	Public []string `json:"public"`
}

// Node is one Kubernetes node of the snapshot.
type Node struct {
	Name          string                      `json:"name"`
	Role          string                      `json:"role"`
	Ready         bool                        `json:"ready"`
	NotReadySince jsonstrict.Nullable[string] `json:"not_ready_since"`
	Unschedulable bool                        `json:"unschedulable"`
	Allocatable   Resources                   `json:"allocatable"`
	Labels        map[string]string           `json:"labels"`
	Taints        []Taint                     `json:"taints"`
	Addresses     NodeAddresses               `json:"addresses"`
	TraefikReady  bool                        `json:"traefik_ready"`
	FencingReady  bool                        `json:"fencing_ready"`
	EtcdMember    bool                        `json:"etcd_member"`
}

// Enrolling is a node between its enrolment and its Kubernetes node
// object.
type Enrolling struct {
	ID         string     `json:"id"`
	Role       string     `json:"role"`
	Class      string     `json:"class"`
	Site       string     `json:"site"`
	MeshIP     string     `json:"mesh_ip"`
	Mesh       MeshReport `json:"mesh"`
	EnrolledAt string     `json:"enrolled_at"`
}

// Toleration is a pod toleration (seconds: tolerationSeconds or null).
type Toleration struct {
	Key      string                     `json:"key"`
	Operator string                     `json:"operator"`
	Value    string                     `json:"value"`
	Effect   string                     `json:"effect"`
	Seconds  jsonstrict.Nullable[int64] `json:"seconds"`
}

// Expr is one node-selector expression.
type Expr struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// PodSet is the set a pod belongs to and the members it needs.
type PodSet struct {
	Name string `json:"name"`
	Min  int    `json:"min"`
}

// Pod is one pod of the snapshot (the N−1 input, §20.7).
type Pod struct {
	Name             string                      `json:"name"`
	Namespace        string                      `json:"namespace"`
	Node             string                      `json:"node"`
	Priority         int                         `json:"priority"`
	PriorityClass    string                      `json:"priority_class"`
	PreemptionPolicy string                      `json:"preemption_policy"`
	Requests         Resources                   `json:"requests"`
	Tolerations      []Toleration                `json:"tolerations"`
	RequiredAffinity [][]Expr                    `json:"required_affinity"`
	AntiAffinityHost bool                        `json:"anti_affinity_host"`
	SpreadHost       bool                        `json:"spread_host"`
	DaemonSet        bool                        `json:"daemonset"`
	Set              jsonstrict.Nullable[PodSet] `json:"set"`
}

// Quorum is the three quorums nodeadm measures.
type Quorum struct {
	Etcd     Voters `json:"etcd"`
	Vault    Voters `json:"vault"`
	Sentinel Voters `json:"sentinel"`
}

// Postgres is CloudNativePG's state.
type Postgres struct {
	Instances    int                         `json:"instances"`
	SyncStandbys int                         `json:"sync_standbys"`
	Primary      jsonstrict.Nullable[string] `json:"primary"`
}

// Volume is one replicated volume's robustness.
type Volume struct {
	Name          string                      `json:"name"`
	Robustness    string                      `json:"robustness"`
	DegradedSince jsonstrict.Nullable[string] `json:"degraded_since"`
}

// Snapshot is GET /v1/cluster (§20.2): nodeadm's JSON exactly.
type Snapshot struct {
	V         int         `json:"v"`
	TakenAt   string      `json:"taken_at"`
	Nodes     []Node      `json:"nodes"`
	Enrolling []Enrolling `json:"enrolling"`
	Pods      []Pod       `json:"pods"`
	Quorum    Quorum      `json:"quorum"`
	Postgres  Postgres    `json:"postgres"`
	Volumes   []Volume    `json:"volumes"`
	Errors    []string    `json:"errors"`
}

// Node is the snapshot's node name (nil: none).
func (s *Snapshot) Node(name string) *Node {
	for i := range s.Nodes {
		if s.Nodes[i].Name == name {
			return &s.Nodes[i]
		}
	}
	return nil
}

// EnrollingNode is the enrolling entry of id (nil: none).
func (s *Snapshot) EnrollingNode(id string) *Enrolling {
	for i := range s.Enrolling {
		if s.Enrolling[i].ID == id {
			return &s.Enrolling[i]
		}
	}
	return nil
}

// The node labels of §20.1.
const (
	LabelClass   = "portcullis.io/class"
	LabelSite    = "portcullis.io/site"
	LabelIngress = "portcullis.io/ingress"
	LabelStorage = "portcullis.io/storage"
)
