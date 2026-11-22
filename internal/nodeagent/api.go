package nodeagent

import "github.com/portcullis/hub/internal/jsonstrict"

// The nodeagent API's wire types (contract §20.4), shared by the Hub's
// client and the host service (internal/nodeagent/host). Pure types: the
// Hub binary imports this package, and nothing here touches the host.

// MeshPort is pcmesh's WireGuard port, FlannelPort flannel's own
// WireGuard port inside it, EchoPort the RTT echo (UDP, mesh address only).
const (
	MeshPort    = 51830
	FlannelPort = 51840
	EchoPort    = 7444
	MeshIface   = "pcmesh"
	MeshMTU     = 1420
	MeshCIDR    = "10.215.0.0/24"
	MaxPeers    = 256
	MaxBody     = 1 << 20
)

// The client certificates' names (CN, pki_node) and who may call what.
const (
	CNHub       = "hub.control"
	CNFrontdoor = "frontdoor.control"
	CNNodeadm   = "nodeadm.control"
)

// MeshPeer is one entry of PUT /v1/mesh/peers (endpoint "<ip:port>" or
// null).
type MeshPeer struct {
	ID         string                      `json:"id"`
	Pub        string                      `json:"pub"`
	Endpoint   jsonstrict.Nullable[string] `json:"endpoint"`
	AllowedIPs []string                    `json:"allowed_ips"`
	Keepalive  int                         `json:"keepalive"`
}

// MeshPlan is PUT /v1/mesh/peers (and a join code's bootstrap plan).
type MeshPlan struct {
	Peers   []MeshPeer `json:"peers"`
	Forward bool       `json:"forward"`
}

// Check is one host check of GET /v1/checks.
type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Checks is GET /v1/checks.
type Checks struct {
	Checks          []Check `json:"checks"`
	MemBytes        int64   `json:"mem_bytes"`
	CPUs            int     `json:"cpus"`
	Model           string  `json:"model"`
	ClassSuggestion string  `json:"class_suggestion"`
}

// ProbeResult is one target's result in a probe round.
type ProbeResult struct {
	OK    bool   `json:"ok"`
	Class string `json:"class"`
}

// ProbeRound is one round of GET /v1/probes (the shape of
// frontdoor_vectors.json's probes).
type ProbeRound struct {
	T          string                 `json:"t"`
	Prober     string                 `json:"prober"`
	Site       string                 `json:"site"`
	ReachedAny bool                   `json:"reached_any"`
	EgressOK   bool                   `json:"egress_ok"`
	Results    map[string]ProbeResult `json:"results"`
}

// Probes is GET /v1/probes: the last 3 rounds, newest first.
type Probes struct {
	Rounds []ProbeRound `json:"rounds"`
}

// ProbeTarget / ProbeTargets are PUT /v1/probes/targets (from nodeadm).
type ProbeTarget struct {
	Node    string `json:"node"`
	Site    string `json:"site"`
	Address string `json:"address"`
}

type ProbeTargets struct {
	Domain     string        `json:"domain"`
	Targets    []ProbeTarget `json:"targets"`
	EgressHost string        `json:"egress_host"`
}

// AgentUpgrade is POST /v1/agent/upgrade (keys in this order): the
// sha256 of nodeadm's nodeagent binary per architecture (Task 30 fix
// round 1: `./portcullis up` rolls nodeadm's image, and nodeadm has every
// joined node take the nodeagent it serves).
type AgentUpgrade struct {
	AMD64 string `json:"amd64"`
	ARM64 string `json:"arm64"`
}

// AgentUpgraded is its answer: "current" (already that binary) or
// "upgraded" (installed; the unit restarts right after the answer).
type AgentUpgraded struct {
	State string `json:"state"`
}

// EtcdRemove is POST /v1/etcd/remove-member (keys in this order).
type EtcdRemove struct {
	MeshIP string `json:"mesh_ip"`
	Node   string `json:"node"`
}

// TokenRotate is POST /v1/k3s/token-rotate. NewToken is a secret.
type TokenRotate struct {
	NewToken string `json:"new_token"`
	Step     string `json:"step"`
}

// The probe classes.
const (
	ClassOK         = "ok"
	ClassTimeout    = "timeout"
	ClassRefused    = "refused"
	ClassTLS        = "tls"
	ClassHTTPStatus = "http_status"
)
