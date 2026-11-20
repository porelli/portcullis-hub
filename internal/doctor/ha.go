package doctor

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
)

// High availability (contract §14.5 "High availability", spec §11): the
// HA kinds. They register only under HUB_CONTAINER_RUNTIME=kubernetes
// (Inputs.HA set; under Docker and Podman it is nil and none fires), all
// explain-only. The four mesh kinds (mesh.go, Inputs.Mesh) and the two
// published-document kinds (publish.go, Inputs.Published) are part of
// HAKinds and keep their own inputs.
const (
	KindNodeDown                    = "node_down"
	KindHAQuorumAtRisk              = "ha_quorum_at_risk"
	KindVolumeDegraded              = "volume_degraded"
	KindPGNotSynchronous            = "pg_not_synchronous"
	KindHAFencingUnavailable        = "ha_fencing_unavailable"
	KindHANMinus1Insufficient       = "ha_n_minus_1_insufficient"
	KindBackupStale                 = "backup_stale"
	KindTemplateNoMemoryLimit       = "template_no_memory_limit"
	KindFrontdoorProbesInternalOnly = "frontdoor_probes_internal_only"
	KindHALeaseLost                 = "ha_lease_lost"
	KindNodeCertExpiring            = "node_cert_expiring"
)

// HAKinds are the HA kinds in the contract's order (§14.5): the spec's
// eight, the plan's eight, then node_cert_expiring (Task 9's carry-over).
var HAKinds = []string{
	KindNodeDown, KindHAQuorumAtRisk, KindVolumeDegraded, KindPGNotSynchronous, KindHAFencingUnavailable,
	KindHANMinus1Insufficient, KindBackupStale, KindTemplateNoMemoryLimit,
	KindFrontdoorProbesInternalOnly, KindPublishedDocTooLarge, KindPublishedDocStale, KindHALeaseLost,
	KindMeshSiteNoGateway, KindMeshPeerStale, KindMeshRTTHigh, KindHATwoSitesNoTiebreaker,
	KindNodeCertExpiring,
}

// The HA thresholds (contract §14.5).
const (
	NodeDownAfter       = time.Minute
	VolumeDegradedAfter = 10 * time.Minute
	BackupStaleAfter    = 26 * time.Hour
	NodeCertWithin      = 7 * 24 * time.Hour
)

// HAIn is what the HA kinds judge. Now is the Hub's clock (the timed
// kinds: node_down, volume_degraded, backup_stale, node_cert_expiring).
type HAIn struct {
	Now time.Time
	// Enabled: HA is on (`./portcullis ha enable`).
	Enabled bool
	// Snapshot is nodeadm's GET /v1/cluster (nil: none read; SnapshotErr
	// says why when nodeadm is configured but its snapshot unreadable).
	Snapshot    *nodeadm.Snapshot
	SnapshotErr string
	// LastNodes: the node count of the last snapshot the Hub read (0:
	// none), so an unreadable one judges the redundancy gate.
	LastNodes int
	// Namespaces name the pods (bare in the core namespace).
	Namespaces nminus1.Namespaces
	// NMinus1 is the check's result per node; NMinus1Err its refusal
	// (every node unknown).
	NMinus1    []nminus1.Result
	NMinus1Err string
	// MustFence are the nodes that must fence (the HA page's
	// fencingRequired rule, contract §20.1 "Fencing").
	MustFence []string
	// Sites are the sites the cluster's nodes are at (the Hub's records).
	Sites []string
	// FrontdoorStatus is frontdoor-status' status.json (nil: not read;
	// FrontdoorErr why), in HA only.
	FrontdoorStatus []byte
	FrontdoorErr    string
	// LastBackup is the last successful core backup to the destination
	// (nil: none known); BackupErr: its source couldn't be read.
	LastBackup *time.Time
	BackupErr  string
	// Lease: why this Hub stands by ("" = it leads).
	Lease string
	// NoMemoryLimit: each enabled instance's services without a memory
	// limit (kube.NoMemoryLimit of its model).
	NoMemoryLimit []NoMemoryLimitIn
	// NodeCerts are the node certificates the Hub holds or pinned.
	NodeCerts []NodeCertIn
}

// NoMemoryLimitIn is one enabled instance's services without mem_limit.
type NoMemoryLimitIn struct {
	Instance string
	Services []string
}

// NodeCertIn is a node certificate: its holder (hub.control, or a
// node's id) and when it ends.
type NodeCertIn struct {
	Name     string
	NotAfter time.Time
}

func init() {
	for _, k := range HAKinds {
		if slices.Contains(MeshKinds, k) || slices.Contains(PublishedKinds, k) {
			continue // registered by mesh.go and publish.go
		}
		Register(haCheck{kind: k})
	}
}

type haCheck struct{ kind string }

func (c haCheck) Kind() string { return c.kind }

// clusterWide: the redundancy kinds (fencing, N−1) judge a cluster that
// can fail over: HA on, or more than one node. A single-node cluster
// without HA has no failover to lose (node_down covers it).
func (h *HAIn) clusterWide() bool {
	return h.Enabled || (h.Snapshot != nil && len(h.Snapshot.Nodes) > 1)
}

// podName is p as the N−1 results name it.
func (h *HAIn) podName(p nodeadm.Pod) string {
	if p.Namespace == h.Namespaces.Core {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

// podsOn are node's pods (DaemonSet pods left out), sorted.
func (h *HAIn) podsOn(node string) []string {
	var out []string
	for _, p := range h.Snapshot.Pods {
		if p.Node == node && !p.DaemonSet {
			out = append(out, h.podName(p))
		}
	}
	sort.Strings(out)
	return out
}

// nameList is x joined for a sentence, at most 20 then "and <n> more".
func nameList(x []string) string {
	if len(x) == 0 {
		return "none"
	}
	if len(x) > 20 {
		return strings.Join(x[:20], ", ") + fmt.Sprintf(" and %d more", len(x)-20)
	}
	return strings.Join(x, ", ")
}

// since parses an RFC 3339 time (ok false: none or malformed).
func since(v string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, v)
	return t, err == nil
}

func (c haCheck) Run(in *Inputs) []Finding {
	h := in.HA
	if h == nil {
		return nil
	}
	switch c.kind {
	case KindHALeaseLost:
		return h.leaseLost()
	case KindBackupStale:
		return h.backupStale()
	case KindTemplateNoMemoryLimit:
		return h.noMemoryLimit()
	case KindNodeCertExpiring:
		return h.nodeCertExpiring()
	case KindHANMinus1Insufficient:
		return h.nMinus1()
	case KindFrontdoorProbesInternalOnly:
		return h.frontdoorInternalOnly()
	}
	if h.Snapshot == nil {
		return nil
	}
	switch c.kind {
	case KindNodeDown:
		return h.nodeDown()
	case KindHAQuorumAtRisk:
		return h.quorumAtRisk()
	case KindVolumeDegraded:
		return h.volumeDegraded()
	case KindPGNotSynchronous:
		return h.pgNotSynchronous()
	case KindHAFencingUnavailable:
		return h.fencingUnavailable()
	}
	return nil
}

func (h *HAIn) nodeDown() []Finding {
	var out []Finding
	for _, n := range h.Snapshot.Nodes {
		if n.Ready {
			continue
		}
		// A NotReady node without a readable not_ready_since is judged
		// down (its duration can't be shown to be short).
		at, ok := since(n.NotReadySince.V)
		ok = ok && n.NotReadySince.Valid
		if ok && h.Now.Sub(at) <= NodeDownAfter {
			continue
		}
		when := "for an unknown time (nodeadm didn't say since when)"
		if ok {
			when = "since " + at.UTC().Format(time.RFC3339)
		}
		pods := h.podsOn(n.Name)
		out = append(out, Finding{FP: Fingerprint(KindNodeDown, n.Name), Kind: KindNodeDown, Severity: Problem,
			Title: "Node " + n.Name + " is down.",
			Why: fmt.Sprintf("Kubernetes has seen node %s NotReady %s. Its pods (%s) are rescheduled on the other nodes where they fit; replicated volumes and Postgres fail over once the node is fenced.",
				n.Name, when, nameList(pods)),
			Class: FixExplain,
			Steps: []string{"Check that the machine is on and reachable (power, network, its pcmesh tunnel).",
				"On the machine: systemctl status k3s (or k3s-agent) and portcullis-nodeagent.",
				"If it is gone for good, remove it from Settings → Servers."},
			Inputs: Digest([]any{n.Name, ok, at.Unix(), pods})})
	}
	return out
}

func (h *HAIn) quorumAtRisk() []Finding {
	q := h.Snapshot.Quorum
	var out []Finding
	for _, s := range []struct {
		name, what string
		v          nodeadm.Voters
	}{{"etcd", "the cluster's datastore (etcd)", q.Etcd}, {"vault", "Vault", q.Vault}, {"sentinel", "the sessions' Sentinel", q.Sentinel}} {
		// A single voter has no quorum to lose (node_down covers it).
		if s.v.Voters < 2 {
			continue
		}
		majority := s.v.Voters/2 + 1
		if s.v.Healthy-1 >= majority {
			continue
		}
		state := "one more failure loses its quorum"
		if s.v.Healthy < majority {
			state = "it has lost its quorum"
		}
		out = append(out, Finding{FP: Fingerprint(KindHAQuorumAtRisk, s.name), Kind: KindHAQuorumAtRisk, Severity: Problem,
			Title: fmt.Sprintf("%s has %d of %d voters healthy: %s.", strings.ToUpper(s.what[:1])+s.what[1:], s.v.Healthy, s.v.Voters, state),
			Why: fmt.Sprintf("%s needs a majority (%d of %d) of its voters to work. Without it, it stops answering writes, and everything that depends on it with it.",
				strings.ToUpper(s.what[:1])+s.what[1:], majority, s.v.Voters),
			Class: FixExplain,
			Steps: []string{"Bring the down nodes back (see node_down) or replace them: Settings → Servers.",
				"Losing two of three voters for good needs ./portcullis ha recover on the survivor."},
			Inputs: Digest([]any{s.name, s.v.Voters, s.v.Healthy})})
	}
	return out
}

func (h *HAIn) volumeDegraded() []Finding {
	var out []Finding
	for _, v := range h.Snapshot.Volumes {
		if v.Robustness == "healthy" {
			continue
		}
		at, ok := since(v.DegradedSince.V)
		ok = ok && v.DegradedSince.Valid
		if ok && h.Now.Sub(at) <= VolumeDegradedAfter {
			continue
		}
		when := "for an unknown time"
		if ok {
			when = "since " + at.UTC().Format(time.RFC3339)
		}
		out = append(out, Finding{FP: Fingerprint(KindVolumeDegraded, v.Name), Kind: KindVolumeDegraded, Severity: Warning,
			Title: "Volume " + v.Name + " is " + nonEmptyText(v.Robustness, "unknown") + ".",
			Why:   fmt.Sprintf("Its replicas aren't all healthy %s: one more node or disk failure may make it unavailable or lose its data. Longhorn rebuilds a replica on a storage node with room.", when),
			Class: FixExplain,
			Steps: []string{"Check that the storage nodes are up and have free disk (Settings → Servers).",
				"Add a storage node if there is none left with room."},
			Inputs: Digest([]any{v.Name, v.Robustness, ok, at.Unix()})})
	}
	return out
}

func nonEmptyText(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (h *HAIn) pgNotSynchronous() []Finding {
	pg := h.Snapshot.Postgres
	if pg.Instances < 2 || pg.SyncStandbys > 0 {
		return nil
	}
	return []Finding{{FP: Fingerprint(KindPGNotSynchronous), Kind: KindPGNotSynchronous, Severity: Warning,
		Title:  "Postgres has no synchronous standby.",
		Why:    fmt.Sprintf("Of its %d instances none confirms the writes before they are acknowledged (the guarantee is Degraded): one more failure may lose the last writes.", pg.Instances),
		Class:  FixExplain,
		Steps:  []string{"Check that the standby's node is up and its pod Ready; CloudNativePG resumes synchronous replication by itself once it is."},
		Inputs: Digest([]any{pg.Instances, pg.SyncStandbys})}}
}

func (h *HAIn) fencingUnavailable() []Finding {
	if !h.clusterWide() {
		return nil
	}
	ready := map[string]bool{}
	for _, n := range h.Snapshot.Nodes {
		ready[n.Name] = n.FencingReady
	}
	var out []Finding
	for _, name := range slices.Sorted(slices.Values(h.MustFence)) {
		if ready[name] {
			continue
		}
		out = append(out, Finding{FP: Fingerprint(KindHAFencingUnavailable, name), Kind: KindHAFencingUnavailable, Severity: Problem,
			Title: "Node " + name + " can't be fenced.",
			Why:   "It holds (or, once HA is on, will hold) replicated-tier pods, but its fencing isn't ready: no watchdog, or Self Node Remediation unhealthy on it. A node that can't be fenced is never declared dead, so no stateful failover happens there.",
			Class: FixExplain,
			Steps: []string{"Give the machine a watchdog (a hardware watchdog, or modprobe softdog and make it load at boot).",
				"Check the Self Node Remediation pod on that node (namespace portcullis-fencing)."},
			Inputs: Digest(name)})
	}
	return out
}

func (h *HAIn) nMinus1() []Finding {
	if h.Snapshot == nil {
		// The redundancy gate on the last snapshot read: a single-node
		// cluster without HA stays quiet through a nodeadm blip.
		if h.SnapshotErr == "" || !(h.Enabled || h.LastNodes > 1) {
			return nil
		}
		return []Finding{h.n1Unknown("nodeadm's snapshot isn't readable: " + h.SnapshotErr)}
	}
	if !h.clusterWide() {
		return nil
	}
	if h.NMinus1Err != "" {
		return []Finding{h.n1Unknown(h.NMinus1Err)}
	}
	var out []Finding
	for _, r := range h.NMinus1 {
		sev := Problem
		switch r.Level {
		case nminus1.Green, "":
			continue
		case nminus1.Yellow:
			sev = Warning
		case nminus1.Red:
		default: // unknown: never a pass
		}
		text := nminus1.Explain(r)
		out = append(out, Finding{FP: Fingerprint(KindHANMinus1Insufficient, r.Node), Kind: KindHANMinus1Insufficient, Severity: sev,
			Title: "If node " + r.Node + " fails, the others don't have room for everything.",
			Why:   "The N−1 check simulated that node's loss on the cluster's current requests: " + text + ".",
			Class: FixExplain,
			Steps: []string{"Add a node, or give the nodes more memory or CPU.",
				"Or lower the priority of an instance (Instance → Availability), or stop one."},
			Inputs: Digest([]any{r.Node, r.Level, r.Unplaced, r.Evicted, r.Lacking})})
	}
	return out
}

func (h *HAIn) n1Unknown(why string) Finding {
	return Finding{FP: Fingerprint(KindHANMinus1Insufficient), Kind: KindHANMinus1Insufficient, Severity: Problem,
		Title:  "The N−1 check can't judge the cluster.",
		Why:    why + ". Until it can, nothing proves the cluster survives losing a node (judged as red).",
		Class:  FixExplain,
		Steps:  []string{"Check nodeadm (./portcullis status) and its snapshot's errors on Settings → High availability."},
		Inputs: Digest(why)}
}

func (h *HAIn) backupStale() []Finding {
	if !h.Enabled {
		return nil
	}
	if h.LastBackup != nil && h.BackupErr == "" && h.Now.Sub(*h.LastBackup) <= BackupStaleAfter {
		return nil
	}
	why := "The Hub knows of no successful core backup to the backup destination."
	var in any = "none"
	switch {
	case h.BackupErr != "":
		why = "The last core backup can't be read: " + h.BackupErr + "."
		in = h.BackupErr
	case h.LastBackup != nil:
		why = "The last successful core backup to the backup destination was at " + h.LastBackup.UTC().Format(time.RFC3339) + ", more than 26 h ago."
		in = h.LastBackup.Unix()
	}
	return []Finding{{FP: Fingerprint(KindBackupStale), Kind: KindBackupStale, Severity: Warning,
		Title:  "No core backup to the backup destination in the last 26 hours.",
		Why:    why + " HA keeps the cluster up through a failure, not through a lost cluster or a bad change: that needs the offsite backup.",
		Class:  FixExplain,
		Steps:  []string{"Run ./portcullis backup destination test, then ./portcullis backup.", "Check that the scheduled backup runs (./portcullis status)."},
		Inputs: Digest(in)}}
}

func (h *HAIn) noMemoryLimit() []Finding {
	var out []Finding
	for _, m := range h.NoMemoryLimit {
		if len(m.Services) == 0 {
			continue
		}
		svcs := slices.Sorted(slices.Values(m.Services))
		out = append(out, Finding{FP: Fingerprint(KindTemplateNoMemoryLimit, m.Instance), Kind: KindTemplateNoMemoryLimit, Severity: Info,
			Instances: []string{m.Instance},
			Title:     m.Instance + " runs with the default memory limit.",
			Why:       "Its template sets no mem_limit for " + nameList(svcs) + ": on Kubernetes each runs with the 512 Mi default (request = limit), which may be too little (the app is killed) or too much (the N−1 check reserves it).",
			Class:     FixExplain,
			Steps:     []string{"Set a memory limit in the instance's settings if the template has one, else in its Expert override (mem_limit)."},
			Inputs:    Digest(svcs)})
	}
	return out
}

// frontdoorProbes are the probes of frontdoor-status (§20.8) the doctor
// reads.
type frontdoorProbes struct {
	Probes map[string]struct {
		Verdict      string `json:"verdict"`
		InternalOnly bool   `json:"internal_only"`
	} `json:"probes"`
}

func (h *HAIn) frontdoorInternalOnly() []Finding {
	if !h.Enabled {
		return nil
	}
	var nodes []string
	unreadable := h.FrontdoorErr
	if unreadable == "" && len(h.FrontdoorStatus) > 0 {
		var d frontdoorProbes
		if err := json.Unmarshal(h.FrontdoorStatus, &d); err != nil {
			unreadable = "status.json doesn't decode"
		}
		for n, p := range d.Probes {
			if p.InternalOnly && p.Verdict != "none" {
				nodes = append(nodes, n)
			}
		}
	}
	var out []Finding
	if unreadable != "" {
		out = append(out, Finding{FP: Fingerprint(KindFrontdoorProbesInternalOnly, "unreadable"), Kind: KindFrontdoorProbesInternalOnly, Severity: Warning,
			Title:  "The front door's probes can't be read.",
			Why:    "frontdoor-status isn't readable (" + unreadable + "): whether the front door judges the ingress nodes from outside isn't known.",
			Class:  FixExplain,
			Steps:  []string{"Check the domains frontdoor pod and its ConfigMap frontdoor-status (./portcullis status)."},
			Inputs: Digest(unreadable)})
	}
	sort.Strings(nodes)
	single := len(h.Sites) == 1
	if !single && len(nodes) == 0 {
		return out
	}
	why := "The cluster's nodes are all at one site (" + h.Sites[0] + "): a probe from the same site never takes the public path, so the front door judges the ingress nodes by node and Traefik readiness only. A broken uplink or router at that site isn't seen."
	if !single {
		why = "No prober at another site judged " + nameList(nodes) + ": the front door judges them by node and Traefik readiness only, so a broken uplink there isn't seen."
	}
	return append(out, Finding{FP: Fingerprint(KindFrontdoorProbesInternalOnly), Kind: KindFrontdoorProbesInternalOnly, Severity: Warning,
		Title:  "The front door can't probe the public addresses from outside.",
		Why:    why,
		Class:  FixExplain,
		Steps:  []string{"Add a node at another site (a small cloud VM is enough): its nodeagent probes the other sites' public addresses."},
		Inputs: Digest([]any{h.Sites, nodes})})
}

func (h *HAIn) leaseLost() []Finding {
	if h.Lease == "" {
		return nil
	}
	return []Finding{{FP: Fingerprint(KindHALeaseLost), Kind: KindHALeaseLost, Severity: Problem,
		Title: "This Hub isn't the active writer: it lost or never got the Lease portcullis-hub.",
		Why: "It stands by (" + h.Lease + "): every write answers 503 while another Hub may be writing. Standing by is final: the Hub exits 15 s after losing the Lease so its restart re-reads the state. " +
			"Each exit grows the kubelet's restart back-off (10 s, 20 s … up to 5 min, reset after 10 min of running), so a few API server blips in a row can keep the Hub down for minutes after the API recovers.",
		Class: FixExplain,
		Steps: []string{"Check the API server and etcd (./portcullis status): the Lease is renewed through them.",
			"kubectl -n <core namespace> get lease portcullis-hub shows the holder; the Hub's pod restarts by itself."},
		Inputs: Digest(h.Lease)}}
}

func (h *HAIn) nodeCertExpiring() []Finding {
	var out []Finding
	for _, c := range h.NodeCerts {
		if c.NotAfter.IsZero() || c.NotAfter.Sub(h.Now) >= NodeCertWithin {
			continue
		}
		left := "it expired at " + c.NotAfter.UTC().Format(time.RFC3339)
		if c.NotAfter.After(h.Now) {
			left = "it expires at " + c.NotAfter.UTC().Format(time.RFC3339)
		}
		out = append(out, Finding{FP: Fingerprint(KindNodeCertExpiring, c.Name), Kind: KindNodeCertExpiring, Severity: Problem,
			Title: "The node certificate of " + c.Name + " expires within 7 days.",
			Why:   left + ": its renewal (at ⅓ of its life left) has kept failing. Once it ends, the cluster's control calls (nodeadm, the nodeagents, the mesh pushes) refuse it.",
			Class: FixExplain,
			Steps: []string{"Check that enroll and nodeadm are up (./portcullis status); the renewal retries every tick.",
				"For a node: check portcullis-nodeagent's log on the machine (its renewal with nodeadm)."},
			Inputs: Digest([]any{c.Name, c.NotAfter.Unix()})})
	}
	return out
}
