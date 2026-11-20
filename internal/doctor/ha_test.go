package doctor

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
)

var haNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// haSeverity is each HA kind's severity (contract §14.5);
// ha_n_minus_1_insufficient is Problem (red, unknown) or Warning (yellow).
var haSeverity = map[string]Severity{
	KindNodeDown: Problem, KindHAQuorumAtRisk: Problem, KindVolumeDegraded: Warning, KindPGNotSynchronous: Warning,
	KindHAFencingUnavailable: Problem, KindHANMinus1Insufficient: Problem, KindBackupStale: Warning,
	KindTemplateNoMemoryLimit: Info, KindFrontdoorProbesInternalOnly: Warning, KindPublishedDocTooLarge: Problem,
	KindPublishedDocStale: Problem, KindHALeaseLost: Problem, KindMeshSiteNoGateway: Problem, KindMeshPeerStale: Warning,
	KindMeshRTTHigh: Warning, KindHATwoSitesNoTiebreaker: Warning, KindNodeCertExpiring: Problem,
}

// haNode is a Ready node n with fencing.
func haNode(n string) nodeadm.Node {
	return nodeadm.Node{Name: n, Role: "server", Ready: true, FencingReady: true, Labels: map[string]string{}}
}

// haBase is a healthy 3-node HA cluster: nothing fires.
func haBase() *HAIn {
	s := &nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{haNode("n1"), haNode("n2"), haNode("n3")},
		Pods:     []nodeadm.Pod{{Name: "vault-0", Namespace: "portcullis", Node: "n1"}, {Name: "web-1", Namespace: "portcullis-apps", Node: "n1"}, {Name: "svclb", Namespace: "kube-system", Node: "n1", DaemonSet: true}},
		Quorum:   nodeadm.Quorum{Etcd: nodeadm.Voters{Voters: 3, Healthy: 3}, Vault: nodeadm.Voters{Voters: 3, Healthy: 3}, Sentinel: nodeadm.Voters{Voters: 3, Healthy: 3}},
		Postgres: nodeadm.Postgres{Instances: 2, SyncStandbys: 1},
		Volumes:  []nodeadm.Volume{{Name: "hub-state-r", Robustness: "healthy"}}}
	last := haNow.Add(-time.Hour)
	return &HAIn{Now: haNow, Enabled: true, Snapshot: s, Namespaces: nminus1.DefaultNamespaces,
		NMinus1:   []nminus1.Result{{Node: "n1", Level: nminus1.Green}, {Node: "n2", Level: nminus1.Green}, {Node: "n3", Level: nminus1.Green}},
		MustFence: []string{"n1", "n2", "n3"}, Sites: []string{"main", "edge"},
		FrontdoorStatus: []byte(`{"v":1,"state":"leading","probes":{"n1":{"ok":true,"verdict":"healthy","internal_only":false}}}`),
		LastBackup:      &last, NodeCerts: []NodeCertIn{{Name: "hub.control", NotAfter: haNow.Add(30 * 24 * time.Hour)}}}
}

// haInputs is a full Inputs around h (the mesh and published inputs
// empty: nothing fires).
func haInputs(h *HAIn) *Inputs {
	return &Inputs{Now: haNow, HA: h, Mesh: &MeshIn{}, Published: &PublishedIn{}}
}

// checksOf are the registered checks of kind.
func checksOf(kind string) []Check {
	var out []Check
	for _, c := range checks() {
		if c.Kind() == kind {
			out = append(out, c)
		}
	}
	return out
}

func runKind(kind string, in *Inputs) []Finding {
	var out []Finding
	for _, c := range checksOf(kind) {
		out = append(out, c.Run(in)...)
	}
	return out
}

// TestHAKinds: every HA kind registered exactly once, in the contract's
// order, with the mesh and published kinds folded in.
func TestHAKinds(t *testing.T) {
	want := "node_down,ha_quorum_at_risk,volume_degraded,pg_not_synchronous,ha_fencing_unavailable,ha_n_minus_1_insufficient,backup_stale,template_no_memory_limit," +
		"frontdoor_probes_internal_only,published_doc_too_large,published_doc_stale,ha_lease_lost,mesh_site_no_gateway,mesh_peer_stale,mesh_rtt_high,ha_two_sites_no_tiebreaker,node_cert_expiring"
	if got := strings.Join(HAKinds, ","); got != want {
		t.Errorf("HAKinds = %s", got)
	}
	for _, k := range MeshKinds {
		if !slices.Contains(HAKinds, k) {
			t.Errorf("mesh kind %s not in HAKinds", k)
		}
	}
	for _, k := range HAKinds {
		if n := len(checksOf(k)); n != 1 {
			t.Errorf("%s registered %d times", k, n)
		}
		if _, ok := haSeverity[k]; !ok {
			t.Errorf("%s: no severity", k)
		}
	}
	// A healthy cluster raises nothing; no HA input (Docker, Podman)
	// raises nothing either, whatever else is wrong.
	for _, k := range HAKinds {
		if f := runKind(k, haInputs(haBase())); len(f) != 0 {
			t.Errorf("healthy: %s raised %+v", k, f)
		}
		if f := runKind(k, &Inputs{Now: haNow}); len(f) != 0 {
			t.Errorf("no HA input: %s raised %+v", k, f)
		}
	}
}

// TestHAKinds_RaiseAndClear: per kind, the input that raises it (with
// its severity, naming its subject), the one that clears it, and the
// boundary of the timed kinds (the injected Now).
func TestHAKinds_RaiseAndClear(t *testing.T) {
	type tc struct {
		kind  string
		raise func(*Inputs)
		clear func(*Inputs) // nil: haBase itself
		name  string        // in the raised title or why
		sev   Severity      // "" = haSeverity
	}
	notReady := func(ago time.Duration) func(*Inputs) {
		return func(in *Inputs) {
			n := &in.HA.Snapshot.Nodes[0]
			n.Ready, n.NotReadySince = false, jsonstrict.Some(haNow.Add(-ago).Format(time.RFC3339))
		}
	}
	degraded := func(ago time.Duration) func(*Inputs) {
		return func(in *Inputs) {
			v := &in.HA.Snapshot.Volumes[0]
			v.Robustness, v.DegradedSince = "degraded", jsonstrict.Some(haNow.Add(-ago).Format(time.RFC3339))
		}
	}
	backupAt := func(ago time.Duration) func(*Inputs) {
		return func(in *Inputs) { t := haNow.Add(-ago); in.HA.LastBackup = &t }
	}
	certIn := func(left time.Duration) func(*Inputs) {
		return func(in *Inputs) { in.HA.NodeCerts[0].NotAfter = haNow.Add(left) }
	}
	cases := []tc{
		{kind: KindNodeDown, raise: notReady(NodeDownAfter + time.Second), clear: notReady(NodeDownAfter), name: "n1"},
		{kind: KindNodeDown + "/no since", raise: func(in *Inputs) { in.HA.Snapshot.Nodes[1].Ready = false }, name: "n2"},
		{kind: KindHAQuorumAtRisk, raise: func(in *Inputs) { in.HA.Snapshot.Quorum.Vault.Healthy = 2 },
			clear: func(in *Inputs) { in.HA.Snapshot.Quorum.Vault = nodeadm.Voters{Voters: 1, Healthy: 1} }, name: "Vault"},
		{kind: KindVolumeDegraded, raise: degraded(VolumeDegradedAfter + time.Second), clear: degraded(VolumeDegradedAfter), name: "hub-state-r"},
		{kind: KindPGNotSynchronous, raise: func(in *Inputs) { in.HA.Snapshot.Postgres.SyncStandbys = 0 },
			clear: func(in *Inputs) { in.HA.Snapshot.Postgres = nodeadm.Postgres{Instances: 1} }, name: "standby"},
		{kind: KindHAFencingUnavailable, raise: func(in *Inputs) { in.HA.Snapshot.Nodes[2].FencingReady = false },
			clear: func(in *Inputs) { in.HA.Snapshot.Nodes[2].FencingReady = false; in.HA.MustFence = []string{"n1"} }, name: "n3"},
		{kind: KindHANMinus1Insufficient, raise: func(in *Inputs) {
			in.HA.NMinus1[1] = nminus1.Result{Node: "n2", Level: nminus1.Red, Lacking: []string{"vault-1"}}
		}, name: "if n2 fails, vault-1 won't have room"},
		{kind: KindHANMinus1Insufficient + "/yellow", raise: func(in *Inputs) {
			in.HA.NMinus1[1] = nminus1.Result{Node: "n2", Level: nminus1.Yellow, Evicted: []string{"portcullis-apps/a"}}
		}, name: "if n2 fails, portcullis-apps/a won't have room", sev: Warning},
		{kind: KindHANMinus1Insufficient + "/unknown", raise: func(in *Inputs) {
			in.HA.NMinus1Err = "the N−1 check can't judge the cluster: nminus1: malformed snapshot: x"
		}, name: "malformed snapshot"},
		{kind: KindHANMinus1Insufficient + "/no snapshot", raise: func(in *Inputs) { in.HA.Snapshot, in.HA.SnapshotErr = nil, "nodeadm: 503" },
			clear: func(in *Inputs) { in.HA.Snapshot = nil }, name: "nodeadm: 503"},
		{kind: KindBackupStale, raise: backupAt(BackupStaleAfter + time.Second), clear: backupAt(BackupStaleAfter), name: "26 h"},
		{kind: KindBackupStale + "/none", raise: func(in *Inputs) { in.HA.LastBackup = nil },
			clear: func(in *Inputs) { in.HA.LastBackup, in.HA.Enabled = nil, false }, name: "no successful core backup"},
		{kind: KindTemplateNoMemoryLimit, raise: func(in *Inputs) {
			in.HA.NoMemoryLimit = []NoMemoryLimitIn{{Instance: "jelly", Services: []string{"web", "db"}}}
		}, clear: func(in *Inputs) { in.HA.NoMemoryLimit = []NoMemoryLimitIn{{Instance: "jelly"}} }, name: "db, web"},
		{kind: KindFrontdoorProbesInternalOnly, raise: func(in *Inputs) { in.HA.Sites = []string{"main"} },
			clear: func(in *Inputs) { in.HA.Sites, in.HA.Enabled = []string{"main"}, false }, name: "one site (main)"},
		{kind: KindFrontdoorProbesInternalOnly + "/probes", raise: func(in *Inputs) {
			in.HA.FrontdoorStatus = []byte(`{"v":1,"probes":{"n1":{"verdict":"healthy","internal_only":true},"n9":{"verdict":"none","internal_only":true}}}`)
		}, name: "judged n1:"},
		{kind: KindPublishedDocTooLarge, raise: func(in *Inputs) {
			in.Published.TooLarge = []PublishedTooLargeIn{{Doc: "portal-apps", Size: 1000001}}
		}, name: "portal-apps"},
		{kind: KindPublishedDocStale, raise: func(in *Inputs) {
			in.Published.Stale = []PublishedStaleIn{{Doc: "mcp-gate", Rev: "r2", Since: haNow.Add(-3 * time.Minute), Pods: []string{"mcp-gate-0"}}}
		}, name: "mcp-gate-0"},
		{kind: KindHALeaseLost, raise: func(in *Inputs) { in.HA.Lease = "this Hub is standing by: another Hub is the active writer" }, name: "restart back-off"},
		{kind: KindMeshSiteNoGateway, raise: func(in *Inputs) { in.Mesh.NoGateway = []string{"edge"} }, name: "edge"},
		{kind: KindMeshPeerStale, raise: func(in *Inputs) { in.Mesh.Stale = map[string]string{"n3": "i/o timeout"} }, name: "n3"},
		{kind: KindMeshRTTHigh, raise: func(in *Inputs) { in.Mesh.RTT = []MeshRTT{{From: "n1", To: "n2", FromServer: true, Ms: 80}} },
			clear: func(in *Inputs) { in.Mesh.RTT = []MeshRTT{{From: "n1", To: "n2", FromServer: true, Ms: 79}} }, name: "n2"},
		{kind: KindHATwoSitesNoTiebreaker, raise: func(in *Inputs) { in.Mesh.Sites = []string{"main", "edge"} },
			clear: func(in *Inputs) { in.Mesh.Sites = []string{"main", "edge", "far"} }, name: "edge and main"},
		{kind: KindNodeCertExpiring, raise: certIn(NodeCertWithin - time.Second), clear: certIn(NodeCertWithin), name: "hub.control"},
		{kind: KindNodeCertExpiring + "/expired", raise: certIn(-time.Hour), name: "expired"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		kind, _, _ := strings.Cut(c.kind, "/")
		seen[kind] = true
		t.Run(c.kind, func(t *testing.T) {
			in := haInputs(haBase())
			c.raise(in)
			f := runKind(kind, in)
			if len(f) != 1 {
				t.Fatalf("raise: %d findings %+v", len(f), f)
			}
			sev := c.sev
			if sev == "" {
				sev = haSeverity[kind]
			}
			if f[0].Kind != kind || f[0].Severity != sev || f[0].Class != FixExplain || f[0].FP == "" {
				t.Errorf("raise: %+v, want %s %s explain-only", f[0], kind, sev)
			}
			if !strings.Contains(f[0].Title+" "+f[0].Why, c.name) {
				t.Errorf("raise: %q / %q doesn't name %q", f[0].Title, f[0].Why, c.name)
			}
			clear := haInputs(haBase())
			if c.clear != nil {
				c.clear(clear)
			}
			if f := runKind(kind, clear); len(f) != 0 {
				t.Errorf("clear: %+v", f)
			}
		})
	}
	for _, k := range HAKinds {
		if !seen[k] {
			t.Errorf("no case for %s", k)
		}
	}
}

// TestHARedundancyKindsNeedACluster: a single-node cluster without HA
// has no failover to lose: fencing and N−1 stay quiet (node_down covers
// it); HA on, they judge it.
func TestHARedundancyKindsNeedACluster(t *testing.T) {
	in := haInputs(haBase())
	in.HA.Enabled = false
	in.HA.Snapshot.Nodes = in.HA.Snapshot.Nodes[:1]
	in.HA.Snapshot.Nodes[0].FencingReady = false
	in.HA.MustFence = []string{"n1"}
	in.HA.NMinus1 = []nminus1.Result{{Node: "n1", Level: nminus1.Red, Lacking: []string{"vault-0"}}}
	for _, k := range []string{KindHAFencingUnavailable, KindHANMinus1Insufficient, KindBackupStale, KindFrontdoorProbesInternalOnly} {
		if f := runKind(k, in); len(f) != 0 {
			t.Errorf("one node, HA off: %s %+v", k, f)
		}
	}
	in.HA.Enabled = true
	for _, k := range []string{KindHAFencingUnavailable, KindHANMinus1Insufficient} {
		if f := runKind(k, in); len(f) != 1 {
			t.Errorf("one node, HA on: %s %+v", k, f)
		}
	}
}

// TestNodeDownNamesItsPods: node_down names the node's pods (core bare,
// others <namespace>/<name>, DaemonSet pods left out).
func TestNodeDownNamesItsPods(t *testing.T) {
	in := haInputs(haBase())
	in.HA.Snapshot.Nodes[0].Ready = false
	f := runKind(KindNodeDown, in)
	if len(f) != 1 || !strings.Contains(f[0].Why, "(portcullis-apps/web-1, vault-0)") || strings.Contains(f[0].Why, "svclb") {
		t.Errorf("%+v", f)
	}
}

// TestKubeAPIPublicPerNode: one exposed node of three → one finding
// naming that node.
func TestKubeAPIPublicPerNode(t *testing.T) {
	in := &Inputs{Kube: &KubeIn{Verified: true, Admission: "ok", Netpol: "proven",
		APIPublic: map[string][]string{"n2": {"203.0.113.2:10250", "203.0.113.2:6443"}, "n1": nil, "n3": {}}}}
	f := kubeCheck{kind: KindKubeAPIPublic}.Run(in)
	if len(f) != 1 || f[0].Severity != Warning || !strings.Contains(f[0].Title, "node n2") || !strings.Contains(f[0].Why, "203.0.113.2:10250, 203.0.113.2:6443") ||
		f[0].FP != Fingerprint(KindKubeAPIPublic, "n2") {
		t.Errorf("%+v", f)
	}
	if f := (kubeCheck{kind: KindKubeAPIPublic}).Run(&Inputs{Kube: &KubeIn{}}); len(f) != 0 {
		t.Errorf("none exposed: %+v", f)
	}
}
