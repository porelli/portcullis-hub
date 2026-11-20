package hub

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/servers"
)

// The doctor's HA inputs (contract §14.5 "High availability"): nil off
// Kubernetes, so under Docker and Podman no HA kind fires. They are
// gathered before mu (nodeadm, the front door's status, the compose
// models and the port dials never run under it); the timed kinds judge
// h.now(), the injected clock.

// apiPorts are the ports kube_api_public dials on every node's public
// address: the API server and the kubelet (both bind the mesh address
// only, so an answer means a misconfiguration).
var apiPorts = []string{"6443", "10250"}

// apiDialWait bounds one dial.
const apiDialWait = 2 * time.Second

// lastCoreBackupReader is a runtime backend that knows the last
// successful core backup to the destination (nil: none).
type lastCoreBackupReader interface {
	LastCoreBackup(ctx context.Context) (*time.Time, error)
}

// doctorHAIn is the HA kinds' input and, per node, the public addresses
// whose API or kubelet answers (kube_api_public). Never under mu.
func (h *Hub) doctorHAIn(ctx context.Context) (*doctor.HAIn, map[string][]string) {
	if !h.kubeOn() {
		return nil, nil
	}
	in := &doctor.HAIn{Now: h.now().UTC(), Enabled: h.cfg.HA, Namespaces: h.nminusNamespaces()}
	lease := h.ha.lease
	if lease == nil {
		lease = fsutil.CheckWrite
	}
	if err := lease(); err != nil {
		in.Lease = clipRunes(err.Error(), 200)
	}
	in.LastBackup, in.BackupErr = h.lastCoreBackup(ctx)
	in.NoMemoryLimit = h.noMemoryLimitIns(ctx)
	in.NodeCerts = h.nodeCertIns()
	var public map[string][]string
	// nodeadm configured: its snapshot (shared with the HA page), else
	// nothing cluster-wide is judged (no cluster nodes are managed).
	if h.clusterNodesOn() == nil {
		r, err := h.haShared(ctx)
		switch {
		case err != nil:
			in.SnapshotErr = clipRunes(err.Error(), 300)
		case r.snapErr != nil:
			in.SnapshotErr = clipRunes(r.snapErr.Error(), 300)
		default:
			snap := r.snap
			in.Snapshot = &snap
			n1, n1Err := h.checkN1(snap)
			in.NMinus1, in.NMinus1Err = n1, n1Err
			place := h.haPlacement(snap)
			in.MustFence = slices.Sorted(maps.Keys(fencingRequired(snap, place, h.cfg.HA, in.Namespaces)))
			set := map[string]bool{}
			for _, p := range place {
				set[p.site] = true
			}
			in.Sites = slices.Sorted(maps.Keys(set))
			public = h.apiPublic(ctx, snap)
		}
		if err == nil && h.cfg.HA {
			if r.statusErr != nil {
				in.FrontdoorErr = clipRunes(r.statusErr.Error(), 200)
			} else {
				in.FrontdoorStatus = r.status
			}
		}
	}
	return in, public
}

// lastCoreBackup is the last successful core backup to the destination:
// the test hook, else the runtime backend's (none known when it can't
// tell).
func (h *Hub) lastCoreBackup(ctx context.Context) (*time.Time, string) {
	f := h.ha.lastBackup
	if f == nil {
		r, ok := unwrapRT(h.rt).(lastCoreBackupReader)
		if !ok {
			return nil, ""
		}
		f = r.LastCoreBackup
	}
	t, err := f(ctx)
	if err != nil {
		return nil, clipRunes(err.Error(), 200)
	}
	return t, ""
}

// noMemoryLimitIns: each enabled instance's services without a memory
// limit, judged on the model the translator gets (kube.NoMemoryLimit); an
// instance whose model doesn't load is skipped (its own errors say why).
func (h *Hub) noMemoryLimitIns(ctx context.Context) []doctor.NoMemoryLimitIn {
	var out []doctor.NoMemoryLimitIn
	for _, t := range h.Templates() {
		if !h.IsEnabled(t.ID) {
			continue
		}
		m, err := h.loadRuntime(ctx, &t)
		if err != nil {
			continue
		}
		if svcs := kube.NoMemoryLimit(m); len(svcs) > 0 {
			out = append(out, doctor.NoMemoryLimitIn{Instance: t.ID, Services: svcs})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// nodeCertIns are the node certificates the Hub holds (hub.control) or
// pinned for a cluster node.
func (h *Hub) nodeCertIns() []doctor.NodeCertIn {
	var out []doctor.NodeCertIn
	h.nodeMu.Lock()
	c, _, err := loadControl(h.nodesDir())
	h.nodeMu.Unlock()
	if err == nil && c.Leaf != nil {
		out = append(out, doctor.NodeCertIn{Name: ControlCN, NotAfter: c.Leaf.NotAfter})
	}
	h.mu.RLock()
	for id, s := range h.st.Servers {
		if s.ClusterNode() && s.State != ServerRevoked && !s.CertNotAfter.IsZero() {
			out = append(out, doctor.NodeCertIn{Name: id, NotAfter: s.CertNotAfter})
		}
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// apiTargets are the public addresses kube_api_public may dial, per
// snapshot node: only the one in the Hub's own records (the node's
// enrolment report, else its mesh record; never the Node object, which
// a node writes itself), and only when the front door would publish it
// (publicEndpointOK: never private, loopback, link-local, CGNAT,
// special-purpose, documentation, nor the mesh, link, pod or service
// CIDRs). Anything else is skipped: a node can't aim the Hub's dials at
// an internal target.
func (h *Hub) apiTargets(snap nodeadm.Snapshot) map[string]netip.Addr {
	excluded := h.meshExcluded()
	h.cl.ms.mu.Lock()
	allowDoc := h.cl.ms.allowDoc
	h.cl.ms.mu.Unlock()
	out := map[string]netip.Addr{}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, n := range snap.Nodes {
		id := n.Name
		if servers.ValidID(id) != nil || h.st.Mesh[id].Removed {
			continue
		}
		rec := h.st.Mesh[id].Public
		if s, listed := h.st.Servers[id]; listed {
			if !s.ClusterNode() || s.State == ServerRevoked {
				continue
			}
			rec = nonEmpty(s.MeshPublic, rec)
		}
		ap, ok := parseEndpoint(rec)
		if !ok || publicEndpointOK(ap, allowDoc, excluded) != nil {
			continue
		}
		out[id] = ap.Addr()
	}
	return out
}

// apiPublic dials the API and kubelet ports on each node's recorded
// public address (apiTargets; in parallel, each bounded): node → what
// answered.
func (h *Hub) apiPublic(ctx context.Context, snap nodeadm.Snapshot) map[string][]string {
	dial := h.ha.dialAPI
	if dial == nil {
		dial = dialAPIPort
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[string][]string{}
	)
	for node, ip := range h.apiTargets(snap) {
		for _, port := range apiPorts {
			addr := net.JoinHostPort(ip.String(), port)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if dial(ctx, addr) {
					mu.Lock()
					out[node] = append(out[node], addr)
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	return out
}

// dialAPIPort: a TCP connection to addr completes within apiDialWait.
func dialAPIPort(ctx context.Context, addr string) bool {
	c, cancel := context.WithTimeout(ctx, apiDialWait)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(c, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// HAFindings is the doctor's HA findings (MCP ha_findings, R; the twin of
// GET /api/doctor): the HA kinds and kube_api_public, refused off
// Kubernetes.
type HAFindings struct {
	Findings []doctor.Finding        `json:"findings"`
	Counts   map[doctor.Severity]int `json:"counts"`
	Muted    int                     `json:"muted"`
	Kinds    []string                `json:"kinds"`
}

// DoctorHA runs the doctor and keeps its HA findings.
func (h *Hub) DoctorHA(ctx context.Context) (*HAFindings, error) {
	if err := h.HAOn(); err != nil {
		return nil, err
	}
	r, err := h.Doctor(ctx)
	if err != nil {
		return nil, err
	}
	kinds := append(slices.Clone(doctor.HAKinds), doctor.KindKubeAPIPublic)
	out := &HAFindings{Findings: []doctor.Finding{}, Counts: map[doctor.Severity]int{doctor.Problem: 0, doctor.Warning: 0, doctor.Info: 0}, Kinds: kinds}
	for _, f := range r.Findings {
		if !slices.Contains(kinds, f.Kind) {
			continue
		}
		out.Findings = append(out.Findings, f)
		if f.Muted != nil {
			out.Muted++
		} else {
			out.Counts[f.Severity]++
		}
	}
	return out, nil
}
