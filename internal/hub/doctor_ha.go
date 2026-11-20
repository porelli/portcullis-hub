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
	"github.com/portcullis/hub/internal/state"
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

// doctorHAWait bounds the doctor's own wait on the shared HA read (the
// read itself keeps running for the HA page, up to haReadWait).
const doctorHAWait = 5 * time.Second

// apiCacheFor: how long the API-port dials' result is reused.
const apiCacheFor = 5 * time.Minute

// apiCache is the last kube_api_public dial: its targets and what
// answered, at at (the injected clock).
type apiCache struct {
	mu      sync.Mutex
	at      time.Time
	targets map[string]netip.Addr
	public  map[string][]string
}

// apiResult is kube_api_public's input: what answered per node, and the
// nodes not checked (no public address on record).
type apiResult struct {
	public    map[string][]string
	unchecked []string
}

// doctorHAIn is the HA kinds' input and kube_api_public's. Never under
// mu. nodeadm's snapshot comes from the HA page's shared read, waited
// for at most doctorHAWait (then SnapshotErr: the N−1 kind's "can't
// judge" Problem, never a pass); the API-port dials run alongside the
// other inputs.
func (h *Hub) doctorHAIn(ctx context.Context) (*doctor.HAIn, *apiResult) {
	if !h.kubeOn() {
		return nil, nil
	}
	in := &doctor.HAIn{Now: h.now().UTC(), Enabled: h.cfg.HA, Namespaces: h.nminusNamespaces()}
	if last := h.lastSnapshot(); last != nil {
		in.LastNodes = len(last.Nodes)
	}
	var (
		api  *apiResult
		done = make(chan struct{})
		snap *nodeadm.Snapshot
	)
	close(done)
	// nodeadm configured: its snapshot (shared with the HA page), else
	// nothing cluster-wide is judged (no cluster nodes are managed).
	if h.clusterNodesOn() == nil {
		wait := h.ha.doctorWait
		if wait <= 0 {
			wait = doctorHAWait
		}
		r, err := h.haSharedWait(ctx, wait)
		switch {
		case err != nil:
			in.SnapshotErr = clipRunes(err.Error(), 300)
		case r.snapErr != nil:
			in.SnapshotErr = clipRunes(r.snapErr.Error(), 300)
		default:
			s := r.snap
			snap = &s
		}
		if err == nil && h.cfg.HA {
			if r.statusErr != nil {
				in.FrontdoorErr = clipRunes(r.statusErr.Error(), 200)
			} else {
				in.FrontdoorStatus = r.status
			}
		}
	}
	if snap != nil {
		in.Snapshot = snap
		in.NMinus1, in.NMinus1Err = h.checkN1(*snap)
		place := h.haPlacement(*snap)
		in.MustFence = slices.Sorted(maps.Keys(fencingRequired(*snap, place, h.cfg.HA, in.Namespaces)))
		set := map[string]bool{}
		for _, p := range place {
			set[p.site] = true
		}
		in.Sites = slices.Sorted(maps.Keys(set))
		targets := h.apiTargets(*snap)
		api = &apiResult{}
		if len(in.Sites) <= 1 {
			for _, n := range snap.Nodes {
				if _, ok := targets[n.Name]; !ok {
					api.unchecked = append(api.unchecked, n.Name)
				}
			}
			sort.Strings(api.unchecked)
		}
		done = make(chan struct{})
		go func() {
			defer close(done)
			api.public = h.apiPublic(ctx, targets)
		}()
	}
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
	<-done
	return in, api
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
// Each run loads every enabled instance's model (local files, no
// network): accepted, as the doctor's other config checks read theirs.
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
// snapshot node: only a Hub-persisted endpoint that never came from the
// Node object — the node's enrolment report (MeshPublic), else its mesh
// record's endpoint once another site confirmed it by a handshake
// (ReachReachable; the mesh plan may have copied an unconfirmed one
// from the Node object) — and only when the front door would publish it
// (publicEndpointOK: never private, loopback, link-local, CGNAT,
// special-purpose, documentation, nor the mesh, link, pod or service
// CIDRs). Anything else is skipped: a node can't aim the Hub's dials at
// an internal target. A node left without one isn't checked (with one
// site, the finding says so).
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
		rec := ""
		if m := h.st.Mesh[id]; m.Reach == state.ReachReachable {
			rec = m.Public
		}
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

// apiPublic dials the API and kubelet ports on targets (apiTargets; in
// parallel, each bounded by apiDialWait): node → what answered. The
// result is reused for apiCacheFor while the targets are the same.
func (h *Hub) apiPublic(ctx context.Context, targets map[string]netip.Addr) map[string][]string {
	now := h.now()
	c := &h.ha.api
	c.mu.Lock()
	if c.public != nil && maps.Equal(c.targets, targets) && now.Sub(c.at) < apiCacheFor && !now.Before(c.at) {
		out := maps.Clone(c.public)
		c.mu.Unlock()
		return out
	}
	c.mu.Unlock()
	dial := h.ha.dialAPI
	if dial == nil {
		dial = dialAPIPort
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[string][]string{}
	)
	for node, ip := range targets {
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
	for n := range out {
		sort.Strings(out[n])
	}
	c.mu.Lock()
	c.at, c.targets, c.public = now, maps.Clone(targets), maps.Clone(out)
	c.mu.Unlock()
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

// SetHADoctorForTest replaces the doctor's HA hooks (tests in other
// packages): the write fence, the last core backup and the API-port dial
// (nil: keep the current one).
func (h *Hub) SetHADoctorForTest(lease func() error, lastBackup func(context.Context) (*time.Time, error), dial func(context.Context, string) bool) {
	if lease != nil {
		h.ha.lease = lease
	}
	if lastBackup != nil {
		h.ha.lastBackup = lastBackup
	}
	if dial != nil {
		h.ha.dialAPI = dial
	}
}
