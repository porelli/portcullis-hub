package hub

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/state"
)

// haKinds counts the report's HA findings by kind.
func haKinds(t *testing.T, h *Hub) map[string]int {
	t.Helper()
	h.mu.RLock()
	none := h.people == nil
	h.mu.RUnlock()
	if none {
		h.SetPeople(newFakePeople())
	}
	r, err := h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, f := range r.Findings {
		if slices.Contains(doctor.HAKinds, f.Kind) || f.Kind == doctor.KindKubeAPIPublic {
			out[f.Kind]++
		}
	}
	return out
}

// TestDoctorHANeverOnDocker: under Docker there is no HA input and no
// HA kind fires, whatever the hooks say.
func TestDoctorHANeverOnDocker(t *testing.T) {
	f := newFixture(t)
	f.h.ha.lease = func() error { return errors.New("standing by") }
	f.h.ha.dialAPI = func(context.Context, string) bool { return true }
	if in, pub := f.h.doctorHAIn(context.Background()); in != nil || pub != nil {
		t.Fatalf("docker: %+v %v", in, pub)
	}
	if got := haKinds(t, f.h); len(got) != 0 {
		t.Errorf("docker: %v", got)
	}
	if _, err := f.h.DoctorHA(context.Background()); err == nil || !strings.Contains(err.Error(), ErrTextHANeedsKube) {
		t.Errorf("DoctorHA on Docker: %v", err)
	}
}

// TestDoctorHAInputs: on Kubernetes the doctor judges nodeadm's
// snapshot on the injected clock (node_down only after 1 min), the
// fence (ha_lease_lost), the backup (HA on), and kube_api_public per
// node; DoctorHA keeps only the HA findings.
func TestDoctorHAInputs(t *testing.T) {
	cf := haFixture(t,
		haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"), true, true),
		haLabels(siteNode("n2", "server", "main", "10.215.0.2", "192.0.2.2", "203.0.113.2"), true, false),
		haLabels(siteNode("n3", "server", "main", "10.215.0.3", "192.0.2.3", "203.0.113.3"), false, false))
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cf.h.srvT.now = func() time.Time { return now }
	// Only a public address on the Hub's own record is dialled: n1's
	// confirmed record is loopback, n3's the mesh, and n1's Node object
	// claims another public address (a node writes its own object).
	cf.h.mu.Lock()
	for id, pub := range map[string]string{"n1": "127.0.0.1:51830", "n2": "203.0.113.2:51830", "n3": "10.215.0.1:51830"} {
		r := cf.h.st.Mesh[id]
		r.Public, r.Reach = pub, state.ReachReachable
		cf.h.st.Mesh[id] = r
	}
	cf.h.mu.Unlock()
	var dmu sync.Mutex
	var dialed []string
	cf.h.ha.dialAPI = func(_ context.Context, addr string) bool {
		dmu.Lock()
		dialed = append(dialed, addr)
		dmu.Unlock()
		return addr == "203.0.113.2:6443"
	}
	cf.h.ha.lease = func() error { return nil }
	cf.na.mu.Lock()
	cf.na.snap.Nodes[0].Addresses.Public = []string{"203.0.113.9", "127.0.0.1"}
	cf.na.snap.Nodes[2].Ready = false
	cf.na.snap.Nodes[2].NotReadySince = jsonstrict.Some(now.Add(-time.Minute).Format(time.RFC3339))
	cf.na.mu.Unlock()

	in, pub := cf.h.doctorHAIn(context.Background())
	if in == nil || in.Snapshot == nil || in.SnapshotErr != "" || !in.Now.Equal(now) {
		t.Fatalf("input %+v", in)
	}
	if !slices.Equal(in.Sites, []string{"main"}) || len(in.MustFence) == 0 {
		t.Errorf("sites %v must fence %v", in.Sites, in.MustFence)
	}
	if pub == nil || len(pub.public) != 1 || !slices.Equal(pub.public["n2"], []string{"203.0.113.2:6443"}) || !slices.Equal(pub.unchecked, []string{"n1", "n3"}) {
		t.Errorf("api public %+v", pub)
	}
	dmu.Lock()
	slices.Sort(dialed)
	if !slices.Equal(dialed, []string{"203.0.113.2:10250", "203.0.113.2:6443"}) {
		t.Errorf("dialled %v: only n2's recorded public address may be", dialed)
	}
	dmu.Unlock()
	got := haKinds(t, cf.h)
	// kube_api_public: n2 exposed, n1 and n3 not checked (one site).
	if got[doctor.KindNodeDown] != 0 || got[doctor.KindKubeAPIPublic] != 3 || got[doctor.KindHALeaseLost] != 0 || got[doctor.KindBackupStale] != 0 {
		t.Errorf("at 1 min: %v", got)
	}
	now = now.Add(time.Second)
	cf.h.ha.lease = func() error { return errors.New("this Hub is standing by: another Hub is the active writer") }
	cf.h.cfg.HA = true
	got = haKinds(t, cf.h)
	if got[doctor.KindNodeDown] != 1 || got[doctor.KindHALeaseLost] != 1 || got[doctor.KindBackupStale] != 1 {
		t.Errorf("after 1 min, standing by, HA on without a backup: %v", got)
	}
	last := now.Add(-time.Hour)
	cf.h.ha.lastBackup = func(context.Context) (*time.Time, error) { return &last, nil }
	if got = haKinds(t, cf.h); got[doctor.KindBackupStale] != 0 {
		t.Errorf("backup an hour ago: %v", got)
	}

	v, err := cf.h.DoctorHA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range v.Findings {
		if !slices.Contains(v.Kinds, f.Kind) {
			t.Errorf("not an HA kind: %+v", f)
		}
		if f.Kind == doctor.KindNodeDown && !strings.Contains(f.Title, "n3") {
			t.Errorf("node_down %+v", f)
		}
		n++
	}
	if n == 0 || v.Counts[doctor.Problem] == 0 {
		t.Errorf("DoctorHA %+v", v)
	}
}

// TestDoctorHASnapshotUnreadable: nodeadm configured but its snapshot
// unreadable → the N−1 kind's Problem with the reason (never a pass),
// once the cluster can fail over (HA on, or the last snapshot had more
// than one node: Q-M4); a single-node cluster without HA stays quiet.
func TestDoctorHASnapshotUnreadable(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.ha.lease = func() error { return nil }
	cf.h.SetNodeadm(failingNodeadm{cf.na, &nodeadm.APIError{Status: 503, Kind: "not_leader", Text: "not the leader"}})
	in, _ := cf.h.doctorHAIn(context.Background())
	if in == nil || in.Snapshot != nil || in.SnapshotErr == "" {
		t.Fatalf("input %+v", in)
	}
	if got := haKinds(t, cf.h); got[doctor.KindHANMinus1Insufficient] != 0 {
		t.Errorf("one node, HA off: %v", got)
	}
	cf.h.cl.mu.Lock()
	cf.h.cl.last = &nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{{Name: "n1"}, {Name: "n2"}}}
	cf.h.cl.mu.Unlock()
	if got := haKinds(t, cf.h); got[doctor.KindHANMinus1Insufficient] != 1 {
		t.Errorf("last snapshot 2 nodes: %v", got)
	}
	cf.h.cl.mu.Lock()
	cf.h.cl.last = nil
	cf.h.cl.mu.Unlock()
	cf.h.cfg.HA = true
	if got := haKinds(t, cf.h); got[doctor.KindHANMinus1Insufficient] != 1 {
		t.Errorf("HA on: %v", got)
	}
}

// blockingNodeadm's snapshot read waits until release closes.
type blockingNodeadm struct {
	*fakeNodeadm
	release chan struct{}
}

func (b blockingNodeadm) Cluster(ctx context.Context) (nodeadm.Snapshot, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nodeadm.Snapshot{}, errors.New("released")
}

// TestDoctorHADoesNotWaitOnNodeadm (Q-I1): a nodeadm that never answers
// costs the doctor its own wait, not the shared read's 20 s: the N−1
// kind then raises "can't judge" (HA on), never a pass.
func TestDoctorHADoesNotWaitOnNodeadm(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.ha.lease = func() error { return nil }
	cf.h.cfg.HA = true
	b := blockingNodeadm{cf.na, make(chan struct{})}
	t.Cleanup(func() { close(b.release) })
	cf.h.SetNodeadm(b)
	cf.h.ha.doctorWait = 300 * time.Millisecond
	start := time.Now()
	in, api := cf.h.doctorHAIn(context.Background())
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the doctor waited %s", d)
	}
	if in == nil || in.Snapshot != nil || in.SnapshotErr != "nodeadm didn't answer within 300ms" || api != nil {
		t.Fatalf("input %+v %+v", in, api)
	}
	cf.h.SetPeople(newFakePeople())
	start = time.Now()
	r, err := cf.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("Doctor took %s", d)
	}
	n := 0
	for _, f := range r.Findings {
		if f.Kind == doctor.KindHANMinus1Insufficient && f.Severity == doctor.Problem && strings.Contains(f.Why, "didn't answer") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("N−1 can't judge: %d findings in %+v", n, r.Findings)
	}
	if doctorHAWait != 5*time.Second {
		t.Errorf("doctorHAWait = %s, want 5 s", doctorHAWait)
	}
}

// TestAPITargetsRecordsOnly: kube_api_public dials only the enrolment
// report's public endpoint or a mesh record's confirmed one, never an
// address copied from the Node object nor an unconfirmed (offered)
// mesh endpoint; the dials are reused for 5 min (the injected clock).
func TestAPITargetsRecordsOnly(t *testing.T) {
	cf := haFixture(t,
		siteNode("a", "server", "main", "10.215.0.1", "192.0.2.1", "203.0.113.1"),
		siteNode("b", "server", "main", "10.215.0.2", "192.0.2.2", "203.0.113.2"),
		siteNode("c", "server", "main", "10.215.0.3", "192.0.2.3", "203.0.113.3"),
		siteNode("d", "agent", "main", "10.215.0.4", "192.0.2.4", "203.0.113.4"))
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cf.h.srvT.now = func() time.Time { return now }
	cf.h.mu.Lock()
	ra := cf.h.st.Mesh["a"]
	ra.Public, ra.Reach = "", ""
	cf.h.st.Mesh["a"] = ra // a: only its Node object names a public address
	rb := cf.h.st.Mesh["b"]
	rb.Public, rb.Reach = "203.0.113.2:51830", state.ReachOffered
	cf.h.st.Mesh["b"] = rb
	rc := cf.h.st.Mesh["c"]
	rc.Public, rc.Reach = "203.0.113.3:51830", state.ReachReachable
	cf.h.st.Mesh["c"] = rc
	rd := cf.h.st.Mesh["d"]
	rd.Public, rd.Reach = "", ""
	cf.h.st.Mesh["d"] = rd
	if cf.h.st.Servers == nil {
		cf.h.st.Servers = map[string]state.Server{}
	}
	cf.h.st.Servers["d"] = state.Server{Kind: state.KindClusterNode, State: ServerReady, Site: "main", MeshIP: "10.215.0.4", MeshPublic: "203.0.113.4:51830"}
	cf.h.mu.Unlock()
	snap := cf.na.snap
	got := cf.h.apiTargets(snap)
	if len(got) != 2 || got["c"].String() != "203.0.113.3" || got["d"].String() != "203.0.113.4" {
		t.Errorf("targets %v", got)
	}
	var dmu sync.Mutex
	dials := 0
	cf.h.ha.dialAPI = func(context.Context, string) bool { dmu.Lock(); dials++; dmu.Unlock(); return false }
	cf.h.apiPublic(context.Background(), got)
	cf.h.apiPublic(context.Background(), got)
	now = now.Add(apiCacheFor - time.Second)
	cf.h.apiPublic(context.Background(), got)
	if dials != 4 {
		t.Errorf("within 5 min: %d dials, want 4 (cached)", dials)
	}
	now = now.Add(time.Second)
	cf.h.apiPublic(context.Background(), got)
	if dials != 8 {
		t.Errorf("after 5 min: %d dials, want 8", dials)
	}
	delete(got, "d")
	cf.h.apiPublic(context.Background(), got)
	if dials != 10 {
		t.Errorf("other targets: %d dials, want 10", dials)
	}
}

// TestPublishedStaleUsesHubClock (Q-M2): the publish tracker judges the
// Hub's injected clock.
func TestPublishedStaleUsesHubClock(t *testing.T) {
	f := newFixture(t)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f.h.srvT.now = func() time.Time { return at }
	if f.h.pub == nil || f.h.pub.Now == nil || !f.h.pub.Now().Equal(at) {
		t.Errorf("tracker clock not the Hub's")
	}
}
