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
	// record is loopback, n3's the mesh, and n1's Node object claims
	// another public address (a node writes its own object).
	cf.h.mu.Lock()
	for id, pub := range map[string]string{"n1": "127.0.0.1:51830", "n2": "203.0.113.2:51830", "n3": "10.215.0.1:51830"} {
		r := cf.h.st.Mesh[id]
		r.Public = pub
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
	if len(pub) != 1 || !slices.Equal(pub["n2"], []string{"203.0.113.2:6443"}) {
		t.Errorf("api public %v", pub)
	}
	dmu.Lock()
	slices.Sort(dialed)
	if !slices.Equal(dialed, []string{"203.0.113.2:10250", "203.0.113.2:6443"}) {
		t.Errorf("dialled %v: only n2's recorded public address may be", dialed)
	}
	dmu.Unlock()
	got := haKinds(t, cf.h)
	if got[doctor.KindNodeDown] != 0 || got[doctor.KindKubeAPIPublic] != 1 || got[doctor.KindHALeaseLost] != 0 || got[doctor.KindBackupStale] != 0 {
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
// unreadable → the N−1 kind's Problem with the reason (never a pass).
func TestDoctorHASnapshotUnreadable(t *testing.T) {
	cf := haFixture(t, haLabels(siteNode("n1", "server", "main", "10.215.0.1", "192.0.2.1", ""), true, true))
	cf.h.ha.lease = func() error { return nil }
	cf.h.SetNodeadm(failingNodeadm{cf.na, &nodeadm.APIError{Status: 503, Kind: "not_leader", Text: "not the leader"}})
	in, _ := cf.h.doctorHAIn(context.Background())
	if in == nil || in.Snapshot != nil || in.SnapshotErr == "" {
		t.Fatalf("input %+v", in)
	}
	if got := haKinds(t, cf.h); got[doctor.KindHANMinus1Insufficient] != 1 {
		t.Errorf("%v", got)
	}
}
