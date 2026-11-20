package kube

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/portcullis/hub/internal/gatelogs"
)

func ownedBy(kind, name string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: kind, Name: name, UID: "u", Controller: &yes}}
}

// TestCoreReplicasListsPods (contract §20.10, pre-flight P13): pods list
// in the core namespace by component label; only pods the component's
// own controller owns, named after it; running = readable; pending,
// terminating and failed listed without an address (the read is then
// incomplete); succeeded left out; an expected ordinal without a pod
// listed without an address. Never a write.
func TestCoreReplicasListsPods(t *testing.T) {
	c := newPubCluster(t)
	ctx := context.Background()
	now := metav1.NewTime(time.Now())
	gg := func(name string, phase corev1.PodPhase, ip string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{LabelComponent: "group-gate"}, OwnerReferences: ownedBy("StatefulSet", "group-gate")},
			Status: corev1.PodStatus{Phase: phase, PodIP: ip}}
	}
	terminating := gg("group-gate-2", corev1.PodRunning, "10.42.0.9")
	terminating.DeletionTimestamp, terminating.Finalizers = &now, []string{"x"}
	foreign := gg("group-gate-7", corev1.PodRunning, "10.42.0.8")
	foreign.OwnerReferences = ownedBy("StatefulSet", "impostor")
	unowned := gg("group-gate-8", corev1.PodRunning, "10.42.0.8")
	unowned.OwnerReferences = nil
	for _, p := range []corev1.Pod{
		gg("group-gate-0", corev1.PodRunning, "10.42.0.7"),
		gg("group-gate-1", corev1.PodPending, ""),
		terminating,
		gg("group-gate-3", corev1.PodFailed, "10.42.0.10"),
		gg("group-gate-5", corev1.PodSucceeded, ""),
		gg("group-gate-x1", corev1.PodRunning, "10.42.0.11"), // not an ordinal
		foreign, unowned,
		{ObjectMeta: metav1.ObjectMeta{Name: "wg-6c9f-d4x2z", Labels: map[string]string{LabelComponent: "wg"}, OwnerReferences: ownedBy("ReplicaSet", "wg-6c9f")},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.20"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "wg-other-1", Labels: map[string]string{LabelComponent: "wg"}, OwnerReferences: ownedBy("ReplicaSet", "wg-6c9f")},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.21"}}, // not named after its ReplicaSet
	} {
		p.Namespace = coreNS
		if err := c.typed.Tracker().Add(&p); err != nil { // the fixture's reactor refuses creates
			t.Fatal(err)
		}
	}
	// An apps-namespace pod with the label is never listed.
	app := gg("group-gate-9", corev1.PodRunning, "10.42.1.1")
	app.Namespace = ns
	if err := c.typed.Tracker().Add(&app); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.writes = nil
	c.mu.Unlock()
	b, err := New(Config{Client: c.typed, Dynamic: newCluster(t).dyn, Namespace: ns, CoreNamespace: coreNS, Exec: c})
	if err != nil {
		t.Fatal(err)
	}
	// Expected 6: ordinal 4 (no pod) and 5 (succeeded) are listed unread;
	// the fixture's own unowned pods (group-gate-5f-a1, -b2) never.
	got, err := b.CoreReplicas("group-gate", ReplicaOptions{StatefulSet: true, Expected: 6})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []gatelogs.Replica{{Name: "group-gate-0", Addr: "10.42.0.7"}, {Name: "group-gate-1"}, {Name: "group-gate-2"}, {Name: "group-gate-3"}, {Name: "group-gate-4"}, {Name: "group-gate-5"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("replicas = %+v, want %+v", got, want)
	}
	// Without Expected, the ordinals seen count (0–3; and a pod gone
	// later is still listed, unread: see below).
	lister := b.CoreReplicas("group-gate", ReplicaOptions{StatefulSet: true})
	if got, _ := lister(ctx); !reflect.DeepEqual(got, want[:4]) {
		t.Errorf("inferred = %+v", got)
	}
	if err := c.typed.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), coreNS, "group-gate-3"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(listCache + 100*time.Millisecond)
	if got, _ := lister(ctx); !reflect.DeepEqual(got, want[:4]) {
		t.Errorf("a gone pod's ordinal dropped: %+v", got)
	}
	if got, _ := b.CoreReplicas("wg", ReplicaOptions{})(ctx); !reflect.DeepEqual(got, []gatelogs.Replica{{Name: "wg-6c9f-d4x2z", Addr: "10.42.0.20"}}) {
		t.Errorf("wg = %+v", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) != 0 {
		t.Errorf("writes: %v", c.writes)
	}
}
