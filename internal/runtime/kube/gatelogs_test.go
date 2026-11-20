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

// TestCoreReplicasListsPods (contract §20.10, pre-flight P13): pods list
// in the core namespace by component label; only pods named after it; a
// deleted or finished pod left out; one not running listed without an
// address (its log unreadable: the read is incomplete). Never a write.
func TestCoreReplicasListsPods(t *testing.T) {
	c := newPubCluster(t)
	ctx := context.Background()
	now := metav1.NewTime(time.Now())
	for _, p := range []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "group-gate-0", Labels: map[string]string{LabelComponent: "group-gate"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.7"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "group-gate-1", Labels: map[string]string{LabelComponent: "group-gate"}}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
		{ObjectMeta: metav1.ObjectMeta{Name: "group-gate-2", Labels: map[string]string{LabelComponent: "group-gate"}, DeletionTimestamp: &now, Finalizers: []string{"x"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.9"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "group-gate-3", Labels: map[string]string{LabelComponent: "group-gate"}}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
		{ObjectMeta: metav1.ObjectMeta{Name: "impostor-0", Labels: map[string]string{LabelComponent: "group-gate"}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.8"}},
	} {
		p.Namespace = coreNS
		if err := c.typed.Tracker().Add(&p); err != nil { // the fixture's reactor refuses creates
			t.Fatal(err)
		}
	}
	// An apps-namespace pod with the label is never listed.
	if err := c.typed.Tracker().Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "group-gate-9", Namespace: ns, Labels: map[string]string{LabelComponent: "group-gate"}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.1.1"}}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.writes = nil
	c.mu.Unlock()
	b, err := New(Config{Client: c.typed, Dynamic: newCluster(t).dyn, Namespace: ns, CoreNamespace: coreNS, Exec: c})
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.CoreReplicas("group-gate")(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// group-gate-5f-a1 / -b2 are the fixture's (Running, no IP yet).
	want := []gatelogs.Replica{{Name: "group-gate-0", Addr: "10.42.0.7"}, {Name: "group-gate-1"}, {Name: "group-gate-5f-a1"}, {Name: "group-gate-5f-b2"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("replicas = %+v, want %+v", got, want)
	}
	if got, _ := b.CoreReplicas("wg")(ctx); len(got) != 1 || got[0].Name != "wg-6c-d4" {
		t.Errorf("wg = %+v", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) != 0 {
		t.Errorf("writes: %v", c.writes)
	}
}
