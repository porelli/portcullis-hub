package kube

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestLastCoreBackup: one get of portcullis-backup-status in the core
// namespace (the Role's resourceNames); missing = none (nil, no error); a
// missing key or a bad time is an error, never "none".
func TestLastCoreBackup(t *testing.T) {
	ctx := context.Background()
	c := fake.NewSimpleClientset()
	var acts []string
	c.PrependReactor("*", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		acts = append(acts, a.GetVerb()+" "+a.GetResource().Resource+" "+a.GetNamespace())
		return false, nil, nil
	})
	b := &Backend{cfg: Config{Client: c, CoreNamespace: "portcullis"}}
	if got, err := b.LastCoreBackup(ctx); got != nil || err != nil {
		t.Fatalf("no record: %v %v", got, err)
	}
	if len(acts) != 1 || acts[0] != "get configmaps portcullis" {
		t.Errorf("actions %q", acts)
	}
	c.CoreV1().ConfigMaps("portcullis").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: BackupStatusObject, Namespace: "portcullis"},
		Data: map[string]string{"last_success": "2026-11-21T03:20:00Z", "what": "core"}}, metav1.CreateOptions{})
	got, err := b.LastCoreBackup(ctx)
	if err != nil || got == nil || !got.Equal(time.Date(2026, 11, 21, 3, 20, 0, 0, time.UTC)) {
		t.Fatalf("recorded: %v %v", got, err)
	}
	for _, d := range []map[string]string{{}, {"last_success": "yesterday"}} {
		cm, _ := c.CoreV1().ConfigMaps("portcullis").Get(ctx, BackupStatusObject, metav1.GetOptions{})
		cm.Data = d
		c.CoreV1().ConfigMaps("portcullis").Update(ctx, cm, metav1.UpdateOptions{})
		if got, err := b.LastCoreBackup(ctx); err == nil || got != nil {
			t.Errorf("%v accepted: %v", d, got)
		}
	}
}
