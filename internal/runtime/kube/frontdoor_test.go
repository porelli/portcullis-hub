package kube

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestFrontdoorStatusIsOneGet: the HA page's read is one get of
// frontdoor-status in the core namespace (the Role's resourceNames),
// never the front door's Secret, never a write; a missing key is an
// error.
func TestFrontdoorStatusIsOneGet(t *testing.T) {
	c := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "frontdoor-status", Namespace: "portcullis"},
		Data: map[string]string{"status.json": `{"v":1,"state":"leading"}`}})
	var acts []string
	c.PrependReactor("*", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		acts = append(acts, a.GetVerb()+" "+a.GetResource().Resource+" "+a.GetNamespace())
		return false, nil, nil
	})
	b := &Backend{cfg: Config{Client: c, CoreNamespace: "portcullis"}}
	doc, err := b.FrontdoorStatus(context.Background())
	if err != nil || string(doc) != `{"v":1,"state":"leading"}` {
		t.Fatalf("%s %v", doc, err)
	}
	if len(acts) != 1 || acts[0] != "get configmaps portcullis" {
		t.Errorf("actions %q", acts)
	}
	cm, _ := c.CoreV1().ConfigMaps("portcullis").Get(context.Background(), "frontdoor-status", metav1.GetOptions{})
	cm.Data = map[string]string{}
	c.CoreV1().ConfigMaps("portcullis").Update(context.Background(), cm, metav1.UpdateOptions{})
	if _, err := b.FrontdoorStatus(context.Background()); err == nil {
		t.Error("no status.json accepted")
	}
}
