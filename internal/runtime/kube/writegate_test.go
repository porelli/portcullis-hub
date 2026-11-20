package kube

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/portcullis/hub/internal/fsutil"
)

var errStandingBy = errors.New("this Hub is standing by: another Hub is the active writer")

func closeGate(t *testing.T) {
	t.Helper()
	fsutil.SetWriteGate(func() error { return errStandingBy })
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
}

// TestApplyRefusedWhileStandingBy: Up applies nothing with the gate closed.
func TestApplyRefusedWhileStandingBy(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	closeGate(t)
	if err := b.Up(context.Background(), project(t, orderedCompose, "app1"), nil); !errors.Is(err, errStandingBy) {
		t.Fatalf("Up = %v, want the gate's error", err)
	}
	if got := c.Applied(); len(got) != 0 {
		t.Errorf("applied %v while standing by", got)
	}
}

// TestGateWritesTransport: with the gate closed no write reaches the API
// server; reads, access reviews and dry runs still do. Open, all pass.
func TestGateWritesTransport(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "selfsubjectrulesreviews"):
			w.Write([]byte(`{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1"}`))
		default:
			w.Write([]byte(`{"kind":"Pod","apiVersion":"v1","metadata":{"name":"p"}}`))
		}
	}))
	defer srv.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL, WrapTransport: GateWrites})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pods := cs.CoreV1().Pods("portcullis-apps")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	writes := map[string]func() error{
		"create": func() error { _, err := pods.Create(ctx, pod, metav1.CreateOptions{}); return err },
		"update": func() error { _, err := pods.Update(ctx, pod, metav1.UpdateOptions{}); return err },
		"patch": func() error {
			_, err := pods.Patch(ctx, "p", "application/merge-patch+json", []byte(`{}`), metav1.PatchOptions{})
			return err
		},
		"delete": func() error { return pods.Delete(ctx, "p", metav1.DeleteOptions{}) },
	}
	reads := map[string]func() error{
		"get": func() error { _, err := pods.Get(ctx, "p", metav1.GetOptions{}); return err },
		"review": func() error {
			_, err := cs.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authv1.SelfSubjectRulesReview{}, metav1.CreateOptions{})
			return err
		},
		"dry run": func() error {
			_, err := pods.Create(ctx, pod, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			return err
		},
	}
	closeGate(t)
	for name, w := range writes {
		if err := w(); !errors.Is(err, errStandingBy) {
			t.Errorf("%s while standing by = %v", name, err)
		}
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Errorf("writes reached the API server: %v", seen)
	}
	mu.Unlock()
	for name, r := range reads {
		if err := r(); err != nil {
			t.Errorf("%s while standing by = %v", name, err)
		}
	}
	for _, path := range []string{"/api/v1/namespaces/a/pods/p/exec", "/api/v1/namespaces/a/pods/p/portforward"} {
		if !changesCluster(httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Errorf("GET %s isn't gated", path)
		}
	}
	up := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	up.Header.Set("Upgrade", "websocket")
	if !changesCluster(up) {
		t.Error("an upgraded GET isn't gated")
	}
	fsutil.SetWriteGate(nil)
	for name, w := range writes {
		if err := w(); err != nil {
			t.Errorf("%s while leading = %v", name, err)
		}
	}
}
