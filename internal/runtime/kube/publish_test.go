package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/exec"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/publish"
)

const coreNS = "portcullis"

// vectorObjects are published_docs.json's object names by kind.
func vectorObjects(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../../publish/testdata/published_docs.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Object string `json:"object"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Object] = r.Kind
	}
	return out
}

// pubCluster is a fake core namespace: the eight objects as the chart
// creates them (empty), reader pods, an exec answering hub rev.
type pubCluster struct {
	typed   *fake.Clientset
	mu      sync.Mutex
	writes  []string          // "<verb> <resource>/<name>"
	mounted map[string]string // "<pod> <dir> <doc>" → rev printed ("" = exit 1)
	execs   [][]string
}

func newPubCluster(t *testing.T) *pubCluster {
	c := &pubCluster{typed: fake.NewSimpleClientset(), mounted: map[string]string{}}
	ctx := context.Background()
	objs := vectorObjects(t)
	for name, kind := range objs {
		meta := metav1.ObjectMeta{Name: name, Namespace: coreNS}
		if kind == "secret" {
			c.typed.CoreV1().Secrets(coreNS).Create(ctx, &corev1.Secret{ObjectMeta: meta}, metav1.CreateOptions{})
		} else {
			c.typed.CoreV1().ConfigMaps(coreNS).Create(ctx, &corev1.ConfigMap{ObjectMeta: meta}, metav1.CreateOptions{})
		}
	}
	// A foreign ConfigMap and Secret in the same namespace.
	c.typed.CoreV1().ConfigMaps(coreNS).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "frontdoor-status", Namespace: coreNS}}, metav1.CreateOptions{})
	c.typed.CoreV1().Secrets(coreNS).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "frontdoor-env", Namespace: coreNS}}, metav1.CreateOptions{})
	for _, p := range []struct{ name, comp string }{{"group-gate-5f-a1", "group-gate"}, {"group-gate-5f-b2", "group-gate"}, {"keycloak-0", "keycloak"},
		{"mcp-gate-7d-c3", "mcp-gate"}, {"wg-6c-d4", "wg"}, {"frontdoor-1", "frontdoor"}} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: coreNS, Labels: map[string]string{LabelComponent: p.comp}},
			Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "sidecar"}, {Name: p.comp, VolumeMounts: []corev1.VolumeMount{{Name: "portcullis-bin", MountPath: "/portcullis-bin", ReadOnly: true}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		c.typed.CoreV1().Pods(coreNS).Create(ctx, pod, metav1.CreateOptions{})
	}
	// From here on every write is judged: only update on the vector's
	// names, never create, delete or anything else.
	c.typed.PrependReactor("*", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		switch a.GetVerb() {
		case "get", "list", "watch":
			return false, nil, nil
		}
		name := ""
		if n, ok := a.(interface{ GetName() string }); ok {
			name = n.GetName()
		}
		if u, ok := a.(k8stesting.UpdateAction); ok {
			if m, ok := u.GetObject().(metav1.Object); ok {
				name = m.GetName()
			}
		}
		c.mu.Lock()
		c.writes = append(c.writes, a.GetVerb()+" "+a.GetResource().Resource+"/"+name)
		c.mu.Unlock()
		kind, named := objs[name]
		want := map[string]string{"configmaps": "configmap", "secrets": "secret"}[a.GetResource().Resource]
		if a.GetVerb() != "update" || !named || kind != want || a.GetNamespace() != coreNS {
			t.Errorf("forbidden write: %s %s/%s in %s", a.GetVerb(), a.GetResource().Resource, name, a.GetNamespace())
			return true, nil, errors.New("forbidden by the test")
		}
		return false, nil, nil
	})
	return c
}

func (c *pubCluster) Exec(_ context.Context, namespace, pod, container string, cmd []string, _ io.Reader, stdout, _ io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs = append(c.execs, append([]string{namespace, pod, container}, cmd...))
	if len(cmd) != 4 || cmd[0] != "/portcullis-bin/hub" || cmd[1] != "rev" {
		return exec.CodeExitError{Err: errors.New("bad"), Code: 2}
	}
	v := c.mounted[pod+" "+cmd[2]+" "+cmd[3]]
	if v == "" {
		return exec.CodeExitError{Err: errors.New("missing"), Code: 1}
	}
	fmt.Fprintln(stdout, v)
	return nil
}

func (c *pubCluster) sink(t *testing.T) publish.Sink {
	b, err := New(Config{Client: c.typed, Dynamic: newCluster(t).dyn, Namespace: ns, CoreNamespace: coreNS, Exec: c})
	if err != nil {
		t.Fatal(err)
	}
	return b.DocSink()
}

// TestDocSinkUpdatesNamedObjectOnly: each publish is one update of its
// named object (the data key and .rev together); nothing else is ever
// written; a document over MaxDoc leaves the object as it was.
func TestDocSinkUpdatesNamedObjectOnly(t *testing.T) {
	c := newPubCluster(t)
	s := c.sink(t)
	ctx := context.Background()
	for _, d := range publish.All {
		data := []byte(`{"doc":"` + string(d) + `"}` + "\n")
		rev, err := s.Publish(ctx, d, data)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if rev != publish.Rev(data) {
			t.Errorf("%s: rev %s", d, rev)
		}
		sp := publish.Spec(d)
		got := map[string]string{}
		if sp.Kind == publish.Secret {
			o, _ := c.typed.CoreV1().Secrets(coreNS).Get(ctx, sp.Object, metav1.GetOptions{})
			for k, v := range o.Data {
				got[k] = string(v)
			}
		} else {
			o, _ := c.typed.CoreV1().ConfigMaps(coreNS).Get(ctx, sp.Object, metav1.GetOptions{})
			got = o.Data
			if len(o.BinaryData) != 0 {
				t.Errorf("%s: binaryData %v", d, o.BinaryData)
			}
		}
		if len(got) != 2 || got[sp.Key] != string(data) || got[".rev"] != rev {
			t.Errorf("%s: object data %v", d, got)
		}
	}
	c.mu.Lock()
	n := len(c.writes)
	c.mu.Unlock()
	if n != len(publish.All) {
		t.Errorf("%d writes, want one per document: %v", n, c.writes)
	}
	// Too large: refused before any write; the object keeps the last
	// good document and its .rev.
	good := []byte(`{"doc":"group-gate-policy"}` + "\n")
	if _, err := s.Publish(ctx, publish.GroupGatePolicy, bytes.Repeat([]byte("x"), publish.MaxDoc+1)); !errors.Is(err, publish.ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	o, _ := c.typed.CoreV1().ConfigMaps(coreNS).Get(ctx, "pub-group-gate-policy", metav1.GetOptions{})
	if o.Data["group-gate-policy.json"] != string(good) || o.Data[".rev"] != publish.Rev(good) {
		t.Errorf("the last good document is gone: %v", o.Data)
	}
	// Remove drops the data key, keeps .rev (the empty document's).
	if err := s.(publish.Remover).Remove(ctx, publish.UserAttributes); err != nil {
		t.Fatal(err)
	}
	o, _ = c.typed.CoreV1().ConfigMaps(coreNS).Get(ctx, "pub-user-attributes", metav1.GetOptions{})
	if len(o.Data) != 1 || o.Data[".rev"] != publish.Rev(nil) {
		t.Errorf("removed: %v", o.Data)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.writes {
		if !strings.HasPrefix(w, "update ") {
			t.Errorf("write %s", w)
		}
	}
}

// TestDocSinkConfirmedReadsRev: Confirmed runs hub rev <mount> <doc> in
// every running reader pod (by component label, the container that
// mounts /portcullis-bin): old rev → false, naming the pods behind; new
// rev everywhere → true. Non-readers are never exec'd.
func TestDocSinkConfirmedReadsRev(t *testing.T) {
	c := newPubCluster(t)
	s := c.sink(t)
	ctx := context.Background()
	data := []byte(`{"version":1}` + "\n")
	rev, err := s.Publish(ctx, publish.Impersonation, data)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.mounted["group-gate-5f-a1 /hub-data impersonation"] = "0000000000000000"
	c.mounted["group-gate-5f-b2 /hub-data impersonation"] = rev
	c.mounted["keycloak-0 /hub-data impersonation"] = rev
	c.mu.Unlock()
	ok, err := s.Confirmed(ctx, publish.Impersonation, rev)
	if ok || err != nil {
		t.Fatalf("old rev confirmed: %v %v", ok, err)
	}
	behind, err := s.(publish.Laggards).Behind(ctx, publish.Impersonation, rev)
	if err != nil || strings.Join(behind, ",") != "group-gate-5f-a1" {
		t.Fatalf("behind %v %v", behind, err)
	}
	c.mu.Lock()
	c.mounted["group-gate-5f-a1 /hub-data impersonation"] = rev
	c.mu.Unlock()
	if ok, err := s.Confirmed(ctx, publish.Impersonation, rev); !ok || err != nil {
		t.Fatalf("new rev not confirmed: %v %v", ok, err)
	}
	// vpn.json: /vpn-doc, readers group-gate and wg.
	vrev, _ := s.Publish(ctx, publish.VPN, data)
	c.mu.Lock()
	c.mounted["wg-6c-d4 /vpn-doc vpn"] = vrev
	c.mu.Unlock()
	behind, _ = s.(publish.Laggards).Behind(ctx, publish.VPN, vrev)
	if strings.Join(behind, ",") != "group-gate-5f-a1,group-gate-5f-b2" {
		t.Errorf("vpn behind %v", behind)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.execs {
		if e[0] != coreNS || e[1] == "frontdoor-1" || e[1] == "mcp-gate-7d-c3" || e[2] == "sidecar" {
			t.Errorf("exec %v", e)
		}
		cmd := e[3:]
		if len(cmd) != 4 || cmd[0] != "/portcullis-bin/hub" || cmd[1] != "rev" || !slices.Contains([]string{"/hub-data", "/vpn-doc"}, cmd[2]) {
			t.Errorf("command %v", cmd)
		}
	}
}

// TestDocSinkFenced: standing by, a publish never reaches the API
// server with a write (the backend's client is gated, contract §20.5);
// open again, it is one PUT of the named object.
func TestDocSinkFenced(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"pub-vpn","namespace":"portcullis","resourceVersion":"1"}}`))
	}))
	defer srv.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL, WrapTransport: GateWrites})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Client: cs, Dynamic: newCluster(t).dyn, Namespace: ns, CoreNamespace: coreNS})
	if err != nil {
		t.Fatal(err)
	}
	closeGate(t)
	if _, err := b.DocSink().Publish(context.Background(), publish.VPN, []byte("{}\n")); !errors.Is(err, errStandingBy) {
		t.Fatalf("standing by: %v", err)
	}
	mu.Lock()
	for _, s := range seen {
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("a write reached the server: %s", s)
		}
	}
	seen = nil
	mu.Unlock()
	fsutil.SetWriteGate(nil)
	if _, err := b.DocSink().Publish(context.Background(), publish.VPN, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != "GET /api/v1/namespaces/portcullis/configmaps/pub-vpn,PUT /api/v1/namespaces/portcullis/configmaps/pub-vpn" {
		t.Errorf("requests %v", seen)
	}
}
