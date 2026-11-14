package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/exec"

	"github.com/portcullis/hub/internal/runtime"
)

const ns = "portcullis-apps"

// cluster is a fake cluster: a typed clientset and a dynamic client
// sharing nothing but this test's view, the apply calls recorded.
type cluster struct {
	t       *testing.T
	typed   *fake.Clientset
	dyn     *dynfake.FakeDynamicClient
	mu      sync.Mutex
	applied []string // "<Kind>/<name>" in order
	deleted []string
	clock   time.Time
	execFn  func(pod, container string, cmd []string, stdout io.Writer) error
}

func newCluster(t *testing.T, objs ...k8sruntime.Object) *cluster {
	c := &cluster{t: t, typed: fake.NewSimpleClientset(), clock: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}
	scheme := k8sruntime.NewScheme()
	lists := map[schema.GroupVersionResource]string{}
	for k, r := range kinds {
		lists[r] = k + "List"
	}
	c.dyn = dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, lists, objs...)
	// Server-side apply: record it and mirror Deployments and Jobs into
	// the typed clientset (the backend reads their status there).
	c.dyn.PrependReactor("patch", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		p := a.(k8stesting.PatchAction)
		var u unstructured.Unstructured
		if err := json.Unmarshal(p.GetPatch(), &u.Object); err != nil {
			return true, nil, err
		}
		c.mu.Lock()
		c.applied = append(c.applied, u.GetKind()+"/"+u.GetName())
		c.mu.Unlock()
		tr := c.dyn.Tracker()
		gvr := p.GetResource()
		pns := p.GetNamespace()
		if _, err := tr.Get(gvr, pns, u.GetName()); err == nil {
			tr.Update(gvr, &u, pns)
		} else {
			tr.Create(gvr, &u, pns)
		}
		c.mirror(&u)
		return true, &u, nil
	})
	c.dyn.PrependReactor("delete", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		d := a.(k8stesting.DeleteAction)
		c.mu.Lock()
		c.deleted = append(c.deleted, d.GetResource().Resource+"/"+d.GetName())
		c.mu.Unlock()
		return false, nil, nil
	})
	return c
}

// mirror puts Deployments and Jobs into the typed clientset.
func (c *cluster) mirror(u *unstructured.Unstructured) {
	ctx := context.Background()
	switch u.GetKind() {
	case "Deployment":
		var d appsv1.Deployment
		k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &d)
		if _, err := c.typed.AppsV1().Deployments(ns).Get(ctx, d.Name, metav1.GetOptions{}); err == nil {
			c.typed.AppsV1().Deployments(ns).Update(ctx, &d, metav1.UpdateOptions{})
		} else {
			c.typed.AppsV1().Deployments(ns).Create(ctx, &d, metav1.CreateOptions{})
		}
	case "Job":
		var j batchv1.Job
		k8sruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &j)
		c.typed.BatchV1().Jobs(ns).Delete(ctx, j.Name, metav1.DeleteOptions{})
		c.typed.BatchV1().Jobs(ns).Create(ctx, &j, metav1.CreateOptions{})
	}
}

func (c *cluster) Applied() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.applied)
}

func (c *cluster) Exec(ctx context.Context, namespace, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if c.execFn == nil {
		return nil
	}
	return c.execFn(pod, container, cmd, stdout)
}

type fakeResolver struct {
	mu    sync.Mutex
	calls []string
}

func (r *fakeResolver) Resolve(_ context.Context, ref string) (string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, ref)
	r.mu.Unlock()
	name, _, _ := strings.Cut(ref, "@")
	return name + "@sha256:" + strings.Repeat("cd", 32), nil
}

func (c *cluster) backend(t *testing.T) *Backend {
	b, err := New(Config{Client: c.typed, Dynamic: c.dyn, Namespace: ns, HubImage: hubImage, Resolver: &fakeResolver{}, Exec: c,
		Clock: func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.clock },
		Sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.mu.Lock()
			c.clock = c.clock.Add(d)
			c.mu.Unlock()
			return nil
		},
		BindRoots: []string{"/srv"}, Settings: Settings{PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16", WGEdgeServiceIP: "10.43.0.22", NodeAddresses: []string{"192.0.2.10"}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func project(t *testing.T, compose, instance string) runtime.Project {
	return runtime.Project{Name: runtime.ProjectName(instance), Instance: instance, Model: modelOf(t, compose, instance), Inputs: &runtime.ProjectInputs{Template: "x"}}
}

const orderedCompose = `services:
  migrate:
    image: docker.io/library/alpine:3.24.3
    restart: "no"
  db:
    image: docker.io/library/postgres:17.6
    user: "70:70"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready"]
  app:
    image: docker.io/library/nginx:1.29
    depends_on:
      db:
        condition: service_healthy
      migrate:
        condition: service_completed_successfully
`

// TestUpAppliesStepsInOrder: the db is ready and the Job completes before
// the app (their dependent) is applied.
func TestUpAppliesStepsInOrder(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	ctx := context.Background()
	// The "kubelet": a Deployment is ready on the second look, a Job
	// succeeds on the second look.
	looks := map[string]int{}
	c.typed.PrependReactor("get", "deployments", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		name := a.(k8stesting.GetAction).GetName()
		o, err := c.typed.Tracker().Get(a.GetResource(), ns, name)
		if err != nil {
			return true, nil, err
		}
		d := o.(*appsv1.Deployment).DeepCopy()
		if looks["d/"+name]++; looks["d/"+name] > 1 {
			d.Status.ReadyReplicas = 1
		}
		return true, d, nil
	})
	c.typed.PrependReactor("get", "jobs", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		name := a.(k8stesting.GetAction).GetName()
		o, err := c.typed.Tracker().Get(a.GetResource(), ns, name)
		if err != nil {
			return true, nil, err
		}
		j := o.(*batchv1.Job).DeepCopy()
		if looks["j/"+name]++; looks["j/"+name] > 1 {
			j.Status.Succeeded = 1
		}
		return true, j, nil
	})
	if err := b.Up(ctx, project(t, orderedCompose, "app1"), nil); err != nil {
		t.Fatal(err)
	}
	got := c.Applied()
	idx := func(s string) int { return slices.Index(got, s) }
	if idx("Deployment/app1--db") < 0 || idx("Job/app1--migrate") < 0 || idx("Deployment/app1--app") < 0 {
		t.Fatalf("applied %v", got)
	}
	if !(idx("Deployment/app1--db") < idx("Deployment/app1--app") && idx("Job/app1--migrate") < idx("Deployment/app1--app")) {
		t.Errorf("order %v", got)
	}
	if looks["d/app1--db"] < 2 || looks["j/app1--migrate"] < 2 {
		t.Errorf("the dependencies weren't waited for: %v", looks)
	}
}

// TestApplyNeverTouchesForeignObjects: an existing object without the
// instance's label is never applied over (force or not).
func TestApplyNeverTouchesForeignObjects(t *testing.T) {
	foreign := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "app2--env", "namespace": ns, "labels": map[string]any{"owner": "someone"}}}}
	c := newCluster(t, foreign)
	b := c.backend(t)
	err := b.Up(context.Background(), project(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n", "app2"), nil)
	if err == nil || !strings.Contains(err.Error(), "isn't instance app2's") {
		t.Fatalf("err = %v", err)
	}
	if slices.Contains(c.Applied(), "Secret/app2--env") {
		t.Error("the foreign Secret was applied over")
	}
	// An object of another instance is refused too.
	other := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "app3--env", "namespace": ns, "labels": map[string]any{LabelInstance: "app3x"}}}}
	c2 := newCluster(t, other)
	if err := c2.backend(t).Up(context.Background(), project(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n", "app3"), nil); err == nil {
		t.Error("another instance's object was applied over")
	}
}

// TestDownKeepsPVCs: Down deletes the instance's Deployments, Services,
// routes, policies, ConfigMaps and Secrets, never a PVC, never another
// instance's object.
func TestDownKeepsPVCs(t *testing.T) {
	obj := func(apiVersion, kind, name, inst string) *unstructured.Unstructured {
		o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{LabelInstance: inst}}}}
		if edgeKinds[kind] {
			o.SetNamespace(EdgeNamespace)
			o.SetLabels(map[string]string{LabelInstance: inst, LabelOwner: OwnerHub})
		}
		return o
	}
	coreRoute := obj("traefik.io/v1alpha1", "IngressRoute", "a--core", "a")
	coreRoute.SetLabels(map[string]string{LabelInstance: "a", LabelOwner: "core"})
	c := newCluster(t, coreRoute,
		obj("apps/v1", "Deployment", "a--web", "a"), obj("v1", "Service", "a--web-80-tcp", "a"), obj("traefik.io/v1alpha1", "IngressRoute", "a--r-web", "a"),
		obj("traefik.io/v1alpha1", "Middleware", "a--m-x", "a"), obj("networking.k8s.io/v1", "NetworkPolicy", "a--net-default", "a"),
		obj("v1", "ConfigMap", "a--people", "a"), obj("v1", "Secret", "a--env", "a"), obj("v1", "PersistentVolumeClaim", "a--data", "a"),
		obj("apps/v1", "Deployment", "b--web", "b"), obj("batch/v1", "Job", "a--migrate", "a"))
	if err := c.backend(t).DownByName(context.Background(), "portcullis-a"); err != nil {
		t.Fatal(err)
	}
	slices.Sort(c.deleted)
	want := []string{"configmaps/a--people", "deployments/a--web", "ingressroutes/a--r-web", "jobs/a--migrate", "middlewares/a--m-x", "networkpolicies/a--net-default", "secrets/a--env", "services/a--web-80-tcp"}
	if !slices.Equal(c.deleted, want) {
		t.Errorf("deleted %v\nwant    %v", c.deleted, want)
	}
	if _, err := c.dyn.Resource(kinds["PersistentVolumeClaim"]).Namespace(ns).Get(context.Background(), "a--data", metav1.GetOptions{}); err != nil {
		t.Errorf("the PVC is gone: %v", err)
	}
}

// TestDigestCachedOnlyAfterDeploy: a resolve followed by a failed Up
// pins nothing; a successful one pins the digest.
func TestDigestCachedOnlyAfterDeploy(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	c.typed.PrependReactor("get", "deployments", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("api server down")
	})
	p := project(t, "services:\n  db:\n    image: docker.io/library/postgres:17.6\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n  web:\n    image: docker.io/library/nginx:1.29\n    depends_on:\n      db:\n        condition: service_healthy\n", "d1")
	if err := b.Up(context.Background(), p, nil); err == nil {
		t.Fatal("Up succeeded")
	}
	if got := b.CachedDigests("d1"); len(got) != 0 {
		t.Errorf("a failed Up pinned %v", got)
	}
	c2 := newCluster(t)
	b2 := c2.backend(t)
	if err := b2.Up(context.Background(), project(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n", "d2"), nil); err != nil {
		t.Fatal(err)
	}
	if got := b2.CachedDigests("d2")["docker.io/library/nginx:1.29"]; !strings.HasSuffix(got, "@sha256:"+strings.Repeat("cd", 32)) {
		t.Errorf("pinned %q", got)
	}
}

func runningPod(name, inst, svc string, containers ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{LabelInstance: inst, LabelService: svc}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c, Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	}
	return p
}

func deployment(name, inst string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{LabelInstance: inst}}}
}

// TestSignalFallsBackToRestart: kill runs by exec; with no kill in the
// image the pod's Deployment gets the pod-template annotation (never a
// pod patch) and ErrReloadDegraded comes back.
func TestSignalFallsBackToRestart(t *testing.T) {
	c := newCluster(t)
	ctx := context.Background()
	c.typed.CoreV1().Pods(ns).Create(ctx, runningPod("s1--web-abc", "s1", "web", "web"), metav1.CreateOptions{})
	c.typed.AppsV1().Deployments(ns).Create(ctx, deployment("s1--web", "s1"), metav1.CreateOptions{})
	b := c.backend(t)
	var cmds [][]string
	c.execFn = func(pod, container string, cmd []string, stdout io.Writer) error {
		cmds = append(cmds, cmd)
		return nil
	}
	if err := b.Signal(ctx, "s1--web-abc/web", "SIGHUP"); err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 || strings.Join(cmds[0], " ") != "kill -s HUP 1" {
		t.Errorf("exec %v", cmds)
	}
	c.execFn = func(pod, container string, cmd []string, stdout io.Writer) error {
		return errors.New(`OCI runtime exec failed: exec: "kill": executable file not found in $PATH`)
	}
	if err := b.Signal(ctx, "s1--web-abc/web", "HUP"); !errors.Is(err, ErrReloadDegraded) {
		t.Fatalf("err = %v", err)
	}
	d, _ := c.typed.AppsV1().Deployments(ns).Get(ctx, "s1--web", metav1.GetOptions{})
	if d.Spec.Template.Annotations[AnnotationRev] == "" {
		t.Error("the Deployment's pod template wasn't annotated")
	}
	for _, a := range c.typed.Actions() {
		if a.GetResource().Resource == "pods" && (a.GetVerb() == "patch" || a.GetVerb() == "update") {
			t.Errorf("a pod was %sed", a.GetVerb())
		}
	}
}

// TestPersonSecretTooLargeRefuses: a *-pw Secret over 1 MiB refuses the
// instance and nothing is applied.
func TestPersonSecretTooLargeRefuses(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	p := project(t, "services:\n  samba:\n    image: ghcr.io/porelli/portcullis-samba:4.22\n    user: \"10001:10001\"\n    volumes:\n      - type: volume\n        source: portcullis-hub-secrets\n        target: /h\n        read_only: true\n        volume:\n          subpath: big/smb\nvolumes:\n  portcullis-hub-secrets:\n    external: true\n", "big")
	p.Inputs.PersonSecrets = map[string]map[string][]byte{"smb": {"alice.nt": make([]byte, 1<<20+1)}}
	err := b.Up(context.Background(), p, nil)
	var r *ErrRefused
	if !errors.As(err, &r) || !strings.Contains(r.Reason, "big--smb-pw exceeds 1 MiB") {
		t.Fatalf("err = %v", err)
	}
	if got := c.Applied(); len(got) != 0 {
		t.Errorf("applied %v", got)
	}
}

// revExec answers `hub rev <mount>` with the mounted .rev from mounted
// (a func of the poll count).
func (c *cluster) revExec(mounted func(n int) string) *int {
	n := 0
	c.execFn = func(pod, container string, cmd []string, stdout io.Writer) error {
		if len(cmd) == 3 && cmd[0] == "/portcullis-bin/hub" && cmd[1] == "rev" {
			n++
			v := mounted(n)
			if v == "" {
				return exec.CodeExitError{Err: errors.New("no .rev"), Code: 1}
			}
			fmt.Fprintln(stdout, v)
		}
		return nil
	}
	return &n
}

func deliverySetup(t *testing.T) (*cluster, *Backend, DeliveryObject) {
	c := newCluster(t)
	ctx := context.Background()
	c.typed.CoreV1().Pods(ns).Create(ctx, runningPod("dl--app-1", "dl", "app", "app"), metav1.CreateOptions{})
	c.typed.AppsV1().Deployments(ns).Create(ctx, deployment("dl--app", "dl"), metav1.CreateOptions{})
	c.typed.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dl--people", Namespace: ns, Labels: map[string]string{LabelInstance: "dl"}}}, metav1.CreateOptions{})
	return c, c.backend(t), DeliveryObject{Kind: "ConfigMap", Name: "dl--people", Data: map[string][]byte{"people.json": []byte("{}")}, Service: "app", Mount: "/portcullis/people"}
}

// TestDeliverWaitsForRev: a stale mounted .rev for 3 polls is not
// enough; Deliver returns only once it matches, and the object carries
// .rev.
func TestDeliverWaitsForRev(t *testing.T) {
	c, b, obj := deliverySetup(t)
	n := c.revExec(func(n int) string {
		if n <= 3 {
			return "r1"
		}
		return "r2"
	})
	if err := b.Deliver(context.Background(), "dl", obj, "r2"); err != nil {
		t.Fatal(err)
	}
	if *n != 4 {
		t.Errorf("polls = %d", *n)
	}
	cm, _ := c.typed.CoreV1().ConfigMaps(ns).Get(context.Background(), "dl--people", metav1.GetOptions{})
	if string(cm.BinaryData[".rev"]) != "r2" || string(cm.BinaryData["people.json"]) != "{}" {
		t.Errorf("configmap %v", cm.BinaryData)
	}
	// Not the instance's own object: refused, nothing written.
	if err := b.Deliver(context.Background(), "other", obj, "r3"); err == nil {
		t.Error("another instance's delivery wrote the object")
	}
}

// TestDeliverTimeoutLeavesRevUnrecorded: no match within the wait, the
// restarted pod doesn't mount it either → an error (the caller records
// nothing); the restart went through the Deployment's pod template.
func TestDeliverTimeoutLeavesRevUnrecorded(t *testing.T) {
	c, b, obj := deliverySetup(t)
	n := c.revExec(func(int) string { return "r1" })
	start := c.clock
	err := b.Deliver(context.Background(), "dl", obj, "r2")
	if !errors.Is(err, ErrRevNotMounted) {
		t.Fatalf("err = %v", err)
	}
	if waited := c.clock.Sub(start); waited < 90*time.Second {
		t.Errorf("waited %s before the restart", waited)
	}
	if *n < 90/0.25 {
		t.Errorf("polls = %d", *n)
	}
	d, _ := c.typed.AppsV1().Deployments(ns).Get(context.Background(), "dl--app", metav1.GetOptions{})
	if d.Spec.Template.Annotations[AnnotationRev] != "r2" {
		t.Error("no pod-template restart")
	}
	// The restarted pod mounts it: done.
	c2, b2, obj2 := deliverySetup(t)
	c2.revExec(func(n int) string {
		if n > 400 {
			return "r2"
		}
		return "r1"
	})
	if err := b2.Deliver(context.Background(), "dl", obj2, "r2"); err != nil {
		t.Errorf("after the restart: %v", err)
	}
}

// The backend answers the guard's refusal on every operation but Kind,
// Env and Info.
func TestBackendGated(t *testing.T) {
	c := newCluster(t)
	b := c.backend(t)
	b.cfg.Guard = gateErr{&UnverifiedError{Why: "admission self-test: guard missing"}}
	ctx := context.Background()
	for name, err := range map[string]error{
		"up":   b.Up(ctx, project(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n", "g"), nil),
		"down": b.DownByName(ctx, "portcullis-g"),
		"sig":  b.Signal(ctx, "p/c", "HUP"),
	} {
		if !errors.Is(err, ErrClusterUnverified) || !strings.Contains(err.Error(), "the cluster is not verified: admission self-test") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := b.List(ctx, runtime.Filter{}); !errors.Is(err, ErrClusterUnverified) {
		t.Errorf("list: %v", err)
	}
	if i, err := b.Info(ctx); err != nil || i.Verified || i.Kind != runtime.KindKubernetes {
		t.Errorf("info = %+v, %v", i, err)
	}
	if len(c.Applied()) != 0 {
		t.Error("applied while unverified")
	}
}

type gateErr struct{ err error }

func (g gateErr) Err() error { return g.err }

// List maps pods to units: <pod>/<container>, the compose labels from
// the annotation, the state words.
func TestListUnits(t *testing.T) {
	c := newCluster(t)
	ctx := context.Background()
	p := runningPod("l--web-1", "l", "web", "web", "side")
	p.Annotations = map[string]string{AnnotationServices: `{"web":"web","side":"side"}`, AnnotationComposeLabels: `{"web":{"traefik.http.routers.w.rule":"Host(` + "`w.example.org`" + `)"}}`}
	p.Spec.Containers[0].ReadinessProbe = &corev1.Probe{}
	c.typed.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{})
	us, err := c.backend(t).List(ctx, runtime.Filter{Instance: "l"})
	if err != nil || len(us) != 2 {
		t.Fatalf("units %v %v", us, err)
	}
	if us[0].ID != "l--web-1/web" || us[0].Service != "web" || us[0].State != "running" || us[0].Project != "portcullis-l" || us[0].Labels["traefik.http.routers.w.rule"] == "" || us[0].Labels["com.docker.compose.service"] != "web" {
		t.Errorf("unit 0 %+v", us[0])
	}
	if us[1].Service != "side" || us[1].Status != "Up" {
		t.Errorf("unit 1 %+v", us[1])
	}
	if _, err := c.backend(t).State(ctx, "nopod"); err == nil {
		t.Error("a bad unit id was read")
	}
	if _, err := c.backend(t).State(ctx, "l--gone-1/web"); !apierrors.IsNotFound(err) {
		t.Errorf("missing pod: %v", err)
	}
}

// Routes land in the edge namespace, labelled owner hub + instance, with
// Service refs into the apps namespace; Down deletes them there and never
// an owner core object.
func TestRoutesInEdgeNamespace(t *testing.T) {
	core := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "traefik.io/v1alpha1", "kind": "IngressRoute",
		"metadata": map[string]any{"name": "rt--r-app", "namespace": EdgeNamespace, "labels": map[string]any{LabelInstance: "rt", LabelOwner: "core"}}}}
	c := newCluster(t)
	b := c.backend(t)
	ctx := context.Background()
	compose := "services:\n  web:\n    image: docker.io/library/nginx:1.29\n    labels:\n      traefik.http.routers.app.rule: Host(`a.example.org`)\n      traefik.http.routers.app.middlewares: own-mw,security-headers@file\n      traefik.http.middlewares.own-mw.headers.customrequestheaders.X-Forwarded-User: \"\"\n      traefik.http.services.app.loadbalancer.server.port: \"80\"\n"
	if err := b.Up(ctx, project(t, compose, "rt"), nil); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"IngressRoute", "Middleware"} {
		l, err := c.dyn.Resource(kinds[k]).Namespace(EdgeNamespace).List(ctx, metav1.ListOptions{})
		if err != nil || len(l.Items) != 1 {
			t.Fatalf("%s in edge: %v %v", k, l, err)
		}
		o := l.Items[0]
		if o.GetLabels()[LabelOwner] != OwnerHub || o.GetLabels()[LabelInstance] != "rt" {
			t.Errorf("%s labels %v", k, o.GetLabels())
		}
		if k == "IngressRoute" {
			r := o.Object["spec"].(map[string]any)["routes"].([]any)[0].(map[string]any)
			if s := r["services"].([]any)[0].(map[string]any); s["namespace"] != ns {
				t.Errorf("service ref %v", s)
			}
			if m := r["middlewares"].([]any)[0].(map[string]any); m["namespace"] != EdgeNamespace {
				t.Errorf("middleware ref %v", m)
			}
		}
		if l, _ := c.dyn.Resource(kinds[k]).Namespace(ns).List(ctx, metav1.ListOptions{}); len(l.Items) != 0 {
			t.Errorf("%s in the apps namespace", k)
		}
	}
	c.dyn.Tracker().Create(kinds["IngressRoute"], core, EdgeNamespace)
	if err := b.DownByName(ctx, "portcullis-rt"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.deleted, "ingressroutes/rt--r-app") || !slices.Contains(c.deleted, "middlewares/rt--m-own-mw") {
		t.Errorf("deleted %v", c.deleted)
	}
	if _, err := c.dyn.Resource(kinds["IngressRoute"]).Namespace(EdgeNamespace).Get(ctx, "rt--r-app", metav1.GetOptions{}); err == nil {
		// the Hub's own is gone; a core one of that name would stay —
		// covered by TestDownKeepsPVCs' a--core
	}
}
