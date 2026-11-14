//go:build envtest

package kube

// Envtest (KUBEBUILDER_ASSETS from `setup-envtest use 1.32.x`): a real
// API server with the admission policies, the Hub's Role and its
// ServiceAccount, everything run as that ServiceAccount through
// impersonation. Envtest has no kubelet: no pod ever runs.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/portcullis/hub/internal/runtime"
)

const hubSA = "system:serviceaccount:portcullis:portcullis-hub"

// traefikCRDs: minimal IngressRoute and Middleware CRDs (schemaless: the
// policies read the fields).
const traefikCRDs = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ingressroutes.traefik.io
spec:
  group: traefik.io
  names: {kind: IngressRoute, listKind: IngressRouteList, plural: ingressroutes, singular: ingressroute}
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: middlewares.traefik.io
spec:
  group: traefik.io
  names: {kind: Middleware, listKind: MiddlewareList, plural: middlewares, singular: middleware}
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}
`

const setupObjects = `apiVersion: v1
kind: Namespace
metadata:
  name: portcullis
  labels: {pod-security.kubernetes.io/enforce: restricted}
---
apiVersion: v1
kind: Namespace
metadata:
  name: portcullis-apps
  labels: {pod-security.kubernetes.io/enforce: privileged, pod-security.kubernetes.io/warn: baseline, pod-security.kubernetes.io/audit: baseline}
---
apiVersion: v1
kind: Namespace
metadata:
  name: portcullis-edge
  labels: {pod-security.kubernetes.io/enforce: restricted}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: portcullis-hub, namespace: portcullis-edge}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: portcullis-hub}
subjects: [{kind: ServiceAccount, name: portcullis-hub, namespace: portcullis}, {kind: ServiceAccount, name: intruder, namespace: portcullis}]
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: intruder, namespace: portcullis}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: portcullis-hub, namespace: portcullis}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: portcullis-hub, namespace: portcullis-apps}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: portcullis-hub}
subjects: [{kind: ServiceAccount, name: portcullis-hub, namespace: portcullis}]
`

// testGeneration is params.yaml's generation (core names the params
// ConfigMap and every binding after it).
const testGeneration = "0123456789abcdef"

var (
	paramsRef   = regexp.MustCompile(`(?m)^(\s+name: portcullis-admission-params)$`)
	bindingName = regexp.MustCompile(`(?m)^(  name: portcullis-(?:apps|edge)-guard-[a-z-]+)$`)
)

type env struct {
	cfg      *rest.Config
	admin    dynamic.Interface
	hub      dynamic.Interface
	hubK     kubernetes.Interface
	intruder dynamic.Interface
}

var shared *env

func gvrOf(o *unstructured.Unstructured) schema.GroupVersionResource {
	gv, _ := schema.ParseGroupVersion(o.GetAPIVersion())
	res := strings.ToLower(o.GetKind()) + "s"
	switch o.GetKind() {
	case "NetworkPolicy":
		res = "networkpolicies"
	case "ValidatingAdmissionPolicy":
		res = "validatingadmissionpolicies"
	case "ValidatingAdmissionPolicyBinding":
		res = "validatingadmissionpolicybindings"
	case "CustomResourceDefinition":
		res = "customresourcedefinitions"
	}
	return gv.WithResource(res)
}

func applyYAML(t *testing.T, d dynamic.Interface, docs []byte) {
	t.Helper()
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(docs), 4096)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		if len(m) == 0 {
			continue
		}
		o := &unstructured.Unstructured{Object: m}
		var err error
		if o.GetNamespace() != "" {
			_, err = d.Resource(gvrOf(o)).Namespace(o.GetNamespace()).Create(context.Background(), o, metav1.CreateOptions{})
		} else {
			_, err = d.Resource(gvrOf(o)).Create(context.Background(), o, metav1.CreateOptions{})
		}
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("creating %s %s: %v", o.GetKind(), o.GetName(), err)
		}
	}
}

func file(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func startEnv(t *testing.T) *env {
	if shared != nil {
		return shared
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	admin := dynamic.NewForConfigOrDie(cfg)
	applyYAML(t, admin, []byte(traefikCRDs))
	applyYAML(t, admin, []byte(setupObjects))
	applyYAML(t, admin, file(t, "testdata/role.yaml"))
	applyYAML(t, admin, file(t, "testdata/role-edge.yaml"))
	// The params as the CLI writes them, with this API server's admin as
	// the CLI's identity (cliUsername).
	whoami, err := kubernetes.NewForConfigOrDie(cfg).AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// As core's kube_admission_params_apply does (5ec559f): the params
	// ConfigMap portcullis-admission-params-<generation>, every binding
	// <name>-<generation> on it.
	params := strings.Replace(string(file(t, "testdata/admission/params.yaml")), "cliUsername: system:admin", "cliUsername: "+whoami.Status.UserInfo.Username, 1)
	applyYAML(t, admin, []byte(paramsRef.ReplaceAllString(params, "${1}-"+testGeneration)))
	applyYAML(t, admin, file(t, "testdata/admission/policies.yaml"))
	bindings := bindingName.ReplaceAllString(string(file(t, "testdata/admission/bindings.yaml")), "${1}-"+testGeneration)
	applyYAML(t, admin, []byte(paramsRef.ReplaceAllString(bindings, "${1}-"+testGeneration)))
	hc := rest.CopyConfig(cfg)
	hc.Impersonate = rest.ImpersonationConfig{UserName: hubSA, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:portcullis", "system:authenticated"}}
	ic := rest.CopyConfig(cfg)
	ic.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:portcullis:intruder", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:portcullis", "system:authenticated"}}
	e := &env{cfg: cfg, admin: admin, hub: dynamic.NewForConfigOrDie(hc), hubK: kubernetes.NewForConfigOrDie(hc), intruder: dynamic.NewForConfigOrDie(ic)}
	// The policies take effect asynchronously: wait for the self-test's
	// Pod to be denied by its binding.
	deadline := time.Now().Add(60 * time.Second)
	pod := SelfTestObjects(ns, EdgeNamespace)["portcullis-apps-guard-pods"]
	for {
		_, err := e.hub.Resource(podsGVR).Namespace(ns).Create(context.Background(), pod, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if SelfTestRejected(err, "portcullis-apps-guard-pods") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the policies never took effect: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The policies type-check clean.
	for _, p := range []string{"portcullis-apps-pods", "portcullis-apps-workloads", "portcullis-apps-services", "portcullis-apps-traefik", "portcullis-apps-netpol", "portcullis-edge-routes"} {
		o, err := admin.Resource(schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}).Get(context.Background(), p, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if w, ok, _ := unstructured.NestedSlice(o.Object, "status", "typeChecking", "expressionWarnings"); ok && len(w) > 0 {
			t.Errorf("policy %s type-check warnings: %v", p, w)
		}
	}
	shared = e
	t.Cleanup(func() {}) // envtest stops with the process
	return e
}

type vector struct {
	Name           string         `json:"name"`
	Object         map[string]any `json:"object"`
	As             string         `json:"as"` // hub | intruder
	Want           string         `json:"want"`
	ReasonContains string         `json:"reason_contains"`
	// Existing (optional) is created as the CLI first; Op update dry-runs
	// Object as an update of it, delete its deletion.
	Existing map[string]any `json:"existing,omitempty"`
	Op       string         `json:"op,omitempty"`
}

// TestAdmissionVectors: every vector dry-run as the Hub's ServiceAccount;
// a denial must come from a Portcullis binding and carry the reason.
func TestAdmissionVectors(t *testing.T) {
	e := startEnv(t)
	var vs []vector
	if err := json.Unmarshal(file(t, "testdata/admission_vectors.json"), &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 40 {
		t.Fatalf("%d vectors", len(vs))
	}
	ctx := context.Background()
	dry := []string{metav1.DryRunAll}
	for _, v := range vs {
		o := &unstructured.Unstructured{Object: v.Object}
		client := e.hub
		if v.As == "intruder" {
			client = e.intruder
		}
		res := client.Resource(gvrOf(o)).Namespace(o.GetNamespace())
		var err error
		if v.Existing != nil {
			ex := &unstructured.Unstructured{Object: v.Existing}
			cur, cerr := e.admin.Resource(gvrOf(ex)).Namespace(ex.GetNamespace()).Create(ctx, ex, metav1.CreateOptions{})
			if cerr != nil {
				t.Fatalf("%s: creating the existing object: %v", v.Name, cerr)
			}
			if v.Op == "delete" {
				err = res.Delete(ctx, ex.GetName(), metav1.DeleteOptions{DryRun: dry})
			} else {
				o.SetResourceVersion(cur.GetResourceVersion())
				_, err = res.Update(ctx, o, metav1.UpdateOptions{DryRun: dry})
			}
			e.admin.Resource(gvrOf(ex)).Namespace(ex.GetNamespace()).Delete(ctx, ex.GetName(), metav1.DeleteOptions{})
		} else {
			_, err = res.Create(ctx, o, metav1.CreateOptions{DryRun: dry})
		}
		switch v.Want {
		case "allow":
			if err != nil {
				t.Errorf("%s: denied: %v", v.Name, err)
			}
		case "deny":
			var st apierrors.APIStatus
			if !errors.As(err, &st) || !strings.Contains(st.Status().Message, "with binding 'portcullis-") || !strings.Contains(st.Status().Message, v.ReasonContains) {
				t.Errorf("%s: want a denial with %q, got %v", v.Name, v.ReasonContains, err)
			}
		}
	}
}

// knownRefused are translations the policies refuse on purpose (core's
// rulings), so a change on either side shows here. None today: a root
// service is refused by the translator itself.
var knownRefused = map[string]string{}

// TestTranslatedObjectsAdmitted: what the translator renders for the
// golden cases passes the policies (the Hub never fights its guard).
func TestTranslatedObjectsAdmitted(t *testing.T) {
	e := startEnv(t)
	for _, c := range []string{"basic", "jobs", "sidecar", "ports", "vpn-gateway", "person-secret", "datafile"} {
		in := baseInput(t, "testdata/translate/"+c, c)
		in.HubImage = "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("1", 64)
		in.Namespace = ns
		// The params' cluster (params.yaml).
		in.Settings.PodCIDR, in.Settings.ServiceCIDR = "10.42.0.0/24", "10.43.0.0/16"
		in.Settings.NodeAddresses, in.Settings.APIAddresses = []string{"10.1.0.4"}, []string{"10.1.0.4"}
		p, err := Translate(in)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		for _, o := range p.Objects() {
			_, err := e.hub.Resource(gvrOf(o)).Namespace(o.GetNamespace()).Create(context.Background(), o, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			want := knownRefused[c+"/"+o.GetKind()+"/"+o.GetName()]
			switch {
			case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
				t.Errorf("%s: %s %s: want the known refusal %q, got %v", c, o.GetKind(), o.GetName(), want, err)
			case want == "" && err != nil:
				t.Errorf("%s: %s %s denied: %v", c, o.GetKind(), o.GetName(), err)
			}
		}
	}
}

// TestSelfTestRequiresPolicyRejection: with the policies the self-test
// passes; without a binding it reports the guard missing (an accepted
// object), and a deny-all webhook's rejection doesn't count either.
func TestSelfTestRequiresPolicyRejection(t *testing.T) {
	e := startEnv(t)
	g := NewGuard(GuardConfig{Client: e.hubK, Dynamic: e.hub, AppsNamespace: ns})
	if err := g.selfTest(context.Background()); err != nil {
		t.Fatalf("with the policies: %v", err)
	}
	bind := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}
	saved, err := e.admin.Resource(bind).Get(context.Background(), "portcullis-apps-guard-services-"+testGeneration, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Resource(bind).Delete(context.Background(), "portcullis-apps-guard-services-"+testGeneration, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		saved.SetResourceVersion("")
		e.admin.Resource(bind).Create(context.Background(), saved, metav1.CreateOptions{})
		time.Sleep(2 * time.Second)
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := g.selfTest(context.Background())
		if err != nil && strings.Contains(err.Error(), "portcullis-apps-guard-services") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("without the services binding: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRoleIsEnough: with exactly role.yaml the Hub creates an instance,
// a helper pod and deletes them; exec and logs pass authorization (no
// kubelet: any error but Forbidden). And it can't do more: no get on
// pods/exec, nothing in the core namespace, no patch on pods.
func TestRoleIsEnough(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	b, err := New(Config{Client: e.hubK, Dynamic: e.hub, Namespace: ns, HubImage: "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("1", 64),
		Resolver: &fakeResolver{}, Exec: RemoteExec{Client: e.hubK, Config: rest.CopyConfig(e.cfg)}, BindRoots: []string{"/srv"},
		Settings: Settings{PodCIDR: "10.42.0.0/24", ServiceCIDR: "10.43.0.0/16", NodeAddresses: []string{"10.1.0.4"}, APIAddresses: []string{"10.1.0.4"}}})
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput(t, "testdata/translate/basic", "basic")
	p := runtime.Project{Name: "portcullis-basic", Instance: "basic", Model: in.Model, Inputs: &runtime.ProjectInputs{Template: "echo", TemplateFiles: in.TemplateFiles}}
	if err := b.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := b.List(ctx, runtime.Filter{Instance: "basic"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	pod := b.helperPod(HelperVolume, "basic", "basic--echo-data", true, nil)
	if _, err := e.hubK.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("helper pod: %v", err)
	}
	// exec and logs: authorized (the pod never runs: any error but 403).
	if _, err := b.Logs(ctx, pod.Name+"/helper", 10, false); apierrors.IsForbidden(err) {
		t.Errorf("logs forbidden: %v", err)
	}
	if _, err := b.Exec(ctx, pod.Name+"/helper", runtime.ExecInput{Cmd: []string{"true"}, NoStdin: true, Timeout: 5 * time.Second}); err != nil && strings.Contains(err.Error(), "forbidden") {
		t.Errorf("exec forbidden: %v", err)
	}
	if err := b.RemoveHelper(ctx, pod.Name+"/helper"); err != nil {
		t.Errorf("remove helper: %v", err)
	}
	if err := b.DownByName(ctx, "portcullis-basic"); err != nil {
		t.Errorf("down: %v", err)
	}
	if err := b.RemoveVolume(ctx, "basic--echo-data"); err != nil && !strings.Contains(err.Error(), "still being deleted") {
		t.Errorf("remove volume: %v", err)
	}
	// Nothing more.
	if _, err := e.hubK.CoreV1().Pods(ns).Patch(ctx, "x", "application/merge-patch+json", []byte(`{}`), metav1.PatchOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("patch pods: %v", err)
	}
	if _, err := e.hubK.CoreV1().Secrets("portcullis").List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("core namespace secrets: %v", err)
	}
	if _, err := e.hubK.CoreV1().Nodes().List(ctx, metav1.ListOptions{}); !apierrors.IsForbidden(err) {
		t.Errorf("nodes: %v", err)
	}
	// The rules review equals the Role.
	g := NewGuard(GuardConfig{Client: e.hubK, Dynamic: e.hub, AppsNamespace: ns, CoreNamespace: "portcullis", EdgeNamespace: EdgeNamespace})
	if err := g.rulesReview(ctx); err != nil {
		t.Errorf("rules review: %v", err)
	}
}
