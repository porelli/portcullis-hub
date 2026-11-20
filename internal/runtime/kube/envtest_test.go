//go:build envtest

package kube

// Envtest (KUBEBUILDER_ASSETS from `setup-envtest use 1.33.x`): a real
// API server with the admission policies, the Hub's Role and its
// ServiceAccount, everything run as that ServiceAccount through
// impersonation. Envtest has no kubelet: no pod ever runs.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/portcullis/hub/internal/publish"
	"github.com/portcullis/hub/internal/runtime"
)

const hubSA = "system:serviceaccount:portcullis:portcullis-hub"

// nodeadmSA is params nodeadmServiceAccount (contract §20.2).
const nodeadmSA = "system:serviceaccount:portcullis-nodeadm:nodeadm"

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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: portcullis-hub-core, namespace: portcullis}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: portcullis-hub-core}
subjects: [{kind: ServiceAccount, name: portcullis-hub, namespace: portcullis}]
`

// haSetupObjects (NEW, HA; contract §6, §20.2): the ingress namespace (PSA
// privileged: portcullis-ingress-pods is its only pod guard) with
// Traefik's ServiceAccount and nodeadm's namespace (the PriorityClasses:
// testdata/priorityclasses.yaml, a byte copy of core's
// kube/priorityclasses.yaml). RBAC wider than the real Roles, on purpose,
// so every HA vector reaches admission: the policies are what is tested
// here (RBAC is the Roles' own tests): nodeadm may create, update and
// delete Secrets in kube-system (its only admission-judged right; ruling R-ADM:
// none on admission objects); the intruder may exec, attach and
// port-forward in the core namespace and create pods (ephemeral
// containers too) and DaemonSets in portcullis-ingress.
const haSetupObjects = `apiVersion: v1
kind: Namespace
metadata:
  name: portcullis-ingress
  labels: {pod-security.kubernetes.io/enforce: privileged}
---
apiVersion: v1
kind: Namespace
metadata:
  name: portcullis-nodeadm
  labels: {pod-security.kubernetes.io/enforce: restricted}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: traefik, namespace: portcullis-ingress}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: nodeadm, namespace: portcullis-nodeadm}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: test-nodeadm, namespace: kube-system}
rules: [{apiGroups: [""], resources: [secrets], verbs: [create, update, delete]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: test-nodeadm, namespace: kube-system}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: test-nodeadm}
subjects: [{kind: ServiceAccount, name: nodeadm, namespace: portcullis-nodeadm}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: test-intruder, namespace: portcullis}
rules: [{apiGroups: [""], resources: [pods/exec, pods/attach, pods/portforward], verbs: [create]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: test-intruder, namespace: portcullis}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: test-intruder}
subjects: [{kind: ServiceAccount, name: intruder, namespace: portcullis}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: test-intruder, namespace: portcullis-ingress}
rules: [{apiGroups: [""], resources: [pods, pods/ephemeralcontainers], verbs: [create, update]}, {apiGroups: [apps], resources: [daemonsets], verbs: [create]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: test-intruder, namespace: portcullis-ingress}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: test-intruder}
subjects: [{kind: ServiceAccount, name: intruder, namespace: portcullis}]
`

// admissionPolicyFiles are core's kube/admission/ policy files (byte
// copies): the nine ValidatingAdmissionPolicies.
var admissionPolicyFiles = []string{"testdata/admission/policies.yaml", "testdata/admission/nodeadm-tokens.yaml"}

// admissionPolicies are their names (each with one binding).
var admissionPolicies = []string{"portcullis-apps-pods", "portcullis-apps-workloads", "portcullis-apps-services", "portcullis-apps-traefik",
	"portcullis-apps-netpol", "portcullis-edge-routes", "portcullis-core-exec", "portcullis-ingress-pods", "portcullis-nodeadm-tokens"}

// testGeneration is params.yaml's generation (core names the params
// ConfigMap and every binding after it).
const testGeneration = "0123456789abcdef"

var (
	paramsRef   = regexp.MustCompile(`(?m)^(\s+name: portcullis-admission-params)$`)
	bindingName = regexp.MustCompile(`(?m)^(  name: portcullis-(?:apps|edge|core|nodeadm|ingress)-guard-[a-z-]+)$`)
	// nowPlus is a bootstrap token's ${NOW+<n>m} (admission_vectors.json).
	nowPlus = regexp.MustCompile(`\$\{NOW\+([0-9]+)m\}`)
)

type env struct {
	cfg      *rest.Config
	admin    dynamic.Interface
	hub      dynamic.Interface
	hubK     kubernetes.Interface
	intruder dynamic.Interface
	// NEW (HA): the intruder's typed client (exec), nodeadm's
	// ServiceAccount, the DaemonSet controller's.
	intruderK kubernetes.Interface
	nodeadm   dynamic.Interface
	dsc       dynamic.Interface
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
	case "PriorityClass":
		res = "priorityclasses"
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
	applyYAML(t, admin, []byte(haSetupObjects))
	applyYAML(t, admin, file(t, "testdata/priorityclasses.yaml"))
	applyYAML(t, admin, file(t, "testdata/role.yaml"))
	applyYAML(t, admin, file(t, "testdata/role-edge.yaml"))
	applyYAML(t, admin, file(t, "testdata/role-core.yaml"))
	// The published documents' objects, as core's chart creates them
	// (empty).
	for name, kind := range vectorObjects(t) {
		k := "ConfigMap"
		if kind == "secret" {
			k = "Secret"
		}
		applyYAML(t, admin, []byte("apiVersion: v1\nkind: "+k+"\nmetadata: {name: "+name+", namespace: portcullis}\n"))
	}
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
	for _, f := range admissionPolicyFiles {
		applyYAML(t, admin, file(t, f))
	}
	bindings := bindingName.ReplaceAllString(string(file(t, "testdata/admission/bindings.yaml")), "${1}-"+testGeneration)
	applyYAML(t, admin, []byte(paramsRef.ReplaceAllString(bindings, "${1}-"+testGeneration)))
	hc := rest.CopyConfig(cfg)
	hc.Impersonate = rest.ImpersonationConfig{UserName: hubSA, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:portcullis", "system:authenticated"}}
	ic := rest.CopyConfig(cfg)
	ic.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:portcullis:intruder", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:portcullis", "system:authenticated"}}
	nc := rest.CopyConfig(cfg)
	nc.Impersonate = rest.ImpersonationConfig{UserName: nodeadmSA, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:portcullis-nodeadm", "system:authenticated"}}
	dc := rest.CopyConfig(cfg)
	dc.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:daemon-set-controller", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"}}
	e := &env{cfg: cfg, admin: admin, hub: dynamic.NewForConfigOrDie(hc), hubK: kubernetes.NewForConfigOrDie(hc), intruder: dynamic.NewForConfigOrDie(ic),
		intruderK: kubernetes.NewForConfigOrDie(ic), nodeadm: dynamic.NewForConfigOrDie(nc), dsc: dynamic.NewForConfigOrDie(dc)}
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
	// And nodeadm's token binding (its matchConditions-only policy can take
	// effect later than the pods one): a 16-minute token refused by it.
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	for {
		tok := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret",
			"metadata": map[string]any{"name": "bootstrap-token-wait00", "namespace": "kube-system"}, "type": "bootstrap.kubernetes.io/token",
			"stringData": map[string]any{"expiration": time.Now().UTC().Add(16 * time.Minute).Format(time.RFC3339)}}}
		_, err := e.nodeadm.Resource(secrets).Namespace("kube-system").Create(context.Background(), tok, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err != nil && strings.Contains(err.Error(), "with binding 'portcullis-nodeadm-guard-tokens-") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the token binding never took effect: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The policies type-check clean.
	for _, p := range admissionPolicies {
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
	As             string         `json:"as"` // hub | intruder | nodeadm | cli | daemonset-controller
	Want           string         `json:"want"`
	ReasonContains string         `json:"reason_contains"`
	// Existing (optional) is created as the CLI first; Op update dry-runs
	// Object as an update of it (of Subresource when set), delete its
	// deletion; Op exec / attach / portforward (NEW, HA) connects Object,
	// a Pod*Options naming its pod, to that subresource.
	Existing    map[string]any `json:"existing,omitempty"`
	Op          string         `json:"op,omitempty"`
	Subresource string         `json:"subresource,omitempty"`
	// Params (NEW, HA; core Task 19 review C1) replaces params keys for
	// this case (only a create of an apps NetworkPolicy): it is judged by
	// its own binding of portcullis-apps-netpol on those params, in a
	// namespace of its own (paramsNamespace).
	Params map[string]string `json:"params,omitempty"`
	// HA marks the high-availability cases (contract §6: placement, core
	// exec, nodeadm tokens, nodeadm admission writes, ingress pods).
	HA bool `json:"ha,omitempty"`
}

// withNow replaces ${NOW+<n>m} with now + n minutes (RFC 3339 UTC).
func withNow(t *testing.T, o map[string]any) map[string]any {
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	b = nowPlus.ReplaceAllFunc(b, func(m []byte) []byte {
		n, _ := strconv.Atoi(string(nowPlus.FindSubmatch(m)[1]))
		return []byte(time.Now().UTC().Add(time.Duration(n) * time.Minute).Format(time.RFC3339))
	})
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// connectAs connects a Pod{Exec,Attach,PortForward}Options to pods/<op>
// of its pod (envtest has no pod: past admission the answer is NotFound).
func connectAs(ctx context.Context, k kubernetes.Interface, op string, o map[string]any) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	var opts kruntime.Object
	switch op {
	case "exec":
		opts = &corev1.PodExecOptions{}
	case "attach":
		opts = &corev1.PodAttachOptions{}
	default:
		opts = &corev1.PodPortForwardOptions{}
	}
	if err := json.Unmarshal(b, opts); err != nil {
		return err
	}
	md, _ := o["metadata"].(map[string]any)
	name, _ := md["name"].(string)
	namespace, _ := md["namespace"].(string)
	return k.CoreV1().RESTClient().Post().Namespace(namespace).Resource("pods").Name(name).SubResource(op).
		VersionedParams(opts, scheme.ParameterCodec).Do(ctx).Error()
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
		t.Run(v.Name, func(t *testing.T) {
			o := &unstructured.Unstructured{Object: withNow(t, v.Object)}
			client, typed := e.hub, e.hubK
			switch v.As {
			case "intruder":
				client, typed = e.intruder, e.intruderK
			case "nodeadm":
				client = e.nodeadm
			case "cli":
				client = e.admin
			case "daemonset-controller":
				client = e.dsc
			}
			if v.Params != nil {
				if o.GetKind() != "NetworkPolicy" || o.GetNamespace() != "portcullis-apps" || v.Existing != nil || v.Op != "" {
					t.Fatalf("%s: a params case must be a create of an apps NetworkPolicy", v.Name)
				}
				o.SetNamespace(e.paramsNamespace(t, v.Params))
			}
			res := client.Resource(gvrOf(o)).Namespace(o.GetNamespace())
			var err error
			if v.Op == "exec" || v.Op == "attach" || v.Op == "portforward" {
				err = connectAs(ctx, typed, v.Op, o.Object)
				if v.Want == "allow" && apierrors.IsNotFound(err) {
					err = nil // past RBAC and admission: no such pod in envtest
				}
			} else if v.Existing != nil {
				ex := &unstructured.Unstructured{Object: v.Existing}
				cur, cerr := e.admin.Resource(gvrOf(ex)).Namespace(ex.GetNamespace()).Create(ctx, ex, metav1.CreateOptions{})
				if cerr != nil {
					t.Fatalf("%s: creating the existing object: %v", v.Name, cerr)
				}
				if v.Op == "delete" {
					err = res.Delete(ctx, ex.GetName(), metav1.DeleteOptions{DryRun: dry})
				} else {
					o.SetResourceVersion(cur.GetResourceVersion())
					if v.Subresource != "" {
						_, err = res.Update(ctx, o, metav1.UpdateOptions{DryRun: dry}, v.Subresource)
					} else {
						_, err = res.Update(ctx, o, metav1.UpdateOptions{DryRun: dry})
					}
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
		})
	}
}

// knownRefused are translations the policies refuse on purpose (core's
// rulings), so a change on either side shows here. None today: a root
// service is refused by the translator itself.
var knownRefused = map[string]string{}

// haParams are the admission params of an HA cluster as they differ
// from params.yaml (core's kube_traefik_peer in HA): Traefik in
// portcullis-ingress, mcp-gate and wg in the core namespace.
var haParams = map[string]string{"traefik": "portcullis-ingress:app.kubernetes.io/name=traefik"}

// TestTranslatedObjectsAdmitted: what the translator renders for every
// golden case passes the policies (the Hub never fights its guard), in
// both modes: without HA under params.yaml, and in HA (HUB_HA=on: the
// HA tolerations, Traefik's peer in portcullis-ingress) with the
// NetworkPolicies judged by a binding on the HA params (haParams).
func TestTranslatedObjectsAdmitted(t *testing.T) {
	e := startEnv(t)
	cases, _ := filepath.Glob("testdata/translate/*")
	n := 0
	for _, dir := range cases {
		c := filepath.Base(dir)
		for _, ha := range []bool{false, true} {
			in := baseInput(t, dir, c)
			in.HubImage = "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("1", 64)
			in.Namespace = ns
			// The params' cluster (params.yaml).
			in.Settings.PodCIDR, in.Settings.ServiceCIDR = "10.42.0.0/24", "10.43.0.0/16"
			in.Settings.NodeAddresses, in.Settings.APIAddresses = []string{"10.1.0.4"}, []string{"10.1.0.4"}
			in.Settings.HA = in.Settings.HA || ha
			if !ha && in.Settings.HA {
				continue // an HA golden: judged in the HA pass
			}
			p, err := Translate(in)
			var r *ErrRefused
			if errors.As(err, &r) && c == "refused-host" {
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", c, err)
			}
			n++
			for _, o := range p.Objects() {
				target := o.GetNamespace()
				if ha && o.GetKind() == "NetworkPolicy" {
					o = o.DeepCopy()
					o.SetNamespace(e.paramsNamespace(t, haParams))
				}
				_, err := e.hub.Resource(gvrOf(o)).Namespace(o.GetNamespace()).Create(context.Background(), o, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				want := knownRefused[c+"/"+o.GetKind()+"/"+o.GetName()]
				switch {
				case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
					t.Errorf("%s (ha %v): %s %s: want the known refusal %q, got %v", c, ha, o.GetKind(), o.GetName(), want, err)
				case want == "" && err != nil:
					t.Errorf("%s (ha %v): %s %s (in %s) denied: %v", c, ha, o.GetKind(), o.GetName(), target, err)
				}
			}
		}
	}
	if n < 16 {
		t.Fatalf("%d translations judged", n)
	}
}

// TestHATraefikPeerOnlyUnderHAParams: the routed policy is admitted
// only under the params of its own mode (core's e2e runs both): the HA
// peer is refused by the non-HA params and the core-namespace one by
// the HA params.
func TestHATraefikPeerOnlyUnderHAParams(t *testing.T) {
	e := startEnv(t)
	for _, ha := range []bool{false, true} {
		pols, err := InstancePolicies(PolicyInput{Instance: "app", Namespace: ns, RoutedPorts: map[string][]int{"web": {8080}}, Settings: Settings{HA: ha}})
		if err != nil || len(pols) != 1 {
			t.Fatalf("%d policies, %v", len(pols), err)
		}
		for _, under := range []bool{false, true} {
			o := pols[0].DeepCopy()
			if under {
				o.SetNamespace(e.paramsNamespace(t, haParams))
			}
			_, err := e.hub.Resource(gvrOf(o)).Namespace(o.GetNamespace()).Create(context.Background(), o, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			if (err == nil) != (ha == under) {
				t.Errorf("rendered ha %v, params ha %v: %v", ha, under, err)
			}
		}
	}
}

// TestHelperAndProbePodsAdmitted (HA Task 13 ruling 3): the helper pods
// (volume, fixer) and the NetworkPolicy probe pods, at portcullis-low,
// pass the pods policy as the Hub's ServiceAccount.
func TestHelperAndProbePodsAdmitted(t *testing.T) {
	e := startEnv(t)
	img := "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("1", 64)
	b := &Backend{cfg: Config{Namespace: ns, HubImage: img}}
	pods := map[string]*corev1.Pod{
		"volume": b.helperPod(HelperVolume, "app", "app--data", true, nil),
		"fixer": b.helperPod(HelperFixer, "", "", false, &runtime.FixerSpec{Image: img, User: "0:0", CapAdd: []string{"DAC_READ_SEARCH"},
			Binds: []runtime.BindMount{{Source: "/srv/photos", Target: "/root", ReadOnly: true}}, Scratch: []string{"/out"}, Memory: 64 << 20}),
	}
	for _, role := range []string{"deny", "allow", "client"} {
		pods["probe-"+role] = probePod(ns, img, role, role != "client")
	}
	for name, p := range pods {
		if p.Spec.PriorityClassName != "portcullis-low" {
			t.Fatalf("%s: class %q", name, p.Spec.PriorityClassName)
		}
		if _, err := e.hubK.CoreV1().Pods(ns).Create(context.Background(), p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
			t.Errorf("%s denied: %v", name, err)
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
// pods/exec, nothing in the core namespace but portcullis-hub-core, no
// patch on pods.
func TestRoleIsEnough(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	b, err := New(Config{Client: e.hubK, Dynamic: e.hub, Namespace: ns, CoreNamespace: "portcullis", HubImage: "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("1", 64),
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
	// Pod metrics (the Usage page): list in the apps namespace allowed,
	// nodes/stats and node metrics denied.
	for _, c := range []struct {
		attr  authorizationv1.ResourceAttributes
		allow bool
	}{
		{authorizationv1.ResourceAttributes{Namespace: ns, Verb: "list", Group: "metrics.k8s.io", Resource: "pods"}, true},
		{authorizationv1.ResourceAttributes{Namespace: ns, Verb: "get", Group: "metrics.k8s.io", Resource: "pods"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "list", Group: "metrics.k8s.io", Resource: "pods"}, false},
		{authorizationv1.ResourceAttributes{Verb: "list", Group: "metrics.k8s.io", Resource: "nodes"}, false},
		{authorizationv1.ResourceAttributes{Verb: "list", Resource: "nodes", Subresource: "stats"}, false},
		{authorizationv1.ResourceAttributes{Verb: "get", Resource: "nodes", Subresource: "proxy"}, false},
	} {
		a := c.attr
		r, err := e.hubK.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}}, metav1.CreateOptions{})
		if err != nil || r.Status.Allowed != c.allow {
			t.Errorf("can-i %s %s/%s %s in %q = %v (%v), want %v", a.Verb, a.Group, a.Resource, a.Subresource, a.Namespace, r != nil && r.Status.Allowed, err, c.allow)
		}
	}
	// The core namespace (contract §6, portcullis-hub-core): every
	// document published by update of its own object; no create, no
	// other name, no list of ConfigMaps or Secrets; pods list allowed.
	sink := b.DocSink()
	for _, d := range publish.All {
		if _, err := sink.Publish(ctx, d, []byte(`{"doc":"`+string(d)+`"}`+"\n")); err != nil {
			t.Errorf("publish %s: %v", d, err)
		}
	}
	if err := sink.(publish.Remover).Remove(ctx, publish.UserAttributes); err != nil {
		t.Errorf("remove: %v", err)
	}
	if _, err := e.hubK.CoreV1().Pods("portcullis").List(ctx, metav1.ListOptions{LabelSelector: LabelComponent + " in (group-gate)"}); err != nil {
		t.Errorf("list core pods: %v", err)
	}
	// The gates' replicas (contract §20.10, Task 7): the backend's own
	// lister, the Hub's identity.
	for _, comp := range []string{"group-gate", "mcp-gate", "wg"} {
		if _, err := b.CoreReplicas(comp, ReplicaOptions{StatefulSet: comp != "wg"})(ctx); err != nil {
			t.Errorf("core replicas %s: %v", comp, err)
		}
	}
	for _, c := range []struct {
		attr  authorizationv1.ResourceAttributes
		allow bool
	}{
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "update", Resource: "configmaps", Name: "pub-vpn"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "update", Resource: "secrets", Name: "pub-mcp-credentials"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "get", Resource: "configmaps", Name: "frontdoor-status"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "update", Resource: "configmaps", Name: "frontdoor-status"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "create", Resource: "configmaps", Name: "pub-vpn"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "delete", Resource: "configmaps", Name: "pub-vpn"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "list", Resource: "configmaps"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "get", Resource: "secrets", Name: "frontdoor-env"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Name: "portcullis-hub"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Name: "portcullis-frontdoor"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "create", Resource: "pods", Subresource: "exec", Name: "group-gate-1"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "get", Resource: "pods", Subresource: "exec", Name: "group-gate-1"}, false},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "list", Resource: "pods"}, true},
		{authorizationv1.ResourceAttributes{Namespace: "portcullis", Verb: "get", Resource: "pods", Name: "group-gate-1"}, false},
	} {
		a := c.attr
		r, err := e.hubK.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &a}}, metav1.CreateOptions{})
		if err != nil || r.Status.Allowed != c.allow {
			t.Errorf("can-i %s %s/%s %s %s in %q = %v (%v), want %v", a.Verb, a.Group, a.Resource, a.Subresource, a.Name, a.Namespace, r != nil && r.Status.Allowed, err, c.allow)
		}
	}
	// The rules review equals the Role.
	g := NewGuard(GuardConfig{Client: e.hubK, Dynamic: e.hub, AppsNamespace: ns, CoreNamespace: "portcullis", EdgeNamespace: EdgeNamespace})
	if err := g.rulesReview(ctx); err != nil {
		t.Errorf("rules review: %v", err)
	}
}

var paramsSets = map[string]string{}

// paramsNamespace: the namespace judged by portcullis-apps-netpol under
// params.yaml with <over> replaced (its own ConfigMap and binding, made
// once per distinct set), once the binding is in effect.
func (e *env) paramsNamespace(t *testing.T, over map[string]string) string {
	t.Helper()
	key := string(mustJSON(over))
	if ns, ok := paramsSets[key]; ok {
		return ns
	}
	n := strconv.Itoa(len(paramsSets))
	ns, cm, b := "portcullis-apps-p"+n, "portcullis-admission-params-p"+n, "portcullis-apps-guard-netpol-p"+n
	var base struct {
		Data map[string]string `json:"data"`
	}
	if err := utilyaml.Unmarshal(file(t, "testdata/admission/params.yaml"), &base); err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base.Data[k] = v
	}
	cmo := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": cm, "namespace": "portcullis"}, "data": base.Data}
	nso := map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns}}
	bo := map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding", "metadata": map[string]any{"name": b},
		"spec": map[string]any{"policyName": "portcullis-apps-netpol", "validationActions": []any{"Deny"},
			"paramRef":       map[string]any{"name": cm, "namespace": "portcullis", "parameterNotFoundAction": "Deny"},
			"matchResources": map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": ns}}}}}
	// The Hub's create on NetworkPolicies there (its apps Role's rule).
	ro := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"name": "hub-netpol", "namespace": ns},
		"rules": []any{map[string]any{"apiGroups": []any{"networking.k8s.io"}, "resources": []any{"networkpolicies"}, "verbs": []any{"create"}}}}
	rbo := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": map[string]any{"name": "hub-netpol", "namespace": ns},
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "hub-netpol"},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": "portcullis-hub", "namespace": "portcullis"}}}
	for _, o := range []map[string]any{nso, cmo, bo, ro, rbo} {
		applyYAML(t, e.admin, mustJSON(o))
	}
	probe := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
		"metadata": map[string]any{"name": "wait", "namespace": ns, "labels": map[string]any{"portcullis.io/instance": "app"}},
		"spec": map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"portcullis.io/instance": "app", "portcullis.io/service": "web"}},
			"policyTypes": []any{"Ingress"}, "ingress": []any{map[string]any{"from": []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}}}}}}
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := e.hub.Resource(gvrOf(probe)).Namespace(ns).Create(context.Background(), probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err != nil && strings.Contains(err.Error(), "binding '"+b+"'") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the binding %s never took effect: %v", b, err)
		}
		time.Sleep(time.Second)
	}
	paramsSets[key] = ns
	return ns
}
