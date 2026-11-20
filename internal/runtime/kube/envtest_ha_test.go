//go:build envtest

package kube

// The HA admission additions (contract §6, NEW HA) beyond the vectors:
// nodeadm's bootstrap token guard as the brief pins it, and the API
// server's own limit that keeps the "nodeadm admission writes" binding
// rules out of reach of any ValidatingAdmissionPolicy.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func bootstrapToken(ttl time.Duration, extra map[string]any) *unstructured.Unstructured {
	data := map[string]any{"token-id": "abcdef", "token-secret": "0123456789abcdef",
		"expiration": time.Now().UTC().Add(ttl).Format(time.RFC3339), "usage-bootstrap-authentication": "true",
		"auth-extra-groups": "system:bootstrappers:k3s:default-node-token"}
	for k, v := range extra {
		data[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "bootstrap-token-abcdef", "namespace": "kube-system"},
		"type":     "bootstrap.kubernetes.io/token", "stringData": data}}
}

// TestNodeadmTokenPolicy: as nodeadm's ServiceAccount, server dry-run in
// kube-system: a 16 min TTL is refused "bootstrap tokens must expire
// within 15 minutes", a signing usage "bootstrap tokens may be used for
// authentication only"; 10 min with authentication only is admitted. The
// same Secrets from another identity aren't nodeadm's to judge.
func TestNodeadmTokenPolicy(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	dry := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	for _, c := range []struct {
		name string
		obj  *unstructured.Unstructured
		want string
	}{
		{"16 min", bootstrapToken(16*time.Minute, nil), "bootstrap tokens must expire within 15 minutes"},
		{"signing", bootstrapToken(10*time.Minute, map[string]any{"usage-bootstrap-signing": "true"}), "bootstrap tokens may be used for authentication only"},
		{"10 min, authentication", bootstrapToken(10*time.Minute, nil), ""},
	} {
		_, err := e.nodeadm.Resource(secrets).Namespace("kube-system").Create(ctx, c.obj, dry)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		var st apierrors.APIStatus
		if !errors.As(err, &st) || !strings.Contains(st.Status().Message, "with binding 'portcullis-nodeadm-guard-tokens-") || !strings.Contains(st.Status().Message, c.want) {
			t.Errorf("%s: want %q from portcullis-nodeadm-guard-tokens, got %v", c.name, c.want, err)
		}
	}
	// k3s and the controllers write kube-system's other Secrets: not judged.
	o := bootstrapToken(16*time.Minute, nil)
	o.Object["type"] = "Opaque"
	if _, err := e.admin.Resource(secrets).Namespace("kube-system").Create(ctx, o, dry); err != nil {
		t.Errorf("another identity's Secret in kube-system: %v", err)
	}
}

// TestAdmissionPolicyObjectsNotJudged pins why the contract's "nodeadm
// admission writes" binding rules aren't in portcullis-nodeadm-admission:
// the API server never evaluates API-defined ValidatingAdmissionPolicies
// on validatingadmissionpolicies or validatingadmissionpolicybindings
// (k8s.io/apiserver admission/plugin/policy/generic: admission
// configuration resources are excluded from API-based hooks). A policy
// that refuses everything, live (it refuses a ConfigMap of its control
// namespace), still lets nodeadm create, update and delete a binding.
// Only RBAC (nodeadm's ClusterRole: create, never update or delete)
// stands there. If this test ever fails, the binding rules can move into
// the policy (Task 18 report).
func TestAdmissionPolicyObjectsNotJudged(t *testing.T) {
	e := startEnv(t)
	ctx := context.Background()
	vap := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}
	vapb := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}
	cms := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	applyYAML(t, e.admin, []byte(`apiVersion: v1
kind: Namespace
metadata: {name: test-vap-control}
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {name: test-refuse-all}
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - {apiGroups: [admissionregistration.k8s.io], apiVersions: [v1], operations: [CREATE, UPDATE, DELETE], resources: [validatingadmissionpolicies, validatingadmissionpolicybindings]}
    - {apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}
  validations:
  - {expression: "false", message: test-refuse-all refuses}
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata: {name: test-refuse-all}
spec:
  policyName: test-refuse-all
  validationActions: [Deny]
  matchResources:
    namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: test-vap-control}}
`))
	defer func() {
		e.admin.Resource(vapb).Delete(ctx, "test-refuse-all", metav1.DeleteOptions{})
		e.admin.Resource(vap).Delete(ctx, "test-refuse-all", metav1.DeleteOptions{})
	}()
	cm := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "x", "namespace": "test-vap-control"}}}
	dry := []string{metav1.DryRunAll}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := e.admin.Resource(cms).Namespace("test-vap-control").Create(ctx, cm, metav1.CreateOptions{DryRun: dry})
		if err != nil && strings.Contains(err.Error(), "test-refuse-all refuses") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the control policy never took effect: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	b := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
		"metadata": map[string]any{"name": "test-weak"},
		"spec":     map[string]any{"policyName": "portcullis-apps-pods", "validationActions": []any{"Warn"}}}}
	if _, err := e.nodeadm.Resource(vapb).Create(ctx, b, metav1.CreateOptions{DryRun: dry}); err != nil {
		t.Errorf("a binding create was judged: %v", err)
	}
	if err := e.nodeadm.Resource(vapb).Delete(ctx, "portcullis-apps-guard-pods-"+testGeneration, metav1.DeleteOptions{DryRun: dry}); err != nil {
		t.Errorf("a binding delete was judged: %v", err)
	}
	if err := e.nodeadm.Resource(vap).Delete(ctx, "portcullis-apps-pods", metav1.DeleteOptions{DryRun: dry}); err != nil {
		t.Errorf("a policy delete was judged: %v", err)
	}
}
