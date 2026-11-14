package kube

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	_ "embed"
)

// The Hub's Role, exactly (testdata/role.yaml is the chart's byte copy;
// the guard compares the rules review with it).
//
//go:embed testdata/role.yaml
var roleYAML []byte

// Role is the Hub's Role (parsed from the embedded copy).
func Role() (*rbacv1.Role, error) {
	var r rbacv1.Role
	if err := yaml.UnmarshalStrict(roleYAML, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// podsGVR is pods (the self-test dry-runs a Pod).
var podsGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

// Policies are the admission guard's five policies (bindings
// portcullis-apps-guard-<policy>).
var Policies = []string{"pods", "workloads", "services", "traefik", "netpol"}

// Admission and probe states (RuntimeView).
const (
	AdmissionOK      = "ok"
	AdmissionMissing = "missing"
	AdmissionUnknown = "unknown"
	NetpolProven     = "proven"
	NetpolUnproven   = "unproven"
)

// ClusterCheckDir is where the chart mounts the CLI's cluster check.
const ClusterCheckDir = "/run/portcullis/cluster-check"

// clusterCheckMaxAge: an older check refuses deploys.
const clusterCheckMaxAge = 24 * time.Hour

// GuardConfig configures a Guard.
type GuardConfig struct {
	Client  kubernetes.Interface
	Dynamic dynamic.Interface
	// AppsNamespace / CoreNamespace: HUB_APPS_NAMESPACE / the Hub's own.
	AppsNamespace, CoreNamespace string
	// InCluster is the in-cluster configuration's error (nil: loaded).
	InCluster error
	// ClusterCheckDir (default ClusterCheckDir): checked_at, ok, why.
	ClusterCheckDir string
	// HubImage is HUB_SELF_IMAGE (probe pods); Exec runs the dials.
	HubImage string
	Exec     Execer
	Clock    func() time.Time
	Sleep    func(ctx context.Context, d time.Duration) error
	// Probe replaces the NetworkPolicy probe (tests; nil: the real one).
	Probe func(ctx context.Context) error
}

// Guard is the cluster guard (contract §6 "On Kubernetes"): four checks
// in order, at start, every minute and before every deploy; until all
// hold every runtime operation answers ErrClusterUnverified.
type Guard struct {
	cfg      GuardConfig
	mu       sync.Mutex
	err      error
	admit    string
	netpol   string
	proven   bool // the probe passed once in this process
	verified chan struct{}
	once     sync.Once
	ran      bool
	version  string
}

// Version is the API server's gitVersion as last read.
func (g *Guard) Version() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.version
}

// NewGuard returns an unverified guard ("not checked yet").
func NewGuard(cfg GuardConfig) *Guard {
	if cfg.ClusterCheckDir == "" {
		cfg.ClusterCheckDir = ClusterCheckDir
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &Guard{cfg: cfg, err: &UnverifiedError{Why: "not checked yet"}, admit: AdmissionUnknown, netpol: NetpolUnproven, verified: make(chan struct{})}
}

// Err is nil while every check holds.
func (g *Guard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Verified is closed once the checks first held.
func (g *Guard) Verified() <-chan struct{} { return g.verified }

// State is the admission and probe states for the runtime view.
func (g *Guard) State() (admission, netpol string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admit, g.netpol
}

func (g *Guard) set(err error) {
	g.mu.Lock()
	g.ran = true
	if err != nil {
		var u *UnverifiedError
		if !errors.As(err, &u) {
			err = &UnverifiedError{Why: err.Error()}
		}
	}
	g.err = err
	g.mu.Unlock()
	if err == nil {
		g.once.Do(func() { close(g.verified) })
	}
}

// Run checks at once and then every period until ctx ends.
func (g *Guard) Run(ctx context.Context, every time.Duration) {
	for {
		g.Check(ctx)
		if err := g.cfg.Sleep(ctx, every); err != nil {
			return
		}
	}
}

// Check runs the four checks in order and records the result: (1) the
// in-cluster configuration and the CLI's cluster check (≤ 24 h old),
// (2) the rules review against the Role, exactly, (3) the admission
// self-test, (4) the NetworkPolicy probe (once proven, for the process).
func (g *Guard) Check(ctx context.Context) error {
	err := g.check(ctx)
	g.set(err)
	return g.Err()
}

func (g *Guard) check(ctx context.Context) error {
	if g.cfg.InCluster != nil {
		return fmt.Errorf("in-cluster configuration: %v", g.cfg.InCluster)
	}
	if err := g.clusterCheck(); err != nil {
		return err
	}
	if v, err := g.cfg.Client.Discovery().ServerVersion(); err == nil {
		g.mu.Lock()
		g.version = v.GitVersion
		g.mu.Unlock()
	}
	if err := g.rulesReview(ctx); err != nil {
		return err
	}
	if err := g.selfTest(ctx); err != nil {
		g.mu.Lock()
		g.admit = AdmissionMissing
		g.mu.Unlock()
		return err
	}
	g.mu.Lock()
	g.admit = AdmissionOK
	proven := g.proven
	g.mu.Unlock()
	if !proven {
		probe := g.cfg.Probe
		if probe == nil {
			probe = g.netpolProbe
		}
		if err := probe(ctx); err != nil {
			return fmt.Errorf("NetworkPolicy probe: %v", err)
		}
		g.mu.Lock()
		g.proven, g.netpol = true, NetpolProven
		g.mu.Unlock()
	}
	return nil
}

// clusterCheck reads the CLI's cluster check (checked_at RFC 3339 UTC,
// ok, why): missing, not ok or older than 24 h refuses.
func (g *Guard) clusterCheck() error {
	read := func(k string) (string, error) {
		b, err := os.ReadFile(filepath.Join(g.cfg.ClusterCheckDir, k))
		return strings.TrimSpace(string(b)), err
	}
	ok, err := read("ok")
	if err != nil {
		return fmt.Errorf("the cluster check is missing (run ./portcullis up): %v", err)
	}
	if ok != "true" {
		why, _ := read("why")
		if why == "" {
			why = "ok is " + clip(ok, 20)
		}
		return fmt.Errorf("the cluster check failed: %s", clip(why, 300))
	}
	at, err := read("checked_at")
	t, perr := time.Parse(time.RFC3339, at)
	if err != nil || perr != nil {
		return fmt.Errorf("the cluster check has no valid checked_at")
	}
	if age := g.cfg.Clock().Sub(t); age > clusterCheckMaxAge || age < -5*time.Minute {
		return fmt.Errorf("the cluster check is from %s, more than 24 h ago (run ./portcullis up)", t.UTC().Format(time.RFC3339))
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// defaultRules are what every authenticated user may do (the
// system:basic-user and system:discovery roles).
var defaultRules = struct {
	resources    []authv1.ResourceRule
	nonResources []authv1.NonResourceRule
}{
	resources: []authv1.ResourceRule{
		{Verbs: []string{"create"}, APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}},
		{Verbs: []string{"create"}, APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}},
	},
	nonResources: []authv1.NonResourceRule{
		{Verbs: []string{"get"}, NonResourceURLs: []string{"/api", "/api/*", "/apis", "/apis/*", "/openapi", "/openapi/*", "/version", "/version/", "/healthz", "/livez", "/readyz"}},
		// system:service-account-issuer-discovery (bound to every
		// ServiceAccount by default).
		{Verbs: []string{"get"}, NonResourceURLs: []string{"/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/openid/v1/jwks", "/openid/v1/jwks/"}},
	},
}

// grant is one (group, resource, verb) triple.
type grant struct{ group, resource, verb string }

func expand(rules []authv1.ResourceRule) (map[grant]bool, error) {
	out := map[grant]bool{}
	for _, r := range rules {
		if len(r.ResourceNames) > 0 {
			return nil, fmt.Errorf("a rule limited to names %v", r.ResourceNames)
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					if g == "*" || res == "*" || v == "*" {
						return nil, fmt.Errorf("a wildcard rule (%s/%s %s)", g, res, v)
					}
					out[grant{g, res, v}] = true
				}
			}
		}
	}
	return out, nil
}

// RulesExact compares a rules review with the expected resource grants
// (plus the defaults): no more, no less.
func RulesExact(st authv1.SubjectRulesReviewStatus, want []rbacv1.PolicyRule) error {
	if st.Incomplete {
		return fmt.Errorf("the rules review is incomplete: %s", clip(st.EvaluationError, 200))
	}
	var w []authv1.ResourceRule
	for _, r := range want {
		w = append(w, authv1.ResourceRule{Verbs: r.Verbs, APIGroups: r.APIGroups, Resources: r.Resources})
	}
	w = append(w, defaultRules.resources...)
	wantG, err := expand(w)
	if err != nil {
		return err
	}
	have, err := expand(st.ResourceRules)
	if err != nil {
		return fmt.Errorf("the ServiceAccount has %v", err)
	}
	var extra, missing []string
	for g := range have {
		if !wantG[g] {
			extra = append(extra, g.group+"/"+g.resource+" "+g.verb)
		}
	}
	for g := range wantG {
		if !have[g] {
			missing = append(missing, g.group+"/"+g.resource+" "+g.verb)
		}
	}
	slices.Sort(extra)
	slices.Sort(missing)
	switch {
	case len(extra) > 0:
		return fmt.Errorf("the ServiceAccount may do more than its Role: %s", strings.Join(extra, ", "))
	case len(missing) > 0:
		return fmt.Errorf("the ServiceAccount lacks %s", strings.Join(missing, ", "))
	}
	okNR := map[string]bool{}
	for _, r := range defaultRules.nonResources {
		for _, u := range r.NonResourceURLs {
			okNR[u] = true
		}
	}
	for _, r := range st.NonResourceRules {
		for _, u := range r.NonResourceURLs {
			for _, v := range r.Verbs {
				if v != "get" || !okNR[u] {
					return fmt.Errorf("the ServiceAccount may %s %s", v, u)
				}
			}
		}
	}
	return nil
}

// rulesReview: the apps namespace holds exactly the Role, the core
// namespace only the defaults.
func (g *Guard) rulesReview(ctx context.Context) error {
	role, err := Role()
	if err != nil {
		return err
	}
	for _, c := range []struct {
		ns   string
		want []rbacv1.PolicyRule
	}{{g.cfg.AppsNamespace, role.Rules}, {g.cfg.CoreNamespace, nil}} {
		if c.ns == "" {
			continue
		}
		r, err := g.cfg.Client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authv1.SelfSubjectRulesReview{Spec: authv1.SelfSubjectRulesReviewSpec{Namespace: c.ns}}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("rules review in %s: %v", c.ns, err)
		}
		if err := RulesExact(r.Status, c.want); err != nil {
			return fmt.Errorf("in %s: %v", c.ns, err)
		}
	}
	return nil
}

// SelfTestObjects are the five forbidden objects of the self-test, one
// per binding (each would pass every other policy).
func SelfTestObjects(ns string) map[string]*unstructured.Unstructured {
	f, t := false, true
	podSpec := corev1.PodSpec{AutomountServiceAccountToken: &f, Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/selftest@sha256:" + strings.Repeat("0", 64),
		SecurityContext: &corev1.SecurityContext{Privileged: &t}}}}
	labels := map[string]string{LabelInstance: "portcullis-selftest"}
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "portcullis-selftest", Namespace: ns, Labels: labels}, Spec: podSpec}
	one := int32(1)
	dep := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: metav1.ObjectMeta{Name: "portcullis-selftest", Namespace: ns, Labels: labels},
		Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: podSpec}}}
	svc := &corev1.Service{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: metav1.ObjectMeta{Name: "portcullis-selftest", Namespace: ns, Labels: labels},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: labels, Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(80)}}}}
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(80)
	np := &networkingv1.NetworkPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: "portcullis-selftest", Namespace: ns, Labels: labels},
		Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{LabelInstance: "portcullis-selftest", LabelService: "x"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}}, Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}}}}}
	out := map[string]*unstructured.Unstructured{}
	for k, o := range map[string]any{"pods": pod, "workloads": dep, "services": svc, "netpol": np} {
		u, _ := toUnstructured(o)
		out[k] = u
	}
	out["traefik"] = &unstructured.Unstructured{Object: map[string]any{"apiVersion": traefikAPI, "kind": "Middleware",
		"metadata": map[string]any{"name": "portcullis-selftest", "namespace": ns, "labels": map[string]any{LabelInstance: "portcullis-selftest"}},
		"spec":     map[string]any{"headers": map[string]any{"customRequestHeaders": map[string]any{"X-Portcullis-User": "root"}}}}}
	return out
}

// SelfTestRejected: err is the API server's Invalid / Forbidden Status
// whose message names policy's binding (never a warning: warnings aren't
// errors; a rejection by RBAC, a quota or another webhook isn't).
func SelfTestRejected(err error, policy string) bool {
	var st apierrors.APIStatus
	if !errors.As(err, &st) {
		return false
	}
	s := st.Status()
	if s.Reason != metav1.StatusReasonInvalid && s.Reason != metav1.StatusReasonForbidden {
		return false
	}
	return strings.Contains(s.Message, "with binding 'portcullis-apps-guard-"+policy+"'")
}

// selfTest dry-runs the five forbidden objects; each must be rejected by
// its own binding.
func (g *Guard) selfTest(ctx context.Context) error {
	objs := SelfTestObjects(g.cfg.AppsNamespace)
	for _, p := range Policies {
		o := objs[p]
		r, _ := gvr(o.GetKind())
		if o.GetKind() == "Pod" {
			r = podsGVR
		}
		_, err := g.cfg.Dynamic.Resource(r).Namespace(g.cfg.AppsNamespace).Create(ctx, o, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if !SelfTestRejected(err, p) {
			why := "accepted"
			if err != nil {
				why = clip(err.Error(), 200)
			}
			return fmt.Errorf("admission self-test: the guard is missing (a forbidden %s wasn't rejected by binding portcullis-apps-guard-%s: %s)", strings.ToLower(o.GetKind()), p, why)
		}
	}
	return nil
}
