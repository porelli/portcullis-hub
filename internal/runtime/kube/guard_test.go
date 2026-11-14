package kube

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func vapDenied(binding, reason string) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusFailure, Code: 422, Reason: metav1.StatusReasonInvalid,
		Message: "ValidatingAdmissionPolicy 'x' with binding '" + binding + "' denied request: " + reason}}
}

func roleRules(t *testing.T) []authv1.ResourceRule {
	r, err := Role()
	if err != nil {
		t.Fatal(err)
	}
	var out []authv1.ResourceRule
	for _, p := range r.Rules {
		out = append(out, authv1.ResourceRule{Verbs: p.Verbs, APIGroups: p.APIGroups, Resources: p.Resources})
	}
	return append(out, defaultRules.resources...)
}

// guardRig: a fake cluster where every check passes until a test
// breaks one.
type guardRig struct {
	c        *cluster
	dir      string
	apps     authv1.SubjectRulesReviewStatus
	edge     authv1.SubjectRulesReviewStatus
	core     authv1.SubjectRulesReviewStatus
	selfTest func(o *unstructured.Unstructured) error
	probe    error
	probes   int
}

func newGuardRig(t *testing.T) (*guardRig, *Guard) {
	r := &guardRig{c: newCluster(t), dir: t.TempDir()}
	r.apps = authv1.SubjectRulesReviewStatus{ResourceRules: roleRules(t), NonResourceRules: defaultRules.nonResources}
	r.core = authv1.SubjectRulesReviewStatus{ResourceRules: defaultRules.resources, NonResourceRules: defaultRules.nonResources}
	er, _ := EdgeRole()
	var edgeRules []authv1.ResourceRule
	for _, p := range er.Rules {
		edgeRules = append(edgeRules, authv1.ResourceRule{Verbs: p.Verbs, APIGroups: p.APIGroups, Resources: p.Resources})
	}
	r.edge = authv1.SubjectRulesReviewStatus{ResourceRules: append(edgeRules, defaultRules.resources...), NonResourceRules: defaultRules.nonResources}
	byKind := map[string]string{"Pod": "portcullis-apps-guard-pods", "Deployment": "portcullis-apps-guard-workloads", "Service": "portcullis-apps-guard-services",
		"Middleware": "portcullis-apps-guard-traefik", "NetworkPolicy": "portcullis-apps-guard-netpol"}
	r.selfTest = func(o *unstructured.Unstructured) error {
		if o.GetNamespace() == EdgeNamespace {
			return vapDenied("portcullis-edge-guard-routes", "nope")
		}
		return vapDenied(byKind[o.GetKind()], "nope")
	}
	r.c.typed.PrependReactor("create", "selfsubjectrulesreviews", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		rv := a.(k8stesting.CreateAction).GetObject().(*authv1.SelfSubjectRulesReview).DeepCopy()
		switch rv.Spec.Namespace {
		case ns:
			rv.Status = r.apps
		case EdgeNamespace:
			rv.Status = r.edge
		default:
			rv.Status = r.core
		}
		return true, rv, nil
	})
	r.c.dyn.PrependReactor("create", "*", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		o := a.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		if err := r.selfTest(o); err != nil {
			return true, nil, err
		}
		return true, o, nil
	})
	r.writeCheck("true", time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC), "")
	g := NewGuard(GuardConfig{Client: r.c.typed, Dynamic: r.c.dyn, AppsNamespace: ns, CoreNamespace: "portcullis", ClusterCheckDir: r.dir, HubImage: hubImage,
		Clock: func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) },
		Probe: func(context.Context) error { r.probes++; return r.probe }})
	return r, g
}

func (r *guardRig) writeCheck(ok string, at time.Time, why string) {
	os.WriteFile(filepath.Join(r.dir, "ok"), []byte(ok+"\n"), 0o644)
	os.WriteFile(filepath.Join(r.dir, "checked_at"), []byte(at.Format(time.RFC3339)+"\n"), 0o644)
	os.WriteFile(filepath.Join(r.dir, "why"), []byte(why), 0o644)
}

func mustUnverified(t *testing.T, g *Guard, name, why string) {
	t.Helper()
	err := g.Check(context.Background())
	if !errors.Is(err, ErrClusterUnverified) || !strings.Contains(err.Error(), "the cluster is not verified: ") || !strings.Contains(err.Error(), why) {
		t.Errorf("%s: %v (want %q)", name, err, why)
	}
	if g.Err() == nil {
		t.Errorf("%s: verified", name)
	}
}

// TestGuardFailsClosed: each check failing alone leaves the cluster
// unverified (503 the cluster is not verified: <why>); all holding
// verifies it.
func TestGuardFailsClosed(t *testing.T) {
	r, g := newGuardRig(t)
	if err := g.Err(); !errors.Is(err, ErrClusterUnverified) || !strings.Contains(err.Error(), "not checked yet") {
		t.Fatalf("before the first check: %v", err)
	}
	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("all hold: %v", err)
	}
	select {
	case <-g.Verified():
	default:
		t.Error("Verified not closed")
	}
	if a, n := g.State(); a != AdmissionOK || n != NetpolProven {
		t.Errorf("state %s %s", a, n)
	}
	// (1) in-cluster config.
	_, g1 := newGuardRig(t)
	g1.cfg.InCluster = errors.New("unable to load in-cluster configuration")
	mustUnverified(t, g1, "in-cluster", "in-cluster configuration")
	// (1) the cluster check: missing, not ok, too old.
	r2, g2 := newGuardRig(t)
	os.Remove(filepath.Join(r2.dir, "ok"))
	mustUnverified(t, g2, "no check", "the cluster check is missing")
	r2.writeCheck("false", time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC), "binding portcullis-apps-guard-netpol is missing")
	mustUnverified(t, g2, "check failed", "binding portcullis-apps-guard-netpol is missing")
	r2.writeCheck("true", time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), "")
	mustUnverified(t, g2, "check old", "more than 24 h ago")
	// (2) the rules review.
	r3, g3 := newGuardRig(t)
	r3.apps.ResourceRules = append(r3.apps.ResourceRules, authv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes"}})
	mustUnverified(t, g3, "extra rule", "may do more than its Role: /nodes get")
	// (3) the self-test.
	r4, g4 := newGuardRig(t)
	r4.selfTest = func(*unstructured.Unstructured) error { return nil }
	mustUnverified(t, g4, "accepted", "admission self-test: the guard is missing")
	if a, _ := g4.State(); a != AdmissionMissing {
		t.Errorf("admission %s", a)
	}
	// (4) the probe.
	r5, g5 := newGuardRig(t)
	r5.probe = errors.New("a connection the policy denies succeeded")
	mustUnverified(t, g5, "probe", "NetworkPolicy probe")
	if _, n := g5.State(); n != NetpolUnproven {
		t.Errorf("netpol %s", n)
	}
	// Proven once: not re-run for the process; a later failure of
	// another check still unverifies.
	g.Check(context.Background())
	if r.probes != 1 {
		t.Errorf("probes %d", r.probes)
	}
	r.selfTest = func(*unstructured.Unstructured) error { return nil }
	mustUnverified(t, g, "later self-test", "guard is missing")
}

// TestRoleExact: one verb more (get on pods/exec included) or one less
// than the Role is unverified.
func TestRoleExact(t *testing.T) {
	r, err := Role()
	if err != nil {
		t.Fatal(err)
	}
	ok := authv1.SubjectRulesReviewStatus{ResourceRules: roleRules(t), NonResourceRules: defaultRules.nonResources}
	if err := RulesExact(ok, r.Rules); err != nil {
		t.Fatalf("exact: %v", err)
	}
	for name, mod := range map[string]func(*authv1.SubjectRulesReviewStatus){
		"get pods/exec": func(s *authv1.SubjectRulesReviewStatus) {
			s.ResourceRules = append(s.ResourceRules, authv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/exec"}})
		},
		"patch pods": func(s *authv1.SubjectRulesReviewStatus) {
			s.ResourceRules = append(s.ResourceRules, authv1.ResourceRule{Verbs: []string{"patch"}, APIGroups: []string{""}, Resources: []string{"pods"}})
		},
		"a wildcard": func(s *authv1.SubjectRulesReviewStatus) {
			s.ResourceRules = append(s.ResourceRules, authv1.ResourceRule{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"secrets"}})
		},
		"missing": func(s *authv1.SubjectRulesReviewStatus) { s.ResourceRules = s.ResourceRules[1:] },
		"a non-resource verb": func(s *authv1.SubjectRulesReviewStatus) {
			s.NonResourceRules = append(s.NonResourceRules, authv1.NonResourceRule{Verbs: []string{"get"}, NonResourceURLs: []string{"/metrics"}})
		},
		"incomplete": func(s *authv1.SubjectRulesReviewStatus) { s.Incomplete = true },
	} {
		s := *ok.DeepCopy()
		mod(&s)
		if RulesExact(s, r.Rules) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The Role itself: pods/exec create only, no patch/update on pods,
	// nothing cluster-scoped.
	for _, p := range r.Rules {
		for _, res := range p.Resources {
			if res == "pods/exec" && (len(p.Verbs) != 1 || p.Verbs[0] != "create") {
				t.Errorf("pods/exec verbs %v", p.Verbs)
			}
			if res == "pods" && (strings.Contains(strings.Join(p.Verbs, ","), "patch") || strings.Contains(strings.Join(p.Verbs, ","), "update")) {
				t.Errorf("pods verbs %v", p.Verbs)
			}
		}
	}
	if r.Namespace != "portcullis-apps" || r.Kind != "Role" {
		t.Errorf("role %s/%s", r.Kind, r.Namespace)
	}
	for _, p := range r.Rules {
		for _, g := range p.APIGroups {
			if g == "traefik.io" {
				t.Error("routes are the edge Role's")
			}
		}
	}
	e, err := EdgeRole()
	if err != nil || e.Namespace != "portcullis-edge" || len(e.Rules) != 1 || e.Rules[0].APIGroups[0] != "traefik.io" || strings.Join(e.Rules[0].Resources, ",") != "ingressroutes,middlewares" {
		t.Errorf("edge role %+v %v", e, err)
	}
}

// The self-test reads the Status message only: another binding's
// denial, RBAC, a webhook or a warning-only answer is guard missing.
func TestSelfTestRejectedOnlyByItsBinding(t *testing.T) {
	if !SelfTestRejected(vapDenied("portcullis-apps-guard-pods", "x"), "portcullis-apps-guard-pods") {
		t.Error("its own binding")
	}
	for name, err := range map[string]error{
		"another binding": vapDenied("portcullis-apps-guard-workloads", "x"),
		"rbac":            apierrors.NewForbidden(podsGVR.GroupResource(), "x", errors.New("cannot create")),
		"webhook":         &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonForbidden, Message: `admission webhook "deny.example" denied the request`}},
		"accepted":        nil,
		"plain":           errors.New("with binding 'portcullis-apps-guard-pods'"),
		"conflict":        &apierrors.StatusError{ErrStatus: metav1.Status{Reason: metav1.StatusReasonAlreadyExists, Message: "with binding 'portcullis-apps-guard-pods'"}},
	} {
		if SelfTestRejected(err, "portcullis-apps-guard-pods") {
			t.Errorf("%s counted as the guard", name)
		}
	}
}

// The backend checks the guard before every deploy.
func TestDeployRunsTheGuard(t *testing.T) {
	r, g := newGuardRig(t)
	g.Check(context.Background())
	b := r.c.backend(t)
	b.cfg.Guard = g
	r.selfTest = func(*unstructured.Unstructured) error { return nil } // the guard went missing
	err := b.Up(context.Background(), project(t, "services:\n  web:\n    image: docker.io/library/nginx:1.29\n", "dg"), nil)
	if !errors.Is(err, ErrClusterUnverified) {
		t.Fatalf("up: %v", err)
	}
	if len(r.c.Applied()) != 0 {
		t.Error("applied without the guard")
	}
}
