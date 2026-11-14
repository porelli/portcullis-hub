package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

// probeReady bounds the wait for the probe pods.
const probeReady = 2 * time.Minute

func probePod(ns, image, role string, listen bool) *corev1.Pod {
	f, t := false, true
	uid := int64(10001)
	// "hub" by PATH: the admission policy pins probe pods to exactly the
	// Hub's image running hub helper listen|idle|dial.
	cmd := []string{"hub", "helper", "idle"}
	if listen {
		cmd = []string{"hub", "helper", "listen", ":8080"}
	}
	q := resource.MustParse("32Mi")
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "portcullis-probe-" + role + "-" + randSuffix(), Namespace: ns,
			Labels: map[string]string{LabelProbe: role, LabelInstance: ProbeInstance}},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &f, EnableServiceLinks: &f, RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{{Name: "probe", Image: image, ImagePullPolicy: corev1.PullIfNotPresent, Command: cmd,
				SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &t, RunAsUser: &uid, AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &t,
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q}, Requests: corev1.ResourceList{corev1.ResourceMemory: q}}}},
		},
	}
}

func probeSel(role string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{LabelProbe: role}}
}

// probePolicies: the deny listener admits nothing, the allow listener
// the client on 8080, the client may reach the listeners on 8080 only.
func probePolicies(ns string) []*networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(8080)
	ports := []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}}
	meta := func(n string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: "portcullis-probe-" + n, Namespace: ns, Labels: map[string]string{LabelInstance: ProbeInstance}}
	}
	peer := func(role string) []networkingv1.NetworkPolicyPeer {
		s := probeSel(role)
		return []networkingv1.NetworkPolicyPeer{{PodSelector: &s}}
	}
	ing := []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	return []*networkingv1.NetworkPolicy{
		{ObjectMeta: meta("deny"), Spec: networkingv1.NetworkPolicySpec{PodSelector: probeSel("deny"), PolicyTypes: ing}},
		{ObjectMeta: meta("allow"), Spec: networkingv1.NetworkPolicySpec{PodSelector: probeSel("allow"), PolicyTypes: ing,
			Ingress: []networkingv1.NetworkPolicyIngressRule{{From: peer("client"), Ports: ports}}}},
		{ObjectMeta: meta("client"), Spec: networkingv1.NetworkPolicySpec{PodSelector: probeSel("client"), PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{To: peer("deny"), Ports: ports}, {To: peer("allow"), Ports: ports}}}},
	}
}

// netpolProbe proves NetworkPolicies are enforced: from the client, the
// deny listener must be unreachable and the allow listener reachable.
// Everything it creates is deleted (background context).
func (g *Guard) netpolProbe(ctx context.Context) error {
	return RunNetpolProbe(ctx, g.cfg.Client, g.cfg.Exec, g.cfg.AppsNamespace, g.cfg.HubImage, g.cfg.Clock, g.cfg.Sleep)
}

// RunNetpolProbe is the probe (see netpolProbe).
func RunNetpolProbe(ctx context.Context, c kubernetes.Interface, ex Execer, ns, image string, clock func() time.Time, sleep func(context.Context, time.Duration) error) error {
	if ex == nil || image == "" {
		return errors.New("no exec transport or no Hub image")
	}
	pods := c.CoreV1().Pods(ns)
	pols := c.NetworkingV1().NetworkPolicies(ns)
	var made []string
	var madePols []string
	defer func() {
		bg := context.Background()
		for _, n := range made {
			if err := pods.Delete(bg, n, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				_ = err
			}
		}
		for _, n := range madePols {
			pols.Delete(bg, n, metav1.DeleteOptions{})
		}
	}()
	for _, p := range probePolicies(ns) {
		pols.Delete(ctx, p.Name, metav1.DeleteOptions{})
		if _, err := pols.Create(ctx, p, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
			return fmt.Errorf("probe policy: %v", err)
		}
		madePols = append(madePols, p.Name)
	}
	ip := map[string]string{}
	var client string
	for _, role := range []string{"deny", "allow", "client"} {
		p := probePod(ns, image, role, role != "client")
		if _, err := pods.Create(ctx, p, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
			return fmt.Errorf("probe pod: %v", err)
		}
		made = append(made, p.Name)
		if role == "client" {
			client = p.Name
		}
	}
	deadline := clock().Add(probeReady)
	for _, n := range made {
		for {
			p, err := pods.Get(ctx, n, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" && podReadyOrRunning(*p) {
				ip[p.Labels[LabelProbe]] = p.Status.PodIP
				break
			}
			if !clock().Before(deadline) {
				return fmt.Errorf("probe pod %s didn't run within %s", n, probeReady)
			}
			if err := sleep(ctx, 500*time.Millisecond); err != nil {
				return err
			}
		}
	}
	dial := func(role string) error {
		var out bytes.Buffer
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return ex.Exec(dctx, ns, client, "probe", []string{"hub", "helper", "dial", ip[role] + ":8080"}, nil, &out, &out)
	}
	// The policies may take a moment to apply: the allowed dial is
	// retried, the denied one must fail every time it's tried.
	var allowErr error
	for i := 0; i < 10; i++ {
		if allowErr = dial("allow"); allowErr == nil {
			break
		}
		if err := sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	if allowErr != nil {
		return fmt.Errorf("the allowed connection failed: %v", allowErr)
	}
	for i := 0; i < 3; i++ {
		if err := dial("deny"); err == nil {
			return errors.New("a connection the policy denies succeeded: NetworkPolicies are not enforced")
		}
	}
	return nil
}

func podReadyOrRunning(p corev1.Pod) bool {
	for _, c := range p.Status.ContainerStatuses {
		if c.State.Running == nil {
			return false
		}
	}
	return true
}
