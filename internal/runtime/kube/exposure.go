package kube

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Exposure is an instance's live IngressRoutes and Middlewares: kind/name
// → spec (JSON).
type Exposure map[string]string

func exposureKey(o *unstructured.Unstructured) string { return o.GetKind() + "/" + o.GetName() }

// LiveExposure reads the instance's IngressRoutes and Middlewares.
func (b *Backend) LiveExposure(ctx context.Context, instance string) (Exposure, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	out := Exposure{}
	for _, k := range []string{"IngressRoute", "Middleware"} {
		l, err := b.cfg.Dynamic.Resource(kinds[k]).Namespace(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelInstance + "=" + instance})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		for i := range l.Items {
			o := &l.Items[i]
			if o.GetKind() == "" {
				o.SetKind(k)
			}
			spec, _ := json.Marshal(o.Object["spec"])
			out[exposureKey(o)] = string(spec)
		}
	}
	return out, nil
}

// ExposureDrift compares the live exposure with the objects the Hub
// renders now from labels ("" = equal): a missing, extra or changed
// IngressRoute or Middleware, named.
func (b *Backend) ExposureDrift(ctx context.Context, instance string, labels map[string]map[string]string) (string, error) {
	want, err := IngressObjects(instance, b.cfg.Namespace, labels)
	if err != nil {
		return "", err
	}
	live, err := b.LiveExposure(ctx, instance)
	if err != nil {
		return "", err
	}
	return live.Diff(want), nil
}

// Diff is how e differs from want ("" = not at all).
func (e Exposure) Diff(want []*unstructured.Unstructured) string {
	w := Exposure{}
	for _, o := range want {
		spec, _ := json.Marshal(o.Object["spec"])
		w[exposureKey(o)] = string(spec)
	}
	var out []string
	for _, k := range slices.Sorted(mapKeys(w)) {
		switch have, ok := e[k]; {
		case !ok:
			out = append(out, "missing "+strings.ToLower(k))
		case have != w[k]:
			out = append(out, strings.ToLower(k)+" differs")
		}
	}
	for _, k := range slices.Sorted(mapKeys(e)) {
		if _, ok := w[k]; !ok {
			out = append(out, "unexpected "+strings.ToLower(k))
		}
	}
	return strings.Join(out, ", ")
}

// GatewayIPs are the wired providers' gateway pods (label
// portcullis.io/vpn-slot) seen Running and Ready with an IPv4 address:
// instance → pod IP (K5). A pod being replaced is left out until its
// successor is Ready.
func (b *Backend) GatewayIPs(ctx context.Context) (map[string]string, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	l, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelVPNSlot + "," + LabelInstance})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	seen := map[string]int{}
	for _, p := range l.Items {
		inst := p.Labels[LabelInstance]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || strings.Contains(p.Status.PodIP, ":") || !podReady(p) {
			continue
		}
		seen[inst]++
		out[inst] = p.Status.PodIP
	}
	for inst, n := range seen {
		if n > 1 {
			delete(out, inst) // two gateways: which one is it? neither
		}
	}
	return out, nil
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
