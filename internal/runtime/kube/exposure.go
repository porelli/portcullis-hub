package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/watch"

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
		l, err := b.cfg.Dynamic.Resource(kinds[k]).Namespace(b.cfg.EdgeNamespace).List(ctx, metav1.ListOptions{LabelSelector: LabelInstance + "=" + instance + "," + LabelOwner + "=" + OwnerHub})
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
	want, err := IngressObjects(instance, b.cfg.EdgeNamespace, b.cfg.Namespace, labels)
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

// GatewayPod is a wired provider's gateway pod as published: its IP and
// its UID (a pod reusing the IP is another pod).
type GatewayPod struct{ IP, UID string }

// gatewayPublished is what may be published from pods (K5, fail
// closed): per instance the one pod labelled portcullis.io/vpn-slot that
// is Running and Ready with an IPv4 address and not terminating; two
// such pods for one instance → neither.
func gatewayPublished(pods map[string]*corev1.Pod) map[string]GatewayPod {
	out := map[string]GatewayPod{}
	seen := map[string]int{}
	for _, p := range pods {
		inst := p.Labels[LabelInstance]
		if inst == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || strings.Contains(p.Status.PodIP, ":") || !podReady(*p) {
			continue
		}
		seen[inst]++
		out[inst] = GatewayPod{IP: p.Status.PodIP, UID: string(p.UID)}
	}
	for inst, n := range seen {
		if n > 1 {
			delete(out, inst)
		}
	}
	return out
}

// GatewayIPs is a one-shot read of the published gateways (tests,
// status).
func (b *Backend) GatewayIPs(ctx context.Context) (map[string]GatewayPod, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	l, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelVPNSlot + "," + LabelInstance})
	if err != nil {
		return nil, err
	}
	pods := map[string]*corev1.Pod{}
	for i := range l.Items {
		pods[string(l.Items[i].UID)] = &l.Items[i]
	}
	return gatewayPublished(pods), nil
}

// WatchGateways keeps fn told of the published gateways (K5): a list,
// then a watch from its resourceVersion; every event recomputes and fn
// hears every change at once (a delete, not-Ready, a terminating pod, a
// new UID or IP unpublishes before anything else). When the watch can't
// be started or ends, fn gets an empty map (nothing is trusted while it
// can't be confirmed) and the list+watch starts again after a pause.
// Returns when ctx ends.
func (b *Backend) WatchGateways(ctx context.Context, fn func(map[string]GatewayPod)) {
	var last map[string]GatewayPod
	emit := func(m map[string]GatewayPod) {
		if last == nil || !maps.EqualFunc(last, m, func(a, b GatewayPod) bool { return a == b }) {
			last = m
			fn(m)
		}
	}
	pause := time.Second
	for ctx.Err() == nil {
		if err := b.watchGatewaysOnce(ctx, emit); err != nil && ctx.Err() == nil {
			log.Printf("kube: the VPN gateway watch broke (%v): no gateway is published until it is back", err)
		}
		emit(map[string]GatewayPod{}) // fail closed
		if b.cfg.Sleep(ctx, pause) != nil {
			return
		}
		if pause < 30*time.Second {
			pause *= 2
		}
	}
}

func (b *Backend) watchGatewaysOnce(ctx context.Context, emit func(map[string]GatewayPod)) error {
	if err := b.gate(); err != nil {
		return err
	}
	sel := LabelVPNSlot + "," + LabelInstance
	podsAPI := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace)
	l, err := podsAPI.List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return err
	}
	pods := map[string]*corev1.Pod{}
	for i := range l.Items {
		pods[string(l.Items[i].UID)] = &l.Items[i]
	}
	w, err := podsAPI.Watch(ctx, metav1.ListOptions{LabelSelector: sel, ResourceVersion: l.ResourceVersion})
	if err != nil {
		return err
	}
	defer w.Stop()
	emit(gatewayPublished(pods))
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.ResultChan():
			if !ok {
				return errors.New("the watch ended")
			}
			switch ev.Type {
			case watch.Error:
				return fmt.Errorf("watch error: %v", apierrors.FromObject(ev.Object))
			case watch.Deleted:
				if p, ok := ev.Object.(*corev1.Pod); ok {
					delete(pods, string(p.UID))
				}
			case watch.Added, watch.Modified:
				if p, ok := ev.Object.(*corev1.Pod); ok {
					pods[string(p.UID)] = p.DeepCopy()
				}
			}
			emit(gatewayPublished(pods))
		}
	}
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
