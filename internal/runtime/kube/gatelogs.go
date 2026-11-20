package kube

import (
	"context"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/portcullis/hub/internal/gatelogs"
)

// CoreReplicas lists a core component's pods in the core namespace (the
// Hub's pods list there, contract §6; §20.10 "finds the replicas"): the
// gates' StatefulSet pods and wg's. Only pods labelled with component and
// named after it (the same double-check as the readers', isReader) count;
// a pod being deleted is left out. A pod that isn't Running or has no
// address yet is listed without one: its log can't be read, so the read
// is incomplete.
func (b *Backend) CoreReplicas(component string) gatelogs.Lister {
	return func(ctx context.Context) ([]gatelogs.Replica, error) {
		pods, err := b.cfg.Client.CoreV1().Pods(b.cfg.CoreNamespace).List(ctx, metav1.ListOptions{LabelSelector: LabelComponent + "=" + component})
		if err != nil {
			return nil, err
		}
		out := []gatelogs.Replica{}
		for _, p := range pods.Items {
			if p.DeletionTimestamp != nil || p.Labels[LabelComponent] != component || !strings.HasPrefix(p.Name, component+"-") {
				continue
			}
			if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				continue // a finished pod of a rollout, never coming back
			}
			r := gatelogs.Replica{Name: p.Name}
			if p.Status.Phase == corev1.PodRunning {
				r.Addr = p.Status.PodIP
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
}
