package kube

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/portcullis/hub/internal/gatelogs"
)

// ReplicaOptions describe a core component's pods for CoreReplicas:
// StatefulSet (the gates: pods <component>-<ordinal> owned by the
// StatefulSet <component>) or not (wg: a Deployment's pods, owned by a
// ReplicaSet <component>-<hash>); Expected the replica count the chart
// runs (HUB_GATE_REPLICAS; 0 = unknown: inferred from the ordinals seen).
type ReplicaOptions struct {
	StatefulSet bool
	Expected    int
}

// Replica listing constants.
const (
	// ordinalMemory: an ordinal seen this recently still counts as
	// expected when its pod is gone (between delete and re-create); after
	// a scale-down the read is incomplete for this long.
	ordinalMemory = 10 * time.Minute
	// listCache: one pods list serves the reads of this long (a history
	// page reads day by day).
	listCache = 2 * time.Second
	// maxOrdinals bounds the ordinals considered.
	maxOrdinals = 64
)

// CoreReplicas lists a core component's pods in the core namespace (the
// Hub's pods list there, contract §6; §20.10 "finds the replicas"). A
// pod counts only when it carries the component label and its controller
// is the component's own (the StatefulSet <component>, its pods named
// <component>-<ordinal>; or a ReplicaSet <component>-<hash>, its pods
// named after it). A pod that is Running with an address is readable;
// one that is pending, terminating or failed is listed without an
// address (unreadable: the read is incomplete); a Succeeded one is left
// out. For a StatefulSet, every expected ordinal without a pod
// (Expected, or any seen in the last ordinalMemory) is listed without an
// address too.
func (b *Backend) CoreReplicas(component string, o ReplicaOptions) gatelogs.Lister {
	stsName := regexp.MustCompile(`^` + regexp.QuoteMeta(component) + `-(0|[1-9][0-9]{0,2})$`)
	rsName := regexp.MustCompile(`^` + regexp.QuoteMeta(component) + `-[a-z0-9]{1,16}$`)
	var (
		mu     sync.Mutex
		seen   = map[int]time.Time{}
		cached []gatelogs.Replica
		at     time.Time
	)
	return func(ctx context.Context) ([]gatelogs.Replica, error) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if cached != nil && now.Sub(at) < listCache {
			return append([]gatelogs.Replica(nil), cached...), nil
		}
		pods, err := b.cfg.Client.CoreV1().Pods(b.cfg.CoreNamespace).List(ctx, metav1.ListOptions{LabelSelector: LabelComponent + "=" + component})
		if err != nil {
			return nil, err
		}
		out := []gatelogs.Replica{}
		have := map[int]bool{}
		for _, p := range pods.Items {
			if p.Labels[LabelComponent] != component || p.Status.Phase == corev1.PodSucceeded {
				continue
			}
			ref := metav1.GetControllerOf(&p)
			if ref == nil || ref.APIVersion != "apps/v1" {
				continue
			}
			if o.StatefulSet {
				m := stsName.FindStringSubmatch(p.Name)
				if ref.Kind != "StatefulSet" || ref.Name != component || m == nil {
					continue
				}
				n, _ := strconv.Atoi(m[1])
				if n >= maxOrdinals {
					continue
				}
				have[n], seen[n] = true, now
			} else if ref.Kind != "ReplicaSet" || !rsName.MatchString(ref.Name) || len(p.Name) <= len(ref.Name)+1 || p.Name[:len(ref.Name)+1] != ref.Name+"-" {
				continue
			}
			r := gatelogs.Replica{Name: p.Name}
			if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
				r.Addr = p.Status.PodIP
			}
			out = append(out, r)
		}
		if o.StatefulSet {
			expected := min(o.Expected, maxOrdinals)
			for n, t := range seen {
				if now.Sub(t) > ordinalMemory {
					delete(seen, n)
					continue
				}
				expected = max(expected, n+1)
			}
			for n := 0; n < expected; n++ {
				if !have[n] {
					out = append(out, gatelogs.Replica{Name: component + "-" + strconv.Itoa(n)})
				}
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		cached, at = out, now
		return append([]gatelogs.Replica(nil), out...), nil
	}
}
