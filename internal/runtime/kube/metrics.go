package kube

// Usage on Kubernetes (contract §6 "On Kubernetes", §11.11): CPU and
// memory per container from metrics.k8s.io PodMetrics (metrics-server),
// one namespaced list cached for 10 s so a sweep makes one API call (U8).
// PIDs, network and block IO stay nil: kubelet stats need nodes/stats or
// nodes/proxy, which the Hub is never granted.

import (
	"context"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"

	"github.com/portcullis/hub/internal/runtime"
)

// PodMetricsGVR is metrics-server's pod metrics resource.
var PodMetricsGVR = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}

// metricsTTL: one list serves every Stats call of a sweep.
const metricsTTL = 10 * time.Second

// The fixed reasons (contract §11.11).
const (
	whyNoMetricsAPI = "the cluster has no metrics API (metrics-server)"
	whyMetricsRole  = "the Hub's Role can't read pod metrics"
	whyNoMetricsYet = "no metrics yet"
)

// metricsCache is the last pod metrics list (by pod, then container).
type metricsCache struct {
	mu   sync.Mutex
	at   time.Time
	err  error
	pods map[string]metricsv1beta1.PodMetrics
}

// metricsList is the namespace's pod metrics, from a list at most
// metricsTTL old (an error is cached as long).
func (b *Backend) metricsList(ctx context.Context) (map[string]metricsv1beta1.PodMetrics, error) {
	c := &b.metrics
	c.mu.Lock()
	defer c.mu.Unlock()
	now := b.cfg.Clock()
	if !c.at.IsZero() && now.Sub(c.at) < metricsTTL {
		return c.pods, c.err
	}
	c.at, c.pods, c.err = now, nil, nil
	if b.cfg.Dynamic == nil {
		c.err = &runtime.NotMeasuredError{Why: whyNoMetricsAPI}
		return nil, c.err
	}
	l, err := b.cfg.Dynamic.Resource(PodMetricsGVR).Namespace(b.cfg.Namespace).List(ctx, metav1.ListOptions{})
	switch {
	case err == nil:
	case apierrors.IsNotFound(err), apierrors.IsServiceUnavailable(err):
		c.err = &runtime.NotMeasuredError{Why: whyNoMetricsAPI}
		return nil, c.err
	case apierrors.IsForbidden(err):
		c.err = &runtime.NotMeasuredError{Why: whyMetricsRole}
		return nil, c.err
	default:
		// Not cached: the next sweep asks again.
		c.at = time.Time{}
		return nil, err
	}
	pods := map[string]metricsv1beta1.PodMetrics{}
	for _, it := range l.Items {
		var pm metricsv1beta1.PodMetrics
		if err := k8sruntime.DefaultUnstructuredConverter.FromUnstructured(it.Object, &pm); err != nil {
			continue
		}
		pods[pm.Name] = pm
	}
	c.pods = pods
	return pods, nil
}

// Stats is one container's CPU (a gauge) and working set from the pod
// metrics list; everything else is nil.
func (b *Backend) Stats(ctx context.Context, id string) (runtime.UnitStats, error) {
	if err := b.gate(); err != nil {
		return runtime.UnitStats{}, err
	}
	pod, cn, err := splitID(id)
	if err != nil {
		return runtime.UnitStats{}, err
	}
	pods, err := b.metricsList(ctx)
	if err != nil {
		return runtime.UnitStats{}, err
	}
	pm, ok := pods[pod]
	if !ok {
		return runtime.UnitStats{}, &runtime.NotMeasuredError{Why: whyNoMetricsYet}
	}
	for _, c := range pm.Containers {
		if c.Name != cn {
			continue
		}
		s := runtime.UnitStats{Read: pm.Timestamp.Time}
		if q, ok := c.Usage["cpu"]; ok {
			v := float64(q.MilliValue()) / 1000
			s.CPUCores = &v
		}
		if q, ok := c.Usage["memory"]; ok && q.Value() >= 0 {
			v := uint64(q.Value())
			s.MemWorkingSet = &v
		}
		return s, nil
	}
	return runtime.UnitStats{}, &runtime.NotMeasuredError{Why: whyNoMetricsYet}
}

// notMeasuredKube: writable layers and images live behind the CRI, which
// the Hub never reaches.
var notMeasuredKube = &runtime.NotMeasuredError{Why: "not measured on Kubernetes"}

func (b *Backend) LayerSize(context.Context, string) (int64, error) { return 0, notMeasuredKube }

func (b *Backend) ImageSize(context.Context, string) (int64, error) { return 0, notMeasuredKube }
