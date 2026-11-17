package kube

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	"github.com/portcullis/hub/internal/runtime"
)

// metricsCluster answers the pod metrics list with items (or err) and
// counts the lists.
func metricsCluster(t *testing.T, err error, items ...map[string]any) (*cluster, *int) {
	c := newCluster(t)
	n := 0
	c.dyn.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		if a.GetResource().Group != "metrics.k8s.io" {
			return false, nil, nil
		}
		n++
		if err != nil {
			return true, nil, err
		}
		l := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": "metrics.k8s.io/v1beta1", "kind": "PodMetricsList"}}
		for _, it := range items {
			l.Items = append(l.Items, unstructured.Unstructured{Object: it})
		}
		return true, l, nil
	})
	return c, &n
}

func podMetrics(pod, container, cpu, mem string) map[string]any {
	return map[string]any{"apiVersion": "metrics.k8s.io/v1beta1", "kind": "PodMetrics",
		"metadata": map[string]any{"name": pod, "namespace": ns}, "timestamp": "2026-11-14T00:00:00Z", "window": "15s",
		"containers": []any{map[string]any{"name": container, "usage": map[string]any{"cpu": cpu, "memory": mem}}}}
}

func TestKubeStatsFromPodMetrics(t *testing.T) {
	c, _ := metricsCluster(t, nil, podMetrics("app--web-abc", "web", "250m", "64Mi"))
	b := c.backend(t)
	s, err := b.Stats(context.Background(), "app--web-abc/web")
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUCores == nil || *s.CPUCores != 0.25 || s.MemWorkingSet == nil || *s.MemWorkingSet != 64<<20 {
		t.Errorf("stats = %+v", s)
	}
	if s.Pids != nil || s.NetRx != nil || s.BlkRead != nil || s.CPUUsageNS != nil || s.Read.IsZero() {
		t.Errorf("not nil: %+v", s)
	}
	var nm *runtime.NotMeasuredError
	if _, err := b.Stats(context.Background(), "other/web"); !errors.As(err, &nm) || nm.Why != "no metrics yet" {
		t.Errorf("unknown pod: %v", err)
	}
	if _, err := b.Stats(context.Background(), "app--web-abc/db"); !errors.As(err, &nm) {
		t.Errorf("unknown container: %v", err)
	}
}

func TestKubeStatsOneListPerSweep(t *testing.T) {
	c, n := metricsCluster(t, nil, podMetrics("p", "web", "1", "1Mi"))
	b := c.backend(t)
	for range 10 {
		b.Stats(context.Background(), "p/web")
		c.mu.Lock()
		c.clock = c.clock.Add(500 * time.Millisecond)
		c.mu.Unlock()
	}
	if *n != 1 {
		t.Errorf("%d lists within 10 s", *n)
	}
	c.mu.Lock()
	c.clock = c.clock.Add(11 * time.Second)
	c.mu.Unlock()
	b.Stats(context.Background(), "p/web")
	if *n != 2 {
		t.Errorf("%d lists after the TTL", *n)
	}
}

func TestKubeStatsNoMetricsAPI(t *testing.T) {
	gr := schema.GroupResource{Group: "metrics.k8s.io", Resource: "pods"}
	for name, c := range map[string]struct {
		err error
		why string
	}{
		"404": {apierrors.NewNotFound(gr, ""), "the cluster has no metrics API (metrics-server)"},
		"503": {apierrors.NewServiceUnavailable("metrics-server down"), "the cluster has no metrics API (metrics-server)"},
		"403": {apierrors.NewForbidden(gr, "", errors.New("no")), "the Hub's Role can't read pod metrics"},
	} {
		cl, _ := metricsCluster(t, c.err)
		_, err := cl.backend(t).Stats(context.Background(), "p/web")
		var nm *runtime.NotMeasuredError
		if !errors.As(err, &nm) || nm.Why != c.why {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKubeInspectOOMAndLimits(t *testing.T) {
	c := newCluster(t)
	started := metav1.NewTime(time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC))
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app--web-x", Namespace: ns, Labels: map[string]string{LabelInstance: "app"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
			VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}, {Name: "media", MountPath: "/media", ReadOnly: true}}}},
			Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "app--data"}}},
				{Name: "media", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv/media"}}}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "web", RestartCount: 2,
			State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: started}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}}}
	if _, err := c.typed.CoreV1().Pods(ns).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	i, err := c.backend(t).Inspect(context.Background(), "app--web-x/web")
	if err != nil {
		t.Fatal(err)
	}
	if !i.OOMKilled || i.RestartCount != 2 || i.NanoCPUs != 5e8 || i.Memory != 64<<20 || i.NetworkMode != "pod" || !i.StartedAt.Equal(started.Time) {
		t.Errorf("inspect = %+v", i)
	}
	if want := []runtime.UnitMount{{Type: "volume", Name: "app--data", Destination: "/data", RW: true}, {Type: "bind", Source: "/srv/media", Destination: "/media"}}; !slices.Equal(i.Mounts, want) {
		t.Errorf("mounts = %+v", i.Mounts)
	}
	var nm *runtime.NotMeasuredError
	b := c.backend(t)
	if _, err := b.LayerSize(context.Background(), "x"); !errors.As(err, &nm) || nm.Why != "not measured on Kubernetes" {
		t.Errorf("layer: %v", err)
	}
	if _, err := b.ImageSize(context.Background(), "x"); !errors.As(err, &nm) {
		t.Errorf("image: %v", err)
	}
}

// TestKubeRunFixerVolume: the usage helper is the volume kind's pod with
// the PVC read-only at /vol, DAC_OVERRIDE only, a read-only root, and the
// exec argv is the spec's.
func TestKubeRunFixerVolume(t *testing.T) {
	c := helperCluster(t, "")
	var made *corev1.Pod
	c.typed.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		made = a.(k8stesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
		return false, nil, nil
	})
	b := c.backend(t)
	ex := &volExecer{}
	b.cfg.Exec = ex
	cmd := []string{"/usr/local/bin/hub", "folderfix", "usage", "--root=/vol", "--max-entries=2000000", "--max-time=2m0s"}
	s := runtime.FixerSpec{Image: hubImage, Cmd: cmd, User: "0:0", CapAdd: []string{"DAC_READ_SEARCH"}, Label: "usage:app--data",
		Pids: 16, Memory: 256 << 20, Timeout: time.Minute, Volumes: []runtime.VolumeMount{{Name: "app--data", Target: "/vol", Instance: "app"}}}
	if _, err := b.RunFixer(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	if made == nil {
		t.Fatal("no pod")
	}
	ct := made.Spec.Containers[0]
	if made.Labels[LabelHelper] != HelperVolume || made.Labels[LabelInstance] != "app" {
		t.Errorf("labels %v", made.Labels)
	}
	if len(made.Spec.Volumes) != 1 || made.Spec.Volumes[0].PersistentVolumeClaim == nil || made.Spec.Volumes[0].PersistentVolumeClaim.ClaimName != "app--data" ||
		!made.Spec.Volumes[0].PersistentVolumeClaim.ReadOnly || len(ct.VolumeMounts) != 1 || ct.VolumeMounts[0].MountPath != "/vol" || !ct.VolumeMounts[0].ReadOnly {
		t.Errorf("volumes %+v mounts %+v", made.Spec.Volumes, ct.VolumeMounts)
	}
	if caps := ct.SecurityContext.Capabilities.Add; !slices.Equal(caps, []corev1.Capability{"DAC_OVERRIDE"}) || !*ct.SecurityContext.ReadOnlyRootFilesystem {
		t.Errorf("caps %v", caps)
	}
	if len(ex.calls) != 1 || strings.Join(ex.calls[0], " ") != strings.Join(cmd, " ") {
		t.Errorf("exec %v", ex.calls)
	}
	s.Binds = []runtime.BindMount{{Source: "/srv/x", Target: "/x", ReadOnly: true}}
	if _, err := b.RunFixer(context.Background(), s, nil); err == nil {
		t.Error("binds with a volume accepted")
	}
	s.Binds, s.Volumes = nil, append(s.Volumes, runtime.VolumeMount{Name: "app--other", Target: "/vol2"})
	if _, err := b.RunFixer(context.Background(), s, nil); err == nil {
		t.Error("two volumes accepted")
	}
}
