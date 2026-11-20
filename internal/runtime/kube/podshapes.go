package kube

import (
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/portcullis/hub/internal/runtime"
)

// PodShapesOf are pl's Deployments as pods (§20.7's N−1 model): each
// Deployment's name, replicas and its pod's requests — the containers'
// sum, at least the largest init container's (the scheduler's rule).
// Jobs are left out (they run to completion).
func PodShapesOf(pl Plan) ([]runtime.PodShape, error) {
	var out []runtime.PodShape
	for _, o := range pl.Objects() {
		if o.GetKind() != "Deployment" {
			continue
		}
		var d appsv1.Deployment
		if err := kruntime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &d); err != nil {
			return nil, fmt.Errorf("deployment %s: %w", o.GetName(), err)
		}
		replicas := 1
		if d.Spec.Replicas != nil {
			replicas = int(*d.Spec.Replicas)
		}
		cpu, mem := podRequests(d.Spec.Template.Spec)
		out = append(out, runtime.PodShape{Workload: d.Name, Replicas: replicas, CPUm: cpu, MemBytes: mem})
	}
	slices.SortFunc(out, func(a, b runtime.PodShape) int {
		switch {
		case a.Workload < b.Workload:
			return -1
		case a.Workload > b.Workload:
			return 1
		}
		return 0
	})
	return out, nil
}

// podRequests is a pod spec's effective requests (millicores, bytes).
func podRequests(s corev1.PodSpec) (int64, int64) {
	var cpu, mem int64
	for _, c := range s.Containers {
		cpu += c.Resources.Requests.Cpu().MilliValue()
		mem += c.Resources.Requests.Memory().Value()
	}
	for _, c := range s.InitContainers {
		cpu = max(cpu, c.Resources.Requests.Cpu().MilliValue())
		mem = max(mem, c.Resources.Requests.Memory().Value())
	}
	return cpu, mem
}
