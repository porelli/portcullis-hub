package kube

import (
	"context"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// TestPodShapesOf: each Deployment's pods with the translator's requests
// (50m CPU per container, memory = mem_limit or 512Mi); a scale 0
// service has no replica, a job no shape.
func TestPodShapesOf(t *testing.T) {
	in := inputOf(t, `services:
  a:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
  b:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
    mem_limit: 256m
  off:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
    scale: 0
`, "shape")
	got, err := PodShapesOf(translateOK(t, in))
	if err != nil {
		t.Fatal(err)
	}
	want := []runtime.PodShape{
		{Workload: "shape--a", Replicas: 1, CPUm: 50, MemBytes: 512 << 20},
		{Workload: "shape--b", Replicas: 1, CPUm: 50, MemBytes: 256 << 20},
		{Workload: "shape--off", Replicas: 0, CPUm: 50, MemBytes: 512 << 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PodShapesOf = %+v\nwant %+v", got, want)
	}
}

// TestBackendPodShapesResolvesNothing: the backend renders the shapes
// without asking the registry and applies nothing.
func TestBackendPodShapesResolvesNothing(t *testing.T) {
	c := newCluster(t)
	r := &fakeResolver{}
	b := c.backend(t)
	b.cfg.Resolver = r
	got, err := b.PodShapes(context.Background(), project(t, `services:
  web:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
`, "shp"))
	if err != nil || len(got) != 1 || got[0].Workload != "shp--web" || got[0].Replicas != 1 {
		t.Fatalf("PodShapes = %+v %v", got, err)
	}
	if len(r.calls) != 0 {
		t.Errorf("resolved %v", r.calls)
	}
	if acts := c.dyn.Actions(); len(acts) != 0 {
		t.Errorf("cluster actions %v", acts)
	}
}
