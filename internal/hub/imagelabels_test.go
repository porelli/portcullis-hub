package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
)

// TestImageLabelsStopProject: a container whose image adds traefik.*
// labels compose wasn't given stops the project (fail closed) and the
// operation fails; reconcile reports the same as drift.
func TestImageLabelsStopProject(t *testing.T) {
	f := newFixture(t)
	c := container("g1", "portcullis-grafana", "grafana", "running")
	c.Labels["traefik.http.routers.grafana.rule"] = "Host(`grafana.example.org`)" // compose's own
	c.Labels["traefik.http.routers.sneaky.rule"] = "Host(`auth.example.org`)"     // from the image
	c.Labels["org.opencontainers.image.title"] = "grafana"                        // not traefik: fine
	f.engine.containers = []docker.Container{c}
	err := f.h.Enable("grafana")
	var oe *OpError
	if !errors.As(err, &oe) || statusOf(err) != 409 || !strings.Contains(oe.Record.Error, "traefik.http.routers.sneaky.rule") || !strings.Contains(oe.Record.Error, "image") {
		t.Fatalf("enable with image traefik labels = %v", err)
	}
	calls := strings.Join(f.runner.Calls(), " ")
	if !strings.Contains(calls, "up:portcullis-grafana") || !strings.Contains(calls, "down:portcullis-grafana") {
		t.Fatalf("calls = %s (want up then down)", calls)
	}
	if f.h.IsEnabled("grafana") {
		t.Fatal("left enabled")
	}
	// A running project of an enabled instance with such labels is drift.
	f.engine.containers = []docker.Container{}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	want, _ := f.h.desiredRouteLabelsLocked(f.h.findLocked("grafana"))
	f.h.mu.RUnlock()
	for k, v := range want["grafana"] {
		c.Labels[k] = v
	}
	f.engine.containers = []docker.Container{c}
	d := driftFor(f.h.Reconcile(context.Background()), "grafana")
	if d == nil || !strings.Contains(d.Message, "from the image") {
		t.Fatalf("drift = %+v", d)
	}
	// Folded keys count (Traefik reads them as routers).
	if x := extraTraefikKeys(map[string]bool{}, map[string]string{"Traefik.HTTP.Routers.x.Rule": "Host(`a.b`)"}); len(x) != 1 {
		t.Fatalf("folded key not caught: %v", x)
	}
}
