package hub

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
)

func TestComputeDrift(t *testing.T) {
	enabled := map[string]bool{"up": true, "down": true, "stopped": true, "gone": true, "busy": true}
	known := map[string]bool{"up": true, "down": true, "stopped": true, "orphan": true, "busy": true}
	counts := map[string]projectCount{
		"up":       {running: 2, total: 3}, // one-shot sidecar exited: not drift
		"stopped":  {running: 0, total: 2},
		"orphan":   {running: 1, total: 1},
		"stranger": {running: 1, total: 1},
		"leftover": {running: 0, total: 1},
	}
	got := computeDrift(enabled, known, counts, func(id string) bool { return id == "busy" })
	type row struct {
		id      string
		kind    DriftKind
		actions string
	}
	var rows []row
	for _, d := range got {
		rows = append(rows, row{d.ID, d.Kind, strings.Join(d.Actions, ",")})
	}
	want := []row{
		{"down", DriftNotRunning, "start,disable"},
		{"gone", DriftTemplateMissing, "disable"},
		{"leftover", DriftLeftovers, "stop"},
		{"orphan", DriftNotEnabled, "stop,adopt"},
		{"stopped", DriftNotRunning, "start,disable"},
		{"stranger", DriftNotEnabled, "stop"}, // no template: cannot adopt
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("drift =\n%v\nwant\n%v", rows, want)
	}
}

func TestReconcile(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	f.engine.containers = []docker.Container{
		container("c1", "portcullis-grafana", "grafana", "exited"),
		container("c2", "portcullis-other", "web", "running"),
		container("c3", "portcullis", "traefik", "running"),   // core project: ignored
		container("c4", "portcullis-Bad..ID", "x", "running"), // invalid id: ignored
		container("c5", "something-else", "x", "running"),     // not ours
	}
	oneoff := container("c6", "portcullis-grafana", "grafana", "running")
	oneoff.Labels[docker.LabelOneoff] = "True"
	f.engine.containers = append(f.engine.containers, oneoff) // `compose run`: ignored

	rep := f.h.Reconcile(context.Background())
	if rep.Error != "" || len(rep.Items) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Items[0].ID != "grafana" || rep.Items[0].Kind != DriftNotRunning ||
		rep.Items[1].ID != "other" || rep.Items[1].Kind != DriftNotEnabled || !rep.Items[1].TemplateExists {
		t.Errorf("items = %+v", rep.Items)
	}
	if got := f.h.Drift(); len(got.Items) != 2 {
		t.Errorf("stored drift = %+v", got)
	}

	// Docker unreachable: error reported, last known items kept.
	f.engine.listErr = errors.New("connection refused")
	rep = f.h.Reconcile(context.Background())
	if rep.Error == "" || len(rep.Items) != 2 {
		t.Errorf("report on error = %+v", rep)
	}
	f.engine.listErr = nil

	// Reconcile never changes anything by itself.
	if !f.h.IsEnabled("grafana") || f.h.IsEnabled("other") {
		t.Error("reconcile changed state")
	}
}

func TestResolveDrift(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	n := len(f.runner.Calls())

	if err := f.h.ResolveDrift("../x", ActionStop); statusOf(err) != 400 {
		t.Errorf("invalid id: %v", err)
	}
	if err := f.h.ResolveDrift("grafana", "rm -rf"); statusOf(err) != 400 {
		t.Errorf("unknown action: %v", err)
	}
	if err := f.h.ResolveDrift("grafana", ActionStop); statusOf(err) != 400 {
		t.Errorf("stop of enabled app must be refused: %v", err)
	}
	if err := f.h.ResolveDrift("other", ActionStart); statusOf(err) != 400 {
		t.Errorf("start of disabled app must be refused: %v", err)
	}
	if err := f.h.ResolveDrift("stranger", ActionAdopt); statusOf(err) != 400 {
		t.Errorf("adopt without template must be refused: %v", err)
	}

	if err := f.h.ResolveDrift("grafana", ActionStart); err != nil {
		t.Fatal(err)
	}
	if err := f.h.ResolveDrift("stranger", ActionStop); err != nil {
		t.Fatal(err)
	}
	c := f.runner.Calls()[n:]
	if strings.Join(c, " ") != "up:portcullis-grafana downbyname:portcullis-stranger" {
		t.Errorf("calls = %v", c)
	}
	if err := f.h.ResolveDrift("grafana", ActionDisable); err != nil || f.h.IsEnabled("grafana") {
		t.Errorf("disable: %v", err)
	}
	f.h.SaveSettings("other", SettingsUpdate{Values: map[string]string{"OTHER_PORT": "3301"}})
	if err := f.h.ResolveDrift("other", ActionAdopt); err != nil || !f.h.IsEnabled("other") {
		t.Errorf("adopt: %v", err)
	}
}

func TestRuntime(t *testing.T) {
	f := newFixture(t)
	r1 := container("w1", "portcullis-other", "web", "running")
	r2 := container("w2", "portcullis-other", "web", "running")
	r2.Labels[docker.LabelNumber] = "2"
	r2.Names = []string{"/portcullis-other-web-2"}
	stopped := container("k1", "portcullis-other", "worker", "exited")
	foreign := container("x1", "portcullis-other", "notinfile", "running")
	f.engine.containers = []docker.Container{r2, r1, stopped, foreign, container("g1", "portcullis-grafana", "grafana", "running")}
	f.engine.logs = map[string]string{
		"w1": "2024-01-01T00:00:02Z second\n",
		"w2": "2024-01-01T00:00:01Z first\n",
		"k1": "2024-01-01T00:00:03Z worker\n",
	}
	ctx := context.Background()

	st, err := f.h.Status(ctx, "other")
	if err != nil || len(st) != 3 {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if _, err := f.h.Status(ctx, "nope"); statusOf(err) != 404 {
		t.Errorf("unknown app: %v", err)
	}

	logs, err := f.h.Logs(ctx, "other", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := "portcullis-other-web-2     | first\nportcullis-other-web-1     | second\nportcullis-other-worker-1  | worker\n"
	if string(logs) != want {
		t.Errorf("logs =\n%q\nwant\n%q", logs, want)
	}
	if logs, _ := f.h.Logs(ctx, "other", "worker", 100); string(logs) != "worker\n" {
		t.Errorf("service logs = %q", logs)
	}
	for _, c := range []struct {
		svc   string
		lines int
	}{{"-f", 10}, {"notinfile", 10}, {"web", 0}, {"web", 10001}} {
		if _, err := f.h.Logs(ctx, "other", c.svc, c.lines); statusOf(err) != 400 {
			t.Errorf("Logs(%q, %d) = %v", c.svc, c.lines, err)
		}
	}

	res, err := f.h.Exec(ctx, "other", "web", "id -u")
	if err != nil || res.Output != "ok\n" {
		t.Fatalf("exec = %+v, %v", res, err)
	}
	if f.engine.execID != "w1" || strings.Join(f.engine.execCmd, "|") != "/bin/sh|-c|id -u" {
		t.Errorf("exec target %s cmd %v", f.engine.execID, f.engine.execCmd)
	}
	if _, err := f.h.Exec(ctx, "other", "worker", "true"); statusOf(err) != 409 {
		t.Errorf("exec in stopped service: %v", err)
	}
	if _, err := f.h.Exec(ctx, "other", "notinfile", "true"); statusOf(err) != 400 {
		t.Errorf("exec in unknown service: %v", err)
	}
	if _, err := f.h.Exec(ctx, "other", "web", ""); statusOf(err) != 400 {
		t.Errorf("empty command: %v", err)
	}
	f.engine.execRes = &docker.ExecResult{Output: []byte("partial"), ExitCode: -1, TimedOut: true}
	if res, _ := f.h.Exec(ctx, "other", "web", "sleep 1000"); !strings.Contains(res.Output, "timed out") || res.ExitCode != -1 {
		t.Errorf("timeout result = %+v", res)
	}

	f.engine.listErr = errors.New("down")
	if _, err := f.h.Status(ctx, "other"); statusOf(err) != 502 {
		t.Errorf("docker down: %v", err)
	}
}
