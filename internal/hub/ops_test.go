package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
)

func bindError(extra string) error {
	return &compose.Error{Command: "up", Err: errors.New("exit status 1"), Output: " Container portcullis-grafana-grafana-1  Creating\n" + extra +
		"Error response from daemon: failed to set up container networking: driver failed programming external connectivity on endpoint portcullis-grafana-grafana-1: failed to bind host port 0.0.0.0:53/tcp: address already in use\n"}
}

// The incident: compose up fails on a port held by a host service. The
// error carries compose's output and a hint, the half-created project is
// rolled back, the app stays disabled, the failure is recorded (and
// survives a restart of the Hub), and neither the fail-closed deny nor
// drift trips afterwards.
func TestEnableFailureExplainedAndRolledBack(t *testing.T) {
	f := newFixture(t)
	// What compose left behind before failing: a created, stopped container.
	c := container("c1", "portcullis-grafana", "grafana", "created")
	c.Labels["traefik.http.routers.grafana.rule"] = "Host(`grafana.example.org`)"
	f.engine.containers = []docker.Container{c}
	f.runner.onDown = func(project string) {
		f.engine.mu.Lock()
		defer f.engine.mu.Unlock()
		var keep []docker.Container
		for _, c := range f.engine.containers {
			if c.Project() != project {
				keep = append(keep, c)
			}
		}
		f.engine.containers = keep
	}
	// Reconcile mid-operation sees the leftovers: deny their subdomain.
	f.h.Reconcile(context.Background())
	if g := readPolicy(t, f).Groups["grafana"]; g != policy.DenyGroup {
		t.Fatalf("leftover project not denied: %q", g)
	}

	f.runner.upErr = bindError("")
	err := f.h.Enable("grafana")
	secret := readEnvFile(f.h.envPath("grafana"))["GF_SECRET"]
	if secret == "" {
		t.Fatal("no generated secret")
	}
	var oe *OpError
	if !errors.As(err, &oe) || statusOf(err) != 500 {
		t.Fatalf("err = %T %v", err, err)
	}
	r := oe.Record
	if r.Op != OpEnable || r.OK || !r.RolledBack ||
		!strings.Contains(r.Error, "address already in use") || !strings.Contains(r.Error, "rolled back") ||
		!strings.Contains(r.Output, "Creating") || !strings.Contains(r.Hint, "0.0.0.0:53/tcp") || !strings.Contains(r.Hint, "Settings") {
		t.Errorf("record = %+v", r)
	}
	if calls := strings.Join(f.runner.Calls(), " "); calls != "up:portcullis-grafana down:portcullis-grafana" {
		t.Errorf("calls = %s", calls)
	}
	if f.h.IsEnabled("grafana") {
		t.Error("enabled after a failed compose up")
	}
	if got := f.h.FailedOps()["grafana"]; got != OpEnable {
		t.Errorf("FailedOps = %v", f.h.FailedOps())
	}

	// Nothing is left: no drift, no deny entry.
	rep := f.h.Reconcile(context.Background())
	if len(rep.Items) != 0 {
		t.Errorf("drift after rollback: %+v", rep.Items)
	}
	if g, ok := readPolicy(t, f).Groups["grafana"]; ok {
		t.Errorf("grafana still in the policy file: %q", g)
	}

	// The record survives a Hub restart.
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	if lo := h2.LastOp("grafana"); lo == nil || lo.OK || lo.Output != r.Output {
		t.Errorf("reloaded record = %+v", lo)
	}

	// Secrets never reach the record.
	f.runner.upErr = bindError("WARN something echoed " + secret + "\n")
	err = f.h.Enable("grafana")
	if !errors.As(err, &oe) || strings.Contains(oe.Record.Output, secret) || !strings.Contains(oe.Record.Output, "[redacted]") {
		t.Errorf("secret not redacted: %q", oe.Record.Output)
	}
	data, _ := os.ReadFile(filepath.Join(f.data, "ops", "grafana.json"))
	if strings.Contains(string(data), secret) {
		t.Error("secret stored in the op record")
	}

	// A later success replaces the failure.
	f.runner.upErr = nil
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	if lo := f.h.LastOp("grafana"); lo == nil || !lo.OK || lo.Op != OpEnable {
		t.Errorf("record after success = %+v", lo)
	}
	if len(f.h.FailedOps()) != 0 {
		t.Errorf("FailedOps = %v", f.h.FailedOps())
	}
}

// A failed rollback says so (and leaves the drift banner to stop it).
func TestEnableRollbackFailure(t *testing.T) {
	f := newFixture(t)
	f.runner.upErr = bindError("")
	f.runner.downErr = errors.New("down broke")
	f.runner.byNameErr = errors.New("down by name broke")
	err := f.h.Enable("grafana")
	var oe *OpError
	if !errors.As(err, &oe) || oe.Record.RolledBack || !strings.Contains(oe.Record.Error, "rolling back (compose down) failed too") {
		t.Errorf("err = %v", err)
	}
}

// Hub-side refusals (pre-flight) are recorded too, without a rollback.
func TestEnablePreflightRecorded(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	n := len(f.runner.Calls())
	err := f.h.Enable("other") // both default to host port 3300
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "3300/tcp already claimed by enabled app grafana") {
		t.Fatalf("err = %v", err)
	}
	if len(f.runner.Calls()) != n {
		t.Errorf("compose ran: %v", f.runner.Calls()[n:])
	}
	if lo := f.h.LastOp("other"); lo == nil || lo.OK || lo.RolledBack {
		t.Errorf("record = %+v", lo)
	}
}

func TestRestartAppError(t *testing.T) {
	f := newFixture(t)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.runner.upErr = bindError("")
	err := f.h.RestartApp("grafana")
	var oe *OpError
	if !errors.As(err, &oe) || oe.Record.Op != OpRestart || oe.Record.Output == "" || oe.Record.Hint == "" {
		t.Fatalf("err = %v", err)
	}
	if !f.h.IsEnabled("grafana") {
		t.Error("a failed restart disabled the app")
	}
	// Background restarts (after a settings save) record their outcome too.
	f.runner.upErr = nil
	f.h.Restart(*f.h.Template("grafana"))
	if lo := f.h.LastOp("grafana"); lo == nil || !lo.OK || lo.Op != OpRestart {
		t.Errorf("record = %+v", lo)
	}
}

func TestOpHint(t *testing.T) {
	for in, want := range map[string]string{
		"Bind for 0.0.0.0:8080 failed: port is already allocated":                 "Host port 0.0.0.0:8080",
		"failed to bind host port [::]:53/udp: address already in use":            "Host port [::]:53/udp",
		"listen tcp4 0.0.0.0:443: bind: address already in use":                   "Host port 0.0.0.0:443",
		"Error response from daemon: something else entirely":                     "",
		"driver failed programming external connectivity: address already in use": "A host port",
	} {
		got := opHint(in)
		if want == "" && got != "" || want != "" && !strings.HasPrefix(got, want) {
			t.Errorf("opHint(%q) = %q", in, got)
		}
	}
}
