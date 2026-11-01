package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

func driftFor(rep DriftReport, id string) *Drift {
	for i := range rep.Items {
		if rep.Items[i].ID == id {
			return &rep.Items[i]
		}
	}
	return nil
}

// An enabled app whose template disappears keeps being enforced from the
// snapshot persisted in state.yaml — across restarts too.
func TestMissingTemplateEnforcesSnapshot(t *testing.T) {
	f := newFixture(t)
	if err := f.h.SaveSettings("grafana", SettingsUpdate{Values: map[string]string{}, Policy: &policy.AuthPolicy{Factors: []string{"mtls"}}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	snap, ok := st.Published["grafana"]
	if !ok || strings.Join(snap.Subdomains, ",") != "grafana" || snap.AccessGroup != "users_grafana" ||
		snap.AdminGroup != "admin_grafana" || len(snap.AdminPaths) != 2 || snap.Policy == nil || snap.Policy.Factors[0] != "mtls" {
		t.Fatalf("snapshot = %+v", snap)
	}

	// The template stops loading (here: removed; same for a broken sync or
	// tightened validation).
	if err := os.RemoveAll(filepath.Join(f.src, "grafana")); err != nil {
		t.Fatal(err)
	}
	f.h.Discover()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		t.Helper()
		doc := readPolicy(t, f)
		if doc.Groups["grafana"] != "users_grafana" || len(doc.PathGroups["grafana"]) != 2 ||
			strings.Join(doc.Policies["grafana"].Factors, ",") != "mtls" {
			t.Errorf("%s: policy file lost the app: %+v", label, doc)
		}
	}
	check("after discover")

	// Restart the Hub from disk: still enforced.
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h2.Wait)
	h2.Init()
	check("after restart")
	f.h = h2

	f.engine.containers = []docker.Container{container("g1", "portcullis-grafana", "grafana", "running")}
	d := driftFor(f.h.Reconcile(context.Background()), "grafana")
	if d == nil || d.Kind != DriftTemplateMissing || !strings.Contains(d.Message, "still enforced from last known config") {
		t.Errorf("drift = %+v", d)
	}

	// Disabling removes both the snapshot and the entries.
	if err := f.h.Disable("grafana"); err != nil {
		t.Fatal(err)
	}
	st, _ = state.Load(filepath.Join(f.data, "state.yaml"))
	if _, ok := st.Published["grafana"]; ok {
		t.Error("snapshot kept after disable")
	}
	f.engine.containers = nil
	f.h.Reconcile(context.Background())
	if doc := readPolicy(t, f); doc.Groups["grafana"] != "" || len(doc.Policies) != 0 {
		t.Errorf("entries kept after disable: %+v", doc)
	}
}

// Snapshots follow the live template while it loads.
func TestSnapshotTracksLiveTemplate(t *testing.T) {
	f := newFixture(t)
	f.h.Enable("grafana")
	writeFile(t, filepath.Join(f.src, "grafana", "compose.yml"), "services:\n  grafana:\n    labels:\n      traefik.http.routers.g.rule: Host(`dash.${PORTCULLIS_DOMAIN}`)\n")
	f.h.Discover()
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if s := st.Published["grafana"].Subdomains; strings.Join(s, ",") != "dash" {
		t.Errorf("snapshot subdomains = %v", s)
	}
	f.h.SaveSettings("grafana", SettingsUpdate{Values: map[string]string{}, Inherit: true})
	st, _ = state.Load(filepath.Join(f.data, "state.yaml"))
	if st.Published["grafana"].Policy != nil {
		t.Error("snapshot still has the dropped override")
	}
}

// No template and no snapshot: deny every subdomain the app's running
// containers route; likewise for running projects that are not enabled.
func TestDenyWithoutConfig(t *testing.T) {
	f := newFixture(t)
	f.h.mu.Lock()
	f.h.st.SetEnabled("ghost", true) // e.g. state.yaml from a lost source, snapshot gone
	f.h.mu.Unlock()
	ghost := container("x1", "portcullis-ghost", "web", "running")
	ghost.Labels["traefik.http.routers.ghost.rule"] = "Host(`Ghost.example.org`) || Host(`ghost-api.example.org`) && PathPrefix(`/v1`)"
	ghost.Labels["traefik.http.routers.core.rule"] = "Host(`auth.example.org`)" // core: never published
	orphan := container("o1", "portcullis-stray", "web", "running")
	orphan.Labels["traefik.http.routers.stray.rule"] = "HostRegexp(`.+`) || Host(`stray.example.org`)"
	// A running-but-not-enabled container that shares a live app's
	// subdomain must not lock that app out.
	shadow := container("s1", "portcullis-shadow", "web", "running")
	shadow.Labels["traefik.http.routers.shadow.rule"] = "Host(`grafana.example.org`)"
	f.engine.containers = []docker.Container{ghost, orphan, shadow}
	f.h.Enable("grafana")

	rep := f.h.Reconcile(context.Background())
	doc := readPolicy(t, f)
	for _, sub := range []string{"ghost", "ghost-api", "stray"} {
		if doc.Groups[sub] != policy.DenyGroup {
			t.Errorf("groups[%s] = %q, want deny", sub, doc.Groups[sub])
		}
	}
	if _, ok := doc.Groups["auth"]; ok {
		t.Error("core subdomain published")
	}
	if doc.Groups["grafana"] != "users_grafana" {
		t.Errorf("live app overridden by deny: %q", doc.Groups["grafana"])
	}
	if d := driftFor(rep, "ghost"); d == nil || d.Kind != DriftTemplateMissing || !strings.Contains(d.Message, "denied") {
		t.Errorf("drift = %+v", d)
	}

	// The containers go away: the deny entries go with them.
	f.engine.mu.Lock()
	f.engine.containers = nil
	f.engine.mu.Unlock()
	f.h.Reconcile(context.Background())
	if doc := readPolicy(t, f); doc.Groups["stray"] != "" {
		t.Errorf("deny kept: %v", doc.Groups)
	}
	// Docker unreachable keeps the last known routes (no fail open).
	f.engine.containers = []docker.Container{ghost}
	f.h.Reconcile(context.Background())
	f.engine.listErr = context.DeadlineExceeded
	f.h.Reconcile(context.Background())
	f.h.WritePolicy()
	if doc := readPolicy(t, f); doc.Groups["ghost"] != policy.DenyGroup {
		t.Errorf("deny dropped while docker is unreachable: %v", doc.Groups)
	}
}
