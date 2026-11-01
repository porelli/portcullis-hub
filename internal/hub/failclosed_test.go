package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func readAttrs(t *testing.T, f *fixture) (policy.UserAttributesDocument, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.data, policy.UserAttributesFile))
	if os.IsNotExist(err) {
		return policy.UserAttributesDocument{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc policy.UserAttributesDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, true
}

// The policy file carries the directory's expiries (one per membership,
// the earliest) and user-attributes.json sits next to it; when the
// directory can't be read, the last published expiries and the existing
// attributes file stay — across restarts too.
func TestDirectoryStateFailsClosed(t *testing.T) {
	f := newFixture(t)
	if doc := readPolicy(t, f); doc.Expiring == nil || len(doc.Expiring) != 0 {
		t.Fatalf("no directory: expiring = %#v", doc.Expiring)
	}
	if _, ok := readAttrs(t, f); ok {
		t.Fatal("no directory: attributes file written")
	}

	var fail atomic.Bool
	attrs := policy.BuildUserAttributes([]policy.AttrField{{Name: "cost_center"}}, map[string]map[string][]string{"Alice": {"cost_center": {"CC-1"}}})
	state := func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		if fail.Load() {
			return nil, nil, errors.New("lldap down")
		}
		return []policy.Expiring{
			{User: "bob", Group: "temps", At: "2027-06-30T00:00:00Z"},
			{User: "alice", Group: "contractors", At: "2027-03-31T23:59:59Z"},
			{User: "alice", Group: "contractors", At: "2027-01-01T00:00:00Z"},
		}, &attrs, nil
	}
	f.h.SetDirectory(state, nil)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	want := []policy.Expiring{{User: "alice", Group: "contractors", At: "2027-01-01T00:00:00Z"}, {User: "bob", Group: "temps", At: "2027-06-30T00:00:00Z"}}
	check := func(label string) {
		t.Helper()
		if doc := readPolicy(t, f); !reflect.DeepEqual(doc.Expiring, want) {
			t.Errorf("%s: expiring = %+v", label, doc.Expiring)
		}
		a, ok := readAttrs(t, f)
		if !ok || a.Fields["cost_center"] != "Cost-Center" || a.Users["alice"]["cost_center"][0] != "CC-1" {
			t.Errorf("%s: attributes = %+v (exists %v)", label, a, ok)
		}
	}
	check("published")
	if fi, err := os.Stat(filepath.Join(f.data, policy.UserAttributesFile)); err != nil || fi.Mode().Perm() != 0644 {
		t.Errorf("attributes file mode: %v %v", fi, err)
	}

	fail.Store(true)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	check("directory failing")

	// Restart while the directory is still failing: the expiries come
	// from the file on disk.
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h2.Wait)
	h2.SetDirectory(state, nil)
	h2.Init()
	f.h = h2
	check("restart, directory failing")

	// Directory back, nothing shared, no attributes document: file removed.
	fail.Store(false)
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, nil
	}, nil)
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if doc := readPolicy(t, f); doc.Expiring == nil || len(doc.Expiring) != 0 {
		t.Errorf("expiring = %#v", doc.Expiring)
	}
	if _, ok := readAttrs(t, f); ok {
		t.Error("attributes file kept without a document")
	}
}

// RunDirectorySync writes the policy then syncs the mappers at start and on
// each trigger; a mapper failure never blocks the policy write.
func TestRunDirectorySync(t *testing.T) {
	f := newFixture(t)
	var states, syncs atomic.Int32
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		states.Add(1)
		return []policy.Expiring{{User: "u", Group: "g", At: "2030-01-01T00:00:00Z"}}, nil, nil
	}, func(context.Context) error {
		syncs.Add(1)
		return errors.New("keycloak down")
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunDirectorySync(ctx); close(done) }()
	waitFor := func(label string, cond func() bool) {
		t.Helper()
		for i := 0; i < 500 && !cond(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !cond() {
			t.Fatalf("%s: states %d, syncs %d", label, states.Load(), syncs.Load())
		}
	}
	waitFor("startup", func() bool { return states.Load() == 1 && syncs.Load() == 1 })
	if len(readPolicy(t, f).Expiring) != 1 {
		t.Error("startup policy write lacks the expiry")
	}
	for i := 0; i < 5; i++ {
		f.h.TriggerDirectorySync()
	}
	waitFor("triggered", func() bool { return states.Load() == 2 && syncs.Load() == 2 })
	cancel()
	<-done
}
