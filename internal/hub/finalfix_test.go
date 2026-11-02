package hub

import (
	"context"
	"errors"
	"github.com/portcullis/hub/internal/state"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMissingDomainKeptWhileUsed (final review I1): a domain the service
// stops listing while instances use it stays known as "missing" — not
// assignable, still an extra domain — and re-enrolling it succeeds.
func TestMissingDomainKeptWhileUsed(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx := context.Background()
	readyDomain(t, f, api, "team-b.example.net")
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.net"}); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	delete(api.list, "team-b.example.net")
	api.mu.Unlock()
	if _, err := f.h.RefreshDomains(ctx); err != nil {
		t.Fatal(err)
	}
	known := f.h.KnownDomains()
	if len(known) != 1 || known[0].Name != "team-b.example.net" || known[0].State != DomainMissing || !strings.Contains(known[0].LastError, "grafana-b") {
		t.Fatalf("known = %+v", known)
	}
	f.h.mu.RLock()
	v := f.h.findLocked("grafana-b")
	broken := f.h.brokenInstances["grafana-b"]
	f.h.mu.RUnlock()
	if v == nil || strings.Join(v.ExtraHosts, ",") != "grafana.team-b.example.net" {
		t.Fatalf("instance stranded: view %v, broken %q", v, broken)
	}
	if doc := readPolicy(t, f); strings.Join(doc.ExtraDomains, ",") != "team-b.example.net" {
		t.Fatalf("extra_domains = %v", doc.ExtraDomains)
	}
	// Not assignable.
	if err := f.h.CreateInstance("grafana", "grafana-c", map[string]string{"grafana": "c.team-b.example.net"}); statusOf(err) != 409 || !strings.Contains(err.Error(), "no longer listed") {
		t.Fatalf("new host on a missing domain: %v", err)
	}
	// The instance's own host is kept (an unchanged SetHosts is fine).
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana.team-b.example.net"}, "alice"); err != nil {
		t.Fatalf("unchanged hosts: %v", err)
	}
	// Survives further refreshes.
	if _, err := f.h.RefreshDomains(ctx); err != nil || f.h.KnownDomains()[0].State != DomainMissing {
		t.Fatalf("second refresh: %v %+v", err, f.h.KnownDomains())
	}
	// Re-enrolling succeeds: the hosts on it are its own.
	if _, err := f.h.EnrollDomain(ctx, "alice", "team-b.example.net", "cloudflare", creds()); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if k := f.h.KnownDomains(); len(k) != 1 || k[0].State == DomainMissing {
		t.Fatalf("after re-enroll: %+v", k)
	}
	// Moved away: the next refresh drops it.
	api.set("team-b.example.net", true, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-b.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	delete(api.list, "team-b.example.net")
	api.mu.Unlock()
	f.h.RefreshDomains(ctx)
	if k := f.h.KnownDomains(); len(k) != 0 {
		t.Fatalf("unused missing domain kept: %+v", k)
	}
}

// TestHostCollisionRuntimeHosts (final review I4): a hostname a running
// project other than the instance's own still routes can't be taken.
func TestHostCollisionRuntimeHosts(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.driftMu.Lock()
	f.h.runtimeHosts = map[string][]string{"grafana-old": {"busy.example.org"}, "grafana-x": {"own.example.org"}}
	f.h.driftMu.Unlock()
	err := f.h.CreateInstance("grafana", "grafana-y", map[string]string{"grafana": "busy.example.org"})
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "still routed by the running project of grafana-old") {
		t.Fatalf("create on a still-routed host: %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-x", map[string]string{"grafana": "x.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("grafana-x", map[string]string{"grafana": "busy.example.org"}, "alice"); statusOf(err) != 409 {
		t.Fatalf("SetHosts onto a still-routed host: %v", err)
	}
	// Its own running project's hosts don't block it.
	if err := f.h.SetHosts("grafana-x", map[string]string{"grafana": "own.example.org"}, "alice"); err != nil {
		t.Fatalf("own runtime host: %v", err)
	}
}

const v2PlexManifest = `name: Plex
category: media
instances: multi
auth:
  method: custom
  sso: false
  group_access: true
  access_group: users_plex
  native_login:
    supported: true
    allow_without_gateway: true
    note: Plex accounts
`

const v2PlexCompose = "services:\n  plex:\n    image: x\n    labels:\n      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.plex.rule: Host(`${PORTCULLIS_HOST_PLEX:-plex.portcullis.local}`)\n" +
	"      traefik.http.routers.plex.entrypoints: websecure\n" +
	"      traefik.http.routers.plex.middlewares: security-headers@file\n"

func plexOnExtra(t *testing.T) *fixture {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"plex": {v2PlexManifest, v2PlexCompose}})
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	if err := f.h.CreateInstance("plex", "plex-b", map[string]string{"plex": "plex.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("plex-b"); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestSignInModeMovesCallbacks (final review I2): switching an enabled
// extra-domain instance to the app's own login removes its sign-in
// callback, switching back adds it; a Keycloak failure changes nothing.
func TestSignInModeMovesCallbacks(t *testing.T) {
	f := plexOnExtra(t)
	cb := "https://plex.team-b.example.org/oauth2/callback"
	f.idp.mu.Lock()
	got := strings.Join(f.idp.callbacks, " ")
	f.idp.callbacks = nil
	f.idp.mu.Unlock()
	if !strings.Contains(got, "+"+cb) {
		t.Fatalf("enable callbacks = %q", got)
	}
	if err := saveApp(t, f, "plex-b", SettingsUpdate{SignIn: strp(SignInNative)}); err != nil {
		t.Fatal(err)
	}
	f.idp.mu.Lock()
	got = strings.Join(f.idp.callbacks, " ")
	f.idp.callbacks = nil
	f.idp.mu.Unlock()
	if got != "+ -"+cb {
		t.Fatalf("native: callbacks = %q", got)
	}
	// Keycloak fails: the mode stays native.
	f.idp.mu.Lock()
	f.idp.callbackErr = errors.New("keycloak down")
	f.idp.mu.Unlock()
	if err := saveApp(t, f, "plex-b", SettingsUpdate{SignIn: strp(SignInGateway)}); statusOf(err) != 502 {
		t.Fatalf("gateway with Keycloak down: %v", err)
	}
	f.h.mu.RLock()
	mode := f.h.st.SignIn["plex-b"]
	f.h.mu.RUnlock()
	if mode != SignInNative {
		t.Fatalf("mode after a failed callback change = %q", mode)
	}
	f.idp.mu.Lock()
	f.idp.callbackErr = nil
	f.idp.mu.Unlock()
	if err := saveApp(t, f, "plex-b", SettingsUpdate{SignIn: strp(SignInGateway)}); err != nil {
		t.Fatal(err)
	}
	f.idp.mu.Lock()
	got = strings.Join(f.idp.callbacks, " ")
	f.idp.mu.Unlock()
	if got != "+"+cb+" -" {
		t.Fatalf("gateway: callbacks = %q", got)
	}
}

// TestInterruptedOpsAndRestoreAs (final review M2): a record still
// "running" at start is marked interrupted (and is no failure while it
// runs); an interrupted restore into a new id is removed at start.
func TestInterruptedOpsAndRestoreAs(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.h.mu.Lock()
	f.h.st.Instances["grafana-c"] = state.Instance{ID: "grafana-c", Template: "grafana",
		Hosts: map[string]string{"grafana": "grafana-c.example.org"}, State: state.InstanceRestoring, RestoreAs: "grafana-b/20261101T000000Z.tar"}
	f.h.st.Settings["grafana-c"] = map[string]string{"X": "y"}
	f.h.rebuildLocked()
	f.h.mu.Unlock()
	f.h.recordOp("grafana", OpRecord{Op: OpBackup, OpID: "abc", Running: true, At: time.Now()})
	if fo := f.h.FailedOps(); len(fo) != 0 {
		t.Fatalf("running op counted as failed: %v", fo)
	}
	for _, v := range f.h.Instances() {
		if v.ID == "grafana" && v.State == StateError {
			t.Fatal("running op shows the instance as error")
		}
	}
	f.h.loadOps()
	lo := f.h.LastOp("grafana")
	if lo == nil || lo.Running || lo.OK || !strings.Contains(lo.Error, "interrupted") {
		t.Fatalf("after reload: %+v", lo)
	}
	if b, _ := os.ReadFile(f.h.opPath("grafana")); strings.Contains(string(b), `"running": true`) {
		t.Fatal("op file still says running")
	}
	if err := f.h.pending("grafana-c"); statusOf(err) != 409 || !strings.Contains(err.Error(), "new id") {
		t.Fatalf("pending = %v", err)
	}
	f.engine.addVolume("portcullis_grafana-c-grafana-data", "portcullis-grafana-c", "grafana-data", 0)
	writeFile(t, f.h.envPath("grafana-c"), "A=b\n")
	f.h.RecoverRestores()
	f.h.Wait()
	f.h.mu.RLock()
	_, inState := f.h.st.Instances["grafana-c"]
	_, settings := f.h.st.Settings["grafana-c"]
	f.h.mu.RUnlock()
	if inState || settings || f.h.Template("grafana-c") != nil {
		t.Fatal("interrupted restore-as instance kept")
	}
	for _, n := range f.engine.volumeNames() {
		if n == "portcullis_grafana-c-grafana-data" {
			t.Fatal("its volume kept")
		}
	}
	if _, err := os.Stat(f.h.envPath("grafana-c")); !os.IsNotExist(err) {
		t.Fatal("its env file kept")
	}
	if !f.h.WaitTimeout(time.Second) {
		t.Fatal("WaitTimeout with nothing running")
	}
}

// TestSetHostsReapplyAfterOtherOp (final review M3): a failed hostname
// change is re-applied even after another operation became the last op.
func TestSetHostsReapplyAfterOtherOp(t *testing.T) {
	f := chatB(t)
	f.runner.upErr = errors.New("boom")
	if err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice"); err == nil {
		t.Fatal("restart did not fail")
	}
	f.runner.upErr = nil
	// Another operation (a backup's record) is now the last one.
	f.h.recordOp("chat-b", OpRecord{Op: OpBackup, OK: true, At: time.Now()})
	f.h.loadOps() // and it survives a restart
	calls := len(f.runner.Calls())
	if err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.runner.Calls()[calls:], " "), "up:portcullis-chat-b") {
		t.Fatal("the failed change was not re-applied")
	}
	if lo := f.h.lastHostsOp("chat-b"); lo == nil || !lo.OK {
		t.Fatalf("hosts record = %+v", lo)
	}
}

// TestFailedEnableRemovesCallbacks (final review M4).
func TestFailedEnableRemovesCallbacks(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	f.runner.upErr = errors.New("boom")
	if err := f.h.Enable("grafana-b"); err == nil {
		t.Fatal("enable did not fail")
	}
	cb := "https://grafana.team-b.example.org/oauth2/callback"
	f.idp.mu.Lock()
	got := strings.Join(f.idp.callbacks, " ")
	f.idp.mu.Unlock()
	if got != "+"+cb+" - + -"+cb {
		t.Fatalf("callbacks = %q", got)
	}
}

const fwdManifest = `name: Fwd
category: misc
instances: multi
auth:
  method: forward-auth
  group_access: true
  access_group: users_fwd
`

func fwdCompose(mw string, extra string) string {
	return "services:\n" +
		"  web:\n    image: y\n    labels:\n      traefik.enable: \"true\"\n" +
		"      traefik.http.routers.fwd.rule: Host(`${PORTCULLIS_HOST_FWD:-fwd.portcullis.local}`)\n" +
		"      traefik.http.routers.fwd.entrypoints: websecure\n" +
		"      traefik.http.routers.fwd.middlewares: " + mw + "\n" +
		"      traefik.http.routers.fwd.service: fwd\n" +
		"      traefik.http.services.fwd.loadbalancer.server.port: \"80\"\n" + extra
}

func fwdFixture(t *testing.T, compose string) *fixture {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"fwd": {fwdManifest, compose}})
	if f.h.Template("fwd") == nil {
		t.Fatal("fwd not loaded")
	}
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	return f
}

// TestChainReachingAuthRefusedOnExtra (final review M6): a router that
// reaches portcullis-auth through its own chain middleware can't get an
// extra-domain hostname (its chain would keep the main-domain sign-in).
func TestChainReachingAuthRefusedOnExtra(t *testing.T) {
	chain := "      traefik.http.middlewares.fwd-chain.chain.middlewares: fwd-inner\n" +
		"      traefik.http.middlewares.fwd-inner.chain.middlewares: portcullis-auth@docker,portcullis-groups@docker\n"
	f := fwdFixture(t, fwdCompose("fwd-chain@docker", chain))
	err := f.h.CreateInstance("fwd", "fwd-b", map[string]string{"fwd": "fwd.team-b.example.org"})
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("create on an extra domain = %v", err)
	}
	if err := f.h.SetHosts("fwd", map[string]string{"fwd": "fwd.team-b.example.org"}, "alice"); statusOf(err) != 400 {
		t.Fatalf("SetHosts onto an extra domain = %v", err)
	}
	// The main domain is fine.
	if err := f.h.CreateInstance("fwd", "fwd-c", nil); err != nil {
		t.Fatal(err)
	}
	// portcullis-auth without a provider is portcullis-auth@docker too.
	f2 := fwdFixture(t, fwdCompose("portcullis-auth,portcullis-groups@docker", ""))
	if err := f2.h.CreateInstance("fwd", "fwd-b", map[string]string{"fwd": "fwd.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	f2.h.mu.RLock()
	ov, err := f2.h.renderOverrideLocked(f2.h.findLocked("fwd-b"), nil)
	f2.h.mu.RUnlock()
	if err != nil || !strings.Contains(ov, "portcullis-auth-ext@docker") || strings.Contains(ov, `"portcullis-auth,`) {
		t.Fatalf("override = %v\n%s", err, ov)
	}
}

// TestMixedHostsRefusedAtCreate (final review M1): a router routing a
// main-domain and an extra-domain host is refused when the hostnames are
// chosen, not at enable.
func TestMixedHostsRefusedAtCreate(t *testing.T) {
	compose := "services:\n  web:\n    image: y\n    labels:\n      traefik.enable: \"true\"\n" +
		"      traefik.http.routers.fwd.rule: Host(`${PORTCULLIS_HOST_FWD:-fwd.portcullis.local}`)\n" +
		"      traefik.http.routers.fwd.middlewares: portcullis-auth@docker\n" +
		"      traefik.http.routers.fwd.service: fwd\n" +
		"      traefik.http.routers.api.rule: Host(`${PORTCULLIS_HOST_API:-api.portcullis.local}`)\n" +
		"      traefik.http.routers.api.service: fwd\n" +
		"      traefik.http.routers.both.rule: Host(`${PORTCULLIS_HOST_FWD:-fwd.portcullis.local}`) || Host(`${PORTCULLIS_HOST_API:-api.portcullis.local}`)\n" +
		"      traefik.http.routers.both.middlewares: portcullis-auth@docker\n" +
		"      traefik.http.routers.both.service: fwd\n" +
		"      traefik.http.services.fwd.loadbalancer.server.port: \"80\"\n"
	f := fwdFixture(t, compose)
	err := f.h.CreateInstance("fwd", "fwd-b", map[string]string{"fwd": "fwd.team-b.example.org", "api": "api-b.example.org"})
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "both extra-domain and main-domain") {
		t.Fatalf("mixed create = %v", err)
	}
	if err := f.h.CreateInstance("fwd", "fwd-b", map[string]string{"fwd": "fwd.team-b.example.org", "api": "api.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("fwd-b", map[string]string{"fwd": "fwd.team-b.example.org", "api": "api-b.example.org"}, "alice"); statusOf(err) != 400 {
		t.Fatalf("mixed SetHosts = %v", err)
	}
}

// TestDefaultImmutableHostsPinned (final review M7): enabling a default
// instance with hosts.immutable routers pins its hostnames in state: a
// main-domain change keeps them (the instance no longer fits the new
// domain and is reported, never silently moved).
func TestDefaultImmutableHostsPinned(t *testing.T) {
	m := v2ChatManifest + "hosts:\n  immutable: [chat]\n"
	f := newInstanceFixtureExtra(t, nil, nil, nil)
	writeFile(t, filepath.Join(f.src, "chat", "manifest.yaml"), m)
	f.h.Discover()
	if err := f.h.Enable("chat"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e, ok := f.h.st.Instances["chat"]
	f.h.mu.RUnlock()
	if !ok || e.Hosts["chat"] != "chat.example.org" {
		t.Fatalf("not pinned: %+v", e)
	}
	// Not dropped by an unchanged-hosts no-op or a reload.
	if err := f.h.SetHosts("chat", map[string]string{"chat": "chat.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	// Main domain changes: the pinned hostname stays.
	h2, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "new.example"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h2.Discover()
	h2.mu.RLock()
	e2 := h2.st.Instances["chat"]
	broken := h2.brokenInstances["chat"]
	h2.mu.RUnlock()
	if e2.Hosts["chat"] != "chat.example.org" || broken == "" {
		t.Fatalf("after the domain change: entry %+v, broken %q", e2, broken)
	}
	// A template without immutable routers is not pinned.
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	_, pinned := f.h.st.Instances["grafana"]
	f.h.mu.RUnlock()
	if pinned {
		t.Fatal("grafana pinned")
	}
}

// TestSyncReassertsCallbacks (core review M4): the access sync loop puts
// the running instances' extra-domain callbacks back.
func TestSyncReassertsCallbacks(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	f.idp.mu.Lock()
	f.idp.callbacks = nil
	f.idp.mu.Unlock()
	if err := f.h.SyncClientAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.idp.mu.Lock()
	got := strings.Join(f.idp.callbacks, " ")
	f.idp.mu.Unlock()
	if got != "+https://grafana.team-b.example.org/oauth2/callback -" {
		t.Fatalf("callbacks = %q", got)
	}
}
