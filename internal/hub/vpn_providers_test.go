package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/vpn"
)

// The VPN test templates: mesh (a headscale-shaped hook provider: ingress
// gateway, hooks in glue), wgplain (static, dns manual) and mesh2 (a
// second hook provider on another range).
const vpnMeshManifest = `name: Mesh
description: A mesh VPN
category: vpn
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_mesh
  admin_group: admin_mesh
hooks:
  - {name: vpn-devices, service: glue, command: [/devices], when: [vpn]}
  - {name: vpn-dns, service: glue, command: [/dns], when: [vpn]}
vpn:
  label: Mesh tailnet
  ranges: ["%s"]
  ingress: {service: gateway, proxy_protocol: v2}
  identity: {source: hook, hook: vpn-devices, owner: %s, refresh: 60s}
  dns: {hook: vpn-dns}
  control_routers: [%s]
`

const vpnMeshCompose = "services:\n  %s:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.%s.rule: Host(`${PORTCULLIS_HOST_%s:-%s.portcullis.local}`)\n" +
	"      traefik.http.routers.%s.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"    networks: [default, portcullis-proxy]\n  gateway:\n    image: x\n  glue:\n    image: x\nnetworks:\n  portcullis-proxy:\n    external: true\n"

func meshTemplate(router, rng, owner string) [2]string {
	up := strings.ToUpper(router)
	return [2]string{fmt.Sprintf(vpnMeshManifest, rng, owner, router), fmt.Sprintf(vpnMeshCompose, router, router, up, router, router)}
}

const vpnStaticManifest = `name: Plain WireGuard
description: WireGuard
category: vpn
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_wgplain
vpn:
  label: Office WireGuard
  ranges: ["10.8.0.0/24"]
  ingress: {service: gateway, proxy_protocol: v2}
  identity: {source: static}
  dns: {manual: true}
`

const vpnStaticCompose = "services:\n  wgui:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.wgui.rule: Host(`${PORTCULLIS_HOST_WGUI:-wgui.portcullis.local}`)\n" +
	"      traefik.http.routers.wgui.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"    networks: [default, portcullis-proxy]\n  gateway:\n    image: x\nnetworks:\n  portcullis-proxy:\n    external: true\n"

var (
	vpnServerKey = keyOf(1)
	vpnT0        = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
)

func keyOf(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

// vpnFixture is a Hub with the VPN templates, a fake wg status file, a
// fake clock, a fake directory and Keycloak.
type vpnFixture struct {
	*fixture
	audit  *fakeAudit
	people *fakePeople
	kc     *fakeVPNKC
	status string
	mu     sync.Mutex
	now    time.Time
	// hook: the fake exec of /devices and /dns (stdin recorded).
	devicesOut  string
	devicesFail *docker.ExecSplitResult
	dnsFail     *docker.ExecSplitResult
	stdins      map[string][]string
}

type fakeVPNKC struct {
	mu   sync.Mutex
	byID map[string]string
	err  error
}

func (k *fakeVPNKC) UsernamesByID(ctx context.Context) (map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return nil, k.err
	}
	out := map[string]string{}
	for a, b := range k.byID {
		out[a] = b
	}
	return out, nil
}

func newVPNFixture(t *testing.T, seed func(*state.AppState)) *vpnFixture {
	t.Helper()
	return newVPNFixtureExtra(t, seed, nil, VPNModeApps)
}

// newVPNFixtureExtra is newVPNFixture with more templates (replacing the
// VPN ones of the same id) and the core env's PORTCULLIS_VPN_MODE.
func newVPNFixtureExtra(t *testing.T, seed func(*state.AppState), more map[string][2]string, mode string) *vpnFixture {
	t.Helper()
	v := &vpnFixture{audit: &fakeAudit{}, kc: &fakeVPNKC{byID: map[string]string{"sub-alice": "alice", "sub-bob": "bob", "sub-ghost": "ghost"}}, now: vpnT0, stdins: map[string][]string{}}
	extra := map[string][2]string{
		"mesh":    meshTemplate("mesh", "100.64.0.0/10", "oidc_sub"),
		"mesh2":   meshTemplate("meshtwo", "100.128.0.0/16", "username"),
		"wgplain": {vpnStaticManifest, vpnStaticCompose},
	}
	for id, files := range more {
		extra[id] = files
	}
	v.fixture = newInstanceFixtureCfg(t, seed, nil, extra, func(root string, c *Config) {
		v.status = filepath.Join(root, "wg-status.json")
		c.VPNStatusFile = v.status
		c.VPNDocDir = filepath.Join(root, "vpn-doc")
		c.VPNDocGID = os.Getgid()
		os.MkdirAll(c.VPNDocDir, 0o750)
		writeFile(t, filepath.Join(c.ProjectDir, ".env"), "CORE_VAR=core-value\nPORTCULLIS_VPN_BUILTIN=on\nPORTCULLIS_VPN_NET=172.31.254.0/26\nPORTCULLIS_VPN_MODE="+mode+"\nPORTCULLIS_VPN_PUBLIC_ENROL=false\n")
	})
	for _, id := range []string{"mesh", "mesh2", "wgplain"} {
		if v.h.Template(id) == nil {
			t.Fatalf("template %s not loaded (see the log)", id)
		}
	}
	v.h.Wait() // the start's publish ran with the real clock
	v.h.vpnrt.now = v.clock
	v.h.vpnrt.validAt, v.h.vpnrt.lastWritten = time.Time{}, nil
	v.h.SetAudit(v.audit)
	v.people = newFakePeople("alice", "bob", "carol")
	v.people.addGroup("lldap_admin", "root")
	v.h.SetPeople(v.people)
	v.h.SetGroups(&fakeGroups{people: v.people, existing: map[string]bool{"users_mesh": true, "users_wgplain": true, "users_cloud": true}})
	v.h.SetVPNKeycloak(v.kc)
	v.engine.mu.Lock()
	for _, p := range []string{"portcullis-mesh", "portcullis-mesh2"} {
		v.engine.containers = append(v.engine.containers, container(p+"-glue", p, "glue", "running"), container(p+"-gw", p, "gateway", "running"))
	}
	v.engine.mu.Unlock()
	v.engine.setExecSplit(v.exec)
	v.writeStatus(t, true)
	return v
}

func (v *vpnFixture) clock() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.now
}

func (v *vpnFixture) advance(d time.Duration) {
	v.mu.Lock()
	v.now = v.now.Add(d)
	v.mu.Unlock()
}

func (v *vpnFixture) exec(cid string, in docker.ExecInput) (*docker.ExecSplitResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stdins[cid+" "+in.Cmd[0]] = append(v.stdins[cid+" "+in.Cmd[0]], string(in.Stdin))
	switch in.Cmd[0] {
	case "/devices":
		if v.devicesFail != nil {
			r := *v.devicesFail
			return &r, nil
		}
		return &docker.ExecSplitResult{Stdout: []byte(v.devicesOut)}, nil
	case "/dns":
		if v.dnsFail != nil {
			r := *v.dnsFail
			return &r, nil
		}
	}
	return &docker.ExecSplitResult{}, nil
}

func (v *vpnFixture) stdinsOf(key string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.stdins[key]...)
}

// writeStatus writes wg's status.json at the fixture's clock (people:
// the built-in role on, with the given peers).
func (v *vpnFixture) writeStatus(t *testing.T, people bool) {
	t.Helper()
	st := map[string]any{"version": 1, "written": v.clock().Format(time.RFC3339), "mode": "apps", "edge": map[string]any{"ok": true, "error": ""}, "people": nil}
	if people {
		st["people"] = map[string]any{"ok": true, "error": "", "public_key": vpnServerKey, "port": 51820, "subnet": "10.213.0.0/22", "mtu": 1280, "peers": []any{}}
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(v.status, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (v *vpnFixture) doc(t *testing.T) *vpn.Doc {
	t.Helper()
	v.h.Wait()
	b, err := os.ReadFile(v.h.vpnJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	d, err := vpn.Parse(b, v.h.vpnrt.now())
	if err != nil {
		t.Fatalf("vpn.json: %v\n%s", err, b)
	}
	return d
}

func (v *vpnFixture) wire(t *testing.T, id string) {
	t.Helper()
	if err := v.h.SetVPNProvider(context.Background(), root, id, true, 0); err != nil {
		t.Fatalf("wire %s: %v", id, err)
	}
}

func devicesDoc(gw string, devs ...string) string {
	return `{"version":1,"gateway":"` + gw + `","devices":[` + strings.Join(devs, ",") + `]}`
}

func hookDev(id, addr, owner string) string {
	return fmt.Sprintf(`{"id":%q,"name":"dev-%s","address":%q,"owner":%q,"online":true,"last_seen":null,"expires":null}`, id, id, addr, owner)
}

func TestWireRefusedWithoutWG(t *testing.T) {
	v := newVPNFixture(t, nil)
	os.Remove(v.status)
	if err := v.h.SetVPNProvider(context.Background(), root, "mesh", true, 0); !errors.Is(err, ErrVPNNotRunning) {
		t.Fatalf("err = %v", err)
	}
	var se *StatusError
	if !errors.As(ErrVPNNotRunning, &se) || se.Status != 409 || se.Error() != "the VPN service isn't running: run ./portcullis vpn init on the host" {
		t.Fatal(ErrVPNNotRunning)
	}
	// A stale status file is wg down too.
	v.writeStatus(t, true)
	v.advance(31 * time.Second)
	if err := v.h.SetVPNProvider(context.Background(), root, "mesh", true, 0); !errors.Is(err, ErrVPNNotRunning) {
		t.Fatalf("stale: err = %v", err)
	}
}

func TestWireAssignsSlotAndGateway(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.wire(t, "wgplain")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(context.Background(), "mesh")
	v.h.TriggerVPNPublish()
	d := v.doc(t)
	byID := map[string]vpn.Provider{}
	for _, p := range d.Providers {
		byID[p.ID] = p
	}
	if p := byID["mesh"]; p.EdgePort != 9001 || p.GatewayIP != "172.31.254.16" {
		t.Errorf("mesh: %+v", p)
	}
	if p := byID["wgplain"]; p.EdgePort != 9002 || p.GatewayIP != "172.31.254.17" {
		t.Errorf("wgplain: %+v", p)
	}
	if err := v.h.SetVPNProvider(context.Background(), root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	v.wire(t, "mesh2")
	v.h.mu.RLock()
	slot := v.h.st.VPN.Providers["mesh2"].Slot
	_, still := v.h.st.VPN.Providers["mesh"]
	v.h.mu.RUnlock()
	if slot != 0 || still {
		t.Fatalf("mesh2 slot %d (want the freed 0), mesh wired %v", slot, still)
	}
	// Refresh bounds; a template without vpn: is 400; unknown 404.
	for _, c := range []struct {
		id      string
		refresh time.Duration
		code    int
	}{{"mesh", 10 * time.Second, 400}, {"mesh", 11 * time.Minute, 400}, {"grafana", 0, 400}, {"nope", 0, 404}} {
		var se *StatusError
		if err := v.h.SetVPNProvider(context.Background(), root, c.id, true, c.refresh); !errors.As(err, &se) || se.Status != c.code {
			t.Errorf("%s %v: %v", c.id, c.refresh, err)
		}
	}
}

func TestWireRefusesOverlap(t *testing.T) {
	ctx := context.Background()
	refused := func(v *vpnFixture, id string, want ...string) {
		t.Helper()
		err := v.h.SetVPNProvider(ctx, root, id, true, 0)
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 409 {
			t.Fatalf("%s: err = %v, want 409", id, err)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q lacks %q", id, err, w)
			}
		}
	}
	// The built-in subnet (from status.json).
	v := newVPNFixture(t, func(st *state.AppState) {
		st.Settings = map[string]state.InstanceSettings{}
	})
	v.engine.mu.Lock()
	v.engine.networks = []docker.Network{{Name: "portcullis_default", Subnets: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}}}
	v.engine.mu.Unlock()
	v.h.mu.Lock()
	tm := v.h.findLocked("mesh2")
	tm.Manifest.VPN.Ranges = []string{"10.213.0.0/24"}
	v.h.mu.Unlock()
	refused(v, "mesh2", "10.213.0.0/24", "10.213.0.0/22", "built-in")
	// Another provider.
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"100.100.0.0/16"}
	v.h.mu.Unlock()
	v.wire(t, "mesh")
	refused(v, "mesh2", "100.100.0.0/16", "100.64.0.0/10", "mesh")
	// A container network.
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"10.99.5.0/24"}
	v.h.mu.Unlock()
	refused(v, "mesh2", "10.99.5.0/24", "10.99.0.0/16", "portcullis_default")
	// portcullis-vpn.
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"172.31.254.0/24"}
	v.h.mu.Unlock()
	refused(v, "mesh2", "172.31.254.0/24", "172.31.254.0/26", "portcullis-vpn")
	// Local networks may overlap (the doctor warns).
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"10.77.0.0/16"}
	nets := []string{"10.77.1.0/24"}
	v.h.st.LocalNetworks = &nets
	v.h.mu.Unlock()
	v.wire(t, "mesh2")
}

func TestWireAuditedAndConfirmed(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	if err := v.h.SetVPNProvider(context.Background(), root, "mesh", false, 0); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range v.audit.entries {
		if strings.HasPrefix(e.Action, "vpn.") {
			got = append(got, e.Action+" "+e.Target+" "+e.Detail+" "+e.Result)
			if e.Actor != "root" {
				t.Errorf("actor %q", e.Actor)
			}
		}
	}
	if strings.Join(got, "|") != "vpn.provider_wired mesh  ok|vpn.provider_unwired mesh  ok" {
		t.Fatalf("%q", got)
	}
}

func TestIdentityHookStdin(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(context.Background(), "mesh")
	in := v.stdinsOf("portcullis-mesh-glue /devices")
	if len(in) != 1 || in[0] != `{"version":1,"trigger":"vpn","instance":"mesh","op":"devices","ranges":["100.64.0.0/10"]}` {
		t.Fatalf("stdin %q", in)
	}
}

func TestOwnerResolution(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.wire(t, "mesh2")
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("1", "100.64.0.7", "sub-alice"), hookDev("2", "100.64.0.8", "sub-ghost"), hookDev("3", "100.64.0.9", "sub-unknown"))
	v.h.runVPNProvider(context.Background(), "mesh")
	pm := v.h.vpnProviderMap("mesh")
	if len(pm.devices) != 1 || pm.devices[0].User != "alice" || pm.devices[0].DeviceID != "mesh:1" {
		t.Fatalf("devices %+v", pm.devices)
	}
	if len(pm.problems) != 2 || pm.problems[0].Reason != "not a Portcullis person" {
		t.Fatalf("problems %+v", pm.problems)
	}
	// The VPN users group narrows it.
	v.h.mu.Lock()
	v.h.st.VPN.UsersGroup = "vpn_users"
	v.h.mu.Unlock()
	v.people.addGroup("vpn_users", "bob")
	v.h.runVPNProvider(context.Background(), "mesh")
	if pm := v.h.vpnProviderMap("mesh"); len(pm.devices) != 0 {
		t.Fatalf("alice outside the users group: %+v", pm.devices)
	}
	// username owners: exact lowercase match.
	v.devicesOut = devicesDoc("100.128.0.1", hookDev("a", "100.128.0.7", "BOB"), hookDev("b", "100.128.0.8", "alice"))
	v.h.runVPNProvider(context.Background(), "mesh2")
	pm = v.h.vpnProviderMap("mesh2")
	if len(pm.devices) != 1 || pm.devices[0].User != "bob" {
		t.Fatalf("mesh2 devices %+v", pm.devices)
	}
}

func TestHookFailureKeepsLastMapUntilStale(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("1", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(context.Background(), "mesh")
	v.h.TriggerVPNPublish()
	if d := v.doc(t); len(d.Devices) != 1 || d.Providers[1].Stale {
		t.Fatalf("%+v", d)
	}
	v.devicesFail = &docker.ExecSplitResult{ExitCode: 2, Stderr: []byte("boom")}
	v.advance(time.Minute)
	v.writeStatus(t, true)
	v.h.runVPNProvider(context.Background(), "mesh")
	pm := v.h.vpnProviderMap("mesh")
	if len(pm.devices) != 1 || !strings.Contains(pm.lastErr, "exited 2") {
		t.Fatalf("after a failure: %+v", pm)
	}
	v.advance(2*time.Minute + time.Second) // past 3 min since the good run
	v.writeStatus(t, true)
	v.h.TriggerVPNPublish()
	d := v.doc(t)
	if !d.Providers[1].Stale || len(d.Devices) != 0 {
		t.Fatalf("stale: %+v", d)
	}
	if _, ok := d.Lookup("mesh", netip.MustParseAddr("100.64.0.7"), v.clock()); ok {
		t.Fatal("a stale provider's device allowed")
	}
	if live := v.h.liveProviders(); strings.Join(live, ",") != "builtin" {
		t.Fatalf("live %v", live)
	}
	v.devicesFail = nil
	v.h.runVPNProvider(context.Background(), "mesh")
	v.h.TriggerVPNPublish()
	if d := v.doc(t); d.Providers[1].Stale || len(d.Devices) != 1 {
		t.Fatalf("fresh again: %+v", d)
	}
}

func TestHookOutputNeverStored(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.devicesOut = `{"version":1,"gateway":"100.64.0.1","devices":[{"id":"1","name":"NAME-MARKER","address":"100.64.0.7","owner":"OWNER-MARKER","online":true,"last_seen":null,"expires":null}]}`
	v.h.runVPNProvider(context.Background(), "mesh")
	// A failing run whose stdout carries the markers: redacted.
	v.devicesFail = &docker.ExecSplitResult{ExitCode: 1, Stdout: []byte("NAME-MARKER OWNER-MARKER"), Stderr: []byte("failed for OWNER-MARKER")}
	v.h.runVPNProvider(context.Background(), "mesh")
	pm := v.h.vpnProviderMap("mesh")
	if strings.Contains(pm.lastErr, "MARKER") || !strings.Contains(pm.lastErr, "exited 1") {
		t.Fatalf("last error %q", pm.lastErr)
	}
	// An invalid document's error quotes nothing either.
	v.devicesFail = nil
	v.devicesOut = `{"version":1,"gateway":"100.64.0.1","devices":[],"OWNER-MARKER":1}`
	v.h.runVPNProvider(context.Background(), "mesh")
	if pm := v.h.vpnProviderMap("mesh"); strings.Contains(pm.lastErr, "MARKER") || pm.lastErr == "" {
		t.Fatalf("last error %q", pm.lastErr)
	}
	v.h.TriggerVPNPublish()
	v.h.Wait()
	for _, dir := range []string{v.data, v.project} {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "OWNER-MARKER") || strings.Contains(string(b), "NAME-MARKER") {
				t.Errorf("%s holds the hook's stdout", p)
			}
			return nil
		})
	}
	for _, e := range v.audit.entries {
		if strings.Contains(e.Detail+e.Error, "MARKER") {
			t.Errorf("audit %+v", e)
		}
	}
}

func TestStartLeavesHookProvidersOutUntilFirstRun(t *testing.T) {
	// Ruling: until its first good run since the start a hook provider is
	// left out of vpn.json (its addresses denied); the builtin and the
	// static providers are published.
	v := newVPNFixture(t, func(st *state.AppState) {
		st.VPN.Providers = map[string]state.VPNProvider{"mesh": {Slot: 0, WiredAt: vpnT0}, "wgplain": {Slot: 1, WiredAt: vpnT0}}
	})
	v.h.TriggerVPNPublish()
	d := v.doc(t)
	var ids []string
	for _, p := range d.Providers {
		ids = append(ids, p.ID+":"+p.Source)
	}
	if strings.Join(ids, ",") != "builtin:builtin,wgplain:static" {
		t.Fatalf("providers at start: %v", ids)
	}
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("1", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(context.Background(), "mesh")
	v.h.TriggerVPNPublish()
	d = v.doc(t)
	if len(d.Providers) != 3 || d.Providers[1].ID != "mesh" || d.Providers[1].RefreshedAt == nil || d.Providers[1].Stale {
		t.Fatalf("after the first run: %+v", d.Providers)
	}
	if _, ok := d.Lookup("mesh", netip.MustParseAddr("100.64.0.7"), v.clock()); !ok {
		t.Fatal("mesh device after its first run")
	}
}

func TestStaticAssignments(t *testing.T) {
	v := newVPNFixture(t, nil)
	ctx := context.Background()
	v.wire(t, "wgplain")
	code := func(err error) int {
		var se *StatusError
		if errors.As(err, &se) {
			return se.Status
		}
		return 0
	}
	if c := code(v.h.AssignVPNAddress(ctx, root, "wgplain", "10.9.0.5", "alice", "laptop")); c != 400 {
		t.Errorf("outside the ranges: %d", c)
	}
	if c := code(v.h.AssignVPNAddress(ctx, root, "wgplain", "10.8.0.5", "dave", "laptop")); c != 400 {
		t.Errorf("not a person: %d", c)
	}
	if c := code(v.h.AssignVPNAddress(ctx, root, "mesh", "100.64.0.5", "alice", "laptop")); c != 400 {
		t.Errorf("a hook provider: %d", c)
	}
	if c := code(v.h.AssignVPNAddress(ctx, root, "wgplain", "10.8.0.5", "alice", "two\nlines")); c != 400 {
		t.Errorf("bad name: %d", c)
	}
	if err := v.h.AssignVPNAddress(ctx, root, "wgplain", "10.8.0.5", "Alice", "laptop"); err != nil {
		t.Fatal(err)
	}
	d := v.doc(t)
	if len(d.Devices) != 1 || d.Devices[0].User != "alice" || d.Devices[0].Provider != "wgplain" {
		t.Fatalf("%+v", d.Devices)
	}
	// Static maps are never stale, however much time passes.
	v.advance(24 * time.Hour)
	v.writeStatus(t, true)
	v.h.TriggerVPNPublish()
	d = v.doc(t)
	if dv, ok := d.Lookup("wgplain", netip.MustParseAddr("10.8.0.5"), v.clock()); !ok || dv.User != "alice" {
		t.Fatal("static device after a day")
	}
	if c := code(v.h.UnassignVPNAddress(ctx, root, "wgplain", "10.8.0.6")); c != 404 {
		t.Errorf("unassign missing: %d", c)
	}
	if err := v.h.UnassignVPNAddress(ctx, root, "wgplain", "10.8.0.5"); err != nil {
		t.Fatal(err)
	}
	if d := v.doc(t); len(d.Devices) != 0 {
		t.Fatalf("%+v", d.Devices)
	}
	var acts []string
	for _, e := range v.audit.entries {
		if strings.HasPrefix(e.Action, "vpn.static") {
			acts = append(acts, e.Action+":"+e.Result+":"+e.Detail)
		}
	}
	want := "vpn.static_assigned:refused:10.9.0.5 alice|vpn.static_assigned:refused:10.8.0.5 dave|vpn.static_assigned:refused:100.64.0.5 alice|vpn.static_assigned:refused:10.8.0.5 alice|vpn.static_assigned:ok:10.8.0.5 alice|vpn.static_unassigned:refused:10.8.0.6|vpn.static_unassigned:ok:10.8.0.5"
	if strings.Join(acts, "|") != want {
		t.Errorf("audit\n got %s\nwant %s", strings.Join(acts, "|"), want)
	}
}

func TestDNSHookRecords(t *testing.T) {
	v := newVPNFixture(t, nil)
	ctx := context.Background()
	v.wire(t, "mesh")
	if err := v.h.Enable("mesh2"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.devicesOut = devicesDoc("100.64.0.1")
	v.h.runVPNProvider(ctx, "mesh")
	v.h.runVPNDNS(ctx, "mesh")
	in := v.stdinsOf("portcullis-mesh-glue /dns")
	if len(in) != 1 {
		t.Fatalf("dns runs %q", in)
	}
	var hi vpn.HookInput
	if err := json.Unmarshal([]byte(in[0]), &hi); err != nil || hi.Op != "dns" || hi.Instance != "mesh" || len(hi.Ranges) != 0 {
		t.Fatalf("%q %v", in[0], err)
	}
	names := map[string]bool{}
	for _, r := range hi.Records {
		if r.Type != "A" || r.Value != "100.64.0.1" {
			t.Errorf("record %+v", r)
		}
		names[r.Name] = true
	}
	for _, n := range []string{"example.org", "hub.example.org", "people.example.org", "auth.example.org", "meshtwo.example.org"} {
		if !names[n] {
			t.Errorf("no record for %s in %v", n, names)
		}
	}
	// Unchanged: not run again.
	v.h.runVPNDNS(ctx, "mesh")
	if n := len(v.stdinsOf("portcullis-mesh-glue /dns")); n != 1 {
		t.Fatalf("%d runs", n)
	}
	// The gateway changes: run again; it fails: lastDNSErr, map fresh.
	v.dnsFail = &docker.ExecSplitResult{ExitCode: 3}
	v.devicesOut = devicesDoc("100.64.0.2")
	v.h.runVPNProvider(ctx, "mesh")
	v.h.runVPNDNS(ctx, "mesh")
	pm := v.h.vpnProviderMap("mesh")
	if !strings.Contains(pm.lastDNSErr, "exited 3") || pm.lastErr != "" {
		t.Fatalf("%+v", pm)
	}
	if live := v.h.liveProviders(); len(live) != 2 {
		t.Fatalf("a failed dns hook made the map stale: %v", live)
	}
	// A hostname change is applied at once.
	v.dnsFail = nil
	if err := v.h.Enable("wgplain"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.h.runVPNDNS(ctx, "mesh") // the tick's run: a new record set runs at once
	in = v.stdinsOf("portcullis-mesh-glue /dns")
	if last := in[len(in)-1]; !strings.Contains(last, "wgui.example.org") || !strings.Contains(last, "100.64.0.2") {
		t.Fatalf("last dns stdin %q", last)
	}
	if pm := v.h.vpnProviderMap("mesh"); pm.lastDNSErr != "" {
		t.Fatalf("%q", pm.lastDNSErr)
	}
}

func TestPublishDoc(t *testing.T) {
	exp := vpnT0.Add(365 * 24 * time.Hour)
	v := newVPNFixture(t, func(st *state.AppState) {
		st.VPN.Devices = []state.VPNDevice{
			{ID: "d2", User: "bob", UUID: "uuid-bob", Name: "phone", IP: "10.213.0.3", PublicKey: keyOf(3), Created: vpnT0},
			{ID: "d1", User: "alice", UUID: "uuid-alice", Name: "laptop", IP: "10.213.0.2", PublicKey: keyOf(2), Created: vpnT0, Expires: &exp},
		}
	})
	ctx := context.Background()
	v.wire(t, "mesh")
	v.wire(t, "wgplain")
	if err := v.h.AssignVPNAddress(ctx, root, "wgplain", "10.8.0.9", "carol", "desk"); err != nil {
		t.Fatal(err)
	}
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("12", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(ctx, "mesh")
	v.h.TriggerVPNPublish()
	v.h.Wait()
	got, _ := os.ReadFile(v.h.vpnJSONPath())
	want := `{
  "version": 2,
  "valid_until": "2026-11-13T13:00:00Z",
  "builtin": {
    "subnet": "10.213.0.0/22",
    "server_public_key": "` + vpnServerKey + `",
    "domains": [
      "example.org"
    ],
    "peers": [
      {
        "ip": "10.213.0.2",
        "public_key": "` + keyOf(2) + `",
        "device_id": "d1",
        "expires": "2027-11-13T12:00:00Z"
      },
      {
        "ip": "10.213.0.3",
        "public_key": "` + keyOf(3) + `",
        "device_id": "d2",
        "expires": null
      }
    ]
  },
  "providers": [
    {
      "id": "builtin",
      "ranges": [
        "10.213.0.0/22"
      ],
      "edge_port": 0,
      "gateway_ip": "",
      "source": "builtin",
      "stale": false
    },
    {
      "id": "mesh",
      "label": "Mesh tailnet",
      "ranges": [
        "100.64.0.0/10"
      ],
      "edge_port": 9001,
      "gateway_ip": "172.31.254.16",
      "source": "hook",
      "refreshed_at": "2026-11-13T12:00:00Z",
      "stale_after": "2026-11-13T12:03:00Z",
      "stale": false
    },
    {
      "id": "wgplain",
      "label": "Office WireGuard",
      "ranges": [
        "10.8.0.0/24"
      ],
      "edge_port": 9002,
      "gateway_ip": "172.31.254.17",
      "source": "static",
      "stale": false
    }
  ],
  "devices": [
    {
      "ip": "10.8.0.9",
      "provider": "wgplain",
      "user": "carol",
      "device_id": "wgplain:10.8.0.9",
      "name": "desk",
      "expires": null
    },
    {
      "ip": "10.213.0.2",
      "provider": "builtin",
      "user": "alice",
      "device_id": "d1",
      "name": "laptop",
      "expires": "2027-11-13T12:00:00Z"
    },
    {
      "ip": "10.213.0.3",
      "provider": "builtin",
      "user": "bob",
      "device_id": "d2",
      "name": "phone",
      "expires": null
    },
    {
      "ip": "100.64.0.7",
      "provider": "mesh",
      "user": "alice",
      "device_id": "mesh:12",
      "name": "dev-12",
      "expires": null
    }
  ]
}
`
	if string(got) != want {
		t.Fatalf("vpn.json:\n%s\nwant:\n%s", got, want)
	}
	st, _ := os.Stat(v.h.vpnJSONPath())
	if st.Mode().Perm() != 0o640 || int(st.Sys().(*syscall.Stat_t).Gid) != os.Getgid() {
		t.Errorf("mode %v gid %d", st.Mode(), st.Sys().(*syscall.Stat_t).Gid)
	}
	// In the vpn_doc volume, never in the Hub's data (hub_data).
	if filepath.Dir(v.h.vpnJSONPath()) == v.data {
		t.Error("vpn.json in the data directory")
	}
	filepath.WalkDir(v.data, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "vpn.json" {
			t.Errorf("vpn.json written to the data directory: %s", p)
		}
		return nil
	})
	// A map change rewrites it; an unchanged doc is rewritten at least
	// every refresh while a provider is live.
	mt := func() time.Time { s, _ := os.Stat(v.h.vpnJSONPath()); return s.ModTime() }
	before := mt()
	time.Sleep(20 * time.Millisecond)
	v.h.TriggerVPNPublish()
	v.h.Wait()
	if !mt().Equal(before) {
		t.Error("an unchanged doc was rewritten within the refresh")
	}
	v.advance(61 * time.Second)
	v.writeStatus(t, true)
	v.h.runVPNProvider(ctx, "mesh") // same devices, new refreshed_at
	v.h.TriggerVPNPublish()
	v.h.Wait()
	if mt().Equal(before) {
		t.Error("not rewritten after a refresh")
	}
	// The builtin off: no builtin, no builtin provider.
	v.h.mu.Lock()
	v.h.st.VPN.BuiltinOff = true
	v.h.mu.Unlock()
	v.h.TriggerVPNPublish()
	if d := v.doc(t); d.Builtin != nil || d.Providers[0].ID == "builtin" {
		t.Fatalf("builtin off: %+v", d)
	}
	v.h.mu.Lock()
	v.h.st.VPN.BuiltinOff = false
	v.h.mu.Unlock()
	v.writeStatus(t, false) // status people == null
	v.h.TriggerVPNPublish()
	if d := v.doc(t); d.Builtin != nil || d.Providers[0].ID == "builtin" {
		t.Fatalf("people null: %+v", d)
	}
}

var _ = directory.Human

// Core's reserved ranges (PORTCULLIS_VPN_RESERVED_RANGES): no provider
// overlapping one is wired or published; an unparsable list refuses all.
func TestVPNReservedRanges(t *testing.T) {
	v := newVPNFixture(t, nil)
	ctx := context.Background()
	env := filepath.Join(v.project, ".env")
	base := "CORE_VAR=core-value\nPORTCULLIS_VPN_BUILTIN=on\nPORTCULLIS_VPN_NET=172.31.254.0/26\n"
	writeFile(t, env, base+"PORTCULLIS_VPN_RESERVED_RANGES=100.100.0.0/16,10.250.0.0/16\n")
	err := v.h.SetVPNProvider(ctx, root, "mesh", true, 0)
	if statusCode(err) != 409 || !strings.Contains(err.Error(), "100.100.0.0/16") || !strings.Contains(err.Error(), "reserves") {
		t.Fatalf("reserved overlap: %v", err)
	}
	v.wire(t, "wgplain")
	writeFile(t, env, base+"PORTCULLIS_VPN_RESERVED_RANGES=10.8.0.0/16\n")
	v.h.TriggerVPNPublish()
	for _, p := range v.doc(t).Providers {
		if p.ID == "wgplain" {
			t.Fatal("a provider in a reserved range was published")
		}
	}
	// Unset: the readers' defaults (172.16/12, 192.168/16, 10.214/24).
	writeFile(t, env, base)
	v.h.mu.Lock()
	tm := v.h.findLocked("mesh2")
	tm.Manifest.VPN.Ranges = []string{"192.168.50.0/24"}
	v.h.mu.Unlock()
	if err := v.h.SetVPNProvider(ctx, root, "mesh2", true, 0); statusCode(err) != 409 || !strings.Contains(err.Error(), "192.168.0.0/16") {
		t.Fatalf("unset list: %v", err)
	}
	// A list from core (Podman's pools under podman) adds to the
	// readers' defaults, never replaces them.
	writeFile(t, env, base+"PORTCULLIS_VPN_RESERVED_RANGES=10.88.0.0/16 10.89.0.0/16\n")
	if err := v.h.SetVPNProvider(ctx, root, "mesh2", true, 0); statusCode(err) != 409 || !strings.Contains(err.Error(), "192.168.0.0/16") {
		t.Fatalf("defaults dropped by a set list: %v", err)
	}
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"10.89.4.0/24"}
	v.h.mu.Unlock()
	if err := v.h.SetVPNProvider(ctx, root, "mesh2", true, 0); statusCode(err) != 409 || !strings.Contains(err.Error(), "10.89.0.0/16") {
		t.Fatalf("podman pool: %v", err)
	}
	if c := v.h.vpnCoreEnv(); c.ReservedDefault || len(c.Reserved) != 5 {
		t.Fatalf("reserved %v (default %v)", c.Reserved, c.ReservedDefault)
	}
	v.h.mu.Lock()
	tm.Manifest.VPN.Ranges = []string{"100.128.0.0/16"}
	v.h.mu.Unlock()
	writeFile(t, env, base+"PORTCULLIS_VPN_RESERVED_RANGES=nope\n")
	if err := v.h.SetVPNProvider(ctx, root, "mesh2", true, 0); statusCode(err) != 409 {
		t.Fatalf("unparsable list: %v", err)
	}
	v.h.TriggerVPNPublish()
	if d := v.doc(t); len(d.Providers) != 1 || d.Providers[0].ID != "builtin" {
		t.Fatalf("unparsable list published %+v", d.Providers)
	}
}

// I3: a failed vpn.json write is retried with backoff and is the doctor's
// vpn_publish_failed until a write succeeds; hook devices outside the
// provider's current ranges are left out with a reason; the file carries
// valid_until an hour ahead.
func TestVPNPublishFailureAndRefilter(t *testing.T) {
	v := newVPNFixture(t, nil)
	ctx := context.Background()
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("1", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(ctx, "mesh")
	v.h.TriggerVPNPublish()
	d := v.doc(t)
	if d.ValidUntil == nil || !d.ValidUntil.Equal(v.clock().Add(time.Hour)) {
		t.Fatalf("valid_until %v", d.ValidUntil)
	}
	var calls atomic.Int32
	v.h.vpnrt.mu.Lock()
	v.h.vpnrt.testWrite = func(string, vpn.Doc, int, time.Time) error { calls.Add(1); return errors.New("disk full") }
	v.h.vpnrt.mu.Unlock()
	// The range narrows (a cidr setting): the device is left out.
	v.h.mu.Lock()
	v.h.findLocked("mesh").Manifest.VPN.Ranges = []string{"100.100.0.0/16"}
	v.h.mu.Unlock()
	v.h.TriggerVPNPublish()
	v.h.Wait()
	if v.h.vpnPublishError() == "" || calls.Load() != 1 {
		t.Fatalf("error %q, %d writes", v.h.vpnPublishError(), calls.Load())
	}
	v.h.TriggerVPNPublish()
	v.h.Wait()
	if calls.Load() != 1 {
		t.Fatal("retried before the backoff")
	}
	f := vpnFindings(t, v, doctor.KindVPNPublishFailed)
	if len(f) != 1 || f[0].Severity != doctor.Problem {
		t.Fatalf("doctor %+v", f)
	}
	v.h.vpnrt.mu.Lock()
	v.h.vpnrt.testWrite = nil
	v.h.vpnrt.mu.Unlock()
	v.advance(6 * time.Second)
	v.writeStatus(t, true)
	v.h.TriggerVPNPublish()
	d = v.doc(t)
	if v.h.vpnPublishError() != "" {
		t.Fatal(v.h.vpnPublishError())
	}
	for _, dv := range d.Devices {
		if dv.Provider == "mesh" {
			t.Fatalf("an out-of-range device published: %+v", dv)
		}
	}
	pm := v.h.vpnProviderMap("mesh")
	found := false
	for _, p := range pm.problems {
		if p.ID == "1" && p.Reason == vpn.DropOutside {
			found = true
		}
	}
	if !found {
		t.Fatalf("no outside_ranges drop: %+v", pm.problems)
	}
}

// M2 (final review): wg's address comes from core.env's
// PORTCULLIS_VPN_WG_IP; a value outside the VPN network, on a gateway
// slot or unparsable keeps core's default .3 (logged).
func TestVPNWGIPFromCoreEnv(t *testing.T) {
	v := newVPNFixture(t, nil)
	env := filepath.Join(v.project, ".env")
	base := "CORE_VAR=core-value\nPORTCULLIS_VPN_BUILTIN=on\nPORTCULLIS_VPN_NET=172.31.254.0/26\n"
	for raw, want := range map[string]string{
		"":               "172.31.254.3",
		"172.31.254.5":   "172.31.254.5",
		"172.31.254.20":  "172.31.254.3", // a gateway slot
		"172.31.254.0":   "172.31.254.3", // the network address
		"172.31.254.63":  "172.31.254.3", // broadcast
		"10.1.2.3":       "172.31.254.3",
		"172.31.255.20":  "172.31.254.3", // outside the /26
		"not-an-address": "172.31.254.3",
	} {
		line := ""
		if raw != "" {
			line = "PORTCULLIS_VPN_WG_IP=" + raw + "\n"
		}
		writeFile(t, env, base+line)
		if got := v.h.vpnCoreEnv().WGIP.String(); got != want {
			t.Errorf("%q: wg at %s, want %s", raw, got, want)
		}
	}
	writeFile(t, env, base+"PORTCULLIS_VPN_WG_IP=172.31.254.5\n")
	if err := v.h.Enable("mesh"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	v.wire(t, "mesh")
	v.h.Wait()
	if ov := overrideOf(t, v, "mesh"); !strings.Contains(ov, `PORTCULLIS_VPN_EDGE: "172.31.254.5:9001"`) {
		t.Fatalf("the gateway's edge doesn't follow the core env:\n%s", ov)
	}
}

func TestVPNWGIPOKWideNet(t *testing.T) {
	n := netip.MustParsePrefix("10.50.0.0/16")
	for a, want := range map[string]bool{"10.50.0.3": true, "10.50.0.20": false, "10.50.1.20": true, "10.50.255.255": false, "10.50.0.0": false, "10.51.0.3": false} {
		if got := vpnWGIPOK(n, netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v, want %v", a, got, want)
		}
	}
}
