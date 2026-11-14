package hub

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/vpn"
)

const lanManifest = `name: Lan
description: x
version: "1.0"
category: x
ai: {unsupported: "test fixture"}
auth:
  method: custom
ports:
  - key: SMB_PORT
    label: SMB
    container: 445
    default: 445
    lan_only: true
  - key: WEB_PORT
    label: Web
    container: 80
    default: 8085
`

const lanCompose = "services:\n  smb:\n    image: x\n    user: \"10001\"\n    ports:\n      - \"${SMB_PORT:-445}:445\"\n      - \"${WEB_PORT:-8085}:80\"\n    volumes:\n      - ./templates/lan/conf:/conf:ro\n"

// TestKubeUpProjectInputs: under Kubernetes an up's project carries the
// loaded model and the inputs read from the Hub's disk and state; under
// Docker nothing is loaded.
func TestKubeUpProjectInputs(t *testing.T) {
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"lan": {lanManifest, lanCompose}})
	tp := f.h.Template("lan")
	if tp == nil {
		t.Fatal("lan fixture not loaded")
	}
	p, err := f.h.upProject(context.Background(), tp)
	if err != nil || p.Model != nil || p.Inputs != nil {
		t.Fatalf("docker: %+v %v", p, err)
	}
	f.h.cfg.Runtime = runtime.KindKubernetes
	dir := filepath.Join(f.project, "templates", "lan", "conf")
	os.MkdirAll(dir, 0o755)
	writeFile(t, filepath.Join(dir, "a.conf"), "x=1\n")
	p, err = f.h.upProject(context.Background(), tp)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model == nil || p.Model.Services["smb"].Image != "x" {
		t.Fatalf("model %+v", p.Model)
	}
	in := p.Inputs
	if in == nil || in.Template != "lan" || string(in.TemplateFiles["conf/a.conf"]) != "x=1\n" {
		t.Fatalf("inputs %+v", in)
	}
	if !in.LanOnly[445] || in.LanOnly[8085] {
		t.Errorf("lan only %v", in.LanOnly)
	}
}

// Under Kubernetes the fixer's image is HUB_SELF_IMAGE (pinned), never
// a container lookup.
func TestKubeSelfImage(t *testing.T) {
	f := newFixture(t)
	f.h.cfg.Runtime = runtime.KindKubernetes
	if _, err := f.h.selfImage(context.Background()); err == nil {
		t.Error("an unset HUB_SELF_IMAGE was used")
	}
	img := "ghcr.io/porelli/portcullis-hub@sha256:" + strings.Repeat("a", 64)
	f.h.cfg.SelfImage = img
	if got, err := f.h.selfImage(context.Background()); err != nil || got != img {
		t.Errorf("self image %q %v", got, err)
	}
}

func publishedGateways(t *testing.T, v *vpnFixture) map[string]string {
	t.Helper()
	b, err := os.ReadFile(v.h.vpnJSONPath())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := vpn.Parse(b, v.clock())
	if err != nil {
		t.Fatalf("vpn.json doesn't parse: %v", err)
	}
	out := map[string]string{}
	for _, p := range doc.Providers {
		if p.ID != "builtin" {
			out[p.ID] = p.GatewayIP
		}
	}
	return out
}

// TestGatewayIPFollowsPod (hub part): under Kubernetes a wired provider
// is published with its confirmed gateway pod's IP; each watch change
// re-renders vpn.json before setKubeGateways returns (no tick): deleted
// → left out (the document still parses: never an empty gateway_ip),
// another pod (UID) → its IP; the UID is kept with the IP.
func TestGatewayIPFollowsPod(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.wire(t, "mesh")
	v.devicesOut = devicesDoc("100.64.0.1", hookDev("12", "100.64.0.7", "sub-alice"))
	v.h.runVPNProvider(context.Background(), "mesh")
	v.h.cfg.Runtime = runtime.KindKubernetes
	v.h.setKubeGateways(map[string]kube.GatewayPod{"mesh": {IP: "10.42.0.5", UID: "uid-a"}})
	if got := publishedGateways(t, v); got["mesh"] != "10.42.0.5" {
		t.Fatalf("A: %v", got)
	}
	if g := v.h.KubeGateways()["mesh"]; g.UID != "uid-a" {
		t.Errorf("uid %+v", g)
	}
	v.h.setKubeGateways(map[string]kube.GatewayPod{})
	if got := publishedGateways(t, v); len(got) != 0 {
		t.Fatalf("deleted: %v", got)
	}
	v.h.setKubeGateways(map[string]kube.GatewayPod{"mesh": {IP: "10.42.1.9", UID: "uid-b"}})
	if got := publishedGateways(t, v); got["mesh"] != "10.42.1.9" {
		t.Fatalf("B: %v", got)
	}
	// An IP without a UID is never trusted.
	v.h.setKubeGateways(map[string]kube.GatewayPod{"mesh": {IP: "10.42.1.9"}})
	if got := publishedGateways(t, v); len(got) != 0 {
		t.Fatalf("no uid: %v", got)
	}
	v.h.mu.RLock()
	_, edge, ok := v.h.vpnGatewayLocked(v.h.findLocked("mesh"))
	v.h.mu.RUnlock()
	if !ok || !strings.HasSuffix(edge, ":9001") {
		t.Errorf("edge %q %v", edge, ok)
	}
}

// TestKubeReservedIncludesClusterCIDRs: under Kubernetes a provider
// range inside the pod or service CIDR is reserved: never wired.
func TestKubeReservedIncludesClusterCIDRs(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.h.cfg.Runtime = runtime.KindKubernetes
	env := filepath.Join(v.h.cfg.ProjectDir, ".env")
	b, _ := os.ReadFile(env)
	os.WriteFile(env, append(b, []byte("PORTCULLIS_POD_CIDR=10.42.0.0/16\nPORTCULLIS_SERVICE_CIDR=10.43.0.0/16\n")...), 0o644)
	for _, r := range []string{"10.42.5.0/24", "10.43.0.0/24"} {
		v.h.mu.Lock()
		v.h.findLocked("mesh2").Manifest.VPN.Ranges = []string{r}
		v.h.mu.Unlock()
		if err := v.h.SetVPNProvider(context.Background(), root, "mesh2", true, 0); statusOf(err) != 409 {
			t.Errorf("%s: wired (%v)", r, err)
		}
	}
	core := v.h.vpnCoreEnv()
	for _, want := range []string{"10.42.0.0/16", "10.43.0.0/16"} {
		if !slices.Contains(core.Reserved, netip.MustParsePrefix(want)) {
			t.Errorf("reserved lacks %s: %v", want, core.Reserved)
		}
	}
}

// degradedRT signals like the kube backend without kill in the image.
type degradedRT struct{ runtime.Instances }

func (degradedRT) Signal(context.Context, string, string) error { return kube.ErrReloadDegraded }

// A reload whose signal can't be sent (Kubernetes, no kill) restarted the
// pod: the unit is ok with reload_degraded, and the doctor lists the
// instance (Info).
func TestReloadDegraded(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	f.h.rt = degradedRT{f.h.rt}
	res, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello")}, directory.Human("admin"))
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	u, ok := unit(res.Deliveries, "reload")
	if !ok || !u.OK || !strings.HasPrefix(u.Message, "reload_degraded") {
		t.Errorf("reload unit = %+v", u)
	}
	f.h.cfg.Runtime = runtime.KindKubernetes
	in := f.h.doctorKubeIn(context.Background())
	if in == nil || !slices.Equal(in.ReloadDegraded, []string{tmID}) {
		t.Errorf("doctor input %+v", in)
	}
	f.h.cfg.Runtime = runtime.KindDocker
	if f.h.doctorKubeIn(context.Background()) != nil {
		t.Error("a docker Hub has Kubernetes doctor inputs")
	}
}
