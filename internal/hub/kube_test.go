package hub

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/templates"
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

// Under Kubernetes a switched-on companion reaches the translator as its
// compose service, gate alias and port (mcp-gate's upstream host); off,
// nothing.
func TestKubeInputsCompanions(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.h.cfg.Runtime = runtime.KindKubernetes
	tp := a.h.Template("aiapp")
	in, err := a.h.kubeInputs(tp)
	if err != nil || len(in.Companions) != 0 {
		t.Fatalf("off: %+v %v", in, err)
	}
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	in, err = a.h.kubeInputs(a.h.Template("aiapp"))
	if err != nil {
		t.Fatal(err)
	}
	var c *templates.Companion
	for i := range tp.Manifest.AI.MCP {
		if tp.Manifest.AI.MCP[i].Name == "tok" {
			c = &tp.Manifest.AI.MCP[i]
		}
	}
	want := []runtime.CompanionInput{{Service: c.Service, Alias: "portcullis-mcp-aiapp--tok", Port: c.Port}}
	if !reflect.DeepEqual(in.Companions, want) {
		t.Errorf("companions %+v, want %+v", in.Companions, want)
	}
}

// Under Kubernetes a restore and a restore-as fill the instance's PVCs,
// <instance>--<volume> (§11.2), never the Docker names.
func TestKubeRestoreTargetsPVCNames(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	// The template, as it must be for Kubernetes: a numeric user.
	cp := filepath.Join(f.src, "grafana", "compose.yml")
	b, _ := os.ReadFile(cp)
	writeFile(t, cp, strings.Replace(string(b), "    image: grafana\n", "    image: grafana\n    user: \"472:472\"\n", 1))
	f.h.Discover()
	f.setRuntime(runtime.KindKubernetes)
	f.h.rt = ownerRT{f.h.rt}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root")); err != nil {
		t.Fatalf("restore-as: %v", err)
	}
	names := f.engine.volumeNames()
	pvc, dock := slices.Contains(names, "grafana-c--grafana-data"), slices.Contains(names, "portcullis_grafana-c-grafana-data")
	if !pvc || dock {
		t.Errorf("restore-as volumes: PVC %v, Docker name %v", pvc, dock)
	}
	// A restore into it again (the PVC exists now) and into a fresh one
	// whose PVC the restore creates.
	own, err := f.h.BackupInstance("grafana-c", directory.Human("root"))
	if err != nil {
		t.Fatalf("backup on kubernetes: %v", err)
	}
	if _, err := f.h.RestoreInstance("grafana-c", own.Archive, directory.Human("root")); err != nil {
		t.Fatalf("restore: %v", err)
	}
	f.engine.RemoveVolume(context.Background(), "grafana-c--grafana-data")
	if _, err := f.h.RestoreInstance("grafana-c", own.Archive, directory.Human("root")); err != nil {
		t.Fatalf("restore with no PVC: %v", err)
	}
	for _, n := range f.engine.volumeNames() {
		if strings.HasPrefix(n, "portcullis_grafana-c") {
			t.Errorf("a Docker-named volume %s", n)
		}
	}
	if !slices.Contains(f.engine.volumeNames(), "grafana-c--grafana-data") {
		t.Errorf("volumes %v", f.engine.volumeNames())
	}
}

// ownerRT adds the kube backend's VolumeOwner to a test runtime and,
// like it, reports volumes without options (a PVC's owner lives in its
// annotations).
type ownerRT struct{ runtime.Instances }

func (o ownerRT) ListVolumes(ctx context.Context, f runtime.Filter) ([]runtime.Volume, error) {
	vs, err := o.Instances.ListVolumes(ctx, f)
	for i := range vs {
		vs[i].Options = nil
	}
	return vs, err
}

func (o ownerRT) InspectVolume(ctx context.Context, name string) (runtime.Volume, error) {
	v, err := o.Instances.InspectVolume(ctx, name)
	v.Options = nil
	return v, err
}

func (ownerRT) VolumeOwner(_ context.Context, p runtime.Project, key string) (map[string]string, error) {
	return map[string]string{"portcullis.io/uid": "472", "portcullis.io/gid": "472", "portcullis.io/mode": "0750"}, nil
}
