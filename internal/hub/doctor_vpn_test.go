package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
)

func vpnFindings(t *testing.T, v *vpnFixture, kind string) []doctor.Finding {
	t.Helper()
	rep, err := v.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []doctor.Finding
	for _, f := range rep.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// A gateway container (or a service sharing its namespace) with
// NET_ADMIN, privileged or host devices: vpn_gateway_privileged (Info)
// naming the service; the inspect goes through the engine.
func TestGatewayPrivilegedFromInspect(t *testing.T) {
	m := meshTemplate("mesh", "100.64.0.0/10", "oidc_sub")
	m[1] = strings.Replace(m[1], "  gateway:\n    image: x\n", "  gateway:\n    image: x\n  fwd:\n    image: ghcr.io/porelli/portcullis-forwarder:1@sha256:"+strings.Repeat("a", 64)+"\n    network_mode: service:gateway\n", 1)
	v := newVPNFixtureExtra(t, nil, map[string][2]string{"mesh": m}, VPNModeApps)
	v.wire(t, "mesh")
	v.engine.mu.Lock()
	v.engine.containers = append(v.engine.containers, container("portcullis-mesh-fwd", "portcullis-mesh", "fwd", "running"))
	v.engine.mu.Unlock()
	fx := v.engine.fx()
	fx.fmu.Lock()
	fx.inspect = map[string]docker.ContainerInfo{
		"portcullis-mesh-gw":  {ID: "portcullis-mesh-gw"},
		"portcullis-mesh-fwd": {ID: "portcullis-mesh-fwd", CapAdd: []string{"CAP_NET_ADMIN"}},
	}
	fx.fmu.Unlock()
	f := vpnFindings(t, v, doctor.KindVPNGatewayPrivileged)
	if len(f) != 1 || f[0].Severity != doctor.Info || !strings.Contains(f[0].Title, "fwd") || strings.Contains(f[0].Title, "gateway,") {
		t.Fatalf("%+v", f)
	}
	fx.fmu.Lock()
	fx.inspect["portcullis-mesh-fwd"] = docker.ContainerInfo{ID: "portcullis-mesh-fwd"}
	fx.inspect["portcullis-mesh-gw"] = docker.ContainerInfo{ID: "portcullis-mesh-gw", Privileged: true}
	fx.fmu.Unlock()
	if f := vpnFindings(t, v, doctor.KindVPNGatewayPrivileged); len(f) != 1 || !strings.Contains(f[0].Title, "gateway") {
		t.Fatalf("privileged: %+v", f)
	}
	fx.fmu.Lock()
	fx.inspect["portcullis-mesh-gw"] = docker.ContainerInfo{ID: "portcullis-mesh-gw", Devices: []string{"/dev/net/tun"}}
	fx.fmu.Unlock()
	if f := vpnFindings(t, v, doctor.KindVPNGatewayPrivileged); len(f) != 1 {
		t.Fatalf("devices: %+v", f)
	}
	fx.fmu.Lock()
	fx.inspect["portcullis-mesh-gw"] = docker.ContainerInfo{ID: "portcullis-mesh-gw"}
	fx.fmu.Unlock()
	if f := vpnFindings(t, v, doctor.KindVPNGatewayPrivileged); len(f) != 0 {
		t.Fatalf("plain gateway: %+v", f)
	}
}

// vpn_provider_stale shows the hook's last error: redacted (a stored
// secret blanked), then clipped.
func TestProviderStaleShowsRedactedError(t *testing.T) {
	m := meshTemplate("mesh", "100.64.0.0/10", "oidc_sub")
	m[0] = strings.Replace(m[0], "hooks:\n", "env:\n  - key: MESH_TOKEN\n    generate: random\nhooks:\n", 1)
	v := newVPNFixtureExtra(t, nil, map[string][2]string{"mesh": m}, VPNModeApps)
	if err := v.h.Enable("mesh"); err != nil {
		t.Fatal(err)
	}
	v.h.Wait()
	env, _ := os.ReadFile(filepath.Join(v.data, "env", "mesh.env"))
	secret := ""
	for _, l := range strings.Split(string(env), "\n") {
		if s, ok := strings.CutPrefix(l, "MESH_TOKEN="); ok {
			secret = s
		}
	}
	if len(secret) < 8 {
		t.Fatalf("no generated secret in %s", env)
	}
	v.wire(t, "mesh")
	v.devicesFail = &docker.ExecSplitResult{ExitCode: 1, Stderr: []byte("login failed with " + secret + " " + strings.Repeat("x", 5000))}
	v.h.runVPNProvider(context.Background(), "mesh")
	f := vpnFindings(t, v, doctor.KindVPNProviderStale)
	if len(f) != 1 || f[0].Severity != doctor.Problem {
		t.Fatalf("%+v", f)
	}
	if strings.Contains(f[0].Why, secret) || !strings.Contains(f[0].Why, "[redacted]") || len(f[0].Why) > unitErrorMax+600 {
		t.Fatalf("why not redacted or clipped (%d): %.200s", len(f[0].Why), f[0].Why)
	}
}

// The VPN kinds stay silent on a Hub with nothing VPN about it.
func TestDoctorVPNSilent(t *testing.T) {
	v := newVPNFixture(t, nil)
	os.Remove(v.status)
	rep, err := v.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Kind, "vpn_") {
			t.Errorf("%s: %s", f.Kind, f.Title)
		}
	}
}
