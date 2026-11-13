package doctor

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var vpnNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// vpnRun is one VPN kind's findings for v.
func vpnRun(kind string, v *VPNIn) []Finding {
	return vpnCheck{kind: kind}.Run(&Inputs{Now: vpnNow, VPN: v})
}

// vpnCase checks a kind fires on yes (once, with sev) and not on no.
func vpnCase(t *testing.T, kind string, sev Severity, yes, no *VPNIn) []Finding {
	t.Helper()
	got := vpnRun(kind, yes)
	if len(got) != 1 || got[0].Severity != sev || got[0].Kind != kind || !strings.HasSuffix(got[0].Why, VPNUDPNote) || got[0].Class != FixExplain {
		t.Fatalf("%s fires = %+v", kind, got)
	}
	if n := vpnRun(kind, no); len(n) != 0 {
		t.Fatalf("%s fires when it shouldn't: %+v", kind, n)
	}
	return got
}

func hookP(id string) VPNProviderIn {
	return VPNProviderIn{ID: id, Label: id, Source: "hook", GatewayUp: true, Ranges: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}
}

func TestVPNKindsSilentWithoutVPN(t *testing.T) {
	for _, k := range VPNKinds {
		if f := vpnRun(k, &VPNIn{Mode: "apps"}); len(f) != 0 {
			t.Errorf("%s: %+v", k, f)
		}
		if f := (vpnCheck{kind: k}).Run(&Inputs{Now: vpnNow}); len(f) != 0 {
			t.Errorf("%s without inputs: %+v", k, f)
		}
	}
	if len(VPNKinds) != 17 {
		t.Fatalf("%d kinds", len(VPNKinds))
	}
}

func TestVPNDown(t *testing.T) {
	f := vpnCase(t, KindVPNDown, Problem, &VPNIn{Mode: "apps", VPNOnly: []string{"cloud"}, WGError: "status stale"}, &VPNIn{Mode: "apps", VPNOnly: []string{"cloud"}, WGUp: true})
	if !strings.Contains(strings.Join(f[0].Steps, " "), "./portcullis up") || !strings.Contains(strings.Join(f[0].Steps, " "), "./portcullis logs wg") {
		t.Fatal(f[0].Steps)
	}
	vpnCase(t, KindVPNDown, Problem, &VPNIn{Mode: "server"}, &VPNIn{Mode: "apps"})
}

func TestVPNProviderStale(t *testing.T) {
	s := hookP("mesh")
	s.Stale, s.LastError = true, "hook vpn-devices: exited 1"
	f := vpnCase(t, KindVPNProviderStale, Problem, &VPNIn{WGUp: true, Providers: []VPNProviderIn{s}}, &VPNIn{WGUp: true, Providers: []VPNProviderIn{hookP("mesh")}})
	if !strings.Contains(f[0].Why, "exited 1") || f[0].Instances[0] != "mesh" {
		t.Fatal(f[0])
	}
	down := hookP("mesh")
	down.GatewayUp = false
	vpnCase(t, KindVPNProviderStale, Problem, &VPNIn{WGUp: true, Providers: []VPNProviderIn{down}}, &VPNIn{WGUp: true})
}

func TestVPNProviderInvalid(t *testing.T) {
	d := hookP("mesh")
	d.Duplicates = 2
	vpnCase(t, KindVPNProviderInvalid, Problem, &VPNIn{Providers: []VPNProviderIn{d}}, &VPNIn{Providers: []VPNProviderIn{hookP("mesh")}})
	o := hookP("mesh")
	o.Unresolved = 1
	vpnCase(t, KindVPNProviderInvalid, Info, &VPNIn{Providers: []VPNProviderIn{o}}, &VPNIn{Providers: []VPNProviderIn{hookP("mesh")}})
}

func TestVPNRangeOverlap(t *testing.T) {
	p := []VPNProviderIn{hookP("mesh")}
	vpnCase(t, KindVPNRangeOverlap, Warning, &VPNIn{Providers: p, LocalNetworks: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}},
		&VPNIn{Providers: p, LocalNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}})
	vpnCase(t, KindVPNRangeOverlap, Problem, &VPNIn{Providers: p, DockerNets: []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")}},
		&VPNIn{Providers: p, DockerNets: []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}})
}

func TestVPNViaDead(t *testing.T) {
	stale := hookP("mesh")
	stale.Stale = true
	inst := []VPNInstanceIn{{ID: "cloud", Via: []string{"mesh"}}}
	vpnCase(t, KindVPNViaDead, Problem, &VPNIn{WGUp: true, Instances: inst, Providers: []VPNProviderIn{stale}},
		&VPNIn{WGUp: true, Instances: inst, Providers: []VPNProviderIn{hookP("mesh")}})
	// Unwired: not in Providers at all.
	vpnCase(t, KindVPNViaDead, Problem, &VPNIn{WGUp: true, Instances: inst}, &VPNIn{WGUp: true, Builtin: true, Instances: []VPNInstanceIn{{ID: "cloud", Via: []string{"builtin"}}}})
	if f := vpnRun(KindVPNViaDead, &VPNIn{WGUp: true, Instances: []VPNInstanceIn{{ID: "cloud", Via: []string{"*"}}}}); len(f) != 0 {
		t.Fatal("via * is vpn_down's or vpn_provider_stale's")
	}
}

func TestVPNDNSFailed(t *testing.T) {
	p := hookP("mesh")
	p.DNSError = "hook vpn-dns: exited 3"
	vpnCase(t, KindVPNDNSFailed, Problem, &VPNIn{Providers: []VPNProviderIn{p}}, &VPNIn{Providers: []VPNProviderIn{hookP("mesh")}})
}

func TestVPNDNSManual(t *testing.T) {
	p := hookP("wg")
	p.DNSManual = true
	acked := p
	acked.DNSAcked = true
	vpnCase(t, KindVPNDNSManual, Info, &VPNIn{Providers: []VPNProviderIn{p}}, &VPNIn{Providers: []VPNProviderIn{acked}})
}

func TestVPNGatewayPrivileged(t *testing.T) {
	p := hookP("netbird")
	p.GatewayPrivileged, p.PrivilegedServices = true, []string{"client"}
	f := vpnCase(t, KindVPNGatewayPrivileged, Info, &VPNIn{Providers: []VPNProviderIn{p}}, &VPNIn{Providers: []VPNProviderIn{hookP("netbird")}})
	if !strings.Contains(f[0].Title, "client") {
		t.Fatal(f[0].Title)
	}
}

func TestVPNStaticMapping(t *testing.T) {
	p := hookP("wg")
	p.Source = "static"
	vpnCase(t, KindVPNStaticMapping, Info, &VPNIn{Providers: []VPNProviderIn{p}}, &VPNIn{Providers: []VPNProviderIn{hookP("mesh")}})
}

func TestVPNSingleProvider(t *testing.T) {
	vpnCase(t, KindVPNSingleProvider, Warning, &VPNIn{Mode: "server", Providers: []VPNProviderIn{hookP("mesh")}},
		&VPNIn{Mode: "server", Builtin: true, Providers: []VPNProviderIn{hookP("mesh")}})
	vpnCase(t, KindVPNSingleProvider, Warning, &VPNIn{Mode: "admin", Builtin: true}, &VPNIn{Mode: "apps", Builtin: true})
}

func TestVPNPublicLinks(t *testing.T) {
	vpnCase(t, KindVPNPublicLinks, Warning, &VPNIn{Instances: []VPNInstanceIn{{ID: "cloud", PublicLinks: true}}}, &VPNIn{Instances: []VPNInstanceIn{{ID: "cloud"}}})
}

func TestVPNNoAdminDevice(t *testing.T) {
	vpnCase(t, KindVPNNoAdminDevice, Problem, &VPNIn{Mode: "admin", AdminSeen: vpnNow.Add(-31 * 24 * time.Hour)}, &VPNIn{Mode: "admin", AdminSeen: vpnNow.Add(-29 * 24 * time.Hour)})
	vpnCase(t, KindVPNNoAdminDevice, Problem, &VPNIn{Mode: "server"}, &VPNIn{Mode: "apps"})
}

func TestVPNDeviceStale(t *testing.T) {
	old := vpnNow.Add(-91 * 24 * time.Hour)
	recent := vpnNow.Add(-89 * 24 * time.Hour)
	f := vpnCase(t, KindVPNDeviceStale, Info, &VPNIn{Devices: []VPNDeviceIn{{ID: "d1", User: "alice", Name: "laptop", Created: old, LastHandshake: &old}}},
		&VPNIn{Devices: []VPNDeviceIn{{ID: "d1", User: "alice", Name: "laptop", Created: old, LastHandshake: &recent}}})
	if f[0].Persons[0] != "alice" {
		t.Fatal(f[0])
	}
	// Never connected: judged from its creation.
	vpnCase(t, KindVPNDeviceStale, Info, &VPNIn{Devices: []VPNDeviceIn{{ID: "d2", User: "bob", Created: old}}}, &VPNIn{Devices: []VPNDeviceIn{{ID: "d2", User: "bob", Created: recent}}})
}

func TestVPNExpiring(t *testing.T) {
	soon, later, past := vpnNow.Add(13*24*time.Hour), vpnNow.Add(15*24*time.Hour), vpnNow.Add(-time.Hour)
	f := vpnCase(t, KindVPNExpiring, Info, &VPNIn{Devices: []VPNDeviceIn{{ID: "d1", User: "alice", Name: "laptop", Expires: &soon}}},
		&VPNIn{Devices: []VPNDeviceIn{{ID: "d1", User: "alice", Expires: &later}, {ID: "d2", User: "bob", Expires: &past}, {ID: "d3", User: "carol"}}})
	if len(f[0].Persons) != 1 || f[0].Persons[0] != "alice" {
		t.Fatal(f[0])
	}
}

func TestVPNReachFailedClosed(t *testing.T) {
	f := vpnCase(t, KindVPNReachFailedClosed, Problem, &VPNIn{FailedClosed: []string{"cloud"}}, &VPNIn{})
	if f[0].Instances[0] != "cloud" {
		t.Fatal(f[0])
	}
}

func TestVPNViaNone(t *testing.T) {
	vpnCase(t, KindVPNViaDead, Warning, &VPNIn{WGUp: true, Instances: []VPNInstanceIn{{ID: "cloud", Via: []string{}}}},
		&VPNIn{WGUp: true, Instances: []VPNInstanceIn{{ID: "cloud", Via: []string{"*"}}}})
}

func TestVPNReservedDefaults(t *testing.T) {
	vpnCase(t, KindVPNReservedDefault, Warning, &VPNIn{ReservedDefault: true, Builtin: true}, &VPNIn{Builtin: true})
}

func TestVPNPublishFailed(t *testing.T) {
	vpnCase(t, KindVPNPublishFailed, Problem, &VPNIn{PublishError: "disk full"}, &VPNIn{})
}
