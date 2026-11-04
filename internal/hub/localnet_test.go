package hub

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/doctor"
)

// Task 10: Local networks, the main domain's addresses and the ports the
// doctor judges (contract §14.7).

const sambaManifest = `name: Samba
category: storage
instances: multi
auth:
  method: forward-auth
ports:
  - key: SAMBA_SMB
    label: SMB
    container: 445
    default: 445
    service: samba
    lan_only: true
  - key: SAMBA_WEB
    label: Web
    container: 80
    default: 8080
    service: samba
  - key: SAMBA_WSDD
    label: Discovery
    container: 3702
    protocol: udp
    default: 3702
    service: wsdd
    network_mode_host: true
    lan_only: true
`

const sambaCompose = "services:\n  samba:\n    image: samba\n    labels:\n" +
	"      traefik.http.routers.samba.rule: Host(`${PORTCULLIS_HOST_SAMBA:-samba.portcullis.local}`)\n" +
	"  wsdd:\n    image: wsdd\n    network_mode: host\n    environment:\n      WSDD_PORT: ${SAMBA_WSDD:-3702}\n"

func sambaFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"samba": {sambaManifest, sambaCompose}})
	if f.h.Template("samba") == nil {
		t.Fatal("samba fixture not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	f.h.SetPeople(newFakePeople("erin"))
	return f, audit
}

func TestLocalNetworksValidate(t *testing.T) {
	f, audit := sambaFixture(t)
	nets, def := f.h.LocalNetworksView()
	if !def || strings.Join(nets, ",") != strings.Join(DefaultLocalNetworks, ",") {
		t.Fatalf("view = %v %v", nets, def)
	}
	for _, bad := range [][]string{{"0.0.0.0/0"}, {"::/0"}, {"10.0.0.1/8"}, {"10.0.0.0/8", "nonsense"}, {"10.0.0.0/8", "10.0.0.0/8"}} {
		err := f.h.SetLocalNetworks(bad, "root")
		if statusOf(err) != 400 || !strings.Contains(err.Error(), bad[len(bad)-1]) {
			t.Errorf("%v: err = %v, want 400 naming the entry", bad, err)
		}
		if e := audit.last(); e.Action != "settings.local_networks" || e.Result != "refused" {
			t.Errorf("%v: audit = %+v", bad, e)
		}
	}
	many := make([]string, 65)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	if err := f.h.SetLocalNetworks(many, "root"); statusOf(err) != 400 {
		t.Errorf("65 entries: %v", err)
	}
	if err := f.h.SetLocalNetworks([]string{"10.0.0.0/8"}, ""); statusOf(err) != 401 {
		t.Errorf("no actor: %v", err)
	}

	// [] = loopback only; it survives a restart.
	if err := f.h.SetLocalNetworks([]string{}, "root"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "settings.local_networks" || e.Result != "ok" || e.Detail != "0 networks" || e.Actor != "root" {
		t.Errorf("audit = %+v", e)
	}
	h2 := reopen(t, f)
	if nets, def := h2.LocalNetworksView(); def || nets == nil || len(nets) != 0 || len(h2.LocalNetworks()) != 0 {
		t.Fatalf("after reopen = %v %v", nets, def)
	}
	if doctor.IsLocal(netip.MustParseAddr("192.168.1.10"), f.h.LocalNetworks()) || !IsLocal(netip.MustParseAddr("127.0.0.1"), f.h.LocalNetworks()) {
		t.Error("[]: only loopback is local")
	}

	// nil = the defaults.
	if err := f.h.SetLocalNetworks(nil, "root"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Detail != "5 networks" || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if nets, def := f.h.LocalNetworksView(); !def || len(nets) != 5 {
		t.Fatalf("nil = %v %v", nets, def)
	}
	f.h.mu.RLock()
	stored := f.h.st.LocalNetworks
	f.h.mu.RUnlock()
	if stored != nil {
		t.Errorf("nil stored as %v", *stored)
	}

	if err := f.h.SetLocalNetworks([]string{"192.168.1.0/24", "fd00::/8"}, "root"); err != nil {
		t.Fatal(err)
	}
	if nets, def := f.h.LocalNetworksView(); def || strings.Join(nets, ",") != "192.168.1.0/24,fd00::/8" {
		t.Fatalf("custom = %v %v", nets, def)
	}
	if e := audit.last(); e.Detail != "2 networks" {
		t.Errorf("audit = %+v", e)
	}
}

func TestDomainAddrsCached(t *testing.T) {
	f, _ := sambaFixture(t)
	var calls atomic.Int32
	fail := false
	f.h.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		if host != "example.org" {
			t.Errorf("lookup %q", host)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("lookup without a deadline")
		}
		if fail {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("::ffff:192.168.1.10")}, nil
	}
	f.h.mu.Lock()
	s := f.h.st.Settings["samba"].Clone()
	s.Ports = map[string]string{"SAMBA_SMB_BIND": "192.168.1.10"}
	f.h.st.Settings["samba"] = s
	f.h.mu.Unlock()
	enableQuiet(f, "samba")

	smbFinding := func() *doctor.Finding {
		r, err := f.h.Doctor(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for i := range r.Findings {
			if r.Findings[i].Kind == doctor.KindLANOnlyExposed && strings.Contains(r.Findings[i].Title, "SMB") {
				return &r.Findings[i]
			}
		}
		return nil
	}
	got := smbFinding()
	if got == nil || got.Severity != doctor.Problem {
		t.Fatalf("bound to the main domain's address: %+v", got)
	}
	_ = smbFinding()
	if calls.Load() != 1 {
		t.Fatalf("lookups = %d, want 1 (cached)", calls.Load())
	}

	// After 5 minutes the cache expires; a failed lookup escalates nothing.
	f.h.dnsMu.Lock()
	f.h.dnsCache.at = f.h.dnsCache.at.Add(-6 * time.Minute)
	f.h.dnsMu.Unlock()
	fail = true
	if got := smbFinding(); got != nil {
		t.Fatalf("failed lookup, local address: %+v", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("lookups = %d, want 2", calls.Load())
	}
	f.h.mu.Lock()
	s = f.h.st.Settings["samba"].Clone()
	s.Ports = map[string]string{"SAMBA_SMB_BIND": "0.0.0.0"}
	f.h.st.Settings["samba"] = s
	f.h.mu.Unlock()
	got = smbFinding()
	if got == nil || got.Severity != doctor.Warning || !strings.Contains(got.Why, "couldn't resolve example.org") {
		t.Fatalf("failed lookup, all interfaces: %+v", got)
	}
}

func TestExposurePortsGathered(t *testing.T) {
	f, _ := sambaFixture(t)
	f.h.lookupIP = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	writeFile(t, f.h.userOverridePath("samba"), "services:\n  samba:\n    ports:\n      - \"8445:445\"\n      - \"[::ffff:192.168.1.10]:8139:139\"\n      - target: 445\n        published: 9445\n        host_ip: 203.0.113.5\n")
	enableQuiet(f, "samba")
	in, err := f.h.doctorInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(in.LocalNetworks) != 5 || in.Domain != "example.org" {
		t.Errorf("networks %v domain %q", in.LocalNetworks, in.Domain)
	}
	byPort := map[int]doctor.PortIn{}
	for _, p := range in.Ports {
		byPort[p.Port] = p
	}
	want := map[int]doctor.PortIn{
		445:  {Instance: "samba", Key: "SAMBA_SMB", Label: "SMB", Service: "samba", Bind: "0.0.0.0", Port: 445, Container: 445, Protocol: "tcp", LanOnly: true},
		8080: {Instance: "samba", Key: "SAMBA_WEB", Label: "Web", Service: "samba", Bind: "0.0.0.0", Port: 8080, Container: 80, Protocol: "tcp"},
		3702: {Instance: "samba", Key: "SAMBA_WSDD", Label: "Discovery", Service: "wsdd", Bind: "0.0.0.0", Port: 3702, Container: 3702, Protocol: "udp", LanOnly: true, HostNetwork: true},
		8445: {Instance: "samba", Key: "SAMBA_SMB", Label: "SMB", Service: "samba", Bind: "0.0.0.0", Port: 8445, Container: 445, Protocol: "tcp", LanOnly: true, Custom: true},
		8139: {Instance: "samba", Key: "custom override", Service: "samba", Bind: "::ffff:192.168.1.10", Port: 8139, Container: 139, Protocol: "tcp", Custom: true},
		9445: {Instance: "samba", Key: "SAMBA_SMB", Label: "SMB", Service: "samba", Bind: "203.0.113.5", Port: 9445, Container: 445, Protocol: "tcp", LanOnly: true, Custom: true},
	}
	if len(byPort) != len(want) {
		t.Fatalf("ports = %+v", in.Ports)
	}
	for port, w := range want {
		if byPort[port] != w {
			t.Errorf("port %d = %+v, want %+v", port, byPort[port], w)
		}
	}

	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sev := map[string]doctor.Severity{}
	for _, fd := range r.Findings {
		if fd.Kind == doctor.KindLANOnlyExposed || fd.Kind == doctor.KindHostNetwork {
			sev[fd.Kind+" "+fd.Title] = fd.Severity
		}
	}
	if len(sev) != 4 {
		t.Fatalf("findings = %v", sev)
	}
}

// No test reaches DNS: the main domain resolves to nothing unless a test
// sets h.lookupIP.
func init() {
	defaultLookupIP = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
}
