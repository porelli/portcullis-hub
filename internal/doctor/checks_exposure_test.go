package doctor

import (
	"net/netip"
	"strings"
	"testing"
)

// Task 10: lan_only_exposed and host_network (contract §14.7).

func defaultNets() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func smb(bind string) PortIn {
	return PortIn{Instance: "samba", Key: "SAMBA_SMB", Label: "SMB", Service: "samba", Bind: bind, Port: 445, Container: 445, Protocol: "tcp", LanOnly: true}
}

func exposure(t *testing.T, ports ...PortIn) []Finding {
	t.Helper()
	in := &Inputs{Ports: ports, LocalNetworks: defaultNets(), Domain: "example.org",
		DomainAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}}
	return append(of(t, KindLANOnlyExposed, in), of(t, KindHostNetwork, in)...)
}

func TestExposureAddressForms(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::", "[::]", ""} {
		got := exposure(t, smb(bind))
		if len(got) != 1 || got[0].Kind != KindLANOnlyExposed || got[0].Severity != Warning ||
			got[0].Class != FixOneClick || got[0].FixKind != FixRebindPort {
			t.Fatalf("bind %q = %+v", bind, got)
		}
		if got[0].Instances[0] != "samba" {
			t.Errorf("bind %q instances = %v", bind, got[0].Instances)
		}
	}
	// A custom-override port "8445:445" matched to the lan_only SMB port:
	// a Warning, explain-only (the Hub never writes the custom override).
	custom := PortIn{Instance: "samba", Key: "SAMBA_SMB", Label: "SMB", Service: "samba", Bind: "0.0.0.0", Port: 8445, Container: 445, Protocol: "tcp", LanOnly: true, Custom: true}
	got := exposure(t, custom)
	if len(got) != 1 || got[0].Severity != Warning || got[0].Class != FixExplain || len(got[0].Steps) == 0 ||
		!strings.Contains(got[0].Title, "8445") {
		t.Fatalf("custom = %+v", got)
	}
	if got[0].FP == exposure(t, smb("0.0.0.0"))[0].FP {
		t.Error("the custom port and the template port share a fingerprint")
	}

	for _, bind := range []string{"192.168.1.10", "::ffff:192.168.1.10", "127.0.0.1", "::1", "fd00::1"} {
		if got := exposure(t, smb(bind)); len(got) != 0 {
			t.Errorf("bind %q = %+v, want none", bind, got)
		}
	}
	for _, bind := range []string{"203.0.113.5", "10.0.0.5", "::ffff:10.0.0.5", "2001:db8::1"} {
		got := exposure(t, smb(bind))
		if len(got) != 1 || got[0].Severity != Problem || got[0].FixKind != FixRebindPort {
			t.Fatalf("bind %q = %+v, want a Problem", bind, got)
		}
	}
	if got := exposure(t, smb("10.0.0.5")); !strings.Contains(got[0].Why, "example.org") {
		t.Errorf("main-domain address: why = %q", got[0].Why)
	}

	// Host networking: a Warning, explain-only, the contract's text.
	host := smb("0.0.0.0")
	host.HostNetwork = true
	got = exposure(t, host)
	if len(got) != 1 || got[0].Kind != KindHostNetwork || got[0].Severity != Warning || got[0].Class != FixExplain ||
		!strings.Contains(got[0].Why, "Docker publishes around host firewalls such as ufw; restrict the port in your router or host firewall") {
		t.Fatalf("host network = %+v", got)
	}

	// No lan_only: no finding, whatever the address.
	plain := smb("0.0.0.0")
	plain.LanOnly = false
	if got := exposure(t, plain, PortIn{Instance: "x", Key: "P", Bind: "203.0.113.5", Port: 80, Protocol: "tcp"}); len(got) != 0 {
		t.Fatalf("no lan_only = %+v", got)
	}

	// The severity follows the address, the fingerprint stays.
	if exposure(t, smb("0.0.0.0"))[0].FP != exposure(t, smb("203.0.113.5"))[0].FP {
		t.Error("fingerprint changes with the bind address")
	}
}

func TestExposureLookupFailed(t *testing.T) {
	in := &Inputs{Ports: []PortIn{smb("0.0.0.0")}, LocalNetworks: defaultNets(), Domain: "example.org", DomainErr: true}
	got := of(t, KindLANOnlyExposed, in)
	if len(got) != 1 || got[0].Severity != Warning || !strings.Contains(got[0].Why, "couldn't resolve example.org") {
		t.Fatalf("lookup failed = %+v", got)
	}
	// A local address can't be checked against the main domain: nothing
	// escalates.
	in.Ports = []PortIn{smb("10.0.0.5")}
	if got := of(t, KindLANOnlyExposed, in); len(got) != 0 {
		t.Fatalf("local address, lookup failed = %+v", got)
	}
}

func TestIsLocal(t *testing.T) {
	nets := defaultNets()
	for s, want := range map[string]bool{
		"127.0.0.1": true, "127.9.9.9": true, "::1": true, "::ffff:127.0.0.1": true,
		"192.168.1.10": true, "::ffff:192.168.1.10": true, "100.64.1.1": true, "fd12::1": true,
		"203.0.113.5": false, "8.8.8.8": false, "2001:db8::1": false,
	} {
		if got := IsLocal(netip.MustParseAddr(s), nets); got != want {
			t.Errorf("IsLocal(%s) = %v", s, got)
		}
	}
	if !IsLocal(netip.MustParseAddr("::1"), nil) || IsLocal(netip.MustParseAddr("10.0.0.1"), nil) {
		t.Error("empty list: only loopback is local")
	}
}
