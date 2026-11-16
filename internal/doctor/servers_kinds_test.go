package doctor

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// worker is a ready worker with healthy facts.
func worker() ServerIn {
	return ServerIn{ID: "nas", Name: "NAS", State: "ready", CertNotAfter: t0.Add(20 * 24 * time.Hour), AgentVersion: "1.4.0", Info: true,
		DiskTotal: 1000, DiskFree: 500, DataTotal: 1000, DataFree: 500, Instances: []string{"notes"}}
}

func serversIn(mut func(*ServersIn)) *Inputs {
	in := &ServersIn{Servers: []ServerIn{worker()}, HubVersion: "1.4.2", Now: t0, LinkSubnet: netip.MustParsePrefix("10.214.0.0/24")}
	mut(in)
	return &Inputs{Servers: in}
}

// TestServerKinds (Task 13): each kind fires on its input and not on the
// boundary value (7 d vs 7 d + 1 s, 10 % vs 9.9 %, 14 d).
func TestServerKinds(t *testing.T) {
	for _, c := range []struct {
		name, kind string
		mut        func(*ServersIn)
		want       int
		sev        Severity
	}{
		{"healthy: no offline", KindServerOffline, func(*ServersIn) {}, 0, Problem},
		{"offline", KindServerOffline, func(in *ServersIn) { in.Servers[0].State, in.Servers[0].Reason = "offline", "server_identity_mismatch" }, 1, Problem},
		{"cert 7d+1s", KindServerCertExpiring, func(in *ServersIn) { in.Servers[0].CertNotAfter = t0.Add(7*24*time.Hour + time.Second) }, 0, Warning},
		{"cert 7d", KindServerCertExpiring, func(in *ServersIn) { in.Servers[0].CertNotAfter = t0.Add(7 * 24 * time.Hour) }, 1, Warning},
		{"cert expired", KindServerCertExpiring, func(in *ServersIn) { in.Servers[0].CertNotAfter = t0.Add(-time.Hour) }, 1, Warning},
		{"agent same minor", KindServerAgentIncompatible, func(*ServersIn) {}, 0, Problem},
		{"agent two behind", KindServerAgentIncompatible, func(in *ServersIn) { in.Servers[0].AgentVersion = "1.2.9" }, 1, Problem},
		{"agent newer", KindServerAgentIncompatible, func(in *ServersIn) { in.Servers[0].AgentVersion = "1.5.0" }, 1, Problem},
		{"agent dev", KindServerAgentIncompatible, func(in *ServersIn) { in.Servers[0].AgentVersion = "edge" }, 1, Problem},
		{"agent unknown (no info)", KindServerAgentIncompatible, func(in *ServersIn) { in.Servers[0].Info, in.Servers[0].AgentVersion = false, "" }, 0, Problem},
		{"agent one behind: not incompatible", KindServerAgentIncompatible, func(in *ServersIn) { in.Servers[0].AgentVersion = "1.3.7" }, 0, Problem},
		{"agent one behind: outdated", KindServerAgentOutdated, func(in *ServersIn) { in.Servers[0].AgentVersion = "1.3.7" }, 1, Info},
		{"agent same minor: not outdated", KindServerAgentOutdated, func(*ServersIn) {}, 0, Info},
		{"agent two behind: not outdated", KindServerAgentOutdated, func(in *ServersIn) { in.Servers[0].AgentVersion = "1.2.0" }, 0, Info},
		{"disk 10%", KindServerDiskLow, func(in *ServersIn) { in.Servers[0].DiskFree = 100 }, 0, Warning},
		{"disk 9.9%", KindServerDiskLow, func(in *ServersIn) { in.Servers[0].DiskFree = 99 }, 1, Warning},
		{"data 9.9%", KindServerDiskLow, func(in *ServersIn) { in.Servers[0].DataTotal, in.Servers[0].DataFree = 10000, 990 }, 1, Warning},
		{"disk unknown", KindServerDiskLow, func(in *ServersIn) { in.Servers[0].DiskTotal, in.Servers[0].DiskFree = 0, 0 }, 0, Warning},
		{"backup 14d", KindServerNoRecentBackup, func(in *ServersIn) {
			in.Placed = []PlacedIn{{ID: "notes", Server: "nas", Enabled: true, LastBackup: t0.Add(-14 * 24 * time.Hour)}}
		}, 0, Warning},
		{"backup 14d+1s", KindServerNoRecentBackup, func(in *ServersIn) {
			in.Placed = []PlacedIn{{ID: "notes", Server: "nas", Enabled: true, LastBackup: t0.Add(-14*24*time.Hour - time.Second)}}
		}, 1, Warning},
		{"never backed up", KindServerNoRecentBackup, func(in *ServersIn) { in.Placed = []PlacedIn{{ID: "notes", Server: "nas", Enabled: true}} }, 1, Warning},
		{"disabled: no backup needed", KindServerNoRecentBackup, func(in *ServersIn) { in.Placed = []PlacedIn{{ID: "notes", Server: "nas"}} }, 0, Warning},
		{"leftover 7d", KindServerMoveLeftover, func(in *ServersIn) {
			in.Leftovers = []LeftoverIn{{Instance: "notes", Server: "", At: t0.Add(-7 * 24 * time.Hour), Volumes: []string{"portcullis-notes_data"}}}
		}, 0, Info},
		{"leftover 7d+1s", KindServerMoveLeftover, func(in *ServersIn) {
			in.Leftovers = []LeftoverIn{{Instance: "notes", Server: "", At: t0.Add(-7*24*time.Hour - time.Second), Volumes: []string{"portcullis-notes_data"}}}
		}, 1, Info},
		{"target leftover at once", KindServerMoveLeftover, func(in *ServersIn) {
			in.Leftovers = []LeftoverIn{{Instance: "notes", Server: "nas", At: t0, Volumes: []string{"portcullis-notes_data"}, Target: true}}
		}, 1, Info},
		{"no overlap", KindLinkSubnetOverlap, func(in *ServersIn) {
			in.Ranges = []RangeIn{{Name: "the VPN range", Prefix: netip.MustParsePrefix("10.8.0.0/24")}}
		}, 0, Problem},
		{"overlap: a provider", KindLinkSubnetOverlap, func(in *ServersIn) {
			in.Ranges = []RangeIn{{Name: "the VPN range", Prefix: netip.MustParsePrefix("10.214.0.128/25")}}
		}, 1, Problem},
		{"overlap: a LAN", KindLinkSubnetOverlap, func(in *ServersIn) {
			in.Ranges = []RangeIn{{Name: "server nas's Local network", Prefix: netip.MustParsePrefix("10.214.0.0/16")}}
		}, 1, Problem},
		{"orphaned", KindInstanceOrphaned, func(in *ServersIn) { in.Orphaned = map[string]string{"notes": "nas"} }, 1, Problem},
		{"none orphaned", KindInstanceOrphaned, func(*ServersIn) {}, 0, Problem},
	} {
		got := of(t, c.kind, serversIn(c.mut))
		if len(got) != c.want {
			t.Errorf("%s: %d findings, want %d: %+v", c.name, len(got), c.want, got)
			continue
		}
		for _, f := range got {
			if f.Severity != c.sev {
				t.Errorf("%s: severity %v, want %v", c.name, f.Severity, c.sev)
			}
		}
	}
	// The leftover is explain-only (its removal is † : fresh sign-in),
	// pointing at the gated page; no Servers input: nothing.
	f := of(t, KindServerMoveLeftover, serversIn(func(in *ServersIn) {
		in.Leftovers = []LeftoverIn{{Instance: "notes", At: t0.Add(-8 * 24 * time.Hour), Volumes: []string{"v"}}}
	}))
	if len(f) != 1 || f[0].Class != FixExplain || f[0].FixKind != "" || f[0].Instances[0] != "notes" || len(f[0].Steps) == 0 ||
		!strings.Contains(f[0].Steps[0], "Remove the old copy") || !strings.Contains(f[0].Steps[0], "fresh sign-in") {
		t.Errorf("leftover fix %+v", f)
	}
	for _, k := range []string{KindServerOffline, KindServerCertExpiring, KindLinkSubnetOverlap, KindInstanceOrphaned} {
		if got := of(t, k, &Inputs{}); len(got) != 0 {
			t.Errorf("%s without inputs: %+v", k, got)
		}
	}
	// No secret field reaches a finding: the offline text names the reason.
	off := of(t, KindServerOffline, serversIn(func(in *ServersIn) { in.Servers[0].State, in.Servers[0].Reason = "offline", "server_identity_mismatch" }))
	if !strings.Contains(off[0].Why, "server_identity_mismatch") || off[0].Instances[0] != "notes" {
		t.Errorf("offline %+v", off[0])
	}
}

// TestLanOnlyExposedPerServer: a worker's port is judged against that
// worker's Local networks, not the primary's.
func TestLanOnlyExposedPerServer(t *testing.T) {
	p := smb("192.168.50.10")
	p.Server = "nas"
	in := &Inputs{Ports: []PortIn{p}, LocalNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")},
		ServerLocalNetworks: map[string][]netip.Prefix{"nas": {netip.MustParsePrefix("10.1.0.0/16")}}}
	got := of(t, KindLANOnlyExposed, in)
	if len(got) != 1 || got[0].Severity != Problem || !strings.Contains(got[0].Why, "server nas's Local networks") {
		t.Fatalf("worker port outside its server's networks: %+v", got)
	}
	in.ServerLocalNetworks["nas"] = []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}
	if got := of(t, KindLANOnlyExposed, in); len(got) != 0 {
		t.Errorf("inside its server's networks: %+v", got)
	}
	// The same bind on the primary is judged by the primary's list.
	p.Server = ""
	in.Ports = []PortIn{p}
	in.ServerLocalNetworks = nil
	if got := of(t, KindLANOnlyExposed, in); len(got) != 0 {
		t.Errorf("primary port inside the primary's networks: %+v", got)
	}
	// A worker with no list known: loopback only (fail closed).
	p.Server = "ghost"
	in.Ports = []PortIn{p}
	if got := of(t, KindLANOnlyExposed, in); len(got) != 1 {
		t.Errorf("unknown server's networks: %+v", got)
	}
}
