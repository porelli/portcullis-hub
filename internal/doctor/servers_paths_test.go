package doctor

import (
	"net/netip"
	"strings"
	"testing"
)

// TestPathChecksPerServer (L1): the same host path on the primary and on
// a worker is two directories (no shared_path); two instances on one
// worker share it, explain-only (manage_as_folder would probe the
// primary), judged against that worker's folder roots; no
// folder_reachable_above across servers; path_outside_roots uses the
// worker's roots.
func TestPathChecksPerServer(t *testing.T) {
	pri := setting("jellyfin", "media", "/srv/media", false)
	wrk := setting("samba", "share", "/srv/media", true)
	wrk.Server = "nas"
	if got := of(t, "shared_path", &Inputs{Paths: []PathIn{pri, wrk}}); len(got) != 0 {
		t.Errorf("across servers: %+v", got)
	}
	wrk2 := setting("sonarr", "tv", "/srv/media", true)
	wrk2.Server = "nas"
	in := &Inputs{Paths: []PathIn{pri, wrk, wrk2}, ServerBindRoots: map[string][]string{"nas": {"/srv"}}}
	got := of(t, "shared_path", in)
	if len(got) != 1 || got[0].Class != FixExplain || got[0].FixKind != "" || !strings.Contains(strings.Join(got[0].Steps, " "), "server nas") ||
		strings.Join(got[0].Instances, ",") != "samba,sonarr" {
		t.Fatalf("one worker: %+v", got)
	}
	// path_outside_roots: the worker's roots, not the primary's.
	out := setting("samba", "x", "/data/x", true)
	out.Server = "nas"
	if got := of(t, "path_outside_roots", &Inputs{Paths: []PathIn{out}, ServerBindRoots: map[string][]string{"nas": {"/data"}}}); len(got) != 0 {
		t.Errorf("inside the worker's roots: %+v", got)
	}
	if got := of(t, "path_outside_roots", &Inputs{Paths: []PathIn{wrk}, ServerBindRoots: map[string][]string{"nas": {"/data"}}}); len(got) != 1 {
		t.Errorf("outside the worker's roots: %+v", got)
	}
	// A folder on the primary and a worker app's mount above its path.
	media := FolderIn{ID: "media", Name: "Media", Path: "/srv/media", GID: 60001}
	use := folderUse("immich", "library", "media", "/srv/media/photos", false, true)
	above := setting("immich", "extra", "/srv", true)
	above.Server = "nas"
	if r := ReachedAbove(media, []PathIn{use, above}); len(r) != 0 {
		t.Errorf("reach across servers: %+v", r)
	}
}

// TestLanOnlyTunnelAddress (L3): a LAN-only port bound to a link (or
// VPN) address is a Problem even inside the Local networks.
func TestLanOnlyTunnelAddress(t *testing.T) {
	p := smb("10.214.0.5")
	p.Server = "nas"
	in := &Inputs{Ports: []PortIn{p}, LocalNetworks: defaultNets(), ServerLocalNetworks: map[string][]netip.Prefix{"nas": defaultNets()},
		NotLocal: []RangeIn{{Name: "the link subnet", Prefix: netip.MustParsePrefix("10.214.0.0/24")}}}
	got := of(t, KindLANOnlyExposed, in)
	if len(got) != 1 || got[0].Severity != Problem || !strings.Contains(got[0].Title, "the link subnet") {
		t.Fatalf("%+v", got)
	}
	p.Bind = "10.1.2.3"
	in.Ports = []PortIn{p}
	if got := of(t, KindLANOnlyExposed, in); len(got) != 0 {
		t.Errorf("a LAN address: %+v", got)
	}
}
