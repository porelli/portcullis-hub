package host

import (
	"context"
	"slices"
	"strings"
	"testing"

	na "github.com/portcullis/hub/internal/nodeagent"
)

func checkByID(c na.Checks, id string) na.Check {
	for _, x := range c.Checks {
		if x.ID == id {
			return x
		}
	}
	return na.Check{ID: "missing"}
}

// TestHostChecksList: every §20.4 check id, in order; each reads the host
// (kernel WireGuard, open-iscsi + iscsid, iscsi_tcp, nfs-common, the
// multipath blacklist, the Longhorn path not on ZFS, the watchdog device,
// the AppArmor stacking sysctl, the ports, the mesh subnet, zfs/btrfs).
func TestHostChecksList(t *testing.T) {
	r := newRig(t, "agent")
	ctx := context.Background()
	r.wg.exists = false // a fresh machine: no pcmesh
	r.a.cfg.Interfaces = func() ([]Iface, error) {
		return []Iface{{Name: "eth0", Addrs: []string{"192.0.2.12/24"}}}, nil
	}
	c := r.a.HostChecks(ctx)
	var ids []string
	for _, x := range c.Checks {
		ids = append(ids, x.ID)
	}
	want := []string{"wireguard", "iscsid", "iscsi_tcp", "nfs_common", "multipath_blacklist", "longhorn_path",
		"watchdog", "apparmor_stacking", "ports", "mesh_subnet", "zfs", "btrfs"}
	if !slices.Equal(ids, want) {
		t.Fatalf("ids %v", ids)
	}
	// An empty host: what is missing fails.
	for _, id := range []string{"wireguard", "iscsid", "iscsi_tcp", "nfs_common", "watchdog"} {
		if checkByID(c, id).OK {
			t.Errorf("%s ok on an empty host", id)
		}
	}
	for _, id := range []string{"multipath_blacklist", "longhorn_path", "apparmor_stacking", "ports", "mesh_subnet", "zfs", "btrfs"} {
		if x := checkByID(c, id); !x.OK {
			t.Errorf("%s fails on an empty host: %s", id, x.Detail)
		}
	}
	// A prepared host.
	writeFile(t, r.root, "/proc/sys/kernel/osrelease", "6.8.0-41-generic\n", 0o644)
	writeFile(t, r.root, "/lib/modules/6.8.0-41-generic/modules.dep", "kernel/drivers/net/wireguard/wireguard.ko: kernel/lib/crypto/libchacha20poly1305.ko\n", 0o644)
	writeFile(t, r.root, "/usr/sbin/iscsiadm", "", 0o755)
	writeFile(t, r.root, "/proc/812/comm", "iscsid\n", 0o644)
	writeFile(t, r.root, "/sys/module/iscsi_tcp/refcnt", "0", 0o644)
	writeFile(t, r.root, "/usr/sbin/mount.nfs", "", 0o755)
	writeFile(t, r.root, "/dev/watchdog", "", 0o600)
	c = r.a.HostChecks(ctx)
	for _, id := range want {
		if x := checkByID(c, id); !x.OK {
			t.Errorf("%s fails on a prepared host: %s", id, x.Detail)
		}
	}
	// multipathd without the blacklist, then with it.
	writeFile(t, r.root, "/usr/sbin/multipathd", "", 0o755)
	writeFile(t, r.root, "/etc/multipath.conf", "defaults {\n  user_friendly_names yes\n}\n", 0o644)
	if x := checkByID(r.a.HostChecks(ctx), "multipath_blacklist"); x.OK || !strings.Contains(x.Detail, `devnode "^sd[a-z0-9]+"`) {
		t.Errorf("multipath without a blacklist: %+v", x)
	}
	writeFile(t, r.root, "/etc/multipath.conf", "defaults {\n  user_friendly_names yes\n}\nblacklist {\n    devnode \"^sd[a-z0-9]+\"\n}\n", 0o644)
	if x := checkByID(r.a.HostChecks(ctx), "multipath_blacklist"); !x.OK {
		t.Errorf("multipath with the blacklist: %+v", x)
	}
	// The Longhorn path on a ZFS dataset.
	r.a.cfg.FSType = func(string) (string, error) { return "zfs", nil }
	if x := checkByID(r.a.HostChecks(ctx), "longhorn_path"); x.OK || !strings.Contains(x.Detail, "ZFS dataset: use a zvol or a separate disk") {
		t.Errorf("zfs: %+v", x)
	}
	// AppArmor stacking.
	writeFile(t, r.root, "/sys/module/apparmor/parameters/enabled", "Y\n", 0o644)
	writeFile(t, r.root, "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined", "1\n", 0o644)
	if x := checkByID(r.a.HostChecks(ctx), "apparmor_stacking"); x.OK {
		t.Errorf("apparmor: %+v", x)
	}
	// A busy port (TCP 6443 listening) and UDP 51840.
	writeFile(t, r.root, "/proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:192B 00000000:0000 0A 00000000\n", 0o644)
	writeFile(t, r.root, "/proc/net/udp6", "  sl  local_address rem_address   st\n   0: 00000000000000000000000000000000:CA80 00000000000000000000000000000000:0000 07 0\n", 0o644)
	if x := checkByID(r.a.HostChecks(ctx), "ports"); x.OK || !strings.Contains(x.Detail, "TCP 6443") || !strings.Contains(x.Detail, "UDP 51840") {
		t.Errorf("ports: %+v", x)
	}
	// The mesh subnet in use elsewhere: an address, then a route.
	r.a.cfg.Interfaces = func() ([]Iface, error) { return []Iface{{Name: "wg0", Addrs: []string{"10.215.0.9/24"}}}, nil }
	if x := checkByID(r.a.HostChecks(ctx), "mesh_subnet"); x.OK {
		t.Errorf("mesh subnet address: %+v", x)
	}
	r.a.cfg.Interfaces = func() ([]Iface, error) { return nil, nil }
	writeFile(t, r.root, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nwg0\t0000D70A\t00000000\t0001\t0\t0\t0\t0000FFFF\n", 0o644)
	if x := checkByID(r.a.HostChecks(ctx), "mesh_subnet"); x.OK || !strings.Contains(x.Detail, "wg0") {
		t.Errorf("mesh subnet route: %+v", x)
	}
	// Memory and the class.
	writeFile(t, r.root, "/proc/meminfo", "MemTotal:        2000000 kB\n", 0o644)
	writeFile(t, r.root, "/proc/device-tree/model", "Raspberry Pi 5 Model B Rev 1.0\x00", 0o644)
	c = r.a.HostChecks(ctx)
	if c.MemBytes != 2048000000 || c.Model != "Raspberry Pi 5 Model B Rev 1.0" || c.ClassSuggestion != "small" || c.CPUs < 1 {
		t.Errorf("resources %+v", c)
	}
}

func TestBlacklistCovers(t *testing.T) {
	for conf, want := range map[string]bool{
		"blacklist {\n devnode \"^sd[a-z0-9]+\"\n}\n":                          true,
		"blacklist {\n  device {\n vendor x\n }\n devnode \"^sd[a-z0-9]+\"\n}": true,
		"# blacklist {\n devnode \"^sd[a-z0-9]+\"\n}\n":                        false,
		"blacklist_exceptions {\n devnode \"^sd[a-z0-9]+\"\n}\n":               false,
		"defaults {\n devnode \"^sd[a-z0-9]+\"\n}\n":                           false,
	} {
		if got := blacklistCovers(conf); got != want {
			t.Errorf("%q: %v", conf, got)
		}
	}
}
