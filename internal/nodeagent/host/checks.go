package host

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// The host checks (contract §20.4 GET /v1/checks; spike S2 for Longhorn's
// prerequisites). Each reads the host only: no package is installed, no
// module loaded, no port bound.

// CheckIDs are the checks, in their answer order.
var CheckIDs = []string{"wireguard", "iscsid", "iscsi_tcp", "nfs_common", "multipath_blacklist", "longhorn_path",
	"watchdog", "apparmor_stacking", "ports", "mesh_subnet", "zfs", "btrfs"}

// joinBlockers are the checks a join can't go on without; the others are
// warnings at the join (they matter for storage and fencing).
var joinBlockers = map[string]bool{"wireguard": true, "ports": true, "mesh_subnet": true}

// LonghornPath is Longhorn's default data path.
const LonghornPath = "/var/lib/longhorn"

// The ports a join needs free (TCP 6443, 2379, 2380, 10250; UDP 51830
// pcmesh and 51840 flannel's WireGuard).
var (
	tcpPorts = []int{6443, 2379, 2380, 10250}
	udpPorts = []int{na.MeshPort, na.FlannelPort}
)

// HostChecks runs every check.
func (a *Agent) HostChecks(ctx context.Context) na.Checks {
	k3s := a.k3sState(ctx)
	meshUp := a.linkExists()
	cs := []na.Check{
		a.checkWireGuard(meshUp),
		a.checkISCSID(),
		a.checkModule("iscsi_tcp", "the iscsi_tcp module is loaded", "the iscsi_tcp module isn't loaded (modprobe iscsi_tcp, and list it in /etc/modules-load.d/)"),
		a.checkNFS(),
		a.checkMultipath(),
		a.checkLonghornPath(),
		a.checkWatchdog(),
		a.checkAppArmor(),
		a.checkPorts(k3s, meshUp),
		a.checkMeshSubnet(),
		a.reportFS("zfs"),
		a.reportFS("btrfs"),
	}
	mem := a.memBytes()
	model := a.model()
	_, public := a.reportAddrs()
	return na.Checks{Checks: cs, MemBytes: mem, CPUs: runtime.NumCPU(), Model: model,
		ClassSuggestion: na.Suggest(mem, runtime.NumCPU(), model, public != nil)}
}

func (a *Agent) linkExists() bool {
	ifs, err := a.cfg.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifs {
		if i.Name == na.MeshIface {
			return true
		}
	}
	return false
}

func (a *Agent) modulePresent(name string) bool {
	if a.fs.exists("/sys/module/" + name) {
		return true
	}
	rel := a.fs.readTrim("/proc/sys/kernel/osrelease")
	if rel == "" {
		return false
	}
	for _, f := range []string{"modules.builtin", "modules.dep"} {
		b, err := a.fs.read("/lib/modules/" + rel + "/" + f)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte("/"+name+".ko")) {
			return true
		}
	}
	return false
}

func (a *Agent) checkWireGuard(meshUp bool) na.Check {
	c := na.Check{ID: "wireguard"}
	switch {
	case meshUp || a.fs.exists("/sys/module/wireguard"):
		c.OK, c.Detail = true, "kernel WireGuard is loaded"
	case a.modulePresent("wireguard"):
		c.OK, c.Detail = true, "kernel WireGuard is available"
	default:
		c.Detail = "this kernel has no WireGuard module (Linux 5.6 or later has it)"
	}
	return c
}

func (a *Agent) anyFile(paths ...string) bool {
	for _, p := range paths {
		if a.fs.exists(p) {
			return true
		}
	}
	return false
}

// processRunning: a /proc/<pid>/comm names it.
func (a *Agent) processRunning(name string) bool {
	ents, err := os.ReadDir(a.fs.p("/proc"))
	if err != nil {
		return false
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if a.fs.readTrim("/proc/"+e.Name()+"/comm") == name {
			return true
		}
	}
	return false
}

func (a *Agent) checkISCSID() na.Check {
	c := na.Check{ID: "iscsid"}
	installed := a.anyFile("/usr/sbin/iscsid", "/sbin/iscsid", "/usr/sbin/iscsiadm", "/sbin/iscsiadm")
	switch {
	case !installed:
		c.Detail = "open-iscsi isn't installed (apt install open-iscsi): Longhorn needs it on storage nodes"
	case !a.processRunning("iscsid"):
		c.Detail = "open-iscsi is installed but iscsid isn't running (systemctl enable --now iscsid)"
	default:
		c.OK, c.Detail = true, "open-iscsi is installed and iscsid runs"
	}
	return c
}

func (a *Agent) checkModule(name, ok, bad string) na.Check {
	c := na.Check{ID: name, Detail: bad}
	if a.fs.exists("/sys/module/" + name) {
		c.OK, c.Detail = true, ok
	}
	return c
}

func (a *Agent) checkNFS() na.Check {
	c := na.Check{ID: "nfs_common", Detail: "nfs-common isn't installed (apt install nfs-common): Longhorn needs it for shared volumes"}
	if a.anyFile("/usr/sbin/mount.nfs", "/sbin/mount.nfs", "/usr/sbin/mount.nfs4", "/sbin/mount.nfs4") {
		c.OK, c.Detail = true, "nfs-common is installed"
	}
	return c
}

// multipathBlacklist is Longhorn's documented blacklist entry.
const multipathBlacklist = `devnode "^sd[a-z0-9]+"`

func (a *Agent) checkMultipath() na.Check {
	c := na.Check{ID: "multipath_blacklist"}
	present := a.anyFile("/usr/sbin/multipathd", "/sbin/multipathd") || a.processRunning("multipathd")
	if !present {
		c.OK, c.Detail = true, "multipathd isn't installed"
		return c
	}
	files := []string{"/etc/multipath.conf"}
	if ents, err := os.ReadDir(a.fs.p("/etc/multipath/conf.d")); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, "/etc/multipath/conf.d/"+e.Name())
			}
		}
	}
	for _, f := range files {
		if b, err := a.fs.read(f); err == nil && blacklistCovers(string(b)) {
			c.OK, c.Detail = true, "multipathd's blacklist covers Longhorn's devices ("+f+")"
			return c
		}
	}
	c.Detail = `multipathd is installed without a blacklist for Longhorn's devices: add blacklist { ` + multipathBlacklist + ` } to /etc/multipath.conf and restart multipathd (or remove multipath-tools)`
	return c
}

// blacklistCovers: a blacklist { … } section holds Longhorn's devnode entry.
func blacklistCovers(conf string) bool {
	depth, in := 0, false
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if depth == 0 && (l == "blacklist {" || l == "blacklist{") {
			in, depth = true, 1
			continue
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if in && depth >= 1 && strings.Join(strings.Fields(l), " ") == multipathBlacklist {
			return true
		}
		if depth <= 0 {
			in, depth = false, 0
		}
	}
	return false
}

// nearestExisting is path or its closest existing parent.
func (a *Agent) nearestExisting(path string) string {
	for p := path; ; p = filepath.Dir(p) {
		if a.fs.exists(p) || p == "/" {
			return p
		}
	}
}

func (a *Agent) checkLonghornPath() na.Check {
	c := na.Check{ID: "longhorn_path"}
	at := a.nearestExisting(LonghornPath)
	fs, err := a.cfg.FSType(a.fs.p(at))
	switch {
	case err != nil:
		c.Detail = "the file system of " + LonghornPath + " is unknown"
	case fs == "zfs":
		c.Detail = LonghornPath + " is on a ZFS dataset: use a zvol or a separate disk"
	default:
		c.OK, c.Detail = true, LonghornPath+" is on "+fs
	}
	return c
}

func (a *Agent) checkWatchdog() na.Check {
	c := na.Check{ID: "watchdog", Detail: "no watchdog device (/dev/watchdog): fencing needs one (modprobe softdog provides it)"}
	if a.fs.exists("/dev/watchdog") {
		c.OK, c.Detail = true, "watchdog device /dev/watchdog"
	}
	return c
}

func (a *Agent) checkAppArmor() na.Check {
	c := na.Check{ID: "apparmor_stacking", OK: true}
	on := strings.HasPrefix(a.fs.readTrim("/sys/module/apparmor/parameters/enabled"), "Y")
	v := a.fs.readTrim("/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined")
	switch {
	case !on:
		c.Detail = "AppArmor is off"
	case v == "1":
		c.OK = false
		c.Detail = "kernel.apparmor_restrict_unprivileged_unconfined=1: containerd's stacked AppArmor label breaks Postgres; set it to 0 in /etc/sysctl.d/"
	default:
		c.Detail = "kernel.apparmor_restrict_unprivileged_unconfined isn't 1"
	}
	return c
}

// listening reads /proc/net/<proto>{,6}: the local ports bound (TCP in
// LISTEN, UDP any).
func (a *Agent) listening(proto string) map[int]bool {
	out := map[int]bool{}
	for _, f := range []string{"/proc/net/" + proto, "/proc/net/" + proto + "6"} {
		b, err := a.fs.read(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, l := range lines[1:] {
			fs := strings.Fields(l)
			if len(fs) < 4 {
				continue
			}
			if proto == "tcp" && fs[3] != "0A" {
				continue
			}
			i := strings.LastIndexByte(fs[1], ':')
			if i < 0 {
				continue
			}
			if p, err := strconv.ParseInt(fs[1][i+1:], 16, 32); err == nil {
				out[int(p)] = true
			}
		}
	}
	return out
}

func (a *Agent) checkPorts(k3s string, meshUp bool) na.Check {
	c := na.Check{ID: "ports"}
	tcp, udp := a.listening("tcp"), a.listening("udp")
	var busy []string
	for _, p := range tcpPorts {
		if tcp[p] && k3s == "absent" {
			busy = append(busy, fmt.Sprintf("TCP %d", p))
		}
	}
	for _, p := range udpPorts {
		if !udp[p] {
			continue
		}
		if (p == na.MeshPort && meshUp) || (p == na.FlannelPort && k3s != "absent") {
			continue
		}
		busy = append(busy, fmt.Sprintf("UDP %d", p))
	}
	if len(busy) > 0 {
		c.Detail = "in use: " + strings.Join(busy, ", ") + " (k3s and the mesh need them free)"
		return c
	}
	c.OK = true
	if k3s != "absent" {
		c.Detail = "the cluster's ports are k3s's and pcmesh's"
	} else {
		c.Detail = "TCP 6443, 2379, 2380, 10250 and UDP 51830, 51840 are free"
	}
	return c
}

func (a *Agent) checkMeshSubnet() na.Check {
	c := na.Check{ID: "mesh_subnet"}
	ifs, err := a.cfg.Interfaces()
	if err != nil {
		c.Detail = "the interfaces can't be read"
		return c
	}
	for _, i := range ifs {
		if i.Name == na.MeshIface {
			continue
		}
		for _, s := range i.Addrs {
			pf, err := netip.ParsePrefix(s)
			if err == nil && pf.Addr().Is4() && pf.Overlaps(meshPrefix) {
				c.Detail = fmt.Sprintf("%s already uses %s (%s): the node mesh needs it", i.Name, na.MeshCIDR, s)
				return c
			}
		}
	}
	if dev := a.meshRouteElsewhere(); dev != "" {
		c.Detail = fmt.Sprintf("a route to %s goes through %s: the node mesh needs it", na.MeshCIDR, dev)
		return c
	}
	c.OK, c.Detail = true, na.MeshCIDR+" is unused"
	return c
}

// meshRouteElsewhere: an IPv4 route (/proc/net/route) into the mesh
// subnet through another interface than pcmesh.
func (a *Agent) meshRouteElsewhere() string {
	b, err := a.fs.read("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 8 || f[0] == na.MeshIface {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		mask, err2 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || mask == 0 {
			continue
		}
		le := func(v uint64) netip.Addr {
			return netip.AddrFrom4([4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
		}
		ones := 0
		for m := mask; m != 0; m >>= 1 {
			ones += int(m & 1)
		}
		if pf := netip.PrefixFrom(le(dst), ones); pf.Overlaps(meshPrefix) {
			return f[0]
		}
	}
	return ""
}

// reportFS: zfs / btrfs, reported only (always ok).
func (a *Agent) reportFS(name string) na.Check {
	c := na.Check{ID: name, OK: true}
	sup := false
	if b, err := a.fs.read("/proc/filesystems"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) > 0 && f[len(f)-1] == name {
				sup = true
			}
		}
	}
	var mounts []string
	if b, err := a.fs.read("/proc/self/mounts"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 3 && f[2] == name {
				mounts = append(mounts, f[1])
			}
		}
	}
	sort.Strings(mounts)
	switch {
	case len(mounts) > 0:
		if len(mounts) > 5 {
			mounts = append(mounts[:5], "…")
		}
		c.Detail = name + " is mounted at " + strings.Join(mounts, ", ")
	case sup:
		c.Detail = name + " is supported, nothing is mounted"
	default:
		c.Detail = name + " isn't in use"
	}
	return c
}

func (a *Agent) memBytes() int64 {
	b, err := a.fs.read("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

func (a *Agent) model() string {
	for _, f := range []string{"/proc/device-tree/model", "/sys/firmware/devicetree/base/model"} {
		if b, err := a.fs.read(f); err == nil {
			if s := strings.TrimSpace(strings.TrimRight(string(b), "\x00")); s != "" {
				return clip(s, 120)
			}
		}
	}
	if b, err := a.fs.read("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(l, ":")
			if ok && strings.TrimSpace(k) == "model name" {
				return clip(strings.TrimSpace(v), 120)
			}
		}
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// reportAddrs is the enrolment's mesh report: the address of the
// default route's interface on UDP 51830 as the LAN endpoint, and as the
// public one too when it is a public address (a cloud VM with its public
// address on the interface). A NATed node reports no public endpoint (the
// Hub may set a forwarded one later).
func (a *Agent) reportAddrs() (lan, public *string) {
	ip := a.defaultSource()
	if !ip.IsValid() {
		return nil, nil
	}
	ep := netip.AddrPortFrom(ip, na.MeshPort).String()
	lan = &ep
	if isPublic(ip) {
		p := ep
		public = &p
	}
	return lan, public
}

func isPublic(ip netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip) && !meshPrefix.Contains(ip)
}

// defaultSource: the source address of the IPv4 default route's
// interface (from /proc/net/route and the interfaces).
func (a *Agent) defaultSource() netip.Addr {
	b, err := a.fs.read("/proc/net/route")
	if err != nil {
		return netip.Addr{}
	}
	dev := ""
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			dev = f[0]
			break
		}
	}
	ifs, err := a.cfg.Interfaces()
	if err != nil || dev == "" {
		return netip.Addr{}
	}
	for _, i := range ifs {
		if i.Name != dev {
			continue
		}
		for _, s := range i.Addrs {
			if pf, err := netip.ParsePrefix(s); err == nil && pf.Addr().Is4() {
				return pf.Addr()
			}
		}
	}
	return netip.Addr{}
}

func hostInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		x := Iface{Name: i.Name}
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				if ip4 := n.IP.To4(); ip4 != nil {
					ones, _ := n.Mask.Size()
					x.Addrs = append(x.Addrs, fmt.Sprintf("%s/%d", ip4, ones))
				}
			}
		}
		out = append(out, x)
	}
	return out, nil
}
