//go:build netns

package host

// TestMeshNetns runs the real mesh in network namespaces (root, kernel
// WireGuard, iptables and nft): `sudo -E go test -tags netns
// ./internal/nodeagent/host/ -run TestMeshNetns`.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/portcullis/hub/internal/meshplan"
	na "github.com/portcullis/hub/internal/nodeagent"
)

const nsPrefix = "pcmt-"

// nsRunner runs the agent's fixed commands inside netns ns.
type nsRunner struct{ ns string }

func (r nsRunner) Run(ctx context.Context, c Cmd) ([]byte, error) {
	args := append([]string{"netns", "exec", r.ns, c.Name}, c.Args...)
	cmd := exec.CommandContext(ctx, "ip", args...)
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", c.Name, strings.Join(c.Args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// nsWG is wgctrl inside netns ns: each call opens its netlink socket on a
// thread switched into the namespace (the socket stays there).
type nsWG struct{ ns string }

func (w nsWG) in(f func(c *wgctrl.Client) error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
		fd, err := unix.Open("/var/run/netns/"+w.ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errc <- err
			return
		}
		defer unix.Close(fd)
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		c, err := wgctrl.New()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		errc <- f(c)
	}()
	return <-errc
}

func (w nsWG) Device(name string) (*wgtypes.Device, error) {
	var d *wgtypes.Device
	err := w.in(func(c *wgctrl.Client) error {
		var err error
		d, err = c.Device(name)
		return err
	})
	return d, err
}

func (w nsWG) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return w.in(func(c *wgctrl.Client) error { return c.ConfigureDevice(name, cfg) })
}

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func nsx(t *testing.T, ns string, args ...string) {
	t.Helper()
	sh(t, append([]string{"ip", "netns", "exec", nsPrefix + ns}, args...)...)
}

// pings: one echo from netns ns to ip answers.
func pings(ns, ip string) bool {
	return exec.Command("ip", "netns", "exec", nsPrefix+ns, "ping", "-n", "-q", "-c", "1", "-W", "1", ip).Run() == nil
}

// link joins netns a (interface ia, address addr) to the bridge br in
// netns b.
func link(t *testing.T, n int, a, ia, addr, b, br string) {
	t.Helper()
	x, y := fmt.Sprintf("pcv%da", n), fmt.Sprintf("pcv%db", n)
	sh(t, "ip", "link", "add", x, "type", "veth", "peer", "name", y)
	sh(t, "ip", "link", "set", x, "netns", nsPrefix+a)
	sh(t, "ip", "link", "set", y, "netns", nsPrefix+b)
	nsx(t, a, "ip", "link", "set", x, "name", ia)
	nsx(t, a, "ip", "addr", "add", addr, "dev", ia)
	nsx(t, a, "ip", "link", "set", ia, "up")
	nsx(t, b, "ip", "link", "set", y, "master", br)
	nsx(t, b, "ip", "link", "set", y, "up")
}

type netnsNode struct {
	node  meshplan.Node
	agent *Agent
}

// TestMeshNetns: 4 namespaces as nodes at 2 sites — n1 (main, public),
// n2 (main, behind an nftables masquerade), e1 (edge, public), e2 (edge,
// behind NAT) — each with a real Agent applying its meshplan plan through
// wgctrl and iptables. Every node pings every mesh address; the NATed
// cross-site pair n2 ↔ e2 answers through the gateway e1; dropping e1's
// forward rule breaks exactly that pair.
func TestMeshNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TestMeshNetns needs root (sudo -E go test -tags netns)")
	}
	for _, ns := range []string{"inet", "natm", "nate", "n1", "n2", "e1", "e2"} {
		exec.Command("ip", "netns", "del", nsPrefix+ns).Run()
		sh(t, "ip", "netns", "add", nsPrefix+ns)
		t.Cleanup(func() { exec.Command("ip", "netns", "del", nsPrefix+ns).Run() })
		nsx(t, ns, "ip", "link", "set", "lo", "up")
	}
	// The internet (a bridge) and the two sites' LANs (bridges in their NAT
	// routers).
	nsx(t, "inet", "ip", "link", "add", "br0", "type", "bridge")
	nsx(t, "inet", "ip", "link", "set", "br0", "up")
	for _, r := range []struct{ ns, lan string }{{"natm", "192.0.2.254/24"}, {"nate", "198.18.0.254/24"}} {
		nsx(t, r.ns, "ip", "link", "add", "brl", "type", "bridge")
		nsx(t, r.ns, "ip", "addr", "add", r.lan, "dev", "brl")
		nsx(t, r.ns, "ip", "link", "set", "brl", "up")
	}
	link(t, 1, "natm", "wan", "203.0.113.100/24", "inet", "br0")
	link(t, 2, "nate", "wan", "203.0.113.101/24", "inet", "br0")
	link(t, 3, "n1", "pub", "203.0.113.1/24", "inet", "br0")
	link(t, 4, "e1", "pub", "203.0.113.5/24", "inet", "br0")
	link(t, 5, "n1", "lan", "192.0.2.1/24", "natm", "brl")
	link(t, 6, "n2", "lan", "192.0.2.2/24", "natm", "brl")
	link(t, 7, "e1", "lan", "198.18.0.5/24", "nate", "brl")
	link(t, 8, "e2", "lan", "198.18.0.6/24", "nate", "brl")
	nsx(t, "n2", "ip", "route", "add", "default", "via", "192.0.2.254")
	nsx(t, "e2", "ip", "route", "add", "default", "via", "198.18.0.254")
	for _, r := range []string{"natm", "nate"} {
		nsx(t, r, "sysctl", "-qw", "net.ipv4.ip_forward=1")
		cmd := exec.Command("ip", "netns", "exec", nsPrefix+r, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader("table ip nat {\n chain post {\n  type nat hook postrouting priority 100;\n  oifname \"wan\" masquerade\n }\n}\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft in %s: %v: %s", r, err, out)
		}
	}

	ca := newCA(t)
	ap := netip.MustParseAddrPort
	specs := []struct {
		id, site, mesh, lan, public string
	}{
		{"e1", "edge", "10.215.0.5", "198.18.0.5:51830", "203.0.113.5:51830"},
		{"e2", "edge", "10.215.0.6", "198.18.0.6:51830", ""},
		{"n1", "main", "10.215.0.1", "192.0.2.1:51830", "203.0.113.1:51830"},
		{"n2", "main", "10.215.0.2", "192.0.2.2:51830", ""},
	}
	ctx := context.Background()
	var nodes []netnsNode
	for _, s := range specs {
		// Every node may route: only PORTCULLIS-MESH keeps a non-gateway
		// from relaying.
		nsx(t, s.id, "sysctl", "-qw", "net.ipv4.ip_forward=1")
		root := t.TempDir()
		k, _ := wgtypes.GeneratePrivateKey()
		writeFile(t, root, MeshKeyFile, k.String()+"\n", 0o600)
		st := State{V: 1, ID: s.id, MeshIP: s.mesh, Role: "agent", Site: s.site, Class: "home", Endpoint: "https://example.org/node", Servers: []string{"10.215.0.1"}}
		sb, _ := json.Marshal(st)
		writeFile(t, root, stateFile, string(sb), 0o600)
		writeFile(t, root, caFile, string(ca.pem), 0o600)
		nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der := ca.sign(t, s.id+"."+clusterDomain, &nk.PublicKey)
		writeFile(t, root, nodePEMFile, string(nodeBundle(nk, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), 0o600)
		a := New(Config{Root: root, Version: "0.0.0-netns", Run: nsRunner{nsPrefix + s.id}, WG: nsWG{nsPrefix + s.id},
			Interfaces: func() ([]Iface, error) { return nil, nil }, Exit: func() {}})
		if err := a.Load(); err != nil {
			t.Fatal(err)
		}
		if err := a.MeshUp(ctx); err != nil {
			t.Fatalf("%s: mesh-up: %v", s.id, err)
		}
		mn := meshplan.Node{ID: s.id, Site: s.site, MeshIP: netip.MustParseAddr(s.mesh), LAN: ap(s.lan), Pub: k.PublicKey().String()}
		if s.public != "" {
			mn.Public = ap(s.public)
		}
		nodes = append(nodes, netnsNode{mn, a})
	}
	var mn []meshplan.Node
	for _, n := range nodes {
		mn = append(mn, n.node)
	}
	plans, err := meshplan.Plan(mn)
	if err != nil {
		t.Fatal(err)
	}
	if !plans["e1"].Forward || plans["n1"].Forward || plans["n2"].Forward || plans["e2"].Forward {
		t.Fatalf("forward: only e1 relays (n2 ↔ e2): %+v", plans)
	}
	apply := func(id string, p meshplan.NodePlan) {
		t.Helper()
		for _, n := range nodes {
			if n.node.ID == id {
				if err := n.agent.ApplyMesh(ctx, na.WirePlan(p)); err != nil {
					t.Fatalf("%s: apply: %v", id, err)
				}
			}
		}
	}
	for _, n := range nodes {
		apply(n.node.ID, plans[n.node.ID])
	}
	// The NATed nodes first: their handshakes give the others their
	// endpoints (keepalive 25).
	order := []string{"n2", "e2", "n1", "e1"}
	reach := func(from, ip string, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for {
			if pings(from, ip) {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
		}
	}
	for _, from := range order {
		for _, to := range nodes {
			if to.node.ID == from {
				continue
			}
			if !reach(from, to.node.MeshIP.String(), 40*time.Second) {
				t.Errorf("%s doesn't reach %s (%s)", from, to.node.ID, to.node.MeshIP)
			}
		}
	}
	if t.Failed() {
		for _, ns := range []string{"n2", "e1", "e2"} {
			out, _ := exec.Command("ip", "netns", "exec", nsPrefix+ns, "iptables", "-S", meshChain).CombinedOutput()
			t.Logf("%s:\n%s", ns, out)
		}
		t.FailNow()
	}
	// The pair n2 ↔ e2 goes through e1: without e1's relay rule exactly
	// that pair breaks.
	off := plans["e1"]
	off.Forward = false
	apply("e1", off)
	for _, from := range order {
		for _, to := range nodes {
			if to.node.ID == from {
				continue
			}
			pair := (from == "n2" && to.node.ID == "e2") || (from == "e2" && to.node.ID == "n2")
			got := reach(from, to.node.MeshIP.String(), 3*time.Second)
			if pair && got {
				t.Errorf("%s still reaches %s without e1's forward rule", from, to.node.ID)
			}
			if !pair && !got {
				t.Errorf("%s lost %s when only e1's forward rule went", from, to.node.ID)
			}
		}
	}
	apply("e1", plans["e1"])
	if !reach("n2", "10.215.0.6", 10*time.Second) || !reach("e2", "10.215.0.2", 10*time.Second) {
		t.Error("n2 ↔ e2 didn't come back with e1's forward rule")
	}
}
