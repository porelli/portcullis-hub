package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// The node mesh pcmesh (contract §20.11): kernel WireGuard on UDP 51830,
// 10.215.0.0/24, MTU 1420. The interface is created with `ip` (fixed
// arguments) and configured through wgctrl; the private key stays in
// /etc/wireguard/pcmesh.key (0600; on the first node init's wg-quick owns
// the interface and the nodeagent only manages its peers).

var meshPrefix = netip.MustParsePrefix(na.MeshCIDR)

const meshChain = "PORTCULLIS-MESH"

type meshPlanState struct {
	plan na.MeshPlan
}

func meshAddrOK(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !meshPrefix.Contains(a) || a.String() != s {
		return false
	}
	last := a.As4()[3]
	return last != 0 && last != 255
}

func validWGKey(s string) bool {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	return !bytes.Equal(b, make([]byte, 32))
}

// validatePlan: the §20.4 refusals (400): the node's own key, an
// allowed_ips entry outside 10.215.0.0/24, more than 256 peers; and a
// malformed peer.
func validatePlan(p na.MeshPlan, ownPub string) error {
	if p.Peers == nil {
		return errStatus(400, "peers: missing")
	}
	if len(p.Peers) > na.MaxPeers {
		return errStatus(400, "more than %d peers", na.MaxPeers)
	}
	seen := map[string]bool{}
	keys := map[string]bool{}
	for _, pr := range p.Peers {
		if !idRe.MatchString(pr.ID) || seen[pr.ID] {
			return errStatus(400, "a peer's id is malformed or repeated")
		}
		seen[pr.ID] = true
		if !validWGKey(pr.Pub) || keys[pr.Pub] {
			return errStatus(400, "peer %s: its key is malformed or repeated", pr.ID)
		}
		keys[pr.Pub] = true
		if pr.Pub == ownPub {
			return errStatus(400, "peer %s has this node's own key", pr.ID)
		}
		if pr.Endpoint != nil {
			ap, err := netip.ParseAddrPort(*pr.Endpoint)
			if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
				return errStatus(400, "peer %s: its endpoint isn't <ipv4:port>", pr.ID)
			}
		}
		if pr.Keepalive != 0 && pr.Keepalive != 25 {
			return errStatus(400, "peer %s: keepalive is 0 or 25", pr.ID)
		}
		if pr.AllowedIPs == nil {
			return errStatus(400, "peer %s: allowed_ips missing", pr.ID)
		}
		for _, c := range pr.AllowedIPs {
			pf, err := netip.ParsePrefix(c)
			if err != nil || !pf.Addr().Is4() || pf.Masked() != pf || pf.Bits() < meshPrefix.Bits() || !meshPrefix.Contains(pf.Addr()) {
				return errStatus(400, "peer %s: allowed_ips entry %.40q is outside %s", pr.ID, c, na.MeshCIDR)
			}
		}
	}
	return nil
}

func peerConfigs(p na.MeshPlan) ([]wgtypes.PeerConfig, error) {
	out := make([]wgtypes.PeerConfig, 0, len(p.Peers))
	for _, pr := range p.Peers {
		k, err := wgtypes.ParseKey(pr.Pub)
		if err != nil {
			return nil, errStatus(400, "peer %s: its key is malformed", pr.ID)
		}
		pc := wgtypes.PeerConfig{PublicKey: k, ReplaceAllowedIPs: true}
		if pr.Endpoint != nil {
			ap := netip.MustParseAddrPort(*pr.Endpoint)
			pc.Endpoint = net.UDPAddrFromAddrPort(ap)
		}
		ka := time.Duration(pr.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
		for _, c := range pr.AllowedIPs {
			pf := netip.MustParsePrefix(c)
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: pf.Addr().AsSlice(), Mask: net.CIDRMask(pf.Bits(), 32)})
		}
		out = append(out, pc)
	}
	return out, nil
}

// peerEqual: the device's peer already is the wanted one.
func peerEqual(have wgtypes.Peer, want wgtypes.PeerConfig) bool {
	if have.PublicKey != want.PublicKey || have.PersistentKeepaliveInterval != *want.PersistentKeepaliveInterval {
		return false
	}
	if (have.Endpoint == nil) != (want.Endpoint == nil) {
		// A peer without a configured endpoint learns one from its
		// handshakes: only a wanted endpoint must match.
		if want.Endpoint != nil {
			return false
		}
	} else if want.Endpoint != nil && have.Endpoint.String() != want.Endpoint.String() {
		return false
	}
	norm := func(l []net.IPNet) []string {
		s := make([]string, len(l))
		for i, n := range l {
			s[i] = n.String()
		}
		sort.Strings(s)
		return s
	}
	return slices.Equal(norm(have.AllowedIPs), norm(want.AllowedIPs))
}

// diffPeers is the wgctrl change from the device's peers to the plan:
// changed or new peers set, missing ones removed; nil when nothing differs.
func diffPeers(have []wgtypes.Peer, want []wgtypes.PeerConfig) []wgtypes.PeerConfig {
	byKey := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range have {
		byKey[p.PublicKey] = p
	}
	var out []wgtypes.PeerConfig
	wanted := map[wgtypes.Key]bool{}
	for _, w := range want {
		wanted[w.PublicKey] = true
		if h, ok := byKey[w.PublicKey]; ok && peerEqual(h, w) {
			continue
		}
		out = append(out, w)
	}
	for _, h := range have {
		if !wanted[h.PublicKey] {
			out = append(out, wgtypes.PeerConfig{PublicKey: h.PublicKey, Remove: true})
		}
	}
	return out
}

// meshPub is the node's pcmesh public key (from its key file).
func (a *Agent) meshKey() (wgtypes.Key, error) {
	s := a.fs.readTrim(MeshKeyFile)
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		return wgtypes.Key{}, errors.New("the pcmesh key is missing or unreadable")
	}
	return k, nil
}

func (a *Agent) meshPub() string {
	k, err := a.meshKey()
	if err != nil {
		return ""
	}
	return k.PublicKey().String()
}

// MeshUp brings pcmesh up (created when absent: the node's key, UDP
// 51830, its /24 address, MTU 1420) and applies the stored plan.
func (a *Agent) MeshUp(ctx context.Context) error {
	st := a.state()
	if err := a.ensureLink(ctx, st.MeshIP); err != nil {
		return err
	}
	a.mu.Lock()
	ps := a.plan
	a.mu.Unlock()
	plan := na.MeshPlan{Peers: []na.MeshPeer{}}
	if ps != nil {
		plan = ps.plan
	}
	return a.ApplyMesh(ctx, plan)
}

func (a *Agent) ensureLink(ctx context.Context, meshIP string) error {
	if a.cfg.WG == nil {
		return errors.New("no WireGuard control")
	}
	key, err := a.meshKey()
	if err != nil {
		return err
	}
	dev, err := a.cfg.WG.Device(na.MeshIface)
	if err != nil {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "ip", Args: []string{"link", "add", "dev", na.MeshIface, "type", "wireguard"}}); err != nil {
			return fmt.Errorf("creating %s: %v (is the wireguard kernel module available?)", na.MeshIface, err)
		}
		if dev, err = a.cfg.WG.Device(na.MeshIface); err != nil {
			return fmt.Errorf("%s: %v", na.MeshIface, err)
		}
	}
	if dev.PrivateKey != key || dev.ListenPort != na.MeshPort {
		port := na.MeshPort
		if err := a.cfg.WG.ConfigureDevice(na.MeshIface, wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
			return fmt.Errorf("configuring %s: %v", na.MeshIface, err)
		}
	}
	if !a.hasAddr(meshIP) {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "ip", Args: []string{"-4", "address", "add", meshIP + "/24", "dev", na.MeshIface}}); err != nil {
			return fmt.Errorf("adding %s to %s: %v", meshIP, na.MeshIface, err)
		}
	}
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "ip", Args: []string{"link", "set", "dev", na.MeshIface, "mtu", fmt.Sprint(na.MeshMTU), "up"}}); err != nil {
		return fmt.Errorf("setting %s up: %v", na.MeshIface, err)
	}
	return nil
}

func (a *Agent) hasAddr(ip string) bool {
	ifs, err := a.cfg.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifs {
		if i.Name != na.MeshIface {
			continue
		}
		for _, c := range i.Addrs {
			if pf, err := netip.ParsePrefix(c); err == nil && pf.Addr().String() == ip {
				return true
			}
		}
	}
	return false
}

// ApplyMesh is PUT /v1/mesh/peers: the full list, idempotent (the same
// list changes nothing: no wgctrl call), missing peers removed, then the
// PORTCULLIS-MESH rules for forward.
func (a *Agent) ApplyMesh(ctx context.Context, p na.MeshPlan) error {
	if err := validatePlan(p, a.meshPub()); err != nil {
		return err
	}
	want, err := peerConfigs(p)
	if err != nil {
		return err
	}
	if a.cfg.WG == nil {
		return errors.New("no WireGuard control")
	}
	dev, err := a.cfg.WG.Device(na.MeshIface)
	if err != nil {
		return errStatus(409, "%s isn't up", na.MeshIface)
	}
	if d := diffPeers(dev.Peers, want); len(d) > 0 {
		if err := a.cfg.WG.ConfigureDevice(na.MeshIface, wgtypes.Config{Peers: d}); err != nil {
			return fmt.Errorf("configuring the %s peers: %v", na.MeshIface, err)
		}
		a.log.Info("mesh peers applied", "peers", len(p.Peers), "changed", len(d))
	}
	if err := a.applyForward(ctx, p.Forward); err != nil {
		return err
	}
	a.mu.Lock()
	changed := a.plan == nil || !planEqual(a.plan.plan, p)
	a.plan = &meshPlanState{plan: p}
	a.mu.Unlock()
	if changed {
		b, _ := json.Marshal(p)
		if err := a.fs.write(planFile, b, 0o600, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func planEqual(x, y na.MeshPlan) bool {
	bx, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return bytes.Equal(bx, by)
}

func (a *Agent) loadPlan() {
	b, err := a.fs.read(planFile)
	if err != nil {
		return
	}
	var p na.MeshPlan
	if json.Unmarshal(b, &p) == nil && p.Peers != nil {
		a.mu.Lock()
		a.plan = &meshPlanState{plan: p}
		a.mu.Unlock()
	}
}

// meshRules are PORTCULLIS-MESH's rules in order (§20.11, Amendment 3):
// conntrack first, the relay rule only on a forwarding gateway, then drop.
func meshRules(forward bool) []string {
	r := []string{"-A " + meshChain + " -i pcmesh -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"}
	if forward {
		r = append(r, "-A "+meshChain+" -i pcmesh -o pcmesh -j ACCEPT")
	}
	return append(r, "-A "+meshChain+" -i pcmesh -j DROP")
}

// normRule: iptables -S prints the ctstate list in its own order.
func normRule(s string) string {
	return strings.Replace(strings.TrimSpace(s), "--ctstate RELATED,ESTABLISHED", "--ctstate ESTABLISHED,RELATED", 1)
}

// applyForward makes PORTCULLIS-MESH exactly meshRules(forward) (one
// atomic iptables-restore --noflush when it differs) and the FORWARD
// jump to it present.
func (a *Agent) applyForward(ctx context.Context, forward bool) error {
	want := meshRules(forward)
	out, err := a.cfg.Run.Run(ctx, Cmd{Name: "iptables", Args: []string{"-w", "5", "-S", meshChain}})
	var have []string
	if err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "-A ") {
				have = append(have, normRule(l))
			}
		}
	}
	if err != nil || !slices.Equal(have, want) {
		in := "*filter\n:" + meshChain + " - [0:0]\n" + strings.Join(want, "\n") + "\nCOMMIT\n"
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "iptables-restore", Args: []string{"-w", "5", "--noflush"}, Stdin: []byte(in)}); err != nil {
			return fmt.Errorf("the %s rules: %v", meshChain, err)
		}
		a.log.Info("mesh rules applied", "forward", forward)
	}
	if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "iptables", Args: []string{"-w", "5", "-C", "FORWARD", "-j", meshChain}}); err != nil {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: "iptables", Args: []string{"-w", "5", "-I", "FORWARD", "1", "-j", meshChain}}); err != nil {
			return fmt.Errorf("the FORWARD jump to %s: %v", meshChain, err)
		}
	}
	if forward {
		if err := a.fs.writeInPlace("/proc/sys/net/ipv4/ip_forward", []byte("1\n")); err != nil {
			a.log.Warn("couldn't turn IPv4 forwarding on", "err", err.Error())
		}
	}
	return nil
}

// removeMesh takes pcmesh and its rules down (the uninstall).
func (a *Agent) removeMesh(ctx context.Context) {
	run := func(name string, args ...string) {
		if _, err := a.cfg.Run.Run(ctx, Cmd{Name: name, Args: args}); err != nil {
			a.log.Info("uninstall step", "cmd", name+" "+strings.Join(args, " "), "result", err.Error())
		}
	}
	run("iptables", "-w", "5", "-D", "FORWARD", "-j", meshChain)
	run("iptables", "-w", "5", "-F", meshChain)
	run("iptables", "-w", "5", "-X", meshChain)
	run("systemctl", "disable", "--now", "wg-quick@"+na.MeshIface)
	run("ip", "link", "del", "dev", na.MeshIface)
}

// ── the RTT echo (UDP :7444 on the mesh address) ──

const (
	echoReq   = "PCE1"
	echoReply = "PCR1"
	echoBody  = 16
)

// ServeEcho answers mesh echo requests on <mesh ip>:7444 until ctx ends:
// "PCE1"+16 bytes from a 10.215.0.0/24 source → "PCR1"+the 16 bytes+the
// node's id.
func (a *Agent) ServeEcho(ctx context.Context, pc net.PacketConn) error {
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	id := []byte(a.state().ID)
	buf := make([]byte, 64)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || n != len(echoReq)+echoBody || string(buf[:4]) != echoReq {
			continue
		}
		if ap := ua.AddrPort(); !meshPrefix.Contains(ap.Addr().Unmap()) {
			continue
		}
		reply := append([]byte(echoReply), buf[4:n]...)
		reply = append(reply, id...)
		pc.WriteTo(reply, from)
	}
}

// RTT settings: 20 rounds per address, a peer needs 10 answers.
var (
	rttRounds  = 20
	rttMin     = 10
	rttTimeout = time.Second
	rttGap     = 50 * time.Millisecond
)

// echoAddrs are the mesh addresses to measure: every /32 of the plan's
// peers (a gateway's entry lists the nodes it relays too), the node's own
// left out.
func echoAddrs(p na.MeshPlan, own string) []string {
	set := map[string]bool{}
	for _, pr := range p.Peers {
		for _, c := range pr.AllowedIPs {
			pf, err := netip.ParsePrefix(c)
			if err != nil || pf.Bits() != 32 {
				continue
			}
			if s := pf.Addr().String(); s != own {
				set[s] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// RTT is GET /v1/mesh/rtt: the p95 (ms, rounded up) of 20 echo rounds to
// every mesh address of the plan, keyed by the id each answer names; an
// id with fewer than 10 answers is left out.
func (a *Agent) RTT(ctx context.Context) map[string]int {
	a.mu.Lock()
	var p na.MeshPlan
	if a.plan != nil {
		p = a.plan.plan
	}
	a.mu.Unlock()
	return a.measure(ctx, echoAddrs(p, a.state().MeshIP))
}

func (a *Agent) measure(ctx context.Context, addrs []string) map[string]int {
	a.rttMu.Lock()
	defer a.rttMu.Unlock()
	own := a.state().MeshIP
	var mu sync.Mutex
	samples := map[string][]time.Duration{}
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, s := echoRounds(ctx, own, addr)
			if id == "" {
				return
			}
			mu.Lock()
			samples[id] = append(samples[id], s...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	out := map[string]int{}
	for id, s := range samples {
		if len(s) < rttMin {
			continue
		}
		out[id] = p95ms(s)
	}
	return out
}

func p95ms(s []time.Duration) int {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(math.Ceil(0.95*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return int(math.Ceil(float64(s[i]) / float64(time.Millisecond)))
}

// echoRounds: rttRounds sequential echoes to addr:7444 from the mesh
// address; the id the answers name and the round trips.
func echoRounds(ctx context.Context, own, addr string) (string, []time.Duration) {
	var laddr *net.UDPAddr
	if own != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(own)}
	}
	c, err := net.DialUDP("udp4", laddr, &net.UDPAddr{IP: net.ParseIP(addr), Port: na.EchoPort})
	if err != nil {
		return "", nil
	}
	defer c.Close()
	id := ""
	var out []time.Duration
	buf := make([]byte, 128)
	for i := 0; i < rttRounds && ctx.Err() == nil; i++ {
		body := make([]byte, echoBody)
		rand.Read(body)
		start := time.Now()
		if _, err := c.Write(append([]byte(echoReq), body...)); err != nil {
			time.Sleep(rttGap)
			continue
		}
		deadline := start.Add(rttTimeout)
		for {
			c.SetReadDeadline(deadline)
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if n < 4+echoBody || string(buf[:4]) != echoReply || !bytes.Equal(buf[4:4+echoBody], body) {
				continue
			}
			rid := string(buf[4+echoBody : n])
			if !idRe.MatchString(rid) || (id != "" && rid != id) {
				break
			}
			id = rid
			out = append(out, time.Since(start))
			break
		}
		time.Sleep(rttGap)
	}
	return id, out
}
