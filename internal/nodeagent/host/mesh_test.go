package host

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/meshplan"
	na "github.com/portcullis/hub/internal/nodeagent"
)

func ep(s string) jsonstrict.Nullable[string] { return jsonstrict.Some(s) }

// TestPeersIdempotent: the same list twice → one wgctrl peer change; a
// peer missing from the list is removed; the node's own key, an
// allowed_ips entry outside the mesh, more than 256 peers → 400.
func TestPeersIdempotent(t *testing.T) {
	r := newRig(t, "server")
	ctx := context.Background()
	k1, k3 := peerKey(t), peerKey(t)
	plan := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "n1", Pub: k1, Endpoint: ep("192.0.2.1:51830"), AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25},
		{ID: "n3", Pub: k3, AllowedIPs: []string{"10.215.0.3/32", "10.215.0.5/32"}, Keepalive: 0},
	}}
	base := r.wg.peerConfigures()
	if err := r.a.ApplyMesh(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := r.a.ApplyMesh(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if n := r.wg.peerConfigures() - base; n != 1 {
		t.Errorf("the same list twice made %d wgctrl calls, want 1", n)
	}
	d, _ := r.wg.Device("pcmesh")
	if len(d.Peers) != 2 {
		t.Fatalf("peers %v", d.Peers)
	}
	// n3 leaves: removed.
	plan.Peers = plan.Peers[:1]
	if err := r.a.ApplyMesh(ctx, plan); err != nil {
		t.Fatal(err)
	}
	d, _ = r.wg.Device("pcmesh")
	if len(d.Peers) != 1 || d.Peers[0].PublicKey.String() != k1 {
		t.Errorf("after the removal: %v", d.Peers)
	}
	if d.Peers[0].PersistentKeepaliveInterval != 25*time.Second {
		t.Errorf("keepalive %v", d.Peers[0].PersistentKeepaliveInterval)
	}
	bad := map[string]na.MeshPlan{
		"own key": {Peers: []na.MeshPeer{{ID: "n1", Pub: r.pub, AllowedIPs: []string{"10.215.0.1/32"}}}},
		"outside": {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, AllowedIPs: []string{"10.214.0.1/32"}}}},
		"wide":    {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, AllowedIPs: []string{"10.0.0.0/8"}}}},
		"default": {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, AllowedIPs: []string{"0.0.0.0/0"}}}},
		"ka 10":   {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 10}}},
		"bad ep":  {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, Endpoint: ep("example.org:1"), AllowedIPs: []string{"10.215.0.1/32"}}}},
		"dup id":  {Peers: []na.MeshPeer{{ID: "n1", Pub: k1, AllowedIPs: []string{}}, {ID: "n1", Pub: k3, AllowedIPs: []string{}}}},
	}
	var many na.MeshPlan
	for i := 0; i < 257; i++ {
		many.Peers = append(many.Peers, na.MeshPeer{ID: "p" + strings.Repeat("a", i%20) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Pub: peerKey(t), AllowedIPs: []string{}})
	}
	bad["257 peers"] = many
	before := r.wg.peerConfigures()
	for name, p := range bad {
		err := r.a.ApplyMesh(ctx, p)
		he, ok := err.(*httpError)
		if !ok || he.code != 400 {
			t.Errorf("%s: %v, want a 400", name, err)
		}
	}
	if r.wg.peerConfigures() != before {
		t.Error("a refused plan changed the device")
	}
	// Through the API: a 400 and a 204.
	s := r.server()
	c := r.client(r.ca, na.CNHub)
	b, _ := json.Marshal(bad["own key"])
	if code, _ := do(t, c, "PUT", s.URL+"/v1/mesh/peers", string(b)); code != 400 {
		t.Errorf("own key over the API: %d", code)
	}
	// A null endpoint (a NATed peer) decodes.
	nullEP := `{"peers":[{"id":"n1","pub":"` + k1 + `","endpoint":null,"allowed_ips":["10.215.0.1/32"],"keepalive":25}],"forward":false}`
	if code, body := do(t, c, "PUT", s.URL+"/v1/mesh/peers", nullEP); code != 204 {
		t.Errorf("a null endpoint: %d %s", code, body)
	}
	b, _ = json.Marshal(plan)
	if code, body := do(t, c, "PUT", s.URL+"/v1/mesh/peers", string(b)); code != 204 {
		t.Errorf("PUT /v1/mesh/peers: %d %s", code, body)
	}
	if code, _ := do(t, c, "PUT", s.URL+"/v1/mesh/peers", `{"peers":[],"forward":false,"extra":1}`); code != 400 {
		t.Errorf("an unknown field: %d", code)
	}
}

// TestMeshRules: PORTCULLIS-MESH holds conntrack first, the relay rule
// only with forward, then the drop; the FORWARD jump once; an unchanged
// chain isn't rewritten.
func TestMeshRules(t *testing.T) {
	r := newRig(t, "agent")
	ctx := context.Background()
	if !slices.Equal(r.run.rules, meshRules(false)) || !r.run.jump {
		t.Fatalf("rules %v jump %v", r.run.rules, r.run.jump)
	}
	if !strings.Contains(r.run.rules[0], "-i pcmesh -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") || !strings.HasSuffix(r.run.rules[len(r.run.rules)-1], "-i pcmesh -j DROP") {
		t.Errorf("order %v", r.run.rules)
	}
	restores := r.run.count("iptables-restore")
	p := na.MeshPlan{Peers: []na.MeshPeer{}, Forward: true}
	if err := r.a.ApplyMesh(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(r.run.rules) != 3 || r.run.rules[1] != "-A PORTCULLIS-MESH -i pcmesh -o pcmesh -j ACCEPT" {
		t.Errorf("gateway rules %v", r.run.rules)
	}
	if err := r.a.ApplyMesh(ctx, p); err != nil {
		t.Fatal(err)
	}
	if n := r.run.count("iptables-restore") - restores; n != 1 {
		t.Errorf("%d restores for one change", n)
	}
	if n := r.run.count("iptables", "-w", "5", "-I"); n != 1 {
		t.Errorf("%d FORWARD inserts", n)
	}
	for _, c := range r.run.cmds {
		if c.Name == "sh" || c.Name == "bash" {
			t.Errorf("a shell ran: %v", c)
		}
	}
	p.Forward = false
	if err := r.a.ApplyMesh(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(r.run.rules) != 2 {
		t.Errorf("forward off: %v", r.run.rules)
	}
}

func TestEchoAndP95(t *testing.T) {
	p := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "g", AllowedIPs: []string{"10.215.0.5/32", "10.215.0.2/32", "10.215.0.6/32"}},
		{ID: "n1", AllowedIPs: []string{"10.215.0.1/32"}},
	}}
	if got := echoAddrs(p, "10.215.0.2"); !slices.Equal(got, []string{"10.215.0.1", "10.215.0.5", "10.215.0.6"}) {
		t.Errorf("echo addrs %v", got)
	}
	var s []time.Duration
	for i := 1; i <= 20; i++ {
		s = append(s, time.Duration(i)*time.Millisecond+300*time.Microsecond)
	}
	if got := p95ms(s); got != 20 {
		t.Errorf("p95 %d", got)
	}
	// The echo answers only mesh sources: a loopback request gets nothing.
	r := newRig(t, "agent")
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.a.ServeEcho(ctx, pc)
	c, _ := net.Dial("udp4", pc.LocalAddr().String())
	defer c.Close()
	c.Write([]byte(echoReq + "0123456789abcdef"))
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 64)); err == nil {
		t.Errorf("a non-mesh source got %d bytes", n)
	}
}

// TestForwardRulesPcmeshOnly: with forward the rule set is exactly the
// chain's conntrack rule, the one relay rule "-i pcmesh -o pcmesh -j
// ACCEPT" and the chain's DROP for pcmesh (no rule names another
// interface); forward false removes exactly the relay rule.
func TestForwardRulesPcmeshOnly(t *testing.T) {
	r := newRig(t, "agent")
	ctx := context.Background()
	p := na.MeshPlan{Peers: []na.MeshPeer{}, Forward: true}
	if err := r.a.ApplyMesh(ctx, p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-A PORTCULLIS-MESH -i pcmesh -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-A PORTCULLIS-MESH -i pcmesh -o pcmesh -j ACCEPT",
		"-A PORTCULLIS-MESH -i pcmesh -j DROP",
	}
	if !slices.Equal(r.run.rules, want) {
		t.Fatalf("forward rules %q", r.run.rules)
	}
	relay := 0
	for _, l := range r.run.rules {
		f := strings.Fields(l)
		for i, w := range f {
			if (w == "-i" || w == "-o") && (i+1 >= len(f) || f[i+1] != "pcmesh") {
				t.Errorf("a rule names another interface: %q", l)
			}
		}
		if strings.Contains(l, "-o ") {
			relay++
		}
	}
	if relay != 1 || !r.run.jump {
		t.Errorf("%d relay rules, jump %v", relay, r.run.jump)
	}
	// Only the FORWARD jump touches the built-in chain.
	for _, c := range r.run.cmds {
		if c.Name == "iptables" && slices.Contains(c.Args, "FORWARD") && !slices.Contains(c.Args, meshChain) {
			t.Errorf("a FORWARD change that isn't the jump: %v", c.Args)
		}
	}
	p.Forward = false
	if err := r.a.ApplyMesh(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.run.rules, []string{want[0], want[2]}) {
		t.Errorf("forward off: %q", r.run.rules)
	}
}

// fakeClock is the agent's clock: the echo peer moves it by its delay
// (X4: no wall-clock assertion).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestRTTEndpoint: an echo peer that answers after an injected 30 ms
// delay (on the agent's clock) → GET /v1/mesh/rtt answers its p95, 33 ms
// exactly, within [30, 40] (X4); a peer that doesn't answer is left out; the answer
// is cached.
func TestRTTEndpoint(t *testing.T) {
	r := newRig(t, "agent")
	ctx := context.Background()
	clk := &fakeClock{t: time.Now()} // the TLS checks read the same clock
	r.a.cfg.Now = clk.Now
	defer func(g time.Duration) { rttGap = g }(rttGap)
	rttGap = 0
	defer func(d time.Duration) { rttTimeout = d }(rttTimeout)
	rttTimeout = 50 * time.Millisecond

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var rounds atomic.Int32
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != len(echoReq)+echoBody || string(buf[:4]) != echoReq {
				continue
			}
			k := rounds.Add(1)
			d := 30 * time.Millisecond
			if k%10 == 0 {
				d = 33 * time.Millisecond // jitter on 2 of 20 rounds
			}
			clk.add(d)
			pc.WriteTo(append(append([]byte(echoReply), buf[4:n]...), "n1"...), from)
		}
	}()
	dials := map[string]int{}
	var dmu sync.Mutex
	r.a.cfg.EchoDial = func(_ context.Context, own, addr string) (net.Conn, error) {
		dmu.Lock()
		dials[own+">"+addr]++
		dmu.Unlock()
		if addr == "10.215.0.1" {
			return net.Dial("udp4", pc.LocalAddr().String())
		}
		// A silent peer: nothing listens there.
		silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { silent.Close() })
		return net.Dial("udp4", silent.LocalAddr().String())
	}
	k1, k3 := peerKey(t), peerKey(t)
	plan := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "n1", Pub: k1, Endpoint: ep("192.0.2.1:51830"), AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25},
		{ID: "n3", Pub: k3, AllowedIPs: []string{"10.215.0.3/32"}, Keepalive: 25},
	}}
	if err := r.a.ApplyMesh(ctx, plan); err != nil {
		t.Fatal(err)
	}
	s := r.server()
	c := r.client(r.ca, na.CNHub)
	code, body := do(t, c, "GET", s.URL+"/v1/mesh/rtt", "")
	if code != 200 {
		t.Fatalf("GET /v1/mesh/rtt: %d %s", code, body)
	}
	var got map[string]int
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	// 18 rounds at 30 ms, 2 at 33 ms: the p95 (19th of 20) is 33, exactly
	// (the clock is injected), within T10's [30, 40].
	if v, ok := got["n1"]; !ok || v != 33 || len(got) != 1 {
		t.Errorf("rtt %v: want n1 = 33 ms and n3 left out", got)
	}
	if dials["10.215.0.2>10.215.0.1"] != 1 || dials["10.215.0.2>10.215.0.3"] != 1 {
		t.Errorf("echo sockets %v: want one from the mesh address to each peer", dials)
	}
	// Under a minute old: answered from the cache (no new round).
	before := rounds.Load()
	if code, _ := do(t, c, "GET", s.URL+"/v1/mesh/rtt", ""); code != 200 || rounds.Load() != before {
		t.Errorf("a second read measured again (%d rounds)", rounds.Load()-before)
	}
	// A frontdoor caller may not read it.
	if code, _ := do(t, r.client(r.ca, na.CNFrontdoor), "GET", s.URL+"/v1/mesh/rtt", ""); code != 403 {
		t.Errorf("frontdoor.control: %d", code)
	}
}

// TestKeyCheckParity: the Hub's key check (meshplan.ValidKey) is exactly
// the nodeagent's (no parser differential between the plan and PUT
// /v1/mesh/peers).
func TestKeyCheckParity(t *testing.T) {
	k := peerKey(t)
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	alt := k[:42] + string(a[strings.IndexByte(a, k[42])^1]) + k[43:]
	for _, s := range []string{k, alt, strings.TrimRight(k, "="), "", "x", strings.Repeat("A", 43) + "=", " " + k, k + "\n",
		strings.Replace(k, "+", "-", -1), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=="} {
		if validWGKey(s) != meshplan.ValidKey(s) {
			t.Errorf("%q: nodeagent %v, Hub %v", s, validWGKey(s), meshplan.ValidKey(s))
		}
	}
}

// TestHealthPeerStatus: GET /v1/health names each plan peer's latest
// handshake and endpoint (null when none), keyed by the plan's ids; a
// device peer the plan doesn't name is left out.
func TestHealthPeerStatus(t *testing.T) {
	r := newRig(t, "agent")
	ctx := context.Background()
	k1, k3 := peerKey(t), peerKey(t)
	plan := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "n1", Pub: k1, Endpoint: ep("192.0.2.1:51830"), AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25},
		{ID: "n3", Pub: k3, AllowedIPs: []string{"10.215.0.3/32"}, Keepalive: 25},
	}}
	if err := r.a.ApplyMesh(ctx, plan); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 20, 10, 0, 5, 0, time.UTC)
	r.wg.mu.Lock()
	for i := range r.wg.dev.Peers {
		if r.wg.dev.Peers[i].PublicKey.String() == k1 {
			r.wg.dev.Peers[i].LastHandshakeTime = at
			r.wg.dev.Peers[i].Endpoint = &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51830}
		}
	}
	r.wg.dev.Peers = append(r.wg.dev.Peers, wgtypes.Peer{PublicKey: mustKey(t, peerKey(t))})
	r.wg.mu.Unlock()
	code, body := do(t, r.client(r.ca, na.CNHub), "GET", r.server().URL+"/v1/health", "")
	var h na.Health
	if code != 200 || jsonstrict.Decode([]byte(body), &h) != nil {
		t.Fatalf("%d %s", code, body)
	}
	if len(h.Peers) != 2 || h.Peers["n1"].LatestHandshake.V != "2026-11-20T10:00:05Z" || h.Peers["n1"].Endpoint.V != "192.0.2.1:51830" ||
		h.Peers["n3"].LatestHandshake.Valid || h.Peers["n3"].Endpoint.Valid {
		t.Errorf("peers %+v", h.Peers)
	}
}

func mustKey(t *testing.T, s string) wgtypes.Key {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestRTTLostRounds (review M6): a lost round counts as the round
// timeout in the p95; more than 2 lost of 20 is no figure.
func TestRTTLostRounds(t *testing.T) {
	var s []time.Duration
	for i := 0; i < 20; i++ {
		s = append(s, 30*time.Millisecond)
	}
	if v, ok := rttFigure(s, 20); !ok || v != 30 {
		t.Errorf("none lost: %d %t", v, ok)
	}
	if v, ok := rttFigure(s[:19], 20); !ok || v != 30 {
		t.Errorf("1 lost (the p95 is the 19th of 20): %d %t", v, ok)
	}
	if v, ok := rttFigure(s[:18], 20); !ok || v != int(rttTimeout/time.Millisecond) {
		t.Errorf("2 lost: %d %t, want the timeout", v, ok)
	}
	if _, ok := rttFigure(s[:17], 20); ok {
		t.Error("3 lost gave a figure")
	}
	if _, ok := rttFigure(s[:10], 20); ok {
		t.Error("half lost gave a figure")
	}
}
