package host

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	na "github.com/portcullis/hub/internal/nodeagent"
)

func ep(s string) *string { return &s }

// TestPeersIdempotent: the same list twice → one wgctrl peer change; a
// peer missing from the list is removed; the node's own key, an
// allowed_ips entry outside the mesh, more than 256 peers → 400.
func TestPeersIdempotent(t *testing.T) {
	r := newRig(t, "server")
	ctx := context.Background()
	k1, k3 := peerKey(t), peerKey(t)
	plan := na.MeshPlan{Peers: []na.MeshPeer{
		{ID: "n1", Pub: k1, Endpoint: ep("192.0.2.1:51830"), AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25},
		{ID: "n3", Pub: k3, Endpoint: nil, AllowedIPs: []string{"10.215.0.3/32", "10.215.0.5/32"}, Keepalive: 0},
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
