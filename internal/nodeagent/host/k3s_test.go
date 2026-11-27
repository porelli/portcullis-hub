package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	na "github.com/portcullis/hub/internal/nodeagent"
)

type ctxT = context.Context

type fakeEtcd struct {
	mu      sync.Mutex
	members []Member
	removed []uint64
	keys    map[string]bool
}

func (f *fakeEtcd) HasKey(_ context.Context, k string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[k], nil
}

func (f *fakeEtcd) set(k string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		f.keys = map[string]bool{}
	}
	f.keys[k] = true
}

func (f *fakeEtcd) Members(context.Context) ([]Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Member(nil), f.members...), nil
}

func (f *fakeEtcd) Remove(_ context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}

func (f *fakeEtcd) gone() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.removed...)
}

type fakeSup struct {
	calls         int
	ip            string
	oldPass, newT secret
	err           error
	// etcd, when set, gets the new bootstrap key (the re-key happened);
	// block, when set, is awaited after it (the answer is late).
	etcd  *fakeEtcd
	block chan struct{}
	// entered, when set, is closed once a call has begun (and re-keyed).
	entered chan struct{}
	mu      sync.Mutex
}

func (f *fakeSup) RotateServerToken(ctx context.Context, ip string, oldPass, newToken secret) error {
	f.mu.Lock()
	f.calls++
	f.ip, f.oldPass, f.newT = ip, oldPass, newToken
	err, block, entered := f.err, f.block, f.entered
	f.entered = nil
	f.mu.Unlock()
	if f.etcd != nil {
		f.etcd.set(bootstrapKey(passphrase(string(newToken), "server")))
	}
	if entered != nil {
		close(entered)
	}
	if block != nil {
		<-block
	}
	return err
}

func (f *fakeSup) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// testK3sCA is the test k3s server CA bundle; caHash its sha256 (what a
// K10 token for this cluster pins).
const testK3sCA = "-----BEGIN CERTIFICATE-----\ntest k3s CA\n-----END CERTIFICATE-----\n"

var caHash = sha256Hex(testK3sCA)

// installK3s: k3s present and running (a server's unit without
// --agent-token-file), its CA, its token file holding tok.
func installK3s(t *testing.T, r *rig, role, tok string) {
	writeFile(t, r.root, K3sBinary, "k3s", 0o755)
	writeFile(t, r.root, K3sTokenFile, tok+"\n", 0o600)
	if role == "server" {
		writeFile(t, r.root, "/var/lib/rancher/k3s/server/tls/server-ca.crt", testK3sCA, 0o644)
		writeFile(t, r.root, "/etc/systemd/system/k3s.service", "ExecStart=/usr/local/bin/k3s \\\n    server \\\n\t'--token-file=/etc/rancher/k3s/token' \\\n", 0o644)
	} else {
		writeFile(t, r.root, "/var/lib/rancher/k3s/agent/server-ca.crt", testK3sCA, 0o644)
	}
	if r.run.active == nil {
		r.run.active = map[string]bool{}
	}
	r.run.active[k3sUnit(role)] = true
}

func TestTokenSteps(t *testing.T) {
	ctx := context.Background()
	srvTok := "K10" + caHash + "::server:newpass0123456789"
	agtTok := "K10" + caHash + "::node:agentpass0123456789"
	r := newRig(t, "server")
	sup := &fakeSup{}
	r.a.cfg.Supervisor = sup
	installK3s(t, r, "server", "rawinittoken0123")
	// rotate: the supervisor with the old passphrase (init's raw token),
	// then the token file, then a restart.
	if err := r.a.TokenStep(ctx, na.TokenRotate{NewToken: srvTok, Step: "rotate"}); err != nil {
		t.Fatal(err)
	}
	if sup.calls != 1 || sup.ip != "10.215.0.2" || sup.oldPass != "rawinittoken0123" || string(sup.newT) != srvTok {
		t.Errorf("supervisor %+v", sup)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, K3sTokenFile)); strings.TrimSpace(string(b)) != srvTok {
		t.Error("the token file isn't the new token")
	}
	fi, _ := os.Stat(filepath.Join(r.root, K3sTokenFile))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v", fi.Mode())
	}
	if r.run.count("systemctl", "restart", "--no-block", "k3s") != 1 {
		t.Error("k3s wasn't restarted")
	}
	// A resumed rotate with the token in place: the supervisor with the new
	// passphrase skipped (old == new), nothing restarted again.
	if err := r.a.TokenStep(ctx, na.TokenRotate{NewToken: srvTok, Step: "rotate"}); err != nil {
		t.Fatal(err)
	}
	if sup.calls != 1 || r.run.count("systemctl", "restart") != 1 {
		t.Errorf("a resumed rotate: %d calls, %d restarts", sup.calls, r.run.count("systemctl", "restart"))
	}
	// apply: the token file, a restart, no supervisor call; never an agent
	// token file.
	srvTok2 := "K10" + caHash + "::server:newpass9876543210"
	if err := r.a.TokenStep(ctx, na.TokenRotate{NewToken: srvTok2, Step: "apply"}); err != nil {
		t.Fatal(err)
	}
	if readTok(t, r, K3sTokenFile) != srvTok2 || sup.calls != 1 || r.run.count("systemctl", "restart") != 2 {
		t.Errorf("apply: %d supervisor calls, %d restarts", sup.calls, r.run.count("systemctl", "restart"))
	}
	if _, err := os.Stat(filepath.Join(r.root, K3sAgentToken)); err == nil {
		t.Error("an agent token file was written")
	}
	// The staging directories are gone.
	ents, _ := os.ReadDir(filepath.Join(r.root, StateDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".rotate-") {
			t.Errorf("staging left: %s", e.Name())
		}
	}
	// Servers get the server token only; the agent token steps are gone.
	for _, c := range []struct {
		step, tok string
		code      int
	}{
		{"rotate", agtTok, 409}, {"apply", agtTok, 409}, {"apply-agent", agtTok, 400}, {"rotate-agent", agtTok, 400},
		{"bogus", srvTok, 400}, {"apply", "plain", 400}, {"apply", "K10" + caHash + "::", 400},
	} {
		err := r.a.TokenStep(ctx, na.TokenRotate{NewToken: c.tok, Step: c.step})
		var he *httpError
		if !errors.As(err, &he) || he.code != c.code {
			t.Errorf("server %s: %v, want %d", c.step, err, c.code)
		}
		if err != nil && (strings.Contains(err.Error(), "pass0123") || strings.Contains(err.Error(), caHash)) {
			t.Errorf("an error carries the token: %v", err)
		}
	}
	a := newRig(t, "agent")
	a.a.cfg.Supervisor = sup
	installK3s(t, a, "agent", "K10"+caHash+"::abcdef.0123456789abcdef")
	for _, c := range []struct {
		step, tok string
		code      int
	}{{"rotate", srvTok, 409}, {"apply", srvTok, 409}, {"apply", agtTok, 409}, {"rotate-agent", agtTok, 400}, {"apply-agent", agtTok, 400}} {
		err := a.a.TokenStep(ctx, na.TokenRotate{NewToken: c.tok, Step: c.step})
		var he *httpError
		if !errors.As(err, &he) || he.code != c.code {
			t.Errorf("agent %s: %v, want %d", c.step, err, c.code)
		}
	}
	// An agent holds no shared token (core agent-token fix): its token file
	// (its own bootstrap token) is never rewritten, k3s-agent never
	// restarted by a token step.
	if readTok(t, a, K3sTokenFile) != "K10"+caHash+"::abcdef.0123456789abcdef" || a.run.count("systemctl", "restart") != 0 {
		t.Error("a token step changed an agent")
	}
	// No token on any argv, ever.
	for _, rr := range []*rig{r, a} {
		for _, c := range rr.run.cmds {
			if strings.Contains(strings.Join(append(c.Args, c.Env...), " "), "pass0123") {
				t.Errorf("a token on argv/env: %s", c.Name)
			}
		}
	}
	if strings.Contains(r.log.String(), "pass0123") || strings.Contains(a.log.String(), "pass0123") {
		t.Error("a token in the log")
	}
}

func TestRemoveMember(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, "server")
	doc := map[string]DocNode{"n3": {Mesh: "10.215.0.3", State: "removed"}, "n4": {Mesh: "10.215.0.4", State: "active"}}
	r.a.cfg.Addresses = func(context.Context) (map[string]DocNode, error) { return doc, nil }
	etcd := &fakeEtcd{members: []Member{
		{ID: 2, Name: "n2-x", PeerURLs: []string{"https://10.215.0.2:2380"}},
		{ID: 3, Name: "n3-x", PeerURLs: []string{"https://10.215.0.3:2380"}},
		{ID: 4, Name: "n4-x", PeerURLs: []string{"https://10.215.0.4:2380"}},
	}}
	r.a.cfg.Etcd = etcd
	code := func(err error) int {
		var he *httpError
		if errors.As(err, &he) {
			return he.code
		}
		if err == nil {
			return 204
		}
		return 500
	}
	for _, c := range []struct {
		q    na.EtcdRemove
		want int
	}{
		{na.EtcdRemove{MeshIP: "10.215.0.4", Node: "n4"}, 409}, // active
		{na.EtcdRemove{MeshIP: "10.215.0.4", Node: "n3"}, 409}, // another mesh address
		{na.EtcdRemove{MeshIP: "10.215.0.2", Node: "n2"}, 409}, // its own
		{na.EtcdRemove{MeshIP: "10.215.0.9", Node: "n9"}, 409}, // unknown
		{na.EtcdRemove{MeshIP: "10.215.1.3", Node: "n3"}, 400},
		{na.EtcdRemove{MeshIP: "10.215.0.3", Node: "n3"}, 204},
		{na.EtcdRemove{MeshIP: "10.215.0.3", Node: "n3"}, 204}, // already absent
	} {
		if c.want == 204 && len(etcd.removed) == 1 {
			etcd.members = etcd.members[:1]
		}
		if got := code(r.a.RemoveMember(ctx, c.q)); got != c.want {
			t.Errorf("%+v: %d, want %d", c.q, got, c.want)
		}
	}
	if len(etcd.removed) != 1 || etcd.removed[0] != 3 {
		t.Errorf("removed %v", etcd.removed)
	}
	a := newRig(t, "agent")
	a.a.cfg.Addresses = r.a.cfg.Addresses
	a.a.cfg.Etcd = etcd
	if got := code(a.a.RemoveMember(ctx, na.EtcdRemove{MeshIP: "10.215.0.3", Node: "n3"})); got != 409 {
		t.Errorf("on an agent: %d", got)
	}
}

func TestUninstall(t *testing.T) {
	r := newRig(t, "agent")
	writeFile(t, r.root, "/usr/local/bin/k3s-agent-uninstall.sh", "#!/bin/sh\n", 0o755)
	exited := false
	r.a.cfg.Exit = func() { exited = true }
	r.a.Uninstall(context.Background())
	if !exited || r.run.count("/usr/local/bin/k3s-agent-uninstall.sh") != 1 || r.run.count("ip", "link", "del") != 1 {
		t.Errorf("exited %v, cmds %d", exited, len(r.run.cmds))
	}
	for _, p := range []string{MeshKeyFile, StateDir} {
		if _, err := os.Stat(filepath.Join(r.root, p)); err == nil {
			t.Errorf("%s left", p)
		}
	}
}

// TestUninstallDisarmsWatchdog (e2e-ha-vm run 10: the removed node reset
// 60 s after its removal, SNR's agent killed with its watchdog armed): an
// active, nowayout-0 watchdog gets the magic close; an idle one is never
// opened (opening arms it); a nowayout one is left alone.
func TestUninstallDisarmsWatchdog(t *testing.T) {
	r := newRig(t, "agent")
	writeFile(t, r.root, "/usr/local/bin/k3s-agent-uninstall.sh", "#!/bin/sh\n", 0o755)
	for name, st := range map[string][2]string{"watchdog0": {"active", "0"}, "watchdog1": {"inactive", "0"}, "watchdog2": {"active", "1"}} {
		writeFile(t, r.root, "/sys/class/watchdog/"+name+"/state", st[0]+"\n", 0o444)
		writeFile(t, r.root, "/sys/class/watchdog/"+name+"/nowayout", st[1]+"\n", 0o444)
		writeFile(t, r.root, "/sys/class/watchdog/"+name+"/timeout", "60\n", 0o444)
		writeFile(t, r.root, "/dev/"+name, "", 0o600)
	}
	r.a.cfg.Exit = func() {}
	r.a.Uninstall(context.Background())
	for name, want := range map[string]string{"watchdog0": "V", "watchdog1": "", "watchdog2": ""} {
		b, err := os.ReadFile(filepath.Join(r.root, "/dev/"+name))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q (%v), want %q", name, b, err, want)
		}
	}
}

// TestDisarmWatchdogNoDevice: an active watchdog whose device can't be
// opened is only logged; the uninstall still finishes.
func TestDisarmWatchdogNoDevice(t *testing.T) {
	r := newRig(t, "agent")
	writeFile(t, r.root, "/sys/class/watchdog/watchdog0/state", "active\n", 0o444)
	writeFile(t, r.root, "/sys/class/watchdog/watchdog0/nowayout", "0\n", 0o444)
	exited := false
	r.a.cfg.Exit = func() { exited = true }
	r.a.Uninstall(context.Background())
	if !exited {
		t.Error("the uninstall didn't finish")
	}
}

// TestEtcdGatewayPort (found live): the JSON gateway is k3s's HTTP
// listener 127.0.0.1:2382, never 2379 (gRPC only under k3s v1.37.2).
func TestEtcdGatewayPort(t *testing.T) {
	if etcdGatewayPort != "2382" {
		t.Fatalf("etcd gateway port %s", etcdGatewayPort)
	}
}
