package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	na "github.com/portcullis/hub/internal/nodeagent"
)

type ctxT = context.Context

type fakeEtcd struct {
	members []Member
	removed []uint64
}

func (f *fakeEtcd) Members(context.Context) ([]Member, error) { return f.members, nil }
func (f *fakeEtcd) Remove(_ context.Context, id uint64) error {
	f.removed = append(f.removed, id)
	return nil
}

type fakeSup struct {
	calls         int
	ip            string
	oldPass, newT secret
	err           error
}

func (f *fakeSup) RotateServerToken(_ context.Context, ip string, oldPass, newToken secret) error {
	f.calls++
	f.ip, f.oldPass, f.newT = ip, oldPass, newToken
	return f.err
}

// installK3s: k3s present and running, its token file holding tok.
func installK3s(t *testing.T, r *rig, role, tok string) {
	writeFile(t, r.root, K3sBinary, "k3s", 0o755)
	writeFile(t, r.root, K3sTokenFile, tok+"\n", 0o600)
	if r.run.active == nil {
		r.run.active = map[string]bool{}
	}
	r.run.active[k3sUnit(role)] = true
}

const caHash = "b7335c14c0febed58f896145ef153d44a59bd0dfa5065771f18cc99c514c0edb"

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
	// rotate-agent / apply-agent: the agent token file.
	if err := r.a.TokenStep(ctx, na.TokenRotate{NewToken: agtTok, Step: "rotate-agent"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, K3sAgentToken)); strings.TrimSpace(string(b)) != agtTok {
		t.Error("the agent token file isn't the new agent token")
	}
	if sup.calls != 1 {
		t.Error("rotate-agent called the server token API")
	}
	// The staging directories are gone.
	ents, _ := os.ReadDir(filepath.Join(r.root, StateDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".rotate-") {
			t.Errorf("staging left: %s", e.Name())
		}
	}
	// Servers get the server token, agents the agent token.
	for _, c := range []struct {
		step, tok string
		code      int
	}{
		{"rotate", agtTok, 409}, {"apply", agtTok, 409}, {"apply-agent", srvTok, 409}, {"rotate-agent", srvTok, 409},
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
	}{{"rotate", srvTok, 409}, {"rotate-agent", agtTok, 409}, {"apply-agent", agtTok, 409}, {"apply", srvTok, 409}} {
		err := a.a.TokenStep(ctx, na.TokenRotate{NewToken: c.tok, Step: c.step})
		var he *httpError
		if !errors.As(err, &he) || he.code != c.code {
			t.Errorf("agent %s: %v, want %d", c.step, err, c.code)
		}
	}
	if err := a.a.TokenStep(ctx, na.TokenRotate{NewToken: agtTok, Step: "apply"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(a.root, K3sTokenFile)); strings.TrimSpace(string(b)) != agtTok {
		t.Error("the agent's token file isn't the agent token")
	}
	if a.run.count("systemctl", "restart", "--no-block", "k3s-agent") != 1 {
		t.Error("k3s-agent wasn't restarted")
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
