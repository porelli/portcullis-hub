package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/state"
)

// sshPeople is a directory for the SSH tests: user → group → id.
type sshPeople struct {
	mu      sync.Mutex
	users   map[string]map[string]int
	pending map[string]map[string]time.Time
	uuids   map[string]string // user → LLDAP uuid (absent: none)
	err     error
	calls   int
}

func (p *sshPeople) Membership(context.Context, time.Time) (*directory.Membership, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	m := &directory.Membership{Users: map[string]map[string]int{}, Groups: map[string]directory.MemberGroup{}, Expired: map[string]map[string]bool{}, Pending: map[string]map[string]time.Time{}}
	m.UUIDs = maps.Clone(p.uuids)
	for u, gs := range p.users {
		m.Users[u] = map[string]int{}
		for g, id := range gs {
			m.Users[u][g] = id
			mg := m.Groups[g]
			mg.ID = id
			mg.Members = append(mg.Members, u)
			sort.Strings(mg.Members)
			m.Groups[g] = mg
		}
	}
	for u, gs := range p.pending {
		m.Pending[u] = map[string]time.Time{}
		for g, t := range gs {
			m.Pending[u][g] = t
		}
	}
	return m, nil
}

func (p *sshPeople) PrivilegeProblem(context.Context, string) (string, error) { return "", nil }

func (p *sshPeople) set(fn func(p *sshPeople)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

// fakeSSH is enroll's SSH API.
type fakeSSH struct {
	mu        sync.Mutex
	roles     map[string]cliapi.RoleSpec
	puts      []string
	deletes   []string
	signs     []invite.SSHUserSign
	hostSigns []invite.SSHHostSign
	mangle    func(hg string, r *cliapi.RoleSpec) // the read-back Vault "stores"
	caErr     error
	signErr   error
	userCA    string
	hostCA    string
	serial    int
	now       func() time.Time
	caKey     ssh.Signer
}

func newFakeSSH(t *testing.T) *fakeSSH {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	return &fakeSSH{roles: map[string]cliapi.RoleSpec{}, userCA: cliapi.NormalAuthorizedKey(signer.PublicKey()), hostCA: cliapi.NormalAuthorizedKey(signer.PublicKey()), caKey: signer, now: time.Now}
}

func (f *fakeSSH) PutSSHRole(_ context.Context, hg string, r cliapi.RoleSpec) (*cliapi.RoleSpec, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, hg)
	back := r
	if f.mangle != nil {
		f.mangle(hg, &back)
	}
	f.roles[hg] = back
	return &back, nil
}

func (f *fakeSSH) DeleteSSHRole(_ context.Context, hg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, hg)
	delete(f.roles, hg)
	return nil
}

func (f *fakeSSH) ListSSHRoles(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for hg := range f.roles {
		out = append(out, hg)
	}
	sort.Strings(out)
	return out, nil
}

// SignSSHUser signs for real with the fake CA, so callers can parse it.
func (f *fakeSSH) SignSSHUser(_ context.Context, r invite.SSHUserSign) (*invite.SSHSigned, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signErr != nil {
		return nil, f.signErr
	}
	f.signs = append(f.signs, r)
	pub, _, err := cliapi.ParseAuthorizedKey(r.PublicKey)
	if err != nil {
		return nil, &invite.APIError{Status: 400, Message: "bad key"}
	}
	f.serial++
	now := f.now()
	cert := &ssh.Certificate{Key: pub, Serial: uint64(f.serial), CertType: ssh.UserCert, KeyId: r.KeyID, ValidPrincipals: r.Principals,
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(time.Duration(r.ValidSeconds) * time.Second).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{}}}
	for _, e := range r.Extensions {
		cert.Extensions[e] = ""
	}
	if err := cert.SignCert(rand.Reader, f.caKey); err != nil {
		return nil, err
	}
	return &invite.SSHSigned{Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), Serial: fmt.Sprint(f.serial), ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC()}, nil
}

func (f *fakeSSH) SignSSHHost(_ context.Context, r invite.SSHHostSign) (*invite.SSHSigned, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostSigns = append(f.hostSigns, r)
	f.serial++
	return &invite.SSHSigned{Certificate: "ssh-ed25519-cert-v01@openssh.com AAAAhost" + fmt.Sprint(f.serial), Serial: fmt.Sprint(f.serial), ValidBefore: f.now().Add(hostCertTTL)}, nil
}

func (f *fakeSSH) SSHCA(context.Context) (*invite.SSHCA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.caErr != nil {
		return nil, f.caErr
	}
	return &invite.SSHCA{UserCAs: []string{f.userCA}, HostCAs: []string{f.hostCA}, Problems: []string{}}, nil
}

func (f *fakeSSH) counts() (puts, deletes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts), len(f.deletes)
}

// sshFixture is a Hub with SSH access on, the spec's example mapping, a
// fake directory and a fake enroll.
type sshFixture struct {
	h      *Hub
	people *sshPeople
	ssh    *fakeSSH
	audit  *fakeAudit
	clk    struct {
		sync.Mutex
		t time.Time
	}
}

// clock is the fixture's time; advance moves it (both locked: the
// background compiles read it).
func (f *sshFixture) clock() time.Time {
	f.clk.Lock()
	defer f.clk.Unlock()
	return f.clk.t
}

func (f *sshFixture) advance(d time.Duration) {
	f.clk.Lock()
	defer f.clk.Unlock()
	f.clk.t = f.clk.t.Add(d)
}

var sshNow = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

func newSSHFixture(t *testing.T) *sshFixture {
	t.Helper()
	h := newBareHub(t)
	f := &sshFixture{h: h, ssh: newFakeSSH(t), audit: &fakeAudit{}}
	f.clk.t = sshNow
	f.ssh.now = f.clock
	f.people = &sshPeople{users: map[string]map[string]int{
		"alice": {"ssh_web": 11, "ssh_admins": 12},
		"bob":   {"ssh_web": 11, "ssh_deploy": 13},
	}}
	h.SetPeople(f.people)
	h.SetSSHActions(f.ssh)
	h.SetAudit(f.audit)
	h.sshrt.now = f.clock
	key := hostKey(t)
	h.mu.Lock()
	h.st.SSH.Settings.Enabled = true
	h.st.SSH.HostGroups["web"] = state.SSHHostGroup{Label: "Web"}
	h.st.SSH.Hosts = map[string]state.SSHHost{
		"web-1": {Names: []string{"web-1.example.com"}, Addrs: []string{"192.0.2.11"}, HostGroups: []string{"web"}, Managed: true, HostKey: key, SudoChecked: true}, // reported: no account with sudo
	}
	h.st.SSH.Grants = []state.SSHGrant{
		{ID: "g-web", Group: "ssh_web", GroupID: 11, HostGroup: "web", Accounts: []string{"{username}"}, Sudo: "none"},
		{ID: "g-admins", Group: "ssh_admins", GroupID: 12, HostGroup: "all", Accounts: []string{"{username}"}, Sudo: "full"},
		{ID: "g-deploy", Group: "ssh_deploy", GroupID: 13, HostGroup: "web", Accounts: []string{"deploy"}, Sudo: "none"},
	}
	h.mu.Unlock()
	return f
}

func hostKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return cliapi.NormalAuthorizedKey(k)
}

func (f *sshFixture) compile(t *testing.T) {
	t.Helper()
	if err := f.h.compileSSH(context.Background()); err != nil {
		t.Fatal(err)
	}
}

var errDirDown = errors.New("lldap down")

func newSigner(t *testing.T) (ed25519.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return pub, s
}

// sshHostForTest is a locked read of a host's state.
func (h *Hub) sshHostForTest(id string) state.SSHHost {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.SSH.Hosts[id]
}

func (h *Hub) sshHostOKForTest(id string) (state.SSHHost, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	x, ok := h.st.SSH.Hosts[id]
	return x, ok
}

// sshStateForTest is a locked copy of the SSH state.
func (h *Hub) sshStateForTest() state.SSHState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.SSH.Clone()
}
