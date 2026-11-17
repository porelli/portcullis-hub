package agentx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newCert(t *testing.T, until time.Time) (ed25519.PrivateKey, *ssh.Certificate) {
	t.Helper()
	_, ca, _ := ed25519.GenerateKey(rand.Reader)
	caS, _ := ssh.NewSignerFromKey(ca)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ssh.NewPublicKey(pub)
	c := &ssh.Certificate{Key: pk, CertType: ssh.UserCert, ValidPrincipals: []string{"u:alice@web"}, ValidAfter: 0, ValidBefore: uint64(until.Unix())}
	if err := c.SignCert(rand.Reader, caS); err != nil {
		t.Fatal(err)
	}
	return priv, c
}

func TestReplaceDomainKeepsOtherKeys(t *testing.T) {
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	_, own, _ := ed25519.GenerateKey(rand.Reader)
	kr.Add(agent.AddedKey{PrivateKey: own, Comment: "my own key"})
	now := time.Now()
	p1, c1 := newCert(t, now.Add(8*time.Hour))
	kr.Add(agent.AddedKey{PrivateKey: p1, Certificate: c1, Comment: Comment("other.example.org", "web")})
	p2, c2 := newCert(t, now.Add(8*time.Hour))
	if _, err := ReplaceDomain(kr, "example.org", []Entry{{HostGroup: "web", Key: p2, Certificate: c2}}, now); err != nil {
		t.Fatal(err)
	}
	p3, c3 := newCert(t, now.Add(4*time.Hour))
	if _, err := ReplaceDomain(kr, "example.org", []Entry{{HostGroup: "all", Key: p3, Certificate: c3}}, now); err != nil {
		t.Fatal(err)
	}
	keys, _ := kr.List()
	var comments []string
	for _, k := range keys {
		comments = append(comments, k.Comment)
	}
	got := strings.Join(comments, "|")
	if !strings.Contains(got, "my own key") || !strings.Contains(got, "portcullis other.example.org web") || !strings.Contains(got, "portcullis example.org all") || strings.Contains(got, "portcullis example.org web") {
		t.Errorf("agent keys %v", comments)
	}
	l, _ := List(kr)
	if len(l) != 2 {
		t.Errorf("listed %+v", l)
	}
	if n, _ := RemoveDomain(kr, ""); n != 2 {
		t.Errorf("logout removed %d", n)
	}
}

// refusingAgent refuses lifetime constraints, or every add.
type refusingAgent struct {
	agent.ExtendedAgent
	refuseAll bool
	added     []agent.AddedKey
}

func (r *refusingAgent) Add(k agent.AddedKey) error {
	if r.refuseAll || k.LifetimeSecs != 0 {
		return errors.New("agent: failure")
	}
	r.added = append(r.added, k)
	return r.ExtendedAgent.Add(k)
}

func TestLifetimeRefusedFallsBack(t *testing.T) {
	r := &refusingAgent{ExtendedAgent: agent.NewKeyring().(agent.ExtendedAgent)}
	p, c := newCert(t, time.Now().Add(time.Hour))
	notes, err := ReplaceDomain(r, "example.org", []Entry{{HostGroup: "web", Key: p, Certificate: c}}, time.Now())
	if err != nil || len(notes) != 1 || len(r.added) != 1 || r.added[0].LifetimeSecs != 0 {
		t.Errorf("notes %v err %v added %+v", notes, err, r.added)
	}
}

func TestAddRefusedHintsKey(t *testing.T) {
	r := &refusingAgent{ExtendedAgent: agent.NewKeyring().(agent.ExtendedAgent), refuseAll: true}
	p, c := newCert(t, time.Now().Add(time.Hour))
	_, err := ReplaceDomain(r, "example.org", []Entry{{HostGroup: "web", Key: p, Certificate: c}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "--key") {
		t.Errorf("err %v", err)
	}
}

func TestLifetimeIsCertificateExpiry(t *testing.T) {
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	r := &recordingAgent{ExtendedAgent: kr}
	now := time.Now()
	p, c := newCert(t, now.Add(2*time.Hour))
	ReplaceDomain(r, "example.org", []Entry{{HostGroup: "web", Key: p, Certificate: c}}, now)
	if len(r.added) != 1 || r.added[0].LifetimeSecs < 7190 || r.added[0].LifetimeSecs > 7200 {
		t.Errorf("lifetime %+v", r.added)
	}
}

type recordingAgent struct {
	agent.ExtendedAgent
	added []agent.AddedKey
}

func (r *recordingAgent) Add(k agent.AddedKey) error {
	r.added = append(r.added, k)
	return r.ExtendedAgent.Add(k)
}

func TestSignerForKey(t *testing.T) {
	kr := agent.NewKeyring().(agent.ExtendedAgent)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr.Add(agent.AddedKey{PrivateKey: priv})
	pk, _ := ssh.NewPublicKey(pub)
	if s, err := Signer(kr, pk); err != nil || s == nil {
		t.Errorf("%v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	opk, _ := ssh.NewPublicKey(other)
	if _, err := Signer(kr, opk); err == nil {
		t.Error("a key not in the agent")
	}
}
