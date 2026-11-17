// Package agentx is the CLI's use of the person's ssh-agent (contract
// §18.15): the CLI speaks the agent protocol itself (x/crypto/ssh/agent)
// and never runs ssh-add. Keys it adds carry the comment
// "portcullis <domain> <host group>" and live until their certificate
// expires.
package agentx

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrNoAgent: no ssh-agent is reachable.
var ErrNoAgent = errors.New("no ssh-agent is running (SSH_AUTH_SOCK is unset, or the Windows OpenSSH agent service is stopped): start one, or use --write-files to write this login's key to ~/.ssh/portcullis (it's useless after the certificates expire)")

// Entry is one key + certificate to add.
type Entry struct {
	HostGroup   string
	Key         any // the private key (ed25519.PrivateKey)
	Certificate *ssh.Certificate
}

// CommentPrefix is the comment prefix of a domain's keys.
func CommentPrefix(domain string) string { return "portcullis " + domain + " " }

// Comment is an entry's comment.
func Comment(domain, hg string) string { return CommentPrefix(domain) + hg }

// RemoveDomain removes every key of the agent whose comment starts with
// domain's prefix (all Portcullis keys when domain is "").
func RemoveDomain(a agent.ExtendedAgent, domain string) (int, error) {
	keys, err := a.List()
	if err != nil {
		return 0, fmt.Errorf("listing the agent's keys: %w", err)
	}
	prefix := "portcullis "
	if domain != "" {
		prefix = CommentPrefix(domain)
	}
	n := 0
	for _, k := range keys {
		if strings.HasPrefix(k.Comment, prefix) {
			pk, err := ssh.ParsePublicKey(k.Blob)
			if err != nil {
				continue
			}
			if err := a.Remove(pk); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// ReplaceDomain removes domain's earlier Portcullis keys and adds keys.
// An agent that refuses lifetime constraints gets the key without one (a
// note says so); an agent that refuses adds altogether is an error that
// hints at --key.
func ReplaceDomain(a agent.ExtendedAgent, domain string, keys []Entry, now time.Time) (notes []string, err error) {
	if _, err := RemoveDomain(a, domain); err != nil {
		return nil, err
	}
	// The plain key too, once, for the longest certificate (found in e2e):
	// the written ssh config pairs IdentityFile id.pub with each
	// CertificateFile, and ssh then asks the agent to sign with the plain
	// key — an agent holding only the certificate identities refuses. The
	// plain key alone opens nothing (no authorized_keys anywhere).
	var plain any
	var plainLife int64
	for _, e := range keys {
		life := int64(time.Unix(int64(e.Certificate.ValidBefore), 0).Sub(now) / time.Second)
		if plain == nil {
			plain = e.Key
		}
		if life > plainLife {
			plainLife = life
		}
	}
	if plain != nil {
		if plainLife < 1 {
			plainLife = 1
		}
		k := agent.AddedKey{PrivateKey: plain, Comment: CommentPrefix(domain) + "(key)", LifetimeSecs: uint32(plainLife)}
		if err := a.Add(k); err != nil {
			k.LifetimeSecs = 0
			if err2 := a.Add(k); err2 != nil {
				return notes, fmt.Errorf("your ssh-agent refused the key (%v): agents like 1Password or Secretive can't take new keys; sign one of their keys with --key instead", err2)
			}
		}
	}
	for _, e := range keys {
		life := int64(time.Unix(int64(e.Certificate.ValidBefore), 0).Sub(now) / time.Second)
		if life < 1 {
			life = 1
		}
		k := agent.AddedKey{PrivateKey: e.Key, Certificate: e.Certificate, Comment: Comment(domain, e.HostGroup), LifetimeSecs: uint32(life)}
		if err := a.Add(k); err != nil {
			k.LifetimeSecs = 0
			if err2 := a.Add(k); err2 != nil {
				return notes, fmt.Errorf("your ssh-agent refused the key (%v): agents like 1Password or Secretive can't take new keys; sign one of their keys with --key instead", err2)
			}
			notes = append(notes, "your ssh-agent doesn't support key lifetimes: the "+e.HostGroup+" key stays in it until you run portcullis logout (its certificate still expires on time)")
		}
	}
	return notes, nil
}

// Signer is the agent's signer for pub (a --key), or an error.
func Signer(a agent.ExtendedAgent, pub ssh.PublicKey) (ssh.Signer, error) {
	signers, err := a.Signers()
	if err != nil {
		return nil, fmt.Errorf("listing the agent's keys: %w", err)
	}
	want := pub.Marshal()
	for _, s := range signers {
		if string(s.PublicKey().Marshal()) == string(want) {
			return s, nil
		}
	}
	return nil, errors.New("that key isn't in your ssh-agent: add it first (ssh-add), then run portcullis login --key again")
}

// Listed is one Portcullis key in the agent.
type Listed struct {
	Domain, HostGroup string
	Certificate       *ssh.Certificate
	KeyType           string
}

// List returns the agent's Portcullis certificates.
func List(a agent.ExtendedAgent) ([]Listed, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	var out []Listed
	for _, k := range keys {
		f := strings.Fields(k.Comment)
		if len(f) != 3 || f[0] != "portcullis" {
			continue
		}
		pk, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		cert, ok := pk.(*ssh.Certificate)
		if !ok {
			continue
		}
		out = append(out, Listed{Domain: f[1], HostGroup: f[2], Certificate: cert, KeyType: cert.Key.Type()})
	}
	return out, nil
}
