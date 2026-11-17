package agent

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/portcullis/hub/internal/servers"
)

// Control names (contract §17.4): the Hub's control certificate and
// link's metrics certificate, both issued by pki_node.
const (
	CNControl = "hub.control"
	CNLink    = "link.control"
)

// ClockTolerance: the agent accepts a peer certificate valid at its own
// now, now − 5 min or now + 5 min (a worker's clock may be off).
const ClockTolerance = 5 * time.Minute

// ErrClock is wrapped when a certificate fails only on validity: the
// message tells the operator to fix the worker's clock.
var ErrClock = errors.New("the certificate isn't valid at the worker's clock (±5 min): check the worker's time (NTP)")

// verifyControl verifies a peer chain (leaf first, as sent) against ca at
// now, now−tolerance and now+tolerance (accepted if one passes), for
// client auth, and returns the leaf's CN, which must be hub.control or
// link.control. Anything else — another CA, a person's certificate, a
// node certificate — is refused.
func verifyControl(raw [][]byte, ca *x509.Certificate, now time.Time) (string, error) {
	if len(raw) == 0 || ca == nil {
		return "", errors.New("no client certificate")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return "", errors.New("client certificate unreadable")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	inter := x509.NewCertPool()
	for _, r := range raw[1:] {
		if c, err := x509.ParseCertificate(r); err == nil && !c.Equal(ca) {
			inter.AddCert(c)
		}
	}
	opts := func(at time.Time) x509.VerifyOptions {
		return x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	ok := false
	for _, at := range []time.Time{now, now.Add(-ClockTolerance), now.Add(ClockTolerance)} {
		if _, err := leaf.Verify(opts(at)); err == nil {
			ok = true
			break
		}
	}
	if !ok {
		// A clock problem only when the chain verifies inside the leaf's
		// own validity window (the standard library checks validity first).
		mid := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
		if _, err := leaf.Verify(opts(mid)); err == nil {
			return "", fmt.Errorf("%w (valid %s – %s)", ErrClock, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		return "", errors.New("client certificate not issued by the pinned pki_node CA for client auth")
	}
	switch cn := leaf.Subject.CommonName; cn {
	case CNControl, CNLink:
		return cn, nil
	default:
		return "", errors.New("client certificate is not hub.control or link.control")
	}
}

// caFromChain finds the CA certificate whose sha256(DER) is caSHA (the
// join code's ca_sha256, pre-flight P5) in a peer chain: a self-signed
// CA (pki_node is its own root).
func caFromChain(raw [][]byte, caSHA string) (*x509.Certificate, error) {
	if !servers.ValidSHA256Hex(caSHA) {
		return nil, errors.New("no CA pin")
	}
	for _, r := range raw[1:] {
		sum := sha256.Sum256(r)
		if hex.EncodeToString(sum[:]) != caSHA {
			continue
		}
		c, err := x509.ParseCertificate(r)
		if err != nil || !c.IsCA || c.CheckSignatureFrom(c) != nil {
			return nil, errors.New("the pinned CA in the chain is not a self-signed CA certificate")
		}
		return c, nil
	}
	return nil, errors.New("the client chain has no certificate matching the join code's ca_sha256")
}

// spkiSHA is a certificate's SubjectPublicKeyInfo DER (the proof's input
// is its sha256, computed by servers.Proof).
func spki(c *x509.Certificate) []byte { return c.RawSubjectPublicKeyInfo }
