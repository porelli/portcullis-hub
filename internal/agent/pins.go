package agent

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/pkinode"
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
	leaf, err := pkinode.Verify(raw, ca, now, ClockTolerance, x509.ExtKeyUsageClientAuth)
	if errors.Is(err, pkinode.ErrValidity) {
		return "", fmt.Errorf("%w%s", ErrClock, strings.TrimPrefix(err.Error(), pkinode.ErrValidity.Error()))
	}
	if err != nil {
		return "", err
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
	return pkinode.CAFromChain(raw, caSHA)
}

// spkiSHA is a certificate's SubjectPublicKeyInfo DER (the proof's input
// is its sha256, computed by servers.Proof).
func spki(c *x509.Certificate) []byte { return c.RawSubjectPublicKeyInfo }
