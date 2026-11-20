// Package pkinode verifies peer certificates issued by the pki_node CA
// (contract §17.4, §20.4): a chain verified against one pinned CA, for one
// key usage, at the local clock with a tolerance either way. The worker
// agent (internal/agent) and the cluster nodeagent (internal/nodeagent/host)
// share it.
package pkinode

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrValidity is wrapped when a chain fails only on its validity window:
// it verifies at the middle of the leaf's own life (the caller's clock is
// probably off).
var ErrValidity = errors.New("the certificate isn't valid at this machine's clock")

// ErrNotIssued: the chain isn't issued by the pinned CA for this usage.
var ErrNotIssued = errors.New("client certificate not issued by the pinned pki_node CA for client auth")

// Verify verifies a peer chain (leaf first, as sent) against ca at now,
// now − tolerance and now + tolerance (accepted if one passes) for usage
// and returns the leaf. A chain that verifies only inside the leaf's own
// validity window returns an error wrapping ErrValidity (with the window).
func Verify(raw [][]byte, ca *x509.Certificate, now time.Time, tolerance time.Duration, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	if len(raw) == 0 || ca == nil {
		return nil, errors.New("no client certificate")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, errors.New("client certificate unreadable")
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
		return x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage}}
	}
	for _, at := range []time.Time{now, now.Add(-tolerance), now.Add(tolerance)} {
		if _, err := leaf.Verify(opts(at)); err == nil {
			return leaf, nil
		}
	}
	// A clock problem only when the chain verifies inside the leaf's own
	// validity window (the standard library checks validity first).
	mid := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if _, err := leaf.Verify(opts(mid)); err == nil {
		return nil, fmt.Errorf("%w (valid %s – %s)", ErrValidity, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil, ErrNotIssued
}

// CAFromChain finds the CA certificate whose sha256(DER) is caSHA (64
// lower-case hex) in a peer chain past the leaf: a self-signed CA
// (pki_node is its own root).
func CAFromChain(raw [][]byte, caSHA string) (*x509.Certificate, error) {
	if len(caSHA) != 64 {
		return nil, errors.New("no CA pin")
	}
	if _, err := hex.DecodeString(caSHA); err != nil {
		return nil, errors.New("no CA pin")
	}
	for _, r := range raw[1:] {
		if DERSHA256(r) != caSHA {
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

// DERSHA256 is the lower-case hex sha256 of a certificate's DER.
func DERSHA256(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}
