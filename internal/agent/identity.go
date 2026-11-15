package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/servers"
)

// Identity files under <data>/identity/ (contract §17.5), all 0600 in a
// 0700 directory. join.json is the join code (it holds the bootstrap key
// and the enrolment secret) and is deleted once the agent is ready.
const (
	joinFile    = "join.json"
	wgKeyFile   = "wg.key"
	tlsKeyFile  = "tls.key"
	tlsCertFile = "tls.crt"
	caFile      = "ca.crt"
	pinsFile    = "pins.json"
	networkFile = "network.json"
	// pending keys between the CSR and its certificate / the key switch
	wgKeyNewFile  = "wg.key.new"
	tlsKeyNewFile = "tls.key.new"
)

// States (pre-flight P33: one word, enrolling, for agent and Hub).
const (
	StateNone      = "none"
	StateEnrolling = "enrolling"
	StateReady     = "ready"
)

// Pins is pins.json: what the agent learned at join and keeps after it.
type Pins struct {
	State    string `json:"state"`
	ServerID string `json:"server_id"`
	TunnelIP string `json:"tunnel_ip"`
	Endpoint string `json:"endpoint"`
	LinkPub  string `json:"link_pub"`
	CASHA256 string `json:"ca_sha256"`
}

// Store is the identity directory.
type Store struct{ Dir string }

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

func (s Store) write(name string, b []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path(name), b, 0o600)
}

func (s Store) read(name string) ([]byte, error) { return os.ReadFile(s.path(name)) }

func (s Store) exists(name string) bool {
	_, err := os.Stat(s.path(name))
	return err == nil
}

// SaveJoin stores a decoded join code and its pins (state enrolling).
// A ready identity is never overwritten ("leave" first).
func (s Store) SaveJoin(c servers.JoinCode) error {
	if p, err := s.Pins(); err == nil && p.State == StateReady {
		return errors.New("this worker has already joined: run ./portcullis worker leave first")
	}
	b, _ := json.Marshal(c)
	if err := s.write(joinFile, b); err != nil {
		return err
	}
	return s.SavePins(Pins{State: StateEnrolling, ServerID: c.ServerID, TunnelIP: c.TunnelIP.String(), Endpoint: c.Endpoint, LinkPub: c.LinkPub, CASHA256: c.CASHA256})
}

// Join is the stored join code.
func (s Store) Join() (servers.JoinCode, error) {
	b, err := s.read(joinFile)
	if err != nil {
		return servers.JoinCode{}, err
	}
	var c servers.JoinCode
	if err := jsonstrict.Decode(b, &c); err != nil {
		return servers.JoinCode{}, fmt.Errorf("identity: %s: %v", joinFile, err)
	}
	return servers.DecodeJoinCode(c.Encode())
}

// SavePins / Pins: pins.json.
func (s Store) SavePins(p Pins) error {
	b, _ := json.Marshal(p)
	return s.write(pinsFile, b)
}

func (s Store) Pins() (Pins, error) {
	b, err := s.read(pinsFile)
	if err != nil {
		return Pins{}, err
	}
	var p Pins
	if err := jsonstrict.Decode(b, &p); err != nil {
		return Pins{}, fmt.Errorf("identity: %s: %v", pinsFile, err)
	}
	return p, nil
}

// State is the identity's state (none: never joined, or left).
func (s Store) State() string {
	p, err := s.Pins()
	if err != nil {
		return StateNone
	}
	return p.State
}

// Wipe removes the whole identity (leave).
func (s Store) Wipe() error { return os.RemoveAll(s.Dir) }

func (s Store) saveWGKey(name string, k Key) error { return s.write(name, []byte(k.String()+"\n")) }

func (s Store) wgKey(name string) (Key, error) {
	b, err := s.read(name)
	if err != nil {
		return Key{}, err
	}
	return ParseKey(string(trimNL(b)))
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// NewTLSKey is a node key (EC P-256, the pki_node roles' key type).
func NewTLSKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func (s Store) saveTLSKey(name string, k *ecdsa.PrivateKey) error {
	b, err := encodeKey(k)
	if err != nil {
		return err
	}
	return s.write(name, b)
}

func (s Store) tlsKey(name string) (*ecdsa.PrivateKey, error) {
	b, err := s.read(name)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("identity: not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("identity: not an EC key")
	}
	return ek, nil
}

// certPEM reads one PEM certificate.
func (s Store) cert(name string) (*x509.Certificate, error) {
	b, err := s.read(name)
	if err != nil {
		return nil, err
	}
	return parseCertPEM(string(b))
}

func parseCertPEM(p string) (*x509.Certificate, error) {
	blk, rest := pem.Decode([]byte(p))
	if blk == nil || blk.Type != "CERTIFICATE" || len(trimSpace(rest)) != 0 {
		return nil, errors.New("not exactly one PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == '\n' || b[0] == '\r' || b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return trimNL(b)
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// Network is the stored PUT /v1/network parameters.
func (s Store) Network() (agentapi.NetworkParams, error) {
	b, err := s.read(networkFile)
	if err != nil {
		return agentapi.NetworkParams{}, err
	}
	var n agentapi.NetworkParams
	err = jsonstrict.Decode(b, &n)
	return n, err
}

func (s Store) saveNetwork(n agentapi.NetworkParams) error {
	b, _ := json.Marshal(n)
	return s.write(networkFile, b)
}
