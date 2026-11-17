// Package agent is portcullis-agent, the worker's only remote access to
// its engine (contract §17.4, §17.5, §17.7): a userspace WireGuard client
// of the primary's link role on its own gVisor netstack (no TUN, no
// capability), listening only inside that netstack on :7443 (control,
// pinned mTLS) and :7000 (data, from link's address only).
package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/portcullis/hub/internal/servers"
)

// Tunnel constants (contract §17.2).
const (
	MTU         = 1380
	Keepalive   = 25 // seconds, set on the worker so NAT keeps the path
	ControlPort = 7443
	DataPort    = 7000
)

// Key is a WireGuard key (X25519).
type Key [32]byte

// GenerateKey returns a new clamped X25519 private key.
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// Public derives the public key.
func (k Key) Public() Key {
	var pub Key
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		panic(err) // a clamped scalar with the base point never fails
	}
	copy(pub[:], p)
	return pub
}

// String is the base64 form WireGuard configs use.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// ParseKey reads a standard-base64 32-byte key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return k, errors.New("not a WireGuard key")
	}
	copy(k[:], b)
	return k, nil
}

// TunnelConfig is the worker's side: its key and tunnel address, link's
// public key and endpoint, and (tests only) the peer's address — link's
// .1 in production.
type TunnelConfig struct {
	PrivateKey Key
	Address    netip.Addr
	LinkPub    Key
	Endpoint   netip.AddrPort
	PeerIP     netip.Addr
}

// Tunnel is the agent's running device and netstack. Its only peer is
// link (AllowedIPs = link's /32): nothing else can reach the netstack.
type Tunnel struct {
	dev  *device.Device
	tnet *netstack.Net
	cfg  TunnelConfig
}

// ResolveEndpoint resolves a join code's <host>:<port> to an address.
func ResolveEndpoint(ctx context.Context, ep string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return netip.AddrPort{}, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return netip.AddrPort{}, errors.New("endpoint port out of range")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a.Unmap(), uint16(n)), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("endpoint %s: can't resolve it", host)
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), uint16(n)), nil
		}
	}
	return netip.AddrPortFrom(addrs[0], uint16(n)), nil
}

// NewTunnel starts the device. The private key reaches the device through
// UAPI in memory only.
func NewTunnel(cfg TunnelConfig) (*Tunnel, error) {
	if !servers.TunnelIPOK(cfg.Address) {
		return nil, errors.New("tunnel: the address is not a worker address of the link subnet")
	}
	if !cfg.PeerIP.IsValid() {
		cfg.PeerIP = servers.LinkAddr
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, nil, MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: netstack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	t := &Tunnel{dev: dev, tnet: tnet, cfg: cfg}
	if err := t.configure(cfg.PrivateKey); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: up: %w", err)
	}
	return t, nil
}

func (t *Tunnel) configure(priv Key) error {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\n", hex.EncodeToString(priv[:]))
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(t.cfg.LinkPub[:]))
	if t.cfg.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", t.cfg.Endpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", Keepalive, t.cfg.PeerIP)
	if err := t.dev.IpcSet(b.String()); err != nil {
		return errors.New("tunnel: device configuration refused")
	}
	return nil
}

// SwitchKey replaces the worker's private key (enrolment: the bootstrap
// key → the agent's own; or back), keeping link as the only peer.
func (t *Tunnel) SwitchKey(priv Key) error {
	t.cfg.PrivateKey = priv
	return t.configure(priv)
}

// LastHandshake is link's last handshake (zero: none yet).
func (t *Tunnel) LastHandshake() time.Time {
	cfg, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec, nsec int64
	sc := bufio.NewScanner(strings.NewReader(cfg))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			sec = n
		case "last_handshake_time_nsec":
			nsec = n
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}

// Listen listens on the agent's tunnel address. The agent opens exactly
// ControlPort and DataPort; every other port refuses (RST).
func (t *Tunnel) Listen(port uint16) (net.Listener, error) {
	return t.tnet.ListenTCPAddrPort(netip.AddrPortFrom(t.cfg.Address, port))
}

// Address is the agent's tunnel address; PeerIP link's.
func (t *Tunnel) Address() netip.Addr { return t.cfg.Address }
func (t *Tunnel) PeerIP() netip.Addr  { return t.cfg.PeerIP }

// Close stops the device.
func (t *Tunnel) Close() { t.dev.Close() }
