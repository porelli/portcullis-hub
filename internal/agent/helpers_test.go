package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/portcullis/hub/internal/servers"
)

// testCA is a pki_node stand-in: a self-signed root issuing control,
// link and node certificates.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	k, _ := NewTLSKey()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: k, cert: c}
}

func (ca *testCA) sha() string {
	s := sha256.Sum256(ca.cert.Raw)
	return hex.EncodeToString(s[:])
}

var serial int64 = 10

// issue signs a leaf for pub (nil: a new key) valid [nb, na].
func (ca *testCA) issue(t *testing.T, cn string, pub *ecdsa.PublicKey, nb, na time.Time, usage ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	var k *ecdsa.PrivateKey
	if pub == nil {
		k, _ = NewTLSKey()
		pub = &k.PublicKey
	}
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if strings.HasSuffix(cn, ".node.portcullis.internal") {
		tpl.DNSNames = []string{cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func (ca *testCA) control(t *testing.T, cn string) tls.Certificate {
	c, k := ca.issue(t, cn, nil, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	return tls.Certificate{Certificate: [][]byte{c.Raw, ca.cert.Raw}, PrivateKey: k, Leaf: c}
}

func pemOf(c *x509.Certificate) string { return string(certPEM(c)) }

// signCSR signs a PEM CSR as enroll would (node-worker: server + client).
func (ca *testCA) signCSR(t *testing.T, csrPEM string) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	c, _ := ca.issue(t, csr.Subject.CommonName, csr.PublicKey.(*ecdsa.PublicKey), time.Now().Add(-30*time.Second), time.Now().Add(30*24*time.Hour),
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	return c
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// linkSide is the primary's link role in a test: a listening WireGuard
// device on its own netstack whose only peer is the agent.
type linkSide struct {
	dev  *device.Device
	tnet *netstack.Net
	priv Key
	port int
	addr netip.Addr
}

func newLink(t *testing.T, addr string) *linkSide {
	t.Helper()
	priv, _ := GenerateKey()
	l := &linkSide{priv: priv, port: freeUDP(t), addr: netip.MustParseAddr(addr)}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{l.addr}, nil, MTU)
	if err != nil {
		t.Fatal(err)
	}
	l.dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	l.tnet = tnet
	if err := l.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), l.port)); err != nil {
		t.Fatal(err)
	}
	l.dev.Up()
	t.Cleanup(l.dev.Close)
	return l
}

// peer makes agent (its public key, its tunnel address) link's only peer.
func (l *linkSide) peer(t *testing.T, agentPub Key, agentIP netip.Addr) {
	t.Helper()
	if err := l.dev.IpcSet(fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n", hex.EncodeToString(agentPub[:]), agentIP)); err != nil {
		t.Fatal(err)
	}
}

func (l *linkSide) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(l.port))
}

func (l *linkSide) dial(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	return l.tnet.DialContextTCPAddrPort(ctx, to)
}

// joinCode is a valid code for server nas at .10 with link's key.
func joinCode(t *testing.T, l *linkSide, ca *testCA, bootstrap Key) servers.JoinCode {
	sec := make([]byte, 32)
	rand.Read(sec)
	c := servers.JoinCode{V: 1, Endpoint: l.endpoint().String(), LinkPub: l.priv.Public().String(), ServerID: "nas",
		TunnelIP: netip.MustParseAddr("10.214.0.10"), BootstrapKey: bootstrap.String(), CASHA256: ca.sha(),
		Secret: b64url(sec)}
	got, err := servers.DecodeJoinCode(c.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
