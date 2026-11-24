package hub

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/state"
)

// smtpServer is a minimal submission server: STARTTLS (when offered)
// with cert, then AUTH PLAIN; it records what it was told.
type smtpServer struct {
	ln       net.Listener
	cert     tls.Certificate
	startTLS bool
	user, pw string

	mu       sync.Mutex
	authed   bool
	authTry  bool
	mailFrom string
	data     string
}

func newSMTPServer(t *testing.T, cert tls.Certificate, startTLS bool, user, pw string) *smtpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{ln: ln, cert: cert, startTLS: startTLS, user: user, pw: pw}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpServer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(l string) { w.WriteString(l + "\r\n"); w.Flush() }
	say("220 mail.example.org ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch {
		case verb == "EHLO" || verb == "HELO":
			switch {
			case !secure && s.startTLS:
				say("250-mail.example.org\r\n250 STARTTLS")
			case secure:
				say("250-mail.example.org\r\n250 AUTH PLAIN")
			default:
				say("250-mail.example.org\r\n250 AUTH PLAIN")
			}
		case verb == "STARTTLS" && s.startTLS && !secure:
			say("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			r, w = bufio.NewReader(tc), bufio.NewWriter(tc)
			secure = true
		case verb == "AUTH":
			s.mu.Lock()
			s.authTry = true
			s.mu.Unlock()
			parts := strings.Fields(line)
			var b64 string
			if len(parts) >= 3 {
				b64 = parts[2]
			} else {
				say("334 ")
				l, _ := r.ReadString('\n')
				b64 = strings.TrimSpace(l)
			}
			raw, _ := base64.StdEncoding.DecodeString(b64)
			f := strings.Split(string(raw), "\x00")
			if secure && len(f) == 3 && f[1] == s.user && f[2] == s.pw {
				s.mu.Lock()
				s.authed = true
				s.mu.Unlock()
				say("235 ok")
			} else {
				say("535 no")
			}
		case verb == "MAIL":
			s.mu.Lock()
			ok := s.authed
			if ok {
				s.mailFrom = line
			}
			s.mu.Unlock()
			if !ok {
				say("530 auth first")
				continue
			}
			say("250 ok")
		case verb == "RCPT":
			say("250 ok")
		case verb == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			say("250 queued")
		case verb == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// selfSigned is a CA-flagged certificate for mail.example.org and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.org"}, DNSNames: []string{"mail.example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSendHubMailStartTLS(t *testing.T) {
	f := newSenderFixture(t)
	f.sync(t)
	cert, pemBytes := selfSigned(t)
	writeFile(t, filepath.Join(f.project, "certs", "ca-bundle.crt"), string(pemBytes))
	f.h.mu.RLock()
	s := f.h.storedSenderLocked(state.MailSenderHub)
	f.h.mu.RUnlock()
	if s == nil || s.Address != "portcullis-hub-mail@example.org" {
		t.Fatalf("hub sender %+v", s)
	}
	point := func(srv *smtpServer) {
		f.h.mu.Lock()
		f.h.hubMailDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.ln.Addr().String())
		}
		f.h.mu.Unlock()
	}
	// STARTTLS offered: AUTH with the stored password, then the message.
	ok := newSMTPServer(t, cert, true, s.Address, s.Password)
	point(ok)
	if err := f.h.SendHubMail(context.Background(), "alice@example.org", "Your code", "12345678"); err != nil {
		t.Fatal(err)
	}
	ok.mu.Lock()
	from, data, authed := ok.mailFrom, ok.data, ok.authed
	ok.mu.Unlock()
	if !authed || !strings.Contains(from, "<portcullis-hub-mail@example.org>") {
		t.Fatalf("authed %v, MAIL %q", authed, from)
	}
	if !strings.Contains(data, `From: "Portcullis" <portcullis-hub-mail@example.org>`) && !strings.Contains(data, "From: Portcullis <portcullis-hub-mail@example.org>") {
		t.Fatalf("message:\n%s", data)
	}
	if !strings.Contains(data, "Subject: Your code") || !strings.Contains(data, "12345678") {
		t.Fatalf("message:\n%s", data)
	}
	// No STARTTLS: refused before any AUTH or MAIL (never plain).
	plain := newSMTPServer(t, cert, false, s.Address, s.Password)
	point(plain)
	err := f.h.SendHubMail(context.Background(), "alice@example.org", "x", "y")
	plain.mu.Lock()
	tried, mailed := plain.authTry, plain.mailFrom
	plain.mu.Unlock()
	if err == nil || tried || mailed != "" {
		t.Fatalf("plain server: err %v, auth tried %v, MAIL %q", err, tried, mailed)
	}
	if strings.Contains(err.Error(), s.Password) {
		t.Fatal("the password in an error")
	}
	// An untrusted certificate: refused too.
	other, _ := selfSigned(t)
	bad := newSMTPServer(t, other, true, s.Address, s.Password)
	point(bad)
	if err := f.h.SendHubMail(context.Background(), "alice@example.org", "x", "y"); err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	bad.mu.Lock()
	tried = bad.authTry
	bad.mu.Unlock()
	if tried {
		t.Fatal("AUTH over an untrusted connection")
	}
}
