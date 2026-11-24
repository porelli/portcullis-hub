package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/portcullis/hub/internal/state"
)

// Portcullis's own mail (contract §19.14, §9.8): the Hub submits as its
// sender portcullis-hub-mail on MAIL_HOSTNAME:587 with STARTTLS required
// (never plain, never an unverified certificate) and its sender password,
// trusting core's CA bundle (certs/ca-bundle.crt: the system CAs and the
// internal ones). The password never reaches a log, an error or the
// audit.

// ErrNoHubSender: Portcullis's own sender isn't wired (no provider, mail
// off, or no credential yet).
var ErrNoHubSender = errors.New("Portcullis can't send mail: no mail provider is wired, mail is off or its sender has no password yet")

// hubMailTimeout bounds one submission.
const hubMailTimeout = 30 * time.Second

// hubMailRoots is the pool the mail certificate is verified against: the
// system pool plus core's CA bundle (when present).
func (h *Hub) hubMailRoots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if b, err := os.ReadFile(filepath.Join(h.cfg.ProjectDir, "certs", "ca-bundle.crt")); err == nil {
		pool.AppendCertsFromPEM(b)
	}
	return pool
}

// SendHubMail sends one plain-text message from Portcullis's own sender
// ("Portcullis <portcullis-hub-mail@<primary domain>>") to to.
func (h *Hub) SendHubMail(ctx context.Context, to, subject, body string) error {
	mc := h.mailCore()
	if !mc.On || mc.Hostname == "" {
		return ErrNoHubSender
	}
	h.mu.RLock()
	s := h.storedSenderLocked(state.MailSenderHub)
	dial := h.hubMailDial
	h.mu.RUnlock()
	if s == nil {
		return ErrNoHubSender
	}
	pw := s.Password
	redact := func(err error) error {
		if err == nil {
			return nil
		}
		return errors.New("sending Portcullis's mail failed: " + redactValues(err.Error(), []string{pw}))
	}
	m := mail.NewMsg()
	if err := m.FromFormat(senderHubLabel, s.Address); err != nil {
		return redact(err)
	}
	if err := m.To(to); err != nil {
		return errors.New("the recipient isn't one address")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return errors.New("the subject must be one line")
	}
	m.Subject(subject)
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(mail.TypeTextPlain, body)
	opts := []mail.Option{
		mail.WithPort(senderPort),
		mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithTLSConfig(&tls.Config{ServerName: mc.Hostname, RootCAs: h.hubMailRoots(), MinVersion: tls.VersionTLS12}),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(s.Address),
		mail.WithPassword(pw),
		mail.WithTimeout(hubMailTimeout),
	}
	if dial != nil {
		opts = append(opts, mail.WithDialContextFunc(dial))
	}
	c, err := mail.NewClient(mc.Hostname, opts...)
	if err != nil {
		return redact(err)
	}
	ctx, cancel := context.WithTimeout(ctx, hubMailTimeout)
	defer cancel()
	return redact(c.DialAndSendWithContext(ctx, m))
}

// hubMailDialer is the submission's dialer seam (tests point it at a
// local server; nil = the default).
type hubMailDialer = func(ctx context.Context, network, address string) (net.Conn, error)
