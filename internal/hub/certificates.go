package hub

// The caller's own certificates on the Sign-in page (contract §5.1
// "Sign-in page", plan D22–D26, D30, D32): creating a browser
// certificate (a fresh sign-in under the people core template that is
// neither a password nor a browser certificate), revoking one's own
// browser certificate, renewing one's YubiKey certificate with the
// certificate the browser presents. enroll does the work (§9.4); the
// Hub decides who may ask and audits. The .p12 and its password are
// never logged, audited or stored here: they go back to the one caller.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/signin"
)

// CertActions are enroll's certificate actions (invite.Client, contract
// §9.4): never called holding mu.
type CertActions interface {
	CreateBrowserCertificate(ctx context.Context, r invite.BrowserCertRequest) (*invite.BrowserCert, error)
	RenewYubiKeyCertificate(ctx context.Context, user, presentedPEM, csrPEM string) (*invite.IssuedCert, error)
	RevokeCertificate(ctx context.Context, user, serial string) error
}

// SetCertActions wires enroll's certificate actions (main: the invite
// client; nil: every certificate action is 503).
func (h *Hub) SetCertActions(c CertActions) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certActions = c
}

func (h *Hub) certActionsOrNil() CertActions {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.certActions
}

// CertRow is one certificate as the Sign-in page lists it: Status is
// valid, expiring (fewer than CertExpiryWarnDays days left), expired or
// revoked.
type CertRow struct {
	Serial    string    `json:"serial"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// The certificate statuses (contract §5.1, D30).
const (
	CertValid    = "valid"
	CertExpiring = "expiring"
	CertExpired  = "expired"
	CertRevoked  = "revoked"
)

// DefaultCertExpiryWarnDays is core's CERT_EXPIRY_WARN_DAYS default.
const DefaultCertExpiryWarnDays = 7

// warnDaysRe is core's grammar for CERT_EXPIRY_WARN_DAYS (certs.sh
// cert_warn_seconds).
var warnDaysRe = regexp.MustCompile(`^[0-9]+$`)

// maxWarnDays bounds a huge (but grammatical) value: a century.
const maxWarnDays = 36500

// ParseCertExpiryWarnDays is HUB_CERT_EXPIRY_WARN_DAYS read as core reads
// CERT_EXPIRY_WARN_DAYS: a value matching ^[0-9]+$ is used (0 included,
// read as decimal, capped at a century); anything else, or unset, is 7.
// It never fails: the Hub never refuses to start over it.
func ParseCertExpiryWarnDays(v string) int {
	if !warnDaysRe.MatchString(v) {
		return DefaultCertExpiryWarnDays
	}
	n := new(big.Int)
	if _, ok := n.SetString(v, 10); !ok {
		return DefaultCertExpiryWarnDays
	}
	if n.Cmp(big.NewInt(maxWarnDays)) > 0 {
		return maxWarnDays
	}
	return int(n.Int64())
}

// certClock is the certificate status clock.
func (h *Hub) certClock() time.Time {
	if h.certNow != nil {
		return h.certNow()
	}
	return time.Now()
}

// certStatus is r's status at now with a warning of warnDays days.
func certStatus(revoked bool, notAfter, now time.Time, warnDays int) string {
	switch {
	case revoked:
		return CertRevoked
	case !notAfter.After(now):
		return CertExpired
	case notAfter.Sub(now) < time.Duration(warnDays)*24*time.Hour:
		return CertExpiring
	}
	return CertValid
}

// NewCertRow is a certificate's row as of now (the create answer's
// certificate).
func (h *Hub) NewCertRow(kind invite.CertKind, serial string, notBefore, notAfter time.Time) CertRow {
	return CertRow{Serial: serial, Kind: string(kind), Status: certStatus(false, notAfter, h.certClock(), h.cfg.CertExpiryWarnDays),
		NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC()}
}

// certRowsFor are user's certificates of a known kind among recs,
// revoked ones included, newest first.
func certRowsFor(recs []invite.CertRecord, user string, now time.Time, warnDays int) []CertRow {
	out := []CertRow{}
	for _, r := range recs {
		if !strings.EqualFold(strings.TrimSpace(r.User), user) || !r.Kind.Known() {
			continue
		}
		out = append(out, CertRow{Serial: r.Serial, Kind: string(r.Kind), Status: certStatus(r.Revoked, r.NotAfter, now, warnDays),
			NotBefore: r.NotBefore.UTC(), NotAfter: r.NotAfter.UTC()})
	}
	slices.SortStableFunc(out, func(a, b CertRow) int {
		if c := b.NotBefore.Compare(a.NotBefore); c != 0 {
			return c
		}
		return strings.Compare(a.Serial, b.Serial)
	})
	return out
}

// activeBrowserCerts counts rows that are unexpired, unrevoked browser
// certificates.
func activeBrowserCerts(rows []CertRow) int {
	n := 0
	for _, r := range rows {
		if r.Kind == string(invite.KindBrowser) && (r.Status == CertValid || r.Status == CertExpiring) {
			n++
		}
	}
	return n
}

// ── refusals ─────────────────────────────────────────────

var (
	// errOwnCertsProtected: admin, portcullis-hub and every portcullis-*
	// name (D32, review I3), before enroll's own 409 "protected account".
	errOwnCertsProtected = &StatusError{Status: http.StatusConflict, Err: errors.New("this account's certificates are managed from the server: ./portcullis cert revoke <serial>")}
	errBrowserCertOff    = &StatusError{Status: http.StatusConflict, Err: errors.New("browser certificates are off on this server")}
	errPresentYubiKey    = &StatusError{Status: http.StatusForbidden, Err: errors.New("present your current YubiKey certificate")}
	errNoSuchOwnCert     = &StatusError{Status: http.StatusNotFound, Err: errors.New("you have no browser certificate with that serial")}
	errCertsUnavailable  = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("certificates can't be managed right now: try again later")}
)

// errCertNeedsKey is D26's refusal when no method may approve a new
// certificate.
func (h *Hub) errCertNeedsKey() error {
	return statusErr(http.StatusConflict, "creating a certificate needs a passkey or YubiKey sign-in that people.%s accepts", NormalizeHost(h.cfg.Domain))
}

// enrollErr is enroll's refusal as the caller sees it: 400, 403, 404
// and 409 with enroll's text (invite.APIError keeps only those, clipped);
// anything else the generic 503, the cause logged.
func enrollErr(what string, err error) error {
	var ae *invite.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict:
			msg := ae.Message
			if msg == "" {
				msg = strings.ToLower(http.StatusText(ae.Status))
			}
			return &StatusError{Status: ae.Status, Err: errors.New(msg)}
		}
	}
	log.Printf("certificates: %s: %v", what, err)
	return errCertsUnavailable
}

// certFreshAllowed are the methods a fresh sign-in may use to add a
// certificate (D26): signin.FreshAccepted of the people core template's
// compiled rule minus password and browser_cert (a password or a copied
// certificate file never mints a new certificate), in canonical order.
// Not a compiled rule: none.
func certFreshAllowed(peopleRule signin.Node, on map[signin.Method]bool) []signin.Method {
	acc, err := signin.FreshAccepted(peopleRule, on)
	if err != nil {
		return nil
	}
	var out []signin.Method
	for _, m := range signin.Methods {
		if acc[m] && m != signin.Password && m != signin.BrowserCert {
			out = append(out, m)
		}
	}
	return out
}

// peopleCertFresh is certFreshAllowed of the people core template as
// it is now (nil when it can't be resolved: refused).
func (h *Hub) peopleCertFresh() ([]signin.Method, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	tmpl, rule, why := h.governingLocked(govCore("people"))
	if why != "" {
		return nil, tmpl
	}
	return certFreshAllowed(rule, h.st.SignIn.MethodsOn()), tmpl
}

// certRecords is enroll's certificate list read now (never the cached
// inventory: a revocation must count at once).
func (h *Hub) certRecords(ctx context.Context) ([]invite.CertRecord, error) {
	c := &h.signInInv
	c.mu.Lock()
	src := c.src.Certificates
	c.mu.Unlock()
	if src == nil {
		return nil, errCertsUnavailable
	}
	recs, err := src(ctx)
	if err != nil {
		log.Printf("certificates: enroll's list can't be read: %v", err)
		return nil, errCertsUnavailable
	}
	return recs, nil
}

// serialKey is a certificate serial's value (hex with or without ':'
// separators, any case), so enroll's "1a:2b" and a leaf's serial
// compare; false for anything else.
func serialKey(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 128 {
		return "", false
	}
	hex := strings.ReplaceAll(s, ":", "")
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok || n.Sign() < 0 || hex == "" || strings.ContainsAny(hex, "+-") {
		return "", false
	}
	return n.Text(16), true
}

// certLock is user's create lock.
func (h *Hub) certLock(user string) *sync.Mutex {
	m, _ := h.certCreate.LoadOrStore(user, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// ── create ───────────────────────────────────────────────

// CreateBrowserCertificate creates a browser certificate for user (the
// caller), valid days days (contract §5.1, D22, D26). Refusals in
// contract order: 409 browser_cert off (enroll isn't called), 409 a
// protected account (D32), 400 days not 1 to the effective
// browser_cert_days, 409 no method may approve it (before the proof, so
// it isn't spent), 403 a refused proof (the reason audited only), 503
// the Hub can't verify proofs or reach enroll; then enroll's answer. One
// create at a time per person. The caller must Clear() the answer once
// it is written; it is never logged, audited or kept. The whole call
// counts toward the people listener's refusal limit.
func (h *Hub) CreateBrowserCertificate(ctx context.Context, user string, days int, p freshauth.Proof) (bc *invite.BrowserCert, err error) {
	u, err := myUser(user)
	if err != nil {
		return nil, err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return nil, errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	return h.createBrowserCert(ctx, u, days, p)
}

func (h *Hub) createBrowserCert(ctx context.Context, u string, days int, p freshauth.Proof) (*invite.BrowserCert, error) {
	actor := directory.Human(u)
	attempt := fmt.Sprintf("browser, %d days", days)
	refuse := func(err error, reason string) error {
		d := attempt
		if reason != "" {
			d += "; " + reason
		}
		h.auditSignIn(actor, "cert.create", u, d, err)
		return err
	}
	h.mu.RLock()
	on := h.st.SignIn.MethodsOn()
	limits := h.limitsViewLocked().Effective
	h.mu.RUnlock()
	if !on[signin.BrowserCert] {
		return nil, refuse(errBrowserCertOff, "")
	}
	if invite.ProtectedName(u) {
		return nil, refuse(errOwnCertsProtected, "")
	}
	if days < 1 || days > limits.BrowserCertDays {
		if limits.BrowserCertDays < 1 {
			return nil, refuse(statusErr(http.StatusBadRequest, "this server allows no browser certificate lifetime"), "")
		}
		return nil, refuse(statusErr(http.StatusBadRequest, "days must be 1 to %d, got %d", limits.BrowserCertDays, days), "")
	}
	if allowed, tmpl := h.peopleCertFresh(); len(allowed) == 0 {
		return nil, refuse(h.errCertNeedsKey(), "no method of template "+tmpl+" may add a certificate")
	}
	ca := h.certActionsOrNil()
	if ca == nil {
		return nil, refuse(errCertsUnavailable, "enroll isn't configured")
	}
	lk := h.certLock(u)
	lk.Lock()
	defer lk.Unlock()
	fresh, reason, err := h.checkFreshAuth(ctx, govCore("people"), p, u)
	if err != nil {
		return nil, refuse(err, reason)
	}
	// D26, after the exchange: the method must still be one that may add
	// a certificate under the people template as it is now.
	allowed, tmpl := h.peopleCertFresh()
	if !slices.Contains(allowed, signin.Method(fresh.Method)) {
		return nil, refuse(errFreshAuth, "pc_fresh names "+fresh.Method+", which can't add a certificate (template "+tmpl+")")
	}
	// The limits as they are now (a Settings change during the exchange).
	h.mu.RLock()
	limits = h.limitsViewLocked().Effective
	h.mu.RUnlock()
	if days > limits.BrowserCertDays {
		return nil, refuse(statusErr(http.StatusBadRequest, "days must be 1 to %d, got %d", limits.BrowserCertDays, days), "")
	}
	bc, err := ca.CreateBrowserCertificate(ctx, invite.BrowserCertRequest{User: u, Days: days, MaxDays: limits.BrowserCertDays, MaxActive: limits.BrowserCertMaxActive})
	if err != nil {
		return nil, refuse(enrollErr("creating a browser certificate for "+u, err), "")
	}
	h.MarkInventoryStale()
	h.auditSignIn(actor, "cert.create", u, fmt.Sprintf("browser %s until %s", bc.Serial, bc.NotAfter.UTC().Format(time.DateOnly)), nil)
	return bc, nil
}

// ── revoke ───────────────────────────────────────────────

// RevokeOwnBrowserCertificate revokes user's own browser certificate
// serial (no fresh auth: it only removes access). A YubiKey
// certificate's serial or someone else's is 404; a protected account
// 409 (D32). Audited cert.revoke.
func (h *Hub) RevokeOwnBrowserCertificate(ctx context.Context, user, serial string) error {
	return h.RevokeOwnBrowserCertificateAs(ctx, directory.Human(user), serial)
}

// RevokeOwnBrowserCertificateAs is RevokeOwnBrowserCertificate for the
// caller a (the person, with the AI attribution of the MCP twin). The
// whole call counts toward the people listener's refusal limit.
func (h *Hub) RevokeOwnBrowserCertificateAs(ctx context.Context, a directory.Actor, serial string) (err error) {
	u, err := myUser(a.User)
	if err != nil {
		return err
	}
	a.User = u
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	shown := clip(serial, 128)
	defer func() {
		h.auditSignIn(a, "cert.revoke", u, "browser "+shown, err)
	}()
	if invite.ProtectedName(u) {
		return errOwnCertsProtected
	}
	want, ok := serialKey(serial)
	if !ok {
		return errNoSuchOwnCert
	}
	recs, err := h.certRecords(ctx)
	if err != nil {
		return err
	}
	var rec *invite.CertRecord
	for i := range recs {
		r := &recs[i]
		if k, ok := serialKey(r.Serial); ok && k == want && r.Kind == invite.KindBrowser && strings.EqualFold(strings.TrimSpace(r.User), u) {
			rec = r
			break
		}
	}
	if rec == nil {
		return errNoSuchOwnCert
	}
	shown = rec.Serial
	ca := h.certActionsOrNil()
	if ca == nil {
		return errCertsUnavailable
	}
	if err := ca.RevokeCertificate(ctx, u, rec.Serial); err != nil {
		return enrollErr("revoking "+u+"'s browser certificate "+rec.Serial, err)
	}
	h.MarkInventoryStale()
	return nil
}

// ── renew ────────────────────────────────────────────────

// maxPresentedHeader bounds X-Forwarded-Tls-Client-Cert (a chain of a
// few certificates).
const maxPresentedHeader = 64 << 10

// presentedLeaf is the first certificate of Traefik's
// X-Forwarded-Tls-Client-Cert value (contract §5.1, D25: base64 DER
// without BEGIN/END lines, possibly URL-escaped, comma-separated, leaf
// first), parsed.
func presentedLeaf(headerValue string) (*x509.Certificate, error) {
	if headerValue == "" || len(headerValue) > maxPresentedHeader {
		return nil, errors.New("no certificate presented")
	}
	first, _, _ := strings.Cut(headerValue, ",")
	// PathUnescape: %2B / %2F / %3D back; a literal '+' (an unescaped
	// value) stays a '+'.
	raw, err := url.PathUnescape(strings.TrimSpace(first))
	if err != nil {
		return nil, errors.New("the presented certificate isn't URL-escaped base64")
	}
	raw = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, raw)
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(der) == 0 {
		return nil, errors.New("the presented certificate isn't base64 DER")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("the presented certificate isn't an X.509 certificate")
	}
	return leaf, nil
}

// presentedCertPEM is the presented leaf as a PEM CERTIFICATE block
// (D25: first entry → DER → parsed X.509 → PEM), what enroll's renewal
// takes.
func presentedCertPEM(headerValue string) (string, error) {
	leaf, err := presentedLeaf(headerValue)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), nil
}

// maxCSR bounds the CSR the Hub passes on (the body is 8 KiB anyway).
const maxCSR = 8 << 10

// RenewYubiKeyCertificate renews user's (the caller's) YubiKey
// certificate with csrPEM (contract §5.1, D25). headerValue is the
// people router's X-Forwarded-Tls-Client-Cert: its leaf must be one of
// the caller's unexpired, unrevoked YubiKey (pki_int) certificates in
// enroll's list — a missing or unparsable header, a browser certificate
// or anyone else's is 403 "present your current YubiKey certificate",
// and enroll isn't called. No fresh auth: the TLS session and the CSR's
// signature prove possession. A protected account is 409 (D32). Audited
// cert.renew. The whole call counts toward the refusal limit.
func (h *Hub) RenewYubiKeyCertificate(ctx context.Context, user, headerValue, csrPEM string) (ic *invite.IssuedCert, err error) {
	u, err := myUser(user)
	if err != nil {
		return nil, err
	}
	if !h.entryLimit.reserve(u, h.entryClock()) {
		return nil, errEntryLimited
	}
	defer func() { h.entryLimit.release(u, h.entryClock(), isRefusal(err)) }()
	detail := "yubikey"
	defer func() {
		h.auditSignIn(directory.Human(u), "cert.renew", u, detail, err)
	}()
	if invite.ProtectedName(u) {
		return nil, errOwnCertsProtected
	}
	if strings.TrimSpace(csrPEM) == "" || len(csrPEM) > maxCSR {
		return nil, statusErr(http.StatusBadRequest, "csr must be a PEM certificate request")
	}
	leaf, perr := presentedLeaf(headerValue)
	if perr != nil {
		detail = "yubikey; " + perr.Error()
		return nil, errPresentYubiKey
	}
	serial := leaf.SerialNumber.Text(16)
	detail = "yubikey " + serial
	recs, err := h.certRecords(ctx)
	if err != nil {
		return nil, err
	}
	now := h.certClock()
	found := false
	for _, r := range recs {
		k, ok := serialKey(r.Serial)
		if ok && k == serial && r.Kind == invite.KindYubiKey && !r.Revoked && strings.EqualFold(strings.TrimSpace(r.User), u) &&
			!r.NotBefore.After(now) && r.NotAfter.After(now) {
			found = true
			break
		}
	}
	if !found {
		detail += "; not the caller's valid YubiKey certificate"
		return nil, errPresentYubiKey
	}
	ca := h.certActionsOrNil()
	if ca == nil {
		return nil, errCertsUnavailable
	}
	presented := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	ic, err = ca.RenewYubiKeyCertificate(ctx, u, presented, csrPEM)
	if err != nil {
		return nil, enrollErr("renewing "+u+"'s YubiKey certificate", err)
	}
	h.MarkInventoryStale()
	detail = fmt.Sprintf("yubikey %s -> %s until %s", serial, ic.Serial, ic.NotAfter.UTC().Format(time.DateOnly))
	return ic, nil
}
