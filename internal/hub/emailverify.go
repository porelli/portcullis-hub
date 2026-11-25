package hub

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// Verifying your own email by code (contract §9.8). The code goes out
// through Portcullis's own sender (SendHubMail, §19.14). Only an
// HMAC-SHA256 of it is kept, in memory (a Hub restart drops every pending
// code), bound to the account (LLDAP uuid) and the email it was sent to.
// The code is never logged, audited, stored or put in an error.

const (
	// EmailCodeTTL is how long a code is valid.
	EmailCodeTTL = 15 * time.Minute
	// EmailCodeTries is how many wrong entries a code allows.
	EmailCodeTries = 5
	// emailSendsPerHour and emailSendsPerDay limit the sends per person
	// and per recipient address.
	emailSendsPerHour = 3
	emailSendsPerDay  = 10

	emailCodeSubject = "Your Portcullis email code"
)

// emailCodeBody is the contract's mail text.
func emailCodeBody(code string) string {
	return "Your code is " + code + ". It expires in 15 minutes. If you didn't ask for it, you can ignore this email."
}

var (
	// ErrWrongCode answers a wrong code (400; ConfirmEmailVerification
	// also answers the attempts left).
	ErrWrongCode = &StatusError{Status: http.StatusBadRequest, Err: errors.New("wrong code")}

	errEmailNoSender = &StatusError{Status: http.StatusConflict, Err: errors.New("mail isn't set up on this server")}
	errTooManyCodes  = &StatusError{Status: http.StatusTooManyRequests, Err: errors.New("too many codes: try again later")}
	errCodeExpired   = &StatusError{Status: http.StatusGone, Err: errors.New(directory.ErrCodeExpiredMsg)}
	errNoOwnEmail    = &StatusError{Status: http.StatusBadRequest, Err: errors.New("you have no email to verify: ask an administrator to set one")}
	errCodeSendFail  = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("sending the code failed: try again later")}
)

// EmailVerifier is the directory's side of the code flow
// (directory.Service). Network calls: never call them holding mu.
type EmailVerifier interface {
	OwnEmail(ctx context.Context, user string) (uuid, email string, err error)
	VerifyOwnEmail(ctx context.Context, a directory.Actor, uuid, email string) error
}

// SetEmailVerifier wires the directory for the code flow (nil: 503).
func (h *Hub) SetEmailVerifier(v EmailVerifier) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emailVerifier = v
}

// pendingCode is one person's outstanding code.
type pendingCode struct {
	mac     []byte // HMAC-SHA256(key, uuid, email, code)
	uuid    string
	email   string
	expires time.Time
	wrong   int
}

// emailCodes is the code flow's state, its own leaf lock (never held
// across a network call or mu).
type emailCodes struct {
	mu      sync.Mutex
	key     []byte
	pending map[string]*pendingCode // lowercase user
	now     func() time.Time        // nil: time.Now
	send    func(ctx context.Context, to, subject, body string) error
}

// SetEmailCodeClockForTest sets the code flow's clock.
func (h *Hub) SetEmailCodeClockForTest(now func() time.Time) {
	h.emailCodes.mu.Lock()
	defer h.emailCodes.mu.Unlock()
	h.emailCodes.now = now
}

// SetHubMailSenderForTest replaces SendHubMail for the code flow (nil:
// SendHubMail).
func (h *Hub) SetHubMailSenderForTest(send func(ctx context.Context, to, subject, body string) error) {
	h.emailCodes.mu.Lock()
	defer h.emailCodes.mu.Unlock()
	h.emailCodes.send = send
}

// nowLocked is the clock. Caller holds ec.mu.
func (ec *emailCodes) nowLocked() time.Time {
	if ec.now != nil {
		return ec.now().UTC()
	}
	return time.Now().UTC()
}

// macLocked is the code's HMAC, bound to the account and the email.
// Caller holds ec.mu.
func (ec *emailCodes) macLocked(uuid, email, code string) ([]byte, error) {
	if ec.key == nil {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		ec.key = k
	}
	m := hmac.New(sha256.New, ec.key)
	for _, p := range []string{uuid, strings.ToLower(strings.TrimSpace(email)), code} {
		fmt.Fprintf(m, "%d:%s", len(p), p)
	}
	return m.Sum(nil), nil
}

// The send limits (3 per hour, 10 per day) hold per person and per
// recipient address, and survive a restart: state.yaml email_code_sends
// keeps, for the last 24 h, the send times under "user:<lowercase user>"
// and "addr:<hex HMAC-SHA256 of the normalised address, keyed by
// email_code_salt>" — never an address in plain text.

// sendKeys are user's and email's keys in EmailCodeSends. Caller holds mu
// (write: it may create the salt).
func (h *Hub) sendKeysLocked(user, email string) ([2]string, error) {
	if h.st.EmailCodeSalt == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return [2]string{}, err
		}
		h.st.EmailCodeSalt = hex.EncodeToString(b)
	}
	m := hmac.New(sha256.New, []byte(h.st.EmailCodeSalt))
	m.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return [2]string{"user:" + user, "addr:" + hex.EncodeToString(m.Sum(nil))}, nil
}

// reserveSend counts a send to email for user at now (both keys) and
// saves state.yaml, or answers 429 when either key is at a limit. A state
// that can't be saved refuses the send (the count must survive a
// restart). Never under ec.mu.
func (h *Hub) reserveSend(user, email string, now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys, err := h.sendKeysLocked(user, email)
	if err != nil {
		return statusErr(http.StatusInternalServerError, "generating a code failed")
	}
	if h.st.EmailCodeSends == nil {
		h.st.EmailCodeSends = map[string][]time.Time{}
	}
	// Prune every key's sends older than a day (no stale addresses kept).
	for k, l := range h.st.EmailCodeSends {
		kept := l[:0:0]
		for _, t := range l {
			if now.Sub(t) < 24*time.Hour {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(h.st.EmailCodeSends, k)
		} else {
			h.st.EmailCodeSends[k] = kept
		}
	}
	for _, k := range keys {
		hour := 0
		for _, t := range h.st.EmailCodeSends[k] {
			if now.Sub(t) < time.Hour {
				hour++
			}
		}
		if hour >= emailSendsPerHour || len(h.st.EmailCodeSends[k]) >= emailSendsPerDay {
			return errTooManyCodes
		}
	}
	for _, k := range keys {
		h.st.EmailCodeSends[k] = append(h.st.EmailCodeSends[k], now)
	}
	if err := h.saveStateLocked(); err != nil {
		for _, k := range keys {
			h.dropSendLocked(k, now)
		}
		return errCodeSendFail
	}
	return nil
}

// releaseSend drops the send reserved at at (nothing went out) and saves.
func (h *Hub) releaseSend(user, email string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys, err := h.sendKeysLocked(user, email)
	if err != nil {
		return
	}
	for _, k := range keys {
		h.dropSendLocked(k, at)
	}
	h.saveLocked()
}

// dropSendLocked removes one send at at under k. Caller holds mu (write).
func (h *Hub) dropSendLocked(k string, at time.Time) {
	l := h.st.EmailCodeSends[k]
	for i := len(l) - 1; i >= 0; i-- {
		if l[i].Equal(at) {
			l = append(l[:i:i], l[i+1:]...)
			break
		}
	}
	if len(l) == 0 {
		delete(h.st.EmailCodeSends, k)
	} else {
		h.st.EmailCodeSends[k] = l
	}
}

// newEmailCode is 8 uniformly random digits.
func newEmailCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func (h *Hub) emailVerifierOrErr() (EmailVerifier, error) {
	h.mu.RLock()
	v := h.emailVerifier
	h.mu.RUnlock()
	if v == nil {
		return nil, statusErr(http.StatusServiceUnavailable, "users & groups is not available")
	}
	return v, nil
}

// StartEmailVerification sends user (the signed-in person) a code for
// their current email: 202's expiry; 409 mail off or no Portcullis sender,
// 429 over the send limits, 400 no email. A new code replaces the last
// one. Audited email.code_sent (never the code).
func (h *Hub) StartEmailVerification(ctx context.Context, user string) (expires time.Time, err error) {
	user = strings.ToLower(strings.TrimSpace(user))
	detail := ""
	defer func() { h.auditOp(directory.Human(user), "email.code_sent", user, detail, err) }()
	v, err := h.emailVerifierOrErr()
	if err != nil {
		return time.Time{}, err
	}
	uuid, email, err := v.OwnEmail(ctx, user)
	if err != nil {
		return time.Time{}, dirStatusErr("email verification of "+user, err)
	}
	if email == "" {
		return time.Time{}, errNoOwnEmail
	}
	detail = "to=" + email
	ec := &h.emailCodes
	ec.mu.Lock()
	now := ec.nowLocked()
	send := ec.send
	ec.mu.Unlock()
	if send == nil {
		send = h.SendHubMail
	}
	if err := h.reserveSend(user, email, now); err != nil {
		return time.Time{}, err
	}
	code, err := newEmailCode()
	if err != nil {
		h.releaseSend(user, email, now)
		return time.Time{}, statusErr(http.StatusInternalServerError, "generating a code failed")
	}
	if serr := send(ctx, email, emailCodeSubject, emailCodeBody(code)); serr != nil {
		if errors.Is(serr, ErrNoHubSender) {
			// Nothing went out: not counted.
			h.releaseSend(user, email, now)
			return time.Time{}, errEmailNoSender
		}
		// It may have gone out: still counted. The cause is logged
		// without the code.
		log.Printf("email verification: sending %s's code: %s", user, strings.ReplaceAll(serr.Error(), code, "[code]"))
		return time.Time{}, errCodeSendFail
	}
	ec.mu.Lock()
	defer ec.mu.Unlock()
	mac, err := ec.macLocked(uuid, email, code)
	if err != nil {
		return time.Time{}, statusErr(http.StatusInternalServerError, "generating a code failed")
	}
	if ec.pending == nil {
		ec.pending = map[string]*pendingCode{}
	}
	expires = now.Add(EmailCodeTTL)
	ec.pending[user] = &pendingCode{mac: mac, uuid: uuid, email: email, expires: expires}
	return expires, nil
}

// ConfirmEmailVerification checks user's code (compared in constant time
// as an HMAC) and, when right, records their email verified by code (the
// directory audits email.verified). A wrong code is ErrWrongCode with
// the attempts left (the fifth wrong one uses the code up); no code,
// an expired or used-up one, or an email changed since the send is 410.
func (h *Hub) ConfirmEmailVerification(ctx context.Context, user, code string) (attemptsLeft int, err error) {
	user = strings.ToLower(strings.TrimSpace(user))
	code = strings.TrimSpace(code)
	v, err := h.emailVerifierOrErr()
	if err != nil {
		return 0, err
	}
	ec := &h.emailCodes
	ec.mu.Lock()
	p := ec.pending[user]
	if p == nil {
		ec.mu.Unlock()
		return 0, errCodeExpired
	}
	if ec.nowLocked().After(p.expires) {
		delete(ec.pending, user)
		ec.mu.Unlock()
		return 0, errCodeExpired
	}
	mac, merr := ec.macLocked(p.uuid, p.email, code)
	if merr != nil || !hmac.Equal(mac, p.mac) {
		p.wrong++
		left := EmailCodeTries - p.wrong
		exhausted := left <= 0
		if exhausted {
			delete(ec.pending, user)
			left = 0
		}
		ec.mu.Unlock()
		if exhausted {
			// Used up by wrong entries (never the code or the entries).
			h.auditOp(directory.Human(user), "user.email_code_exhausted", user, "to="+p.email, nil)
		}
		return left, ErrWrongCode
	}
	delete(ec.pending, user) // used, whatever the directory answers
	ec.mu.Unlock()
	if err := v.VerifyOwnEmail(ctx, directory.Human(user), p.uuid, p.email); err != nil {
		var de *directory.Error
		if errors.As(err, &de) && de.Status == http.StatusGone {
			return 0, errCodeExpired
		}
		return 0, dirStatusErr("email verification of "+user, err)
	}
	return 0, nil
}
