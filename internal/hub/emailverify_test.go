package hub

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// fakeVerifier is the directory's side of the code flow.
type fakeVerifier struct {
	mu       sync.Mutex
	uuid     string
	email    string
	recorded []string          // "uuid email"
	others   map[string]string // more people: user → email
}

func (v *fakeVerifier) OwnEmail(_ context.Context, user string) (string, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.others[user]; ok {
		return "uuid-" + user, e, nil
	}
	if user != "alice" {
		return "", "", &directory.Error{Status: 404, Msg: "no such user"}
	}
	return v.uuid, v.email, nil
}

func (v *fakeVerifier) VerifyOwnEmail(_ context.Context, a directory.Actor, uuid, email string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if a.User != "alice" || uuid != v.uuid || !strings.EqualFold(email, v.email) {
		return &directory.Error{Status: http.StatusGone, Msg: directory.ErrCodeExpiredMsg}
	}
	v.recorded = append(v.recorded, uuid+" "+email)
	return nil
}

func (v *fakeVerifier) setEmail(e string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.email = e
}

type sentMail struct{ to, subject, body string }

type codeFixture struct {
	f     *fixture
	h     *Hub
	v     *fakeVerifier
	audit *fakeAudit
	now   time.Time
	mu    sync.Mutex
	sent  []sentMail
	fail  error
}

func newCodeFixture(t *testing.T) *codeFixture {
	t.Helper()
	f := newFixture(t)
	c := &codeFixture{f: f, h: f.h, v: &fakeVerifier{uuid: "uuid-alice", email: "alice@example.org"}, audit: &fakeAudit{}, now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	c.h.SetAudit(c.audit)
	c.h.SetEmailVerifier(c.v)
	c.h.SetEmailCodeClockForTest(func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now })
	c.h.SetHubMailSenderForTest(func(_ context.Context, to, subject, body string) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.fail != nil {
			return c.fail
		}
		c.sent = append(c.sent, sentMail{to, subject, body})
		return nil
	})
	return c
}

func (c *codeFixture) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var codeRe = regexp.MustCompile(`^Your code is ([0-9]{8})\. It expires in 15 minutes\. If you didn't ask for it, you can ignore this email\.$`)

// lastCode answers the code of the last mail sent.
func (c *codeFixture) lastCode(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		t.Fatal("no mail sent")
	}
	m := codeRe.FindStringSubmatch(c.sent[len(c.sent)-1].body)
	if m == nil {
		t.Fatalf("body %q", c.sent[len(c.sent)-1].body)
	}
	return m[1]
}

// wrong is a code that isn't code.
func wrong(code string) string {
	if code == "00000000" {
		return "11111111"
	}
	return "00000000"
}

func TestCodeFlow(t *testing.T) {
	c := newCodeFixture(t)
	exp, err := c.h.StartEmailVerification(context.Background(), "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(c.now.Add(15 * time.Minute)) {
		t.Errorf("expires %v", exp)
	}
	code := c.lastCode(t)
	if m := c.sent[0]; m.to != "alice@example.org" || m.subject != "Your Portcullis email code" {
		t.Errorf("mail %+v", m)
	}
	if e := c.audit.last(); e.Action != "email.code_sent" || e.Actor != "alice" || e.Target != "alice" || e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", " "+code+" "); err != nil {
		t.Fatal(err)
	}
	if len(c.v.recorded) != 1 || c.v.recorded[0] != "uuid-alice alice@example.org" {
		t.Errorf("recorded %v", c.v.recorded)
	}
	// Used: gone.
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", code); statusOf(err) != 410 || err.Error() != directory.ErrCodeExpiredMsg {
		t.Errorf("reuse = %v", err)
	}
	// Nobody else's code: bob has none.
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "bob", code); statusOf(err) != 410 {
		t.Errorf("bob = %v", err)
	}
}

func TestCodeBoundToEmail(t *testing.T) {
	c := newCodeFixture(t)
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code := c.lastCode(t)
	c.v.setEmail("alice.other@example.org")
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", code); statusOf(err) != 410 {
		t.Errorf("changed email = %v", err)
	}
	if len(c.v.recorded) != 0 {
		t.Error("recorded")
	}
}

func TestCodeAttempts(t *testing.T) {
	c := newCodeFixture(t)
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code := c.lastCode(t)
	var lefts []int
	for i := 0; i < 5; i++ {
		left, err := c.h.ConfirmEmailVerification(context.Background(), "alice", wrong(code))
		if statusOf(err) != 400 || !errors.Is(err, ErrWrongCode) {
			t.Fatalf("wrong %d = %v", i, err)
		}
		lefts = append(lefts, left)
	}
	if got := toStr(lefts); got != "4 3 2 1 0" {
		t.Errorf("attempts_left %v", lefts)
	}
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", code); statusOf(err) != 410 {
		t.Errorf("the right code after 5 wrong = %v", err)
	}
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", "not-digits"); statusOf(err) != 410 {
		t.Errorf("after = %v", err)
	}
}

func toStr(l []int) string {
	var b strings.Builder
	for i, n := range l {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte(byte('0' + n))
	}
	return b.String()
}

func TestCodeExpiry(t *testing.T) {
	c := newCodeFixture(t)
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code := c.lastCode(t)
	c.advance(15*time.Minute + time.Second)
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", code); statusOf(err) != 410 {
		t.Errorf("expired = %v", err)
	}
	// Just inside the window it still works.
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code = c.lastCode(t)
	c.advance(15 * time.Minute)
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", code); err != nil {
		t.Errorf("at 15 min = %v", err)
	}
}

func TestSendLimits(t *testing.T) {
	c := newCodeFixture(t)
	ctx := context.Background()
	start := func() error { _, err := c.h.StartEmailVerification(ctx, "alice"); return err }
	for i := 0; i < 3; i++ {
		if err := start(); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	if err := start(); statusOf(err) != 429 || err.Error() != "too many codes: try again later" {
		t.Fatalf("4th within the hour = %v", err)
	}
	if e := c.audit.last(); e.Action != "email.code_sent" || e.Result != "refused" {
		t.Errorf("audit %+v", e)
	}
	// A new code replaces the old one: only the last mail's code works.
	// 3 more each hour: 9 within the day, the 10th in hour 4, then 429.
	for h := 1; h <= 3; h++ {
		c.advance(time.Hour + time.Second)
		n := 3
		if h == 3 {
			n = 1
		}
		for i := 0; i < n; i++ {
			if err := start(); err != nil {
				t.Fatalf("hour %d send %d: %v", h, i+1, err)
			}
		}
	}
	if err := start(); statusOf(err) != 429 {
		t.Fatalf("11th within 24 h = %v", err)
	}
	c.advance(time.Hour)
	if err := start(); statusOf(err) != 429 {
		t.Fatalf("still within 24 h = %v", err)
	}
	c.advance(24 * time.Hour)
	if err := start(); err != nil {
		t.Fatalf("a day later = %v", err)
	}
	c.mu.Lock()
	n := len(c.sent)
	c.mu.Unlock()
	if n != 11 {
		t.Errorf("%d mails sent, want 11", n)
	}
}

// TestVerifyNoSender: mail off is 409 with the contract's text, counts
// no send and is audited refused.
func TestVerifyNoSender(t *testing.T) {
	c := newCodeFixture(t)
	c.mu.Lock()
	c.fail = ErrNoHubSender
	c.mu.Unlock()
	for i := 0; i < 4; i++ {
		_, err := c.h.StartEmailVerification(context.Background(), "alice")
		if statusOf(err) != 409 || err.Error() != "mail isn't set up on this server" {
			t.Fatalf("no sender = %v", err)
		}
	}
	if e := c.audit.last(); e.Action != "email.code_sent" || e.Result != "refused" {
		t.Errorf("audit %+v", e)
	}
	// The real sender with mail off answers the same.
	c.h.SetHubMailSenderForTest(nil)
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); statusOf(err) != 409 {
		t.Errorf("real sender, mail off = %v", err)
	}
	// No email: 400.
	c.v.setEmail("")
	c.h.SetHubMailSenderForTest(func(context.Context, string, string, string) error { return nil })
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); statusOf(err) != 400 {
		t.Errorf("no email = %v", err)
	}
}

// TestCodeNeverStoredOrAudited: the code is in no file, audit entry, log
// line or error — a failed send included.
func TestCodeNeverStoredOrAudited(t *testing.T) {
	c := newCodeFixture(t)
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code := c.lastCode(t)
	if _, err := c.h.ConfirmEmailVerification(context.Background(), "alice", wrong(code)); statusOf(err) != 400 || strings.Contains(err.Error(), code) {
		t.Fatalf("wrong = %v", err)
	}
	// A send failing with the code in its text.
	var failCode string
	c.h.SetHubMailSenderForTest(func(_ context.Context, _, _, body string) error {
		failCode = codeRe.FindStringSubmatch(body)[1]
		return errors.New("smtp said: " + body)
	})
	_, err := c.h.StartEmailVerification(context.Background(), "alice")
	if statusOf(err) != 503 || strings.Contains(err.Error(), failCode) {
		t.Fatalf("failed send = %v", err)
	}
	for _, secret := range []string{code, failCode} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("a code in the log:\n%s", logs.String())
		}
		for _, e := range c.audit.entries {
			if strings.Contains(e.Detail+e.Error+e.Target, secret) {
				t.Errorf("a code in the audit: %+v", e)
			}
		}
		filepath.Walk(filepath.Dir(c.h.cfg.DataDir), func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(secret)) {
					t.Errorf("a code in %s", p)
				}
			}
			return nil
		})
	}
	// Memory keeps only an HMAC.
	c.h.emailCodes.mu.Lock()
	p := c.h.emailCodes.pending["alice"]
	c.h.emailCodes.mu.Unlock()
	if p == nil || len(p.mac) != 32 {
		t.Fatalf("pending %+v", p)
	}
	if bytes.Contains(p.mac, []byte(code)) {
		t.Error("the code in memory")
	}
}

// TestSendLimitsPerAddress (fix round 1): the limits hold per recipient
// address too (normalised), whoever asks; they survive a Hub restart, and
// state.yaml keeps no address in plain text.
func TestSendLimitsPerAddress(t *testing.T) {
	c := newCodeFixture(t)
	ctx := context.Background()
	c.v.others = map[string]string{"bob": " ALICE@Example.org ", "carol": "carol@example.org"}
	for i := 0; i < 3; i++ {
		if _, err := c.h.StartEmailVerification(ctx, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	// bob's (stale) copy of alice's address: the address's limit.
	if _, err := c.h.StartEmailVerification(ctx, "bob"); statusOf(err) != 429 {
		t.Fatalf("same address, another person = %v", err)
	}
	if _, err := c.h.StartEmailVerification(ctx, "carol"); err != nil {
		t.Fatalf("another address = %v", err)
	}
	raw, err := os.ReadFile(c.h.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "example.org") || !strings.Contains(string(raw), "email_code_sends:") || !strings.Contains(string(raw), "addr:") {
		t.Errorf("state.yaml:\n%s", raw)
	}
	// A restart keeps the counts (per person and per address).
	h2 := restart(t, c.f, "", c.audit, nil)
	h2.SetEmailVerifier(c.v)
	h2.SetEmailCodeClockForTest(func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now })
	h2.SetHubMailSenderForTest(func(context.Context, string, string, string) error { return nil })
	if _, err := h2.StartEmailVerification(ctx, "alice"); statusOf(err) != 429 {
		t.Errorf("alice after a restart = %v", err)
	}
	c.v.setEmail("alice.new@example.org")
	if _, err := h2.StartEmailVerification(ctx, "alice"); statusOf(err) != 429 {
		t.Errorf("alice's person limit after a restart = %v", err)
	}
	c.advance(time.Hour + time.Second)
	if _, err := h2.StartEmailVerification(ctx, "bob"); err != nil {
		t.Errorf("an hour later = %v", err)
	}
	// Past a day nothing is kept.
	c.advance(25 * time.Hour)
	if _, err := h2.StartEmailVerification(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	h2.mu.RLock()
	n := len(h2.st.EmailCodeSends)
	h2.mu.RUnlock()
	if n != 2 {
		t.Errorf("%d keys kept a day later, want carol's 2", n)
	}
}

// TestCodeExhaustedAudited (fix round 1): the fifth wrong entry is
// audited user.email_code_exhausted, never with the code.
func TestCodeExhaustedAudited(t *testing.T) {
	c := newCodeFixture(t)
	if _, err := c.h.StartEmailVerification(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	code := c.lastCode(t)
	for i := 0; i < 5; i++ {
		c.h.ConfirmEmailVerification(context.Background(), "alice", wrong(code))
	}
	e := c.audit.last()
	if e.Action != "user.email_code_exhausted" || e.Actor != "alice" || e.Target != "alice" || e.Result != "ok" {
		t.Errorf("audit %+v", e)
	}
	for _, x := range c.audit.entries {
		if strings.Contains(x.Detail+x.Error, code) || strings.Contains(x.Detail+x.Error, wrong(code)) {
			t.Errorf("a code in the audit: %+v", x)
		}
	}
}
