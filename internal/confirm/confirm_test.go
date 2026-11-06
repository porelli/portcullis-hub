package confirm

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func req(user, tool, digest string) Request {
	return Request{User: user, Client: "portcullis-ai-claude", Resource: "https://app.example.org/mcp", Tool: tool,
		ArgsSHA256: digest, ArgsPreview: `{}`, Listener: ListenerPeople, Typed: "App", Label: "App"}
}

const d1 = "1111111111111111111111111111111111111111111111111111111111111111"

var idR = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}-[A-Z2-7]{2}$`)

// TestConfirmStore: TTL 10 min (9:59 ok, 10:01 expired); single use;
// another user's id → not found; ids unique, 128 bits; the binding; the
// limits (G27).
func TestConfirmStore(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)}
	s := New(c.now)
	a, err := s.Create(req("alice", "delete_repo", d1))
	if err != nil {
		t.Fatal(err)
	}
	if !idR.MatchString(a.ID) || a.State != Pending || !a.Expires.Equal(a.Created.Add(TTL)) || TTL != 10*time.Minute {
		t.Fatalf("created %+v", a)
	}
	// Another user: not found (no oracle), with any spelling of the id.
	for _, id := range []string{a.ID, strings.ToLower(a.ID), strings.ReplaceAll(a.ID, "-", "")} {
		if _, err := s.Get(id, "bob"); !errors.Is(err, ErrNotFound) {
			t.Errorf("bob Get(%s) = %v", id, err)
		}
		if g, err := s.Get(id, "alice"); err != nil || g.ID != a.ID {
			t.Errorf("alice Get(%s) = %v %v", id, g, err)
		}
	}
	if _, err := s.Get("AAAA-BBBB", "alice"); !errors.Is(err, ErrNotFound) {
		t.Error("a malformed id found")
	}
	if err := s.Decide(a.ID, "bob", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob Decide = %v", err)
	}
	// Same binding while pending: the same confirmation.
	if again, err := s.Create(req("alice", "delete_repo", d1)); err != nil || again.ID != a.ID {
		t.Errorf("re-create = %v %v", again, err)
	}
	// Consume: pending, then approved → consumed once.
	if _, err := s.Consume("alice", a.Resource, "delete_repo", d1); !errors.Is(err, ErrPending) {
		t.Errorf("consume pending = %v", err)
	}
	c.add(9*time.Minute + 59*time.Second)
	if err := s.Decide(a.ID, "alice", true); err != nil {
		t.Fatalf("decide at 9:59: %v", err)
	}
	if err := s.Decide(a.ID, "alice", false); !errors.Is(err, ErrNotPending) {
		t.Errorf("second decide = %v", err)
	}
	for _, bad := range [][3]string{{"bob", "delete_repo", d1}, {"alice", "delete_other", d1}, {"alice", "delete_repo", strings.Repeat("2", 64)}} {
		if _, err := s.Consume(bad[0], a.Resource, bad[1], bad[2]); !errors.Is(err, ErrNotFound) {
			t.Errorf("consume %v = %v", bad, err)
		}
	}
	if _, err := s.Consume("alice", "https://other.example.org/mcp", "delete_repo", d1); !errors.Is(err, ErrNotFound) {
		t.Error("another resource consumed it")
	}
	got, err := s.Consume("alice", a.Resource, "delete_repo", d1)
	if err != nil || got.ID != a.ID || got.State != Consumed {
		t.Fatalf("consume = %+v %v", got, err)
	}
	if _, err := s.Consume("alice", a.Resource, "delete_repo", d1); !errors.Is(err, ErrNotFound) {
		t.Errorf("second consume = %v", err)
	}

	// Expiry: 10:01 after creation is expired (Get shows it, Decide and
	// Consume refuse it); the sweeper reports it once.
	b, _ := s.Create(req("alice", "delete_b", d1))
	c.add(10*time.Minute + time.Second)
	if g, _ := s.Get(b.ID, "alice"); g == nil || g.State != Expired {
		t.Errorf("expired Get = %+v", g)
	}
	if err := s.Decide(b.ID, "alice", true); !errors.Is(err, ErrNotPending) {
		t.Errorf("expired decide = %v", err)
	}
	if _, err := s.Consume("alice", b.Resource, "delete_b", d1); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired consume = %v", err)
	}
	ex := s.Sweep()
	if len(ex) != 1 || ex[0].ID != b.ID || ex[0].State != Expired {
		t.Errorf("sweep = %+v", ex)
	}
	if len(s.Sweep()) != 0 {
		t.Error("swept twice")
	}
	// A declined one consumes as declined.
	d, _ := s.Create(req("alice", "delete_d", d1))
	if err := s.Decide(d.ID, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume("alice", d.Resource, "delete_d", d1); !errors.Is(err, ErrDeclined) {
		t.Errorf("declined consume = %v", err)
	}

	// Ids: unique, 26 base32 characters (128 bits).
	s2 := New(c.now)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		u := "u" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		x, err := s2.Create(req(u, "t", d1))
		if err != nil {
			t.Fatal(err)
		}
		raw := strings.ReplaceAll(x.ID, "-", "")
		if len(raw) != 26 || seen[raw] {
			t.Fatalf("id %s", x.ID)
		}
		seen[raw] = true
	}
}

// TestConfirmLimits (G27): ≤ 10 created per person per hour, ≤ 20
// pending per person, ≤ 1000 pending in total.
func TestConfirmLimits(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)}
	s := New(c.now)
	for i := 0; i < 10; i++ {
		if _, err := s.Create(req("alice", "t"+string(rune('a'+i)), d1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Create(req("alice", "tz", d1)); !errors.Is(err, ErrTooMany) {
		t.Fatalf("11th = %v", err)
	}
	// An existing binding is still answered.
	if _, err := s.Create(req("alice", "ta", d1)); err != nil {
		t.Errorf("existing binding: %v", err)
	}
	if _, err := s.Create(req("bob", "t", d1)); err != nil {
		t.Errorf("bob: %v", err)
	}
	c.add(time.Hour + time.Second)
	if _, err := s.Create(req("alice", "tz", d1)); err != nil {
		t.Errorf("after an hour: %v", err)
	}

	// Pending per person: the hourly limit is raised for this check.
	p := New(c.now)
	p.perHour = 1000
	for i := 0; i < 20; i++ {
		if _, err := p.Create(req("alice", "p"+strings.Repeat("x", i), d1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Create(req("alice", "pz", d1)); !errors.Is(err, ErrTooMany) {
		t.Errorf("21st pending = %v", err)
	}
	// Total pending.
	g := New(c.now)
	for i := 0; i < 1000; i++ {
		u := "u" + strings.Repeat("a", i/26) + string(rune('a'+i%26))
		if _, err := g.Create(req(u, "t", d1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Create(req("newcomer", "t", d1)); !errors.Is(err, ErrTooMany) {
		t.Errorf("1001st pending = %v", err)
	}
}
