// Package confirm is the Hub's confirmation store (contract §15.6): a
// person approves, in their browser and with a fresh passkey touch, one
// call of a destructive or `confirm` tool before the AI may make it.
//
// A confirmation is bound to (person, resource, tool, args_sha256), lives
// TTL from its creation, and is used once: the first matching retry
// consumes an approved one. It is kept in memory only: a Hub restart
// expires every confirmation. The store also enforces the Hub-side
// limits (G27) over every creation path: the gate's internal API
// (companions) and the Hub's own MCP (Portcullis tools, in-process).
package confirm

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"time"
)

// Request is what a confirmation is created for. Every field is the
// Hub's own rendering of the stored call, never text the model wrote:
// Tool / Resource / ArgsSHA256 are the binding, ArgsPreview the
// arguments' canonical JSON (RFC 8785) shown on the page, Listener the
// listener whose page serves it (ListenerHub or ListenerPeople), Typed
// the typed check the page asks for, Consequences the lines the page
// shows, Label the target (an app's instance label, an instance id …).
type Request struct {
	User, Client, Resource, Tool, ArgsSHA256, ArgsPreview, Listener string
	Typed                                                           string
	Consequences                                                    []string
	Label                                                           string
}

// Confirmation is one stored confirmation (a copy: the store's own is
// never handed out).
type Confirmation struct {
	ID string // the display form: uppercase base32 in groups of four
	Request
	State            string
	Created, Expires time.Time
}

// States (§15.6). Expired is never stored by a request path: Get shows
// it once the TTL has passed, and Sweep records it (and reports it for
// the audit).
const (
	Pending, Approved, Declined, Consumed = "pending", "approved", "declined", "consumed"
	Expired                               = "expired"
)

// Listeners: the page of a confirmation is on exactly one of them.
const (
	ListenerHub    = "hub"
	ListenerPeople = "people"
)

// TTL is a confirmation's life from creation.
const TTL = 10 * time.Minute

// Limits (G27, contract §15.6).
const (
	PerHour         = 10
	PendingPerUser  = 20
	PendingTotal    = 1000
	retainAfterLife = TTL // a decided / expired one stays visible this long
)

var (
	ErrNotFound   = errors.New("no such confirmation")
	ErrPending    = errors.New("the confirmation is still pending")
	ErrDeclined   = errors.New("the confirmation was declined")
	ErrTooMany    = errors.New("Too many confirmations requested; try again later")
	ErrNotPending = errors.New("the confirmation is no longer pending")
	ErrInvalid    = errors.New("invalid confirmation request")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Store holds the confirmations in memory.
type Store struct {
	mu      sync.Mutex
	now     func() time.Time
	byID    map[string]*Confirmation // key: the 26 base32 characters
	created map[string][]time.Time   // user → creation times within the last hour
	perHour int
}

// New is an empty store on the clock now (nil: time.Now).
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, byID: map[string]*Confirmation{}, created: map[string][]time.Time{}, perHour: PerHour}
}

// normID is id's store key: dashes dropped, uppercased, exactly 26
// base32 characters (case-insensitive, with or without dashes, §15.6).
func normID(id string) (string, bool) {
	k := strings.ToUpper(strings.ReplaceAll(id, "-", ""))
	if len(k) != 26 {
		return "", false
	}
	for _, r := range k {
		if !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			return "", false
		}
	}
	return k, true
}

// display groups k by four with "-".
func display(k string) string {
	var b strings.Builder
	for i := 0; i < len(k); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(k[i:min(i+4, len(k))])
	}
	return b.String()
}

// newKey is 16 random bytes in base32, no padding.
func newKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw[:]), nil
}

// stateAt is c's state at now: pending or approved past Expires is
// expired.
func stateAt(c *Confirmation, now time.Time) string {
	if (c.State == Pending || c.State == Approved) && !now.Before(c.Expires) {
		return Expired
	}
	return c.State
}

func (s *Store) copyAt(c *Confirmation, now time.Time) *Confirmation {
	out := *c
	out.Consequences = append([]string(nil), c.Consequences...)
	out.State = stateAt(c, now)
	return &out
}

// Create stores a pending confirmation for r, or returns the pending one
// with the same binding (and listener). Over a limit: ErrTooMany.
func (s *Store) Create(r Request) (*Confirmation, error) {
	if r.User == "" || r.Resource == "" || r.Tool == "" || r.ArgsSHA256 == "" || (r.Listener != ListenerHub && r.Listener != ListenerPeople) {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	pendingUser, pendingAll := 0, 0
	for _, c := range s.byID {
		if stateAt(c, now) != Pending {
			continue
		}
		pendingAll++
		if c.User == r.User {
			pendingUser++
			if c.Resource == r.Resource && c.Tool == r.Tool && c.ArgsSHA256 == r.ArgsSHA256 && c.Listener == r.Listener {
				return s.copyAt(c, now), nil
			}
		}
	}
	hour := s.created[r.User]
	if len(hour) >= s.perHour || pendingUser >= PendingPerUser || pendingAll >= PendingTotal {
		return nil, ErrTooMany
	}
	var k string
	for {
		var err error
		if k, err = newKey(); err != nil {
			return nil, err
		}
		if s.byID[k] == nil {
			break
		}
	}
	r.Consequences = append([]string(nil), r.Consequences...)
	r.Typed = strings.TrimSpace(r.Typed)
	c := &Confirmation{ID: display(k), Request: r, State: Pending, Created: now, Expires: now.Add(TTL)}
	s.byID[k] = c
	s.created[r.User] = append(hour, now)
	return s.copyAt(c, now), nil
}

// pruneLocked forgets creation times older than an hour and decided
// confirmations past their retention. A confirmation still stored as
// pending or approved is never forgotten here, however old: Sweep records
// it as expired (and reports it for the audit) first.
func (s *Store) pruneLocked(now time.Time) {
	for u, ts := range s.created {
		i := 0
		for i < len(ts) && now.Sub(ts[i]) >= time.Hour {
			i++
		}
		if i == len(ts) {
			delete(s.created, u)
		} else if i > 0 {
			s.created[u] = append([]time.Time(nil), ts[i:]...)
		}
	}
	for k, c := range s.byID {
		if c.State != Pending && c.State != Approved && now.Sub(c.Expires) >= retainAfterLife {
			delete(s.byID, k)
		}
	}
}

// get is the stored confirmation id of user (nil: none — another
// user's is none too).
func (s *Store) getLocked(id, user string) *Confirmation {
	k, ok := normID(id)
	if !ok {
		return nil
	}
	c := s.byID[k]
	if c == nil || c.User != user {
		return nil
	}
	return c
}

// Get is user's confirmation id (any spelling); another user's, an
// unknown or a forgotten one is ErrNotFound (no oracle).
func (s *Store) Get(id, user string) (*Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getLocked(id, user)
	if c == nil {
		return nil, ErrNotFound
	}
	return s.copyAt(c, s.now()), nil
}

// Decide records user's approval or decline of a pending, unexpired
// confirmation; any other state is ErrNotPending.
func (s *Store) Decide(id, user string, approve bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.getLocked(id, user)
	if c == nil {
		return ErrNotFound
	}
	if stateAt(c, s.now()) != Pending {
		return ErrNotPending
	}
	if approve {
		c.State = Approved
	} else {
		c.State = Declined
	}
	return nil
}

// Consume uses the first approved, unexpired confirmation of listener
// matching the binding (it becomes consumed and is returned); another
// listener's confirmation is never matched (nor consumed). Else ErrPending when a
// pending one matches, ErrDeclined when a declined one does, ErrNotFound
// otherwise (the caller creates a new one).
func (s *Store) Consume(listener, user, resource, tool, digest string) (*Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var first *Confirmation
	pending, declined := false, false
	for _, c := range s.byID {
		if c.Listener != listener || c.User != user || c.Resource != resource || c.Tool != tool || c.ArgsSHA256 != digest {
			continue
		}
		switch stateAt(c, now) {
		case Approved:
			if first == nil || c.Created.Before(first.Created) {
				first = c
			}
		case Pending:
			pending = true
		case Declined:
			if !now.After(c.Expires) {
				declined = true
			}
		}
	}
	switch {
	case first != nil:
		first.State = Consumed
		return s.copyAt(first, now), nil
	case pending:
		return nil, ErrPending
	case declined:
		return nil, ErrDeclined
	}
	return nil, ErrNotFound
}

// Sweep records every pending or approved confirmation past its TTL as
// expired and returns them (for the audit: each is reported once), and
// forgets old ones.
func (s *Store) Sweep() []Confirmation {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Confirmation
	for _, c := range s.byID {
		if (c.State == Pending || c.State == Approved) && stateAt(c, now) == Expired {
			c.State = Expired
			out = append(out, *s.copyAt(c, now))
		}
	}
	s.pruneLocked(now)
	return out
}
