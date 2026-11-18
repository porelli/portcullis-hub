package hub

// Rate limits of the CLI's signing routes (contract §18.5, plan C20):
// refusals 10 a minute per address and per person, successful signings 6
// a minute per person. golang.org/x/time/rate; idle limiters are dropped
// after 10 minutes.

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	sshRefusalsPerMinute = 10
	sshSigningsPerMinute = 6
	sshLimiterIdle       = 10 * time.Minute
)

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// keyedLimiter is one rate.Limiter per key.
type keyedLimiter struct {
	mu     sync.Mutex
	perMin int
	m      map[string]*limiterEntry
	swept  time.Time
}

func (k *keyedLimiter) get(key string, now time.Time) *rate.Limiter {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]*limiterEntry{}
	}
	if now.Sub(k.swept) > time.Minute {
		for key, e := range k.m {
			if now.Sub(e.seen) > sshLimiterIdle {
				delete(k.m, key)
			}
		}
		k.swept = now
	}
	e := k.m[key]
	if e == nil {
		e = &limiterEntry{l: rate.NewLimiter(rate.Every(time.Minute/time.Duration(k.perMin)), k.perMin)}
		k.m[key] = e
	}
	e.seen = now
	return e.l
}

// sshLimits are the three limiters.
type sshLimits struct {
	byAddr, byUser, signings keyedLimiter
	once                     sync.Once
}

func (s *sshLimits) init() {
	s.once.Do(func() {
		s.byAddr.perMin, s.byUser.perMin, s.signings.perMin = sshRefusalsPerMinute, sshRefusalsPerMinute, sshSigningsPerMinute
	})
}

// addrBlocked reports whether addr has used up its refusals (no token taken).
func (s *sshLimits) addrBlocked(addr string, now time.Time) bool {
	s.init()
	return s.byAddr.get(addr, now).TokensAt(now) < 1
}

// userBlocked: the same per person.
func (s *sshLimits) userBlocked(user string, now time.Time) bool {
	s.init()
	return s.byUser.get(user, now).TokensAt(now) < 1
}

// refused takes one refusal token from addr and, when known, user.
func (s *sshLimits) refused(addr, user string, now time.Time) {
	s.init()
	s.byAddr.get(addr, now).AllowN(now, 1)
	if user != "" {
		s.byUser.get(user, now).AllowN(now, 1)
	}
}

// signing takes a success token from user; false = over the limit.
func (s *sshLimits) signing(user string, now time.Time) bool {
	s.init()
	return s.signings.get(user, now).AllowN(now, 1)
}
