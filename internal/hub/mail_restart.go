package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/runtime"
)

// The session reset (contract §19.6): a server may keep authenticated
// sessions alive through a revocation, so after every removal and every
// revoked mail password the Hub restarts the wired provider's declared
// sessions.restart service (one service of its own project; the Hub
// restarts no core container); requests within one restart's time share
// one restart.

const (
	// mailRestartGrace is the stop timeout (POST …/restart?t=2).
	mailRestartGrace = 2 * time.Second
	// mailRestartTimeout bounds one restart.
	mailRestartTimeout = 30 * time.Second
	// OpMailRestart is the op record of a restart (key opKeyMail).
	OpMailRestart = "mail_restart"
	// opKeyMail is mail's op record key.
	opKeyMail = "_mail"
)

// restartMailProvider restarts the wired provider's sessions.restart
// service through the runtime's narrow verb (exactly one container of
// project portcullis-<instance> and that service, not a one-off; zero or
// several matches restart nothing). Never under Kubernetes.
func (h *Hub) restartMailProvider(ctx context.Context) error {
	if h.rt == nil {
		return errors.New("no container runtime")
	}
	if h.rt.Kind() == runtime.KindKubernetes {
		return runtime.ErrUnsupported
	}
	h.mu.RLock()
	t, m := h.mailWiredLocked()
	var project, service string
	if t != nil {
		project, service = projectName(t.ID), m.Sessions.Restart
	}
	h.mu.RUnlock()
	if t == nil {
		return errMailNotWired
	}
	return h.rt.RestartService(ctx, project, service, mailRestartGrace)
}

// sharedRestart runs restarts one at a time: a request while one runs
// joins the next one (which starts after it: the running restart may
// have begun before the request's change), and every request waiting for
// that next one shares it.
type sharedRestart struct {
	mu   sync.Mutex
	cur  *restartRun
	next *restartRun
}

type restartRun struct {
	done chan struct{}
	err  error
}

func (s *sharedRestart) do(ctx context.Context, run func() error) error {
	s.mu.Lock()
	var r *restartRun
	start := false
	if s.cur == nil {
		r = &restartRun{done: make(chan struct{})}
		s.cur, start = r, true
	} else {
		if s.next == nil {
			s.next = &restartRun{done: make(chan struct{})}
		}
		r = s.next
	}
	s.mu.Unlock()
	if start {
		go s.loop(r, run)
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *sharedRestart) loop(r *restartRun, run func() error) {
	for r != nil {
		r.err = safeRun(run)
		close(r.done)
		s.mu.Lock()
		s.cur, s.next = s.next, nil
		r = s.cur
		s.mu.Unlock()
	}
}

// mailRestart restarts the provider's sessions (shared), records the outcome (op
// mail_restart) and logs a failure. why names the cause (never a secret).
func (h *Hub) mailRestart(ctx context.Context, why string) error {
	err := h.mailRestarts.do(ctx, func() error {
		rctx, cancel := context.WithTimeout(context.Background(), mailRestartTimeout)
		defer cancel()
		return h.restartMailProvider(rctx)
	})
	if err != nil {
		h.mu.RLock()
		held := h.st.Mail.Held != nil
		h.mu.RUnlock()
		if held {
			h.mailStopHeld("a session reset: " + err.Error()) // R-HH1
		}
	}
	rec := OpRecord{Op: OpMailRestart, At: h.mailNow(), OK: err == nil}
	if err != nil {
		rec.Error = "restarting mail after " + why + " failed: " + err.Error() + ": mail sessions may still be open"
		log.Printf("mail: %s", rec.Error)
	}
	h.recordOp(opKeyMail, rec)
	return err
}

// MailRestartFailed: the last restart of mail failed (doctor
// mail_rate_held's "mail sessions may still be open").
func (h *Hub) MailRestartFailed() (bool, string) {
	r := h.LastOp(opKeyMail)
	if r == nil || r.OK {
		return false, ""
	}
	return true, r.Error
}

// prefixStrings renders prefixes.
func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// safeRun runs f; a panic is an error (a restart never takes the Hub
// down).
func safeRun(f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("restart failed: %v", p)
		}
	}()
	return f()
}
