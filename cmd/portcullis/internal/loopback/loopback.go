// Package loopback is the CLI's one-shot OAuth redirect listener
// (contract §18.15): 127.0.0.1:38917, then 38918, then 38919 — never
// 0.0.0.0 or localhost. It accepts exactly one GET /callback with the
// right state; anything else is 404. The code never reaches a log.
package loopback

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// Timeout is how long the CLI waits for the browser.
const Timeout = 5 * time.Minute

// page is the browser's answer: static, no script.
const page = `<!doctype html><html><head><meta charset="utf-8"><title>Portcullis</title></head><body><p>You can close this tab.</p></body></html>`

// ErrPortsTaken: all three loopback ports are in use.
var ErrPortsTaken = errors.New("ports 38917, 38918 and 38919 on 127.0.0.1 are all in use: close the program using them (another portcullis login?) and try again")

// ErrTimeout: the browser never came back.
var ErrTimeout = errors.New("no sign-in arrived within 5 minutes (was the browser opened on another machine?): run portcullis login again")

// SignInError is an error= callback (the sign-in was refused or
// cancelled). Its text is the OAuth error code only, never a description
// the redirect carried.
type SignInError struct{ Code string }

func (e *SignInError) Error() string { return "the sign-in didn't complete (" + e.Code + ")" }

// Listener is a bound loopback listener.
type Listener struct {
	ln   net.Listener
	srv  *http.Server
	port int
	mu   sync.Mutex
	done bool
	want string
	res  chan result
}

type result struct {
	code string
	err  error
}

// Ports is the order tried (a var for tests).
var Ports = cliapi.RedirectPorts[:]

// Listen binds the first free port of Ports on 127.0.0.1.
func Listen(ctx context.Context) (*Listener, error) {
	var lc net.ListenConfig
	for _, p := range Ports {
		ln, err := lc.Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		l := &Listener{ln: ln, port: p, res: make(chan result, 1)}
		l.srv = &http.Server{Handler: http.HandlerFunc(l.serve), ReadHeaderTimeout: 10 * time.Second}
		go l.srv.Serve(ln)
		return l, nil
	}
	return nil, ErrPortsTaken
}

// Port is the bound port.
func (l *Listener) Port() int { return l.port }

// RedirectURI is the redirect URI of the bound port.
func (l *Listener) RedirectURI() string { return cliapi.RedirectURI(l.port) }

// Wait waits for the one callback carrying state and returns its code;
// the listener is closed afterwards whatever happens.
func (l *Listener) Wait(ctx context.Context, state string) (string, error) {
	l.mu.Lock()
	l.want = state
	l.mu.Unlock()
	defer l.Close()
	timer := time.NewTimer(Timeout)
	defer timer.Stop()
	select {
	case r := <-l.res:
		return r.code, r.err
	case <-timer.C:
		return "", ErrTimeout
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close stops the listener.
func (l *Listener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = l.srv.Shutdown(ctx)
}

func (l *Listener) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet || r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	l.mu.Lock()
	want, done := l.want, l.done
	ok := !done && want != "" && subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(want)) == 1 && len(q["state"]) == 1
	if ok {
		l.done = true
	}
	l.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	var res result
	switch {
	case q.Get("error") != "":
		res.err = &SignInError{Code: safeCode(q.Get("error"))}
	case q.Get("code") == "" || len(q.Get("code")) > 4096:
		res.err = errors.New("the sign-in came back without a code")
	default:
		res.code = q.Get("code")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	fmt.Fprint(w, page)
	l.res <- res
}

// safeCode keeps an OAuth error code's characters (RFC 6749 §4.1.2.1).
func safeCode(s string) string {
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			out = append(out, c)
		}
		if len(out) == 64 {
			break
		}
	}
	return string(out)
}
