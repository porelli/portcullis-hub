// Package gatelogs reads the gates' per-replica logs and wg's status on
// Kubernetes (contract §20.10): group-gate's opened log (:8091) and
// mcp-gate's access log (:8092) from each replica's read-only log port,
// paged with the exclusive cursor and merged by time, then replica; wg's
// status document from :8093. A replica that can't be read marks the
// result incomplete (*Incomplete, returned with what was read). On Docker
// and Podman nothing here is used: the Hub reads the files
// (HUB_GATE_LOG_SOURCES unset).
//
// Every request is a GET through fsutil.Do (the write fence's transport:
// reads pass while the Hub stands by, contract §20.5).
package gatelogs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// The ports and limits of contract §20.10.
const (
	GroupGatePort = 8091
	MCPGatePort   = 8092
	WGStatusPort  = 8093

	// MaxAnswer is the most one answer may hold (4 MiB): a longer one is
	// refused and its replica counts as unreadable.
	MaxAnswer = 4 << 20
	// PageLimit is the limit every page asks for (the contract's maximum).
	PageLimit = 10000
)

// Defaults of one read.
const (
	// DefaultMaxPages bounds the pages one read takes per replica; past
	// it the replica's part is incomplete.
	DefaultMaxPages = 64
	// DefaultBudget is the bytes one read fetches over all its replicas
	// (the Docker path's OpenedTotalScan, 64 MiB) when the query names no
	// Budget of its own.
	DefaultBudget = 64 << 20
	// Skew is how far past a window's end a line's time may be before the
	// read of that replica stops early (lines are in time order up to a
	// few seconds' skew, §20.10).
	Skew = 5 * time.Minute
	// RestartBack is how far before the last line's time a 410
	// cursor_expired restart begins (the gates' queued writes may put a
	// line after the cursor with an earlier time); the lines served again
	// are dropped.
	RestartBack = 10 * time.Second
	// maxRestarts bounds the 410 restarts per replica and read.
	maxRestarts = 3
	// requestTimeout bounds one request (the servers' own deadline is
	// 30 s per connection).
	requestTimeout = 30 * time.Second
)

// Replica is one pod of a gate: its name (the merge's tie-break and the
// key of its state) and address (its pod IP; "" = not readable now: not
// running, terminating, failed, or an expected ordinal with no pod).
type Replica struct {
	Name string
	Addr string
}

// Lister lists a gate's replicas (the Hub's pods list in the core
// namespace, contract §6 / §20.10).
type Lister func(ctx context.Context) ([]Replica, error)

// Replicas is one gate's replicas: Service the gate (its component
// label, e.g. "group-gate"), Port its log port, Lister its pods, Client
// the HTTP client (nil: a plain one without proxies), MaxPages the
// per-replica page budget of one read (0: DefaultMaxPages).
type Replicas struct {
	Service  string
	Port     int
	Lister   Lister
	Client   *http.Client
	MaxPages int
}

// Query is one read: the lines with From <= time (To zero = no end;
// with To set a replica's read stops once its lines pass To + Skew, and
// lines past it are dropped) that Keep accepts (nil: all). Budget bounds
// the bytes fetched (nil: a fresh DefaultBudget); share one across reads
// to bound them together.
type Query struct {
	From, To time.Time
	Keep     func(line []byte) bool
	Budget   *Budget
}

// Source is a merged log: Query's lines from every replica, merged by
// time then replica. A *Incomplete error comes with the lines that could
// be read; any other error with none.
type Source interface {
	Read(ctx context.Context, q Query) ([]byte, error)
}

// Budget is a byte budget over the answers fetched (every replica's,
// every page's): past Max, reads stop (*Incomplete with OverBudget).
type Budget struct {
	max  int64
	used atomic.Int64
}

// NewBudget is a budget of max bytes.
func NewBudget(max int64) *Budget { return &Budget{max: max} }

// take counts n fetched bytes: false once the budget is spent.
func (b *Budget) take(n int) bool { return b.used.Add(int64(n)) <= b.max }

// Spent: nothing more may be fetched.
func (b *Budget) Spent() bool { return b.used.Load() >= b.max }

// Incomplete is the error of a read that missed at least one replica (or
// found none), or stopped at its budget: the lines returned with it are
// what was read. Unread names the replicas (pod names) that couldn't be
// read, Listed how many were listed (0: none, or the list failed),
// OverBudget whether the byte budget stopped a replica's read.
type Incomplete struct {
	Service    string
	Unread     []string
	Listed     int
	OverBudget bool
	Why        string
}

func (e *Incomplete) Error() string {
	if len(e.Unread) == 0 {
		return fmt.Sprintf("%s: incomplete: %s", e.Service, e.Why)
	}
	return fmt.Sprintf("%s: incomplete: %s unreadable: %s", e.Service, strings.Join(e.Unread, ", "), e.Why)
}

// NoneRead: not one replica was read.
func (e *Incomplete) NoneRead() bool { return e.Listed == 0 || len(e.Unread) >= e.Listed }

// IsIncomplete reports whether err is (or wraps) an *Incomplete.
func IsIncomplete(err error) bool {
	var inc *Incomplete
	return errors.As(err, &inc)
}

var _ Source = Replicas{}

// plainClient: no proxy (in-cluster pod addresses), no keep-alive (the
// servers answer one request per connection), no redirect. Its dial has
// no timeout of its own (a custom dialer would be an unlisted external
// writer to fsutil's scan): a SYN to a dead pod address is bounded by
// Client.Timeout and the caller's context (5–30 s).
var plainClient = &http.Client{Transport: &http.Transport{
	Proxy:                  nil,
	DisableKeepAlives:      true,
	ResponseHeaderTimeout:  requestTimeout,
	MaxResponseHeaderBytes: 16 << 10,
}, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (r Replicas) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return plainClient
}

func (r Replicas) maxPages() int {
	if r.MaxPages > 0 {
		return r.MaxPages
	}
	return DefaultMaxPages
}

// list is the replicas sorted by name.
func (r Replicas) list(ctx context.Context) ([]Replica, error) {
	if r.Lister == nil {
		return nil, errors.New("no replica lister")
	}
	reps, err := r.Lister(ctx)
	if err != nil {
		return nil, err
	}
	reps = append([]Replica(nil), reps...)
	sort.Slice(reps, func(i, j int) bool { return reps[i].Name < reps[j].Name })
	return reps, nil
}

// Read is Source.Read over every replica, concurrently.
func (r Replicas) Read(ctx context.Context, q Query) ([]byte, error) {
	if q.Budget == nil {
		q.Budget = NewBudget(DefaultBudget)
	}
	reps, err := r.list(ctx)
	if err != nil {
		return nil, &Incomplete{Service: r.Service, Why: "its replicas can't be listed: " + err.Error()}
	}
	if len(reps) == 0 {
		return nil, &Incomplete{Service: r.Service, Why: "no replica is running"}
	}
	parts := make([][]byte, len(reps))
	errs := make([]error, len(reps))
	var wg sync.WaitGroup
	for i, rep := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parts[i], errs[i] = r.scan(ctx, rep, q)
		}()
	}
	wg.Wait()
	return Merge(parts), r.incomplete(reps, errs)
}

// incomplete is the read's *Incomplete (nil when every replica was read
// whole): the replicas that failed are Unread; a budget stop only sets
// OverBudget.
func (r Replicas) incomplete(reps []Replica, errs []error) error {
	var unread, whys []string
	over := false
	for i, e := range errs {
		switch {
		case e == nil:
		case errors.Is(e, errBudget):
			over = true
			whys = append(whys, reps[i].Name+": "+e.Error())
		default:
			unread = append(unread, reps[i].Name)
			whys = append(whys, e.Error())
		}
	}
	if len(unread) == 0 && !over {
		return nil
	}
	return &Incomplete{Service: r.Service, Unread: unread, Listed: len(reps), OverBudget: over, Why: strings.Join(whys, "; ")}
}

// cursorRe is a cursor as the Hub accepts it back (opaque, URL-safe).
var cursorRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// errExpired is a 410 cursor_expired; errBudget a read stopped at its
// byte budget.
var (
	errExpired = errors.New("cursor_expired")
	errBudget  = errors.New("the read's byte budget ran out")
)

// page is one /v1/log answer.
type page struct {
	body      []byte
	next      string
	truncated bool
}

// fetch asks rep for one page: at cursor when it is set, else from (zero:
// the start of the log). 410 is errExpired; 503 busy, 500 and anything
// else unexpected are errors (the replica is unreadable this time). The
// answer's bytes count against b: past it, the page is returned with
// errBudget.
func (r Replicas) fetch(ctx context.Context, rep Replica, cursor string, from time.Time, b *Budget) (page, error) {
	if rep.Addr == "" {
		return page{}, errors.New("not readable (no running pod)")
	}
	if b != nil && b.Spent() {
		return page{}, errBudget
	}
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	} else if !from.IsZero() {
		// Whole seconds, rounded down: never past a line at from.
		q.Set("from", from.UTC().Truncate(time.Second).Format(time.RFC3339))
	}
	q.Set("limit", strconv.Itoa(PageLimit))
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(rep.Addr, strconv.Itoa(r.Port)), Path: "/v1/log", RawQuery: q.Encode()}
	body, h, err := r.get(ctx, u.String())
	if err != nil {
		return page{}, err
	}
	next := h.Get("X-Portcullis-Next")
	if !cursorRe.MatchString(next) {
		return page{}, errors.New("an answer without a valid X-Portcullis-Next")
	}
	var truncated bool
	switch h.Get("X-Portcullis-Truncated") {
	case "true":
		truncated = true
	case "false":
	default:
		return page{}, errors.New("an answer without a valid X-Portcullis-Truncated")
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		return page{}, errors.New("an answer that doesn't end with a whole line")
	}
	pg := page{body: body, next: next, truncated: truncated}
	if b != nil && !b.take(len(body)) {
		return pg, errBudget
	}
	return pg, nil
}

// statusError is a non-200 answer.
type statusError struct {
	code int
	text string
}

func (e *statusError) Error() string {
	if e.text != "" {
		return fmt.Sprintf("answered %d %s", e.code, e.text)
	}
	return fmt.Sprintf("answered %d", e.code)
}

// get is one GET (through the write fence's transport, fsutil.Do): the
// body of a 200, at most MaxAnswer bytes (a longer answer is an error).
func (r Replicas) get(ctx context.Context, u string) ([]byte, http.Header, error) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := fsutil.Do(r.client(), req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		text := strings.TrimSpace(string(b))
		if !reShort.MatchString(text) {
			text = ""
		}
		if resp.StatusCode == http.StatusGone && text == "cursor_expired" {
			return nil, nil, errExpired
		}
		return nil, nil, &statusError{code: resp.StatusCode, text: text}
	}
	if resp.ContentLength > MaxAnswer {
		return nil, nil, fmt.Errorf("an answer of %d bytes: over the 4 MiB cap", resp.ContentLength)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > MaxAnswer {
		return nil, nil, errors.New("an answer over the 4 MiB cap")
	}
	return b, resp.Header, nil
}

// reShort: an error body worth logging (a short token, never data).
var reShort = regexp.MustCompile(`^[a-z_]{1,32}$`)

// lineTime is a line's "time" (zero when it has none).
func lineTime(line []byte) time.Time {
	var v struct {
		Time string `json:"time"`
	}
	if json.Unmarshal(line, &v) != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, v.Time)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// lineKey is a line's dedupe key (a hash: no copy of the line is held).
type lineKey [sha256.Size]byte

func keyOf(l []byte) lineKey { return sha256.Sum256(l) }

// again counts the lines a 410 restart may serve a second time: those
// in kept whose time is at or after from (its whole second). Each is
// dropped once when it comes again.
func again(kept [][]byte, from time.Time) map[lineKey]int {
	m := map[lineKey]int{}
	from = from.Truncate(time.Second)
	for _, l := range kept {
		if !lineTime(l).Before(from) {
			m[keyOf(l)]++
		}
	}
	return m
}

// restartFrom is where a 410 restart begins: RestartBack before the last
// line's time, never before the read's own from.
func restartFrom(last, from time.Time) time.Time {
	t := last.Add(-RestartBack)
	if t.Before(from) {
		return from
	}
	return t
}

// scan reads rep's lines from q.From on, page by page with the cursor
// until an answer isn't truncated (or, with q.To set, a page's last line
// is past To + Skew): the lines q.Keep accepts with From <= time (and
// time <= To + Skew), in file order. A 410 restarts RestartBack before
// the last line's time with from; the lines it serves a second time are
// dropped (counted: the gate's own identical lines stay).
func (r Replicas) scan(ctx context.Context, rep Replica, q Query) ([]byte, error) {
	var out [][]byte
	cursor, last := "", q.From
	from := q.From // the next fetch's from, when there is no cursor
	restarts := 0
	var dup map[lineKey]int
	for pages := 0; ; pages++ {
		if pages == r.maxPages() {
			return join(out), errors.New("its log is longer than the read's page budget")
		}
		pg, err := r.fetch(ctx, rep, cursor, from, q.Budget)
		if errors.Is(err, errExpired) && cursor != "" {
			if restarts++; restarts > maxRestarts {
				return join(out), errors.New("its cursor kept expiring")
			}
			from = restartFrom(last, q.From)
			cursor, dup = "", again(out, from)
			continue
		}
		if err != nil && (!errors.Is(err, errBudget) || pg.next == "") {
			return join(out), err
		}
		lines := splitLines(pg.body)
		for _, l := range lines {
			if q.Keep != nil && !q.Keep(l) {
				continue
			}
			t := lineTime(l)
			if t.Before(q.From) || !q.To.IsZero() && t.After(q.To.Add(Skew)) {
				continue
			}
			if dup != nil {
				if k := keyOf(l); dup[k] > 0 {
					dup[k]--
					continue
				}
			}
			out = append(out, append([]byte(nil), l...))
		}
		if err != nil { // the budget: this page is in, nothing more
			return join(out), err
		}
		if n := len(lines); n > 0 {
			if t := lineTime(lines[n-1]); !t.IsZero() {
				last = t
			}
			if !q.To.IsZero() && last.After(q.To.Add(Skew)) {
				return join(out), nil
			}
		}
		if !pg.truncated {
			return join(out), nil
		}
		if len(lines) == 0 && pg.next == cursor {
			return join(out), errors.New("its log port made no progress")
		}
		cursor = pg.next
	}
}

// splitLines is a body's lines (each without its newline; empty ones
// dropped).
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			i = len(b)
		}
		if l := b[:i]; len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
		b = b[min(i+1, len(b)):]
	}
	return out
}

func join(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// ── wg's status ───────────────────────────────────────────

// StatusSource is wg's status document (GET /v1/status on :8093): the
// bytes the Hub reads from HUB_VPN_STATUS_FILE on Docker.
type StatusSource interface {
	Status(ctx context.Context) ([]byte, error)
}

var _ StatusSource = Replicas{}

// Status is the status of wg's replica (with several, during a rollout,
// the one whose document was written last), asked concurrently. An error
// when none answers.
func (r Replicas) Status(ctx context.Context) ([]byte, error) {
	reps, err := r.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: its replicas can't be listed: %w", r.Service, err)
	}
	bodies := make([][]byte, len(reps))
	errs := make([]error, len(reps))
	var wg sync.WaitGroup
	for i, rep := range reps {
		if rep.Addr == "" {
			errs[i] = errors.New("not readable (no running pod)")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := url.URL{Scheme: "http", Host: net.JoinHostPort(rep.Addr, strconv.Itoa(r.Port)), Path: "/v1/status"}
			bodies[i], _, errs[i] = r.get(ctx, u.String())
		}()
	}
	wg.Wait()
	var best []byte
	var bestAt time.Time
	var msgs []string
	for i, b := range bodies {
		if errs[i] != nil {
			msgs = append(msgs, reps[i].Name+": "+errs[i].Error())
			continue
		}
		var v struct {
			Written time.Time `json:"written"`
		}
		_ = json.Unmarshal(b, &v)
		if best == nil || v.Written.After(bestAt) {
			best, bestAt = b, v.Written
		}
	}
	if best != nil {
		return best, nil
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%s: no replica is running", r.Service)
	}
	return nil, fmt.Errorf("%s: %s", r.Service, strings.Join(msgs, "; "))
}
