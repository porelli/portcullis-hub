package gatelogs

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

// Merge is the replicas' parts (one per replica, in replica order, each
// JSONL in its file order) as one stream: stable by time, then replica
// (equal times keep the replica order, and each replica's file order).
// Every line is kept: the lines a 410 restart serves a second time are
// dropped by the reads themselves (scan, Tail), counted, so a gate's own
// identical lines stay. A line without a time sorts first.
func Merge(parts [][]byte) []byte {
	type ln struct {
		t   time.Time
		rep int
		b   []byte
	}
	var all []ln
	for i, p := range parts {
		for _, l := range splitLines(p) {
			all = append(all, ln{lineTime(l), i, l})
		}
	}
	slices.SortStableFunc(all, func(a, b ln) int {
		if c := a.t.Compare(b.t); c != 0 {
			return c
		}
		return a.rep - b.rep
	})
	lines := make([][]byte, len(all))
	for i, l := range all {
		lines[i] = l.b
	}
	return join(lines)
}

// ── the access log's tail ─────────────────────────────────

// Tail defaults.
const (
	// DefaultFirstWindow is how far back the first fill of a replica
	// starts; it widens ×4 while the replica holds less than Max bytes
	// of lines, up to DefaultRetention.
	DefaultFirstWindow = time.Hour
	// DefaultRetention is the access log's retention (mcp-gate prunes
	// lines older than 90 days): the widest the first fill goes.
	DefaultRetention = 90 * 24 * time.Hour
	// TailGrace is how long a replica's state is kept while it isn't
	// listed (a pod between delete and re-create keeps its cursor).
	TailGrace = time.Hour
)

// Tail follows each replica's log and keeps its newest Max bytes of
// lines (the 4 MiB Docker's Hub reads of the end of the file, contract
// §15.8), so a read only fetches what was appended since the last one.
// The first fill of a replica starts FirstWindow back and widens
// backward (×4) until it holds Max bytes or reaches Retention; until then
// every read is *Incomplete ("catching up"). Its zero value is not
// usable: R is required; Max 0 is MaxAnswer, FirstWindow 0
// DefaultFirstWindow, Retention 0 DefaultRetention, Now nil time.Now.
type Tail struct {
	R           Replicas
	Max         int
	FirstWindow time.Duration
	Retention   time.Duration
	Now         func() time.Time

	once sync.Once
	sem  chan struct{} // one read at a time; a waiter can give up

	mu   sync.Mutex // per and snap
	per  map[string]*tailState
	snap []byte // the last read's merged lines
}

// tailState is one replica's position and kept lines.
type tailState struct {
	cursor  string
	last    time.Time // the last line served's time (a 410 restarts near it)
	lines   [][]byte
	size    int
	listed  time.Time // when it was last listed
	started bool      // the first fill's newest part is in (cursor set)
	t0      time.Time // when the first fill began
	anchor  time.Time // the oldest from the fill has read from
	window  time.Duration
	filled  bool // holds Max bytes, or reaches back Retention
	// restart: a 410 restart pending (from), and the kept lines it may
	// serve again (dup), kept across reads until the scan reaches the end.
	restart time.Time
	dup     map[lineKey]int
}

func (t *Tail) max() int {
	if t.Max > 0 {
		return t.Max
	}
	return MaxAnswer
}

func (t *Tail) now() time.Time {
	if t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}

func (t *Tail) firstWindow() time.Duration {
	if t.FirstWindow > 0 {
		return t.FirstWindow
	}
	return DefaultFirstWindow
}

func (t *Tail) retention() time.Duration {
	if t.Retention > 0 {
		return t.Retention
	}
	return DefaultRetention
}

// errCatchingUp: a replica's first fill hasn't reached Max bytes or the
// retention yet.
var errCatchingUp = errors.New("still reading its log back (catching up)")

// Read is every replica's tail merged (Merge); *Incomplete with what was
// read when a replica couldn't be followed this time (its earlier lines
// are still in the answer), is still catching up, or when there is none.
// A read waiting for another one that ctx ends answers the last read's
// lines, *Incomplete.
func (t *Tail) Read(ctx context.Context) ([]byte, error) {
	t.once.Do(func() { t.sem = make(chan struct{}, 1) })
	select {
	case t.sem <- struct{}{}:
	case <-ctx.Done():
		t.mu.Lock()
		snap := t.snap
		t.mu.Unlock()
		return snap, &Incomplete{Service: t.R.Service, Why: "another read of the log is in progress"}
	}
	defer func() { <-t.sem }()
	reps, err := t.R.list(ctx)
	if err != nil {
		return nil, &Incomplete{Service: t.R.Service, Why: "its replicas can't be listed: " + err.Error()}
	}
	now := t.now()
	t.mu.Lock()
	if t.per == nil {
		t.per = map[string]*tailState{}
	}
	listed := map[string]bool{}
	for _, rep := range reps {
		listed[rep.Name] = true
		st := t.per[rep.Name]
		if st == nil {
			st = &tailState{}
			t.per[rep.Name] = st
		}
		st.listed = now
	}
	// A replica not listed keeps its state for TailGrace (its lines are
	// shown, and it counts as unread).
	var gone []string
	for name, st := range t.per {
		if listed[name] {
			continue
		}
		if now.Sub(st.listed) > TailGrace {
			delete(t.per, name)
			continue
		}
		gone = append(gone, name)
	}
	t.mu.Unlock()
	slices.Sort(gone)
	if len(reps) == 0 && len(gone) == 0 {
		return nil, &Incomplete{Service: t.R.Service, Why: "no replica is running"}
	}
	budget := NewBudget(DefaultBudget)
	errs := make([]error, len(reps))
	var wg sync.WaitGroup
	for i, rep := range reps {
		st := t.per[rep.Name] // only this goroutine touches st
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = t.follow(ctx, rep, st, budget, now)
		}()
	}
	wg.Wait()
	for _, g := range gone {
		reps = append(reps, Replica{Name: g})
		errs = append(errs, errors.New("not listed"))
	}
	parts := make([][]byte, len(reps))
	t.mu.Lock()
	for i, r := range reps {
		parts[i] = join(t.per[r.Name].lines)
	}
	out := Merge(parts)
	t.snap = out
	t.mu.Unlock()
	var unread, whys []string
	for i, e := range errs {
		if e != nil {
			unread = append(unread, reps[i].Name)
			whys = append(whys, reps[i].Name+": "+e.Error())
		}
	}
	if len(unread) > 0 {
		return out, &Incomplete{Service: t.R.Service, Unread: unread, Listed: len(reps), Why: strings.Join(whys, "; ")}
	}
	return out, nil
}

// follow brings st up to date: the first fill (from FirstWindow back),
// then forward from its cursor until an answer isn't truncated, then the
// fill widened backward while it is short. errCatchingUp until filled.
func (t *Tail) follow(ctx context.Context, rep Replica, st *tailState, b *Budget, now time.Time) error {
	if !st.started {
		st.t0, st.window = now, t.firstWindow()
		st.anchor = now.Add(-st.window).Truncate(time.Second)
		st.cursor, st.restart, st.dup = "", time.Time{}, nil
		st.lines, st.size = nil, 0
	}
	if err := t.forward(ctx, rep, st, b); err != nil {
		if !st.filled {
			return errors.Join(errCatchingUp, err)
		}
		return err
	}
	for !st.filled {
		if st.size >= t.max() || st.t0.Sub(st.anchor) >= t.retention() {
			st.filled = true
			break
		}
		older := st.t0.Add(-4 * st.window).Truncate(time.Second)
		if st.t0.Sub(older) > t.retention() {
			older = st.t0.Add(-t.retention()).Truncate(time.Second)
		}
		until := st.anchor
		part, err := t.R.scan(ctx, rep, Query{From: older, To: until, Budget: b,
			Keep: func(l []byte) bool { return lineTime(l).Before(until) }})
		if err != nil {
			return errors.Join(errCatchingUp, err)
		}
		ls := splitLines(part)
		n := 0
		for _, l := range ls {
			n += len(l) + 1
		}
		st.lines = append(ls, st.lines...)
		st.size += n
		st.anchor, st.window = older, 4*st.window
		t.trim(st)
	}
	return nil
}

// forward pages st on from its cursor (from its anchor at first, or from
// a pending restart) until an answer isn't truncated. A 410 sets a
// restart RestartBack before the last line's time with from; the kept
// lines it serves again are dropped (counted), across reads if need be.
func (t *Tail) forward(ctx context.Context, rep Replica, st *tailState, b *Budget) error {
	restarts := 0
	for pages := 0; pages < t.R.maxPages(); pages++ {
		from := st.anchor
		if !st.restart.IsZero() {
			from = st.restart
		}
		pg, err := t.R.fetch(ctx, rep, st.cursor, from, b)
		if errors.Is(err, errExpired) && st.cursor != "" {
			if restarts++; restarts > maxRestarts {
				return errors.New("its cursor kept expiring")
			}
			st.restart = restartFrom(st.last, st.anchor)
			st.cursor, st.dup = "", again(st.lines, st.restart)
			continue
		}
		if err != nil && (!errors.Is(err, errBudget) || pg.next == "") {
			return err
		}
		lines := splitLines(pg.body)
		for _, l := range lines {
			if st.dup != nil {
				if k := keyOf(l); st.dup[k] > 0 {
					st.dup[k]--
					continue
				}
			}
			if !st.started && lineTime(l).Before(st.anchor) {
				continue
			}
			st.lines = append(st.lines, append([]byte(nil), l...))
			st.size += len(l) + 1
		}
		if n := len(lines); n > 0 {
			if lt := lineTime(lines[n-1]); !lt.IsZero() {
				st.last = lt
			}
		}
		t.trim(st)
		progress := len(lines) > 0 || pg.next != st.cursor
		st.cursor, st.restart, st.started = pg.next, time.Time{}, true
		if err != nil {
			return err // the budget: read on next time
		}
		if !pg.truncated {
			st.dup = nil // past every line a restart could serve again
			return nil
		}
		if !progress {
			return errors.New("its log port made no progress")
		}
	}
	return errors.New("its log is longer than the read's page budget (read on next time)")
}

// trim drops st's oldest lines past Max bytes (the fill is then done).
func (t *Tail) trim(st *tailState) {
	drop := 0
	for st.size > t.max() && drop < len(st.lines) {
		st.size -= len(st.lines[drop]) + 1
		drop++
	}
	if drop > 0 {
		st.lines = append([][]byte(nil), st.lines[drop:]...)
		st.filled = st.filled || st.started
	}
}
