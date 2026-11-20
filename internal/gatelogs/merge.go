package gatelogs

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	// MinSegment: a backward segment this short that still fails without
	// progress twice ends the fill (older activity not loaded).
	MinSegment = time.Minute
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
	// The backward segment in progress, [segFrom, anchor): seg its lines
	// so far (from segFrom forward), segNext where its next fetch starts,
	// minFails its failures without progress at MinSegment or less.
	segFrom, segNext time.Time
	seg              [][]byte
	segSize          int
	minFails         int
	// olderMissing: some older activity was given up on (a segment that
	// couldn't be fetched was narrowed, or abandoned): permanent, never
	// "incomplete" (OlderNotLoaded).
	olderMissing atomic.Bool
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
		if err := t.backward(ctx, rep, st, b); err != nil {
			if st.filled {
				return nil // given up: older activity not loaded
			}
			return errors.Join(errCatchingUp, err)
		}
	}
	return nil
}

// backward reads the segment before st.anchor: [t0 − 4 × window, anchor)
// (at most back to Retention), forward from its start. A read that can't
// fetch it all (the budget, the page budget, the deadline, an error)
// keeps what it got and starts the next one after it; one that got
// nothing new halves what is left (the skipped part is older activity
// not loaded) — so no read fetches the same window as the one before.
// At MinSegment or less, a second failure without progress ends the fill
// (olderMissing). A finished segment joins the lines and moves anchor.
func (t *Tail) backward(ctx context.Context, rep Replica, st *tailState, b *Budget) error {
	if st.segFrom.IsZero() {
		older := st.t0.Add(-4 * st.window).Truncate(time.Second)
		if st.t0.Sub(older) > t.retention() {
			older = st.t0.Add(-t.retention()).Truncate(time.Second)
		}
		st.segFrom, st.segNext, st.seg, st.segSize, st.minFails = older, older, nil, 0, 0
	}
	until := st.anchor
	var dup map[lineKey]int
	if len(st.seg) > 0 {
		dup = again(st.seg, st.segNext) // the lines at segNext's second come again
	}
	part, err := t.R.scan(ctx, rep, Query{From: st.segNext, To: until, Budget: b,
		Keep: func(l []byte) bool { return lineTime(l).Before(until) }})
	added := 0
	for _, l := range splitLines(part) {
		if k := keyOf(l); dup[k] > 0 {
			dup[k]--
			continue
		}
		st.seg = append(st.seg, l)
		st.segSize += len(l) + 1
		added++
	}
	if err == nil {
		st.lines = append(st.seg, st.lines...)
		st.size += st.segSize
		st.anchor, st.window = st.segFrom, st.t0.Sub(st.segFrom)
		st.segFrom, st.segNext, st.seg, st.segSize = time.Time{}, time.Time{}, nil, 0
		t.trim(st)
		return nil
	}
	// Partly read, or not at all: never the same window next time.
	if added > 0 {
		if lt := lineTime(st.seg[len(st.seg)-1]); lt.After(st.segNext) {
			st.segNext = lt
		} else {
			st.segNext = st.segNext.Add(time.Second) // a second full of lines: on past it
			st.olderMissing.Store(true)
		}
		t.trimSeg(st)
		return err
	}
	left := until.Sub(st.segNext)
	if left <= MinSegment {
		if st.minFails++; st.minFails >= 2 || left <= time.Second {
			// Give up on what is older: the newer lines are all here.
			st.olderMissing.Store(true)
			st.filled = true
			log.Printf("%s: %s: older access log activity not loaded (a segment before %s couldn't be fetched)", t.R.Service, rep.Name, until.Format(time.RFC3339))
			st.segFrom, st.segNext, st.seg, st.segSize = time.Time{}, time.Time{}, nil, 0
			return err
		}
	}
	st.segNext = st.segNext.Add(left / 2).Truncate(time.Second)
	st.olderMissing.Store(true)
	return err
}

// trimSeg keeps the segment in progress within Max bytes (its oldest
// lines dropped: the newest Max bytes are all a fill ever keeps).
func (t *Tail) trimSeg(st *tailState) {
	drop := 0
	for st.segSize > t.max() && drop < len(st.seg) {
		st.segSize -= len(st.seg[drop]) + 1
		drop++
	}
	if drop > 0 {
		st.seg = append([][]byte(nil), st.seg[drop:]...)
	}
}

// OlderNotLoaded reports whether the first fill of any replica gave up
// on some older activity (a backward segment that couldn't be fetched):
// what is shown is complete for the newer part only. Permanent for that
// replica's state; not an "incomplete" read.
func (t *Tail) OlderNotLoaded() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, st := range t.per {
		if st.olderMissing.Load() {
			return true
		}
	}
	return false
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
