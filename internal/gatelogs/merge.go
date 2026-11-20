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
// A line that comes twice from the same replica (served again after a
// cursor_expired restart, contract §20.10) is kept once. A line without
// a time sorts first.
func Merge(parts [][]byte) []byte { return merge(parts, true) }

// merge is Merge, dropping a replica's repeated lines only with dedupe.
func merge(parts [][]byte, dedupe bool) []byte {
	type ln struct {
		t   time.Time
		rep int
		b   []byte
	}
	var all []ln
	for i, p := range parts {
		seen := map[string]bool{}
		for _, l := range splitLines(p) {
			if dedupe {
				if seen[string(l)] {
					continue
				}
				seen[string(l)] = true
			}
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

// Tail follows each replica's log from its start and keeps its newest
// Max bytes of lines (the 4 MiB Docker's Hub reads of the end of the
// file, contract §15.8), so a read only fetches what was appended since
// the last one. Its zero value is not usable: R is required; Max 0 is
// MaxAnswer.
type Tail struct {
	R   Replicas
	Max int

	mu  sync.Mutex
	per map[string]*tailState
}

// tailState is one replica's position and kept lines.
type tailState struct {
	cursor string
	last   time.Time // the last line served's time (a 410 restarts there)
	lines  [][]byte
	size   int
}

func (t *Tail) max() int {
	if t.Max > 0 {
		return t.Max
	}
	return MaxAnswer
}

// Read is every replica's tail merged (Merge); *Incomplete with what was
// read when a replica couldn't be followed this time (its earlier lines
// are still in the answer) or when there is none.
func (t *Tail) Read(ctx context.Context) ([]byte, error) {
	reps, err := t.R.list(ctx)
	if err != nil {
		return nil, &Incomplete{Service: t.R.Service, Why: "its replicas can't be listed: " + err.Error()}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.per == nil {
		t.per = map[string]*tailState{}
	}
	listed := map[string]bool{}
	for _, rep := range reps {
		listed[rep.Name] = true
		if t.per[rep.Name] == nil {
			t.per[rep.Name] = &tailState{}
		}
	}
	for name := range t.per {
		if !listed[name] {
			delete(t.per, name) // the pod is gone (its log with it)
		}
	}
	if len(reps) == 0 {
		return nil, &Incomplete{Service: t.R.Service, Why: "no replica is running"}
	}
	errs := make([]error, len(reps))
	var wg sync.WaitGroup
	for i, rep := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = t.follow(ctx, rep, t.per[rep.Name])
		}()
	}
	wg.Wait()
	parts := make([][]byte, len(reps))
	var unread, whys []string
	for i, rep := range reps {
		parts[i] = join(t.per[rep.Name].lines)
		if errs[i] != nil {
			unread = append(unread, rep.Name)
			whys = append(whys, errs[i].Error())
		}
	}
	// follow already dropped what a restart served again: repeated
	// lines here are the gate's own.
	out := merge(parts, false)
	if len(unread) > 0 {
		return out, &Incomplete{Service: t.R.Service, Unread: unread, Listed: len(reps), Why: strings.Join(whys, "; ")}
	}
	return out, nil
}

// follow pages st on from its cursor (the start of the log at first)
// until an answer isn't truncated; a 410 restarts at the last line's time
// with from (what is served again is dropped: the kept lines from that
// second on are matched).
func (t *Tail) follow(ctx context.Context, rep Replica, st *tailState) error {
	restarts := 0
	var again map[string]int // after a restart: kept lines that may come again
	for pages := 0; pages < t.R.maxPages(); pages++ {
		pg, err := t.R.fetch(ctx, rep, st.cursor, st.last)
		if errors.Is(err, errExpired) && st.cursor != "" {
			if restarts++; restarts > maxRestarts {
				return errFmt("its cursor kept expiring")
			}
			st.cursor, again = "", map[string]int{}
			from := st.last.Truncate(time.Second)
			for _, l := range st.lines {
				if !lineTime(l).Before(from) {
					again[string(l)]++
				}
			}
			continue
		}
		if err != nil {
			return err
		}
		lines := splitLines(pg.body)
		for _, l := range lines {
			if again[string(l)] > 0 {
				again[string(l)]--
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
		st.cursor = pg.next
		if !pg.truncated {
			return nil
		}
		if !progress {
			return errFmt("its log port made no progress")
		}
	}
	return errFmt("its log is longer than the read budget (read on next time)")
}

// trim drops st's oldest lines past Max bytes.
func (t *Tail) trim(st *tailState) {
	drop := 0
	for st.size > t.max() && drop < len(st.lines) {
		st.size -= len(st.lines[drop]) + 1
		drop++
	}
	if drop > 0 {
		st.lines = append([][]byte(nil), st.lines[drop:]...)
	}
}

type errFmt string

func (e errFmt) Error() string { return string(e) }
