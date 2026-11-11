package hub

// Sign-in history (contract §8.2, plan D28): merged at read time from
// Keycloak's LOGIN / LOGIN_ERROR events, group-gate's opened log
// (<HUB_GROUP_GATE_DATA_DIR>/opened) and the Hub's audit, plus any source
// part 3 adds (AddHistorySource). Nothing is stored. Reads take no lock a
// sign-in needs (Keycloak's extension reads signin-keycloak.json, never
// the Hub): the client names come from that file on disk, history_days
// from a short read lock. A source that fails is named in Unknown and the
// others are still shown.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// The built-in sources' names (HistoryPage.Unknown).
const (
	HistoryKeycloak = "keycloak"
	HistoryOpened   = "opened"
	HistoryAudit    = "audit"
)

// History page sizes (the routes': 1–100, default 50).
const (
	HistoryDefaultLimit = 50
	HistoryMaxLimit     = 100
)

// historyReadTimeout bounds one source's read.
const historyReadTimeout = 10 * time.Second

// HistoryPage is one page of a person's history: entries newest first;
// Next the cursor to pass as the next before (HistoryCursor: the oldest
// returned entry's time, RFC 3339 nano, with per-source skips only when
// equal times cross the cut; a Partial source's Through + 1 ns when its
// budget ended the page), "" at the end; Unknown the sources that couldn't be read
// (never nil).
type HistoryPage struct {
	Entries []signinhistory.Entry `json:"entries"`
	Next    string                `json:"next"`
	Unknown []string              `json:"unknown"`
}

// HistorySources are the history's wired sources (main: Keycloak's
// UserLoginEventsPage and the directory's RecentMatching); nil = that
// source is unknown.
type HistorySources struct {
	Events signinhistory.KeycloakEvents
	Audit  signinhistory.AuditReader
}

type namedSource struct {
	name string
	src  signinhistory.Source
}

// historyState is the Hub's history wiring, under its own mutex.
type historyState struct {
	mu    sync.Mutex
	src   HistorySources
	extra []namedSource
	// now is the clock (nil: time.Now); prune deletes old day files
	// (nil: the opened log's Prune). Tests replace both.
	now   func() time.Time
	prune func(days int) (int, error)
}

// SetHistorySources wires the Keycloak and audit sources.
func (h *Hub) SetHistorySources(src HistorySources) {
	h.history.mu.Lock()
	defer h.history.mu.Unlock()
	h.history.src = src
}

// AddHistorySource adds a source merged like the built-in three (the
// part-3 hook); its failure is named in Unknown as name, which cursors
// carry too (1–32 of a-z 0-9 _ -, starting with a letter or digit). A
// source added again under the same name replaces it; the built-in names
// are refused.
func (h *Hub) AddHistorySource(name string, s signinhistory.Source) {
	if !historyNameRe.MatchString(name) || s == nil || name == HistoryKeycloak || name == HistoryOpened || name == HistoryAudit {
		log.Printf("history: source %q not added (nil, a built-in name, or not 1–32 of a-z 0-9 _ -)", name)
		return
	}
	h.history.mu.Lock()
	defer h.history.mu.Unlock()
	for i := range h.history.extra {
		if h.history.extra[i].name == name {
			h.history.extra[i].src = s
			return
		}
	}
	h.history.extra = append(h.history.extra, namedSource{name, s})
}

func (h *Hub) historyNow() time.Time {
	h.history.mu.Lock()
	now := h.history.now
	h.history.mu.Unlock()
	if now != nil {
		return now().UTC()
	}
	return time.Now().UTC()
}

// openedLog is group-gate's opened log under HUB_GROUP_GATE_DATA_DIR.
func (h *Hub) openedLog() signinhistory.OpenedLog {
	return signinhistory.OpenedLog{Dir: h.cfg.GroupGateDataDir, Now: h.historyNow}
}

// historyClientNames are the published signin-keycloak.json's clients
// (client id → name): an unreadable file names none (their SSO events
// are then dropped, as for any unlisted client).
func (h *Hub) historyClientNames() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(h.signInKeycloakPath())
	if err != nil {
		return out
	}
	var doc struct {
		Clients map[string]KeycloakClientTemplate `json:"clients"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return out
	}
	for id, c := range doc.Clients {
		out[id] = c.Name
	}
	return out
}

// historySources is every source by name, in merge order (nil src: not
// wired, so unknown).
func (h *Hub) historySources() []namedSource {
	h.history.mu.Lock()
	src := h.history.src
	extra := append([]namedSource(nil), h.history.extra...)
	h.history.mu.Unlock()
	var kc, au signinhistory.Source
	if src.Events != nil {
		kc = signinhistory.KeycloakSource{Events: src.Events, ClientNames: h.historyClientNames}
	}
	if src.Audit != nil {
		au = signinhistory.AuditSource{Read: src.Audit}
	}
	var opened signinhistory.Source
	if h.cfg.GroupGateDataDir != "" {
		opened = h.openedLog()
	}
	return append([]namedSource{{HistoryKeycloak, kc}, {HistoryOpened, opened}, {HistoryAudit, au}}, extra...)
}

// maxCursorSkip bounds a cursor's per-source skip count (a source then
// reads limit+1+skip entries).
const maxCursorSkip = 10000

// historyNameRe is an added source's name (it appears in cursors).
var historyNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// HistoryCursor is where a page starts (HistoryPage.Next, the routes'
// before=): entries older than At; with Skips, entries at At too, after
// the first Skips[source] of that source's entries at exactly At (the
// ones earlier pages showed). It is "<RFC 3339 nano>" and, only when a
// run of equal times crosses the page cut, ",<source>=<n>" per source,
// sorted. "" = now.
type HistoryCursor struct {
	At    time.Time
	Skips map[string]int
}

// String is the cursor's text.
func (c HistoryCursor) String() string {
	var b strings.Builder
	b.WriteString(c.At.UTC().Format(time.RFC3339Nano))
	names := make([]string, 0, len(c.Skips))
	for n, k := range c.Skips {
		if k > 0 {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, ",%s=%d", n, c.Skips[n])
	}
	return b.String()
}

// ParseHistoryCursor reads a cursor ("" = the zero cursor: now). A bad
// one is a 400.
func ParseHistoryCursor(s string) (HistoryCursor, error) {
	var c HistoryCursor
	if s == "" {
		return c, nil
	}
	parts := strings.Split(s, ",")
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return c, statusErr(http.StatusBadRequest, "before must be an RFC 3339 time (or a history page's next)")
	}
	c.At = t.UTC()
	for _, p := range parts[1:] {
		name, num, ok := strings.Cut(p, "=")
		k, err := strconv.Atoi(num)
		if !ok || !historyNameRe.MatchString(name) || err != nil || k < 1 || k > maxCursorSkip || c.Skips[name] != 0 {
			return HistoryCursor{}, statusErr(http.StatusBadRequest, "before: not a history page's next")
		}
		if c.Skips == nil {
			c.Skips = map[string]int{}
		}
		c.Skips[name] = k
	}
	return c, nil
}

// taggedEntry is an entry and the index of its source.
type taggedEntry struct {
	signinhistory.Entry
	src int
}

// SignInHistory is user's history from cursor on (ParseHistoryCursor; ""
// or later than now: now), at most limit entries (1–100; else 400), never
// older than history_days. Nothing is ever skipped between pages:
//   - every source is asked for limit+1 entries (plus what the cursor
//     skips of it), concurrently, each within historyReadTimeout;
//   - a source that answers *Partial (its read budget ran out) has its
//     entries kept, and the page ends after its Through — newer entries
//     only, from every source — with Next continuing at Through;
//   - a page cut inside a run of equal times gives a cursor that skips,
//     per source, the entries of that time already shown;
//   - a source that fails (or a Partial that can't move the page on) is
//     named in Unknown, and the others are still shown.
func (h *Hub) SignInHistory(ctx context.Context, user, cursor string, limit int) (*HistoryPage, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" {
		return nil, statusErr(http.StatusBadRequest, "no person named")
	}
	if limit < 1 || limit > HistoryMaxLimit {
		return nil, statusErr(http.StatusBadRequest, "limit must be 1 to %d, got %d", HistoryMaxLimit, limit)
	}
	cur, err := ParseHistoryCursor(cursor)
	if err != nil {
		return nil, err
	}
	now := h.historyNow()
	h.mu.RLock()
	days := h.st.SignIn.Limits.HistoryDays
	h.mu.RUnlock()
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	if cur.At.IsZero() || cur.At.After(now) {
		cur = HistoryCursor{At: now}
	}
	// before: the sources' exclusive bound (At itself included when the
	// cursor skips some of At's entries).
	before := cur.At
	if len(cur.Skips) > 0 {
		before = cur.At.Add(time.Nanosecond)
	}
	page := &HistoryPage{Entries: []signinhistory.Entry{}, Unknown: []string{}}
	if !since.Before(before) {
		return page, nil
	}
	srcs := h.historySources()
	lists := make([][]signinhistory.Entry, len(srcs))
	partial := make([]*signinhistory.Partial, len(srcs))
	failed := make([]bool, len(srcs))
	var wg sync.WaitGroup
	for i, ns := range srcs {
		if ns.src == nil {
			failed[i] = true
			continue
		}
		skip := cur.Skips[ns.name]
		wg.Add(1)
		go func() {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, historyReadTimeout)
			defer cancel()
			es, err := readSource(rctx, ns.src, user, since, before, limit+1+skip)
			var p *signinhistory.Partial
			switch {
			case errors.As(err, &p) && p.Through.Before(before) && !p.Through.Before(since):
				partial[i] = p
			case err != nil:
				log.Printf("history: %s: %s unreadable: %v", user, ns.name, err)
				failed[i] = true
				return
			}
			lists[i] = sourceList(es, since, before, cur.At, skip, limit+1, p)
		}()
	}
	wg.Wait()
	// The page ends after the newest Through: older entries wait for the
	// next page, which starts at Through + 1 ns — only when that is older
	// than this page's own bound (else the reader would never move on).
	var cutoff time.Time
	for i, p := range partial {
		if p == nil {
			continue
		}
		if !p.Through.Add(time.Nanosecond).Before(before) {
			log.Printf("history: %s: %s: %v (no progress: shown as unknown)", user, srcs[i].name, p)
			failed[i], lists[i] = true, nil
			continue
		}
		if p.Through.After(cutoff) {
			cutoff = p.Through
		}
	}
	for i, ns := range srcs {
		if failed[i] {
			page.Unknown = append(page.Unknown, ns.name)
		}
	}
	var all []taggedEntry
	for i, l := range lists {
		for _, e := range l {
			if cutoff.IsZero() || e.Time.After(cutoff) {
				all = append(all, taggedEntry{e, i})
			}
		}
	}
	slices.SortStableFunc(all, func(a, b taggedEntry) int { return b.Time.Compare(a.Time) })
	shown := all[:min(len(all), limit)]
	for _, e := range shown {
		page.Entries = append(page.Entries, e.Entry)
	}
	switch {
	case len(all) > limit:
		last := shown[len(shown)-1].Time
		next := HistoryCursor{At: last}
		if all[limit].Time.Equal(last) {
			// A run of equal times crosses the cut: skip what is shown.
			next.Skips = map[string]int{}
			if len(cur.Skips) > 0 && cur.At.Equal(last) {
				for n, k := range cur.Skips {
					next.Skips[n] = k
				}
			}
			for _, e := range shown {
				if e.Time.Equal(last) {
					next.Skips[srcs[e.src].name]++
				}
			}
		}
		page.Next = next.String()
	case !cutoff.IsZero():
		// Everything newer than cutoff is shown; continue at cutoff.
		page.Next = HistoryCursor{At: cutoff.Add(time.Nanosecond)}.String()
	}
	return page, nil
}

// sourceList is one source's entries for the page: within [since,
// before) (and after a Partial's Through), newest first in the source's
// order, the first skip of those at exactly at dropped, at most n.
func sourceList(es []signinhistory.Entry, since, before, at time.Time, skip, n int, p *signinhistory.Partial) []signinhistory.Entry {
	es = signinhistory.Within(es, since, before)
	slices.SortStableFunc(es, func(a, b signinhistory.Entry) int { return b.Time.Compare(a.Time) })
	out := make([]signinhistory.Entry, 0, min(len(es), n))
	for _, e := range es {
		if p != nil && !e.Time.After(p.Through) {
			continue
		}
		if skip > 0 && e.Time.Equal(at) {
			skip--
			continue
		}
		if len(out) == n {
			break
		}
		out = append(out, e)
	}
	return out
}

// readSource reads one source, a panic counted as its failure.
func readSource(ctx context.Context, s signinhistory.Source, user string, since, before time.Time, limit int) (es []signinhistory.Entry, err error) {
	defer func() {
		if r := recover(); r != nil {
			es, err = nil, fmt.Errorf("history source panicked: %v", r)
		}
	}()
	return s.Entries(ctx, user, since, before, limit)
}

// pruneSignInHistory deletes the opened log's day files older than
// history_days (never today's); a failure is logged.
func (h *Hub) pruneSignInHistory() {
	h.mu.RLock()
	days := h.st.SignIn.Limits.HistoryDays
	h.mu.RUnlock()
	if days < state.MinHistoryDays || days > state.MaxHistoryDays {
		log.Printf("history: not pruning the opened log: history_days %d is outside %d–%d", days, state.MinHistoryDays, state.MaxHistoryDays)
		return
	}
	h.history.mu.Lock()
	prune := h.history.prune
	h.history.mu.Unlock()
	if prune == nil {
		if h.cfg.GroupGateDataDir == "" {
			return
		}
		prune = h.openedLog().Prune
	}
	n, err := prune(days)
	if err != nil {
		log.Printf("history: pruning the opened log (%d days): %v", days, err)
	}
	if n > 0 {
		log.Printf("history: pruned %d day file(s) of the opened log older than %d days", n, days)
	}
}

// RunHistoryPrune prunes the opened log now and then every interval
// (default a day) until ctx ends.
func (h *Hub) RunHistoryPrune(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.pruneSignInHistory()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
