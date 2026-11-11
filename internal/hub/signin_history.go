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
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/signinhistory"
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
// Next the oldest returned entry's time (RFC 3339 nano) to pass as the
// next before, "" at the end; Unknown the sources that couldn't be read
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
// part-3 hook); its failure is named in Unknown as name. A source added
// again under the same name replaces it; the built-in names are refused.
func (h *Hub) AddHistorySource(name string, s signinhistory.Source) {
	name = strings.TrimSpace(name)
	if name == "" || s == nil || name == HistoryKeycloak || name == HistoryOpened || name == HistoryAudit {
		log.Printf("history: source %q not added (empty, nil or a built-in name)", name)
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

// SignInHistory is user's history older than before (zero or later than
// now: now), at most limit entries (1–100; else 400), never older than
// history_days. Each source reads at most limit+1 entries, concurrently,
// each within historyReadTimeout. When the page is full and the next
// entry has the same time as its oldest, the entries of that time are
// left to the next page (before is exclusive), unless that would empty
// the page.
func (h *Hub) SignInHistory(ctx context.Context, user string, before time.Time, limit int) (*HistoryPage, error) {
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" {
		return nil, statusErr(http.StatusBadRequest, "no person named")
	}
	if limit < 1 || limit > HistoryMaxLimit {
		return nil, statusErr(http.StatusBadRequest, "limit must be 1 to %d, got %d", HistoryMaxLimit, limit)
	}
	now := h.historyNow()
	h.mu.RLock()
	days := h.st.SignIn.Limits.HistoryDays
	h.mu.RUnlock()
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	if before.IsZero() || before.After(now) {
		before = now
	}
	page := &HistoryPage{Entries: []signinhistory.Entry{}, Unknown: []string{}}
	if !since.Before(before) {
		return page, nil
	}
	srcs := h.historySources()
	lists := make([][]signinhistory.Entry, len(srcs))
	failed := make([]bool, len(srcs))
	var wg sync.WaitGroup
	for i, ns := range srcs {
		if ns.src == nil {
			failed[i] = true
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, historyReadTimeout)
			defer cancel()
			es, err := readSource(rctx, ns.src, user, since, before, limit)
			if err != nil {
				log.Printf("history: %s: %s unreadable: %v", user, ns.name, err)
				failed[i] = true
				return
			}
			// Never outside the window, never more than limit+1.
			lists[i] = signinhistory.Merge(limit+1, signinhistory.Within(es, since, before))
		}()
	}
	wg.Wait()
	for i, ns := range srcs {
		if failed[i] {
			page.Unknown = append(page.Unknown, ns.name)
		}
	}
	all := signinhistory.Merge(limit+1, lists...)
	if len(all) <= limit {
		page.Entries = all
		return page, nil
	}
	cut := limit
	for cut > 0 && all[cut-1].Time.Equal(all[limit].Time) {
		cut--
	}
	if cut == 0 {
		cut = limit
	}
	page.Entries = all[:cut]
	page.Next = page.Entries[cut-1].Time.UTC().Format(time.RFC3339Nano)
	return page, nil
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
