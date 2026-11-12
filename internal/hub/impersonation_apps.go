package hub

// The apps opened during an impersonation and whether it was used
// (contract §8.2 Source 4 "Apps opened", D44), run once at the end
// (finishEnd) and at created + 120 s (the not-used check), never per
// history entry; and the history's impersonation source (F22), which
// reads the audit and the kept records only.

import (
	"context"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// HistoryImpersonation is the impersonation source's name (Unknown).
const HistoryImpersonation = "impersonation"

// ImpersonationEvents are the Keycloak reads the apps function needs
// (keycloak.Client), by username.
type ImpersonationEvents interface {
	UserClientLoginEvents(ctx context.Context, username, clientID string, from, to time.Time, first, max int) ([]keycloak.Event, error)
	UserImpersonateEvents(ctx context.Context, username string, from, to time.Time) ([]keycloak.Event, error)
}

// impEventSettle is how long after the last moment Keycloak's resource
// could still use a start (min(ended, created + 120 s)) its IMPERSONATE
// event may take to be readable: a "not used" answer before then is
// asked again once it has passed.
const impEventSettle = 3 * time.Second

// impLoginPage / impLoginPages bound the native LOGIN read per client
// (type=LOGIN&client=<id>, a window of at most 30 minutes): a budget
// spent without a match leaves the list marked incomplete.
const (
	impLoginPage  = 100
	impLoginPages = 10
)

// impSlack widens Keycloak's windows (its times are milliseconds, its
// clock the host's).
const impSlack = time.Second

// impApps is the live apps function (SetImpersonationApps).
type impApps struct {
	h  *Hub
	kc ImpersonationEvents
	// sleep waits d or until ctx ends (false); tests replace it.
	sleep func(ctx context.Context, d time.Duration) bool
}

// ImpersonationAppsFunc is the apps function main wires with
// SetImpersonationApps: the opened log and Keycloak's events (kc nil: no
// native apps, used).
func (h *Hub) ImpersonationAppsFunc(kc ImpersonationEvents) func(ctx context.Context, rec state.Impersonation) ([]signinhistory.OpenedApp, bool) {
	a := &impApps{h: h, kc: kc, sleep: sleepCtx}
	return a.run
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// run is rec's apps opened, for the person between started and ended (or
// now): the opened log's lines with act = the administrator (gateway
// apps, own_session false), then Keycloak LOGIN events with pc_act = the
// administrator for the clients signin-keycloak.json lists other than
// portcullis-forward-auth (native apps, own_session true), deduped by
// name, gateway apps first. When either read may have missed apps (an
// error, a read budget spent: review of Task 7), the list ends with
// signinhistory.MoreApps, so the notice and the history say so. used: an
// IMPERSONATE event with pc_imp = the id; whenever that can't be told
// (events unreadable, the event maybe not readable yet), used (fail
// toward telling).
//
// It runs with imp.endMu held (finishEnd), never mu: the settle wait (up
// to impEventSettle) and up to impLoginPages Keycloak reads per native
// client make another end (another administrator's Stop) wait behind
// it, while starts, the file and every read go on. Accepted (review).
func (a *impApps) run(ctx context.Context, rec state.Impersonation) ([]signinhistory.OpenedApp, bool) {
	now := a.h.impNow()
	from, to := rec.Started, rec.Ended
	if to.IsZero() || to.After(now) {
		to = now
	}
	apps := []signinhistory.OpenedApp{}
	at := map[string]int{}
	add := func(name string, own bool) {
		name = signinhistory.Clean(name, 200)
		if name == "" {
			return
		}
		if i, ok := at[name]; ok {
			// The same name from both sources (an app behind forward-auth
			// that also signs in with OIDC): it keeps its own session
			// (review I2).
			apps[i].OwnSession = apps[i].OwnSession || own
			return
		}
		at[name] = len(apps)
		apps = append(apps, signinhistory.OpenedApp{Name: name, OwnSession: own})
	}
	incomplete := false
	if a.h.cfg.GroupGateDataDir != "" {
		// group-gate writes whole seconds: the start's own second counts
		// (review I3; over-reporting is the safe side).
		names, err := a.h.openedLog().ActApps(rec.Target, rec.Admin, from.Truncate(time.Second), to)
		if err != nil {
			incomplete = true
			log.Printf("impersonation: %s: the opened log couldn't all be read: %v (apps marked incomplete)", rec.ID, err)
		}
		for _, n := range names {
			add(n, false)
		}
	} else {
		incomplete = true
		log.Printf("impersonation: %s: no opened log (apps marked incomplete)", rec.ID)
	}
	if a.kc != nil {
		names, complete := a.nativeApps(ctx, rec, from, to)
		for _, n := range names {
			add(n, true)
		}
		incomplete = incomplete || !complete
	} else {
		incomplete = true
	}
	// An app opened is a use, whatever the IMPERSONATE events say (a lost
	// event write, a drifted events config: review I1); then Keycloak
	// isn't asked.
	used := len(apps) > 0 || a.used(ctx, rec, now, to)
	if incomplete {
		apps = append(apps, signinhistory.OpenedApp{Name: signinhistory.MoreApps})
	}
	return apps, used
}

// nativeApps are the listed native clients' names with a LOGIN of the
// person carrying pc_act = the administrator, ordered by that LOGIN's
// time; each client is read on its own (type=LOGIN&client=<id>) until
// a match. complete is false when a read failed or a client's page
// budget ran out without a match (logged with the id only).
func (a *impApps) nativeApps(ctx context.Context, rec state.Impersonation, from, to time.Time) (names []string, complete bool) {
	clients, err := a.h.historyClientNamesErr()
	if err != nil {
		// Which clients are native isn't known (review I4).
		log.Printf("impersonation: %s: signin-keycloak.json can't be read: %v (apps marked incomplete)", rec.ID, err)
		return nil, false
	}
	delete(clients, signinhistory.ForwardAuthClient)
	delete(clients, signinhistory.FreshAuthClient)
	type hit struct {
		name string
		at   time.Time
	}
	var hits []hit
	complete = true
	for _, id := range slices.Sorted(maps.Keys(clients)) {
		found, read := false, 0
		for page := 0; !found; page++ {
			if page == impLoginPages {
				complete = false
				log.Printf("impersonation: %s: a native client's login events exceed the read budget (apps marked incomplete)", rec.ID)
				break
			}
			got, err := a.kc.UserClientLoginEvents(ctx, rec.Target, id, from.Add(-impSlack), to.Add(impSlack), read, impLoginPage)
			if err != nil {
				complete = false
				log.Printf("impersonation: %s: Keycloak's login events can't be read: %v (apps marked incomplete)", rec.ID, err)
				break
			}
			read += len(got)
			for _, ev := range got {
				if ev.Type == "LOGIN" && ev.ClientID == id && ev.Details["pc_act"] == rec.Admin {
					name := clients[id]
					if strings.TrimSpace(name) == "" {
						name = id
					}
					hits = append(hits, hit{name, ev.Time})
					found = true
					break
				}
			}
			if len(got) < impLoginPage {
				break
			}
		}
	}
	slices.SortStableFunc(hits, func(x, y hit) int { return x.at.Compare(y.at) })
	for _, h := range hits {
		names = append(names, h.name)
	}
	return names, complete
}

// used reports whether rec was used (D44): an IMPERSONATE event of the
// person with pc_imp = the id. Unsure is used: no Keycloak, an
// unreadable answer, or no event while the start could still have been
// used moments ago and the event may not be readable yet (then asked
// once more after impEventSettle).
func (a *impApps) used(ctx context.Context, rec state.Impersonation, now, to time.Time) bool {
	if rec.Used {
		return true
	}
	if a.kc == nil {
		return true
	}
	ask := func() (bool, bool) {
		evs, err := a.kc.UserImpersonateEvents(ctx, rec.Target, rec.Started.Add(-impSlack), a.h.impNow().Add(impSlack))
		if err != nil {
			log.Printf("impersonation: %s: Keycloak's impersonate events can't be read: %v (counted as used)", rec.ID, err)
			return false, false
		}
		for _, ev := range evs {
			if ev.Type == "IMPERSONATE" && ev.Details["pc_imp"] == rec.ID {
				return true, true
			}
		}
		return false, true
	}
	found, ok := ask()
	if !ok || found {
		return true
	}
	last := rec.Started.Add(impPendingFor)
	if to.Before(last) {
		last = to
	}
	if settle := last.Add(impEventSettle); now.Before(settle) {
		if !a.sleep(ctx, settle.Sub(now)) {
			return true
		}
		if found, ok := ask(); !ok || found {
			return true
		}
	}
	return false
}

// impHistoryAuditMax bounds the impersonation entries one history read
// takes (within the audit's last directory.AuditScan bytes).
const impHistoryAuditMax = 10000

// ImpersonationHistorySource is the history's impersonation source (main
// adds it with AddHistorySource): the person's kept records (state, F1;
// an audit flood can't hide them, review I5) joined by id with their
// impersonation.* audit entries (by target) from read
// (directory.Service.RecentMatchingScan). A read that didn't reach the
// audit's start answers *Partial at the oldest entry it scanned (the
// source then shows its records and answers *Incomplete when it may lack
// a start). It never runs the apps function (F22).
func (h *Hub) ImpersonationHistorySource(read func(n int, maxScan int64, keep func(directory.AuditEntry) bool) ([]directory.AuditEntry, bool, error)) signinhistory.ImpersonationSource {
	return signinhistory.ImpersonationSource{
		Records: func(user string) []signinhistory.ImpersonationRecord {
			h.mu.RLock()
			defer h.mu.RUnlock()
			var out []signinhistory.ImpersonationRecord
			for _, r := range h.st.Impersonations {
				if r.Target != user {
					continue
				}
				rec := signinhistory.ImpersonationRecord{ID: r.ID, Admin: r.Admin, Reason: r.Reason, Started: r.Started, Until: r.Until,
					Ended: r.Ended, How: r.How, EndedBy: r.EndedBy, Used: r.Used, Finished: r.Finished}
				for _, a := range r.Apps {
					rec.Apps = append(rec.Apps, signinhistory.OpenedAppOf(a))
				}
				out = append(out, rec)
			}
			return out
		},
		Audit: func(ctx context.Context, user string, since time.Time) ([]directory.AuditEntry, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			user = strings.ToLower(strings.TrimSpace(user))
			// oldest: the oldest entry the scan decoded (keep sees each).
			var oldest time.Time
			got, whole, err := read(impHistoryAuditMax, directory.AuditScan, func(e directory.AuditEntry) bool {
				if oldest.IsZero() || e.Time.Before(oldest) {
					oldest = e.Time
				}
				return strings.HasPrefix(e.Action, "impersonation.") && strings.ToLower(strings.TrimSpace(e.Target)) == user &&
					!e.Time.Before(since)
			})
			if err != nil {
				return nil, err
			}
			if !whole && oldest.After(since) {
				return got, &signinhistory.Partial{Through: oldest, Why: "the audit was read only down to its last " +
					"scan limit (older impersonation starts may be missing)"}
			}
			return got, nil
		},
		Now: h.impNow,
	}
}
