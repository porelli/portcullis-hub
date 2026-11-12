package hub

// The apps opened during an impersonation and whether it was used
// (contract §8.2 Source 4 "Apps opened", D44), run once at the end
// (finishEnd) and at created + 120 s (the not-used check), never per
// history entry; and the history's impersonation source (F22), which
// reads the audit and the kept records only.

import (
	"context"
	"log"
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
	UserLoginEventsPage(ctx context.Context, username string, from, to time.Time, first, max int) ([]keycloak.Event, error)
	UserImpersonateEvents(ctx context.Context, username string, from, to time.Time) ([]keycloak.Event, error)
}

// impEventSettle is how long after the last moment Keycloak's resource
// could still use a start (min(ended, created + 120 s)) its IMPERSONATE
// event may take to be readable: a "not used" answer before then is
// asked again once it has passed.
const impEventSettle = 3 * time.Second

// impLoginPage / impLoginPages bound the native LOGIN read (a window of
// at most 30 minutes).
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
// name, gateway apps first. used: an IMPERSONATE event with pc_imp = the
// id; whenever that can't be told (events unreadable, the event maybe
// not readable yet), used (fail toward telling).
func (a *impApps) run(ctx context.Context, rec state.Impersonation) ([]signinhistory.OpenedApp, bool) {
	now := a.h.impNow()
	from, to := rec.Started, rec.Ended
	if to.IsZero() || to.After(now) {
		to = now
	}
	apps := []signinhistory.OpenedApp{}
	seen := map[string]bool{}
	add := func(name string, own bool) {
		name = signinhistory.Clean(name, 200)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		apps = append(apps, signinhistory.OpenedApp{Name: name, OwnSession: own})
	}
	if a.h.cfg.GroupGateDataDir != "" {
		names, err := a.h.openedLog().ActApps(rec.Target, rec.Admin, from, to)
		if err != nil {
			log.Printf("impersonation: %s: the opened log can't be read: %v (gateway apps not listed)", rec.ID, err)
		}
		for _, n := range names {
			add(n, false)
		}
	}
	if a.kc != nil {
		for _, n := range a.nativeApps(ctx, rec, from, to) {
			add(n, true)
		}
	}
	return apps, a.used(ctx, rec, now, to)
}

// nativeApps are the listed native clients' names with a LOGIN of the
// person carrying pc_act = the administrator, in time order (unreadable
// events: none, logged).
func (a *impApps) nativeApps(ctx context.Context, rec state.Impersonation, from, to time.Time) []string {
	names := a.h.historyClientNames()
	delete(names, signinhistory.ForwardAuthClient)
	delete(names, signinhistory.FreshAuthClient)
	var evs []keycloak.Event
	for page := 0; page < impLoginPages; page++ {
		got, err := a.kc.UserLoginEventsPage(ctx, rec.Target, from.Add(-impSlack), to.Add(impSlack), len(evs), impLoginPage)
		if err != nil {
			log.Printf("impersonation: %s: Keycloak's login events can't be read: %v (native apps not listed)", rec.ID, err)
			break
		}
		evs = append(evs, got...)
		if len(got) < impLoginPage {
			break
		}
	}
	var out []string
	// Keycloak answers newest first: oldest first here.
	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		if ev.Type != "LOGIN" || ev.Details["pc_act"] != rec.Admin {
			continue
		}
		name, ok := names[ev.ClientID]
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == "" {
			name = ev.ClientID
		}
		out = append(out, name)
	}
	return out
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
// adds it with AddHistorySource): the person's impersonation.* entries
// (by target) from read (directory.Service.RecentMatching), the kept
// records' apps (F1) and the running records' until. It never runs the
// apps function (F22).
func (h *Hub) ImpersonationHistorySource(read signinhistory.AuditReader) signinhistory.ImpersonationSource {
	return signinhistory.ImpersonationSource{
		Audit: func(ctx context.Context, user string, since time.Time) ([]directory.AuditEntry, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			user = strings.ToLower(strings.TrimSpace(user))
			return read(impHistoryAuditMax, directory.AuditScan, func(e directory.AuditEntry) bool {
				return strings.HasPrefix(e.Action, "impersonation.") && strings.ToLower(strings.TrimSpace(e.Target)) == user &&
					!e.Time.Before(since)
			})
		},
		Stored: func(id string) ([]signinhistory.OpenedApp, bool) {
			h.mu.RLock()
			defer h.mu.RUnlock()
			for _, r := range h.st.Impersonations {
				if r.ID == id && !r.Running() && r.Finished {
					out := make([]signinhistory.OpenedApp, 0, len(r.Apps))
					for _, a := range r.Apps {
						out = append(out, signinhistory.OpenedAppOf(a))
					}
					return out, true
				}
			}
			return nil, false
		},
		Until: func(id string) (time.Time, bool) {
			h.mu.RLock()
			defer h.mu.RUnlock()
			for _, r := range h.st.Impersonations {
				if r.ID == id && r.Running() {
					return r.Until, true
				}
			}
			return time.Time{}, false
		},
		Now: h.impNow,
	}
}
