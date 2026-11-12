package signinhistory

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// OpenedApp is an app opened during an impersonation (contract §8.2
// "Impersonation entries"): its name and whether it keeps its own session
// (a native-OIDC app, which may outlast the end).
type OpenedApp struct {
	Name       string `json:"name"`
	OwnSession bool   `json:"own_session"`
}

// MoreApps is the last "app" of a list that may be missing some (the
// events or the opened log couldn't all be read): it is stored, written
// to the file's notices and the end detail like an app, so the notice
// and the history read "apps opened: Gitea, possibly other apps".
const MoreApps = "possibly other apps"

// OpenedAppOf converts a stored record's app (state never imports this
// package, F1).
func OpenedAppOf(a state.ImpersonationApp) OpenedApp {
	return OpenedApp{Name: a.Name, OwnSession: a.OwnSession}
}

// The audit actions of an impersonation (contract §8.1 "Hub API and
// audit").
const (
	ImpersonationStartAction = "impersonation.start"
	ImpersonationEndAction   = "impersonation.end"
)

// impSep separates an impersonation audit detail's fields.
const impSep = " · "

// impIDRe is an impersonation id.
var impIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// impMinRe is an end detail's "<n> min" field.
var impMinRe = regexp.MustCompile(`^([0-9]{1,6}) min$`)

// ImpersonationRecord is a kept impersonation record (state's, F1) as
// the history reads it.
type ImpersonationRecord struct {
	ID, Admin, Reason     string
	Started, Until, Ended time.Time // Ended zero: running
	How, EndedBy          string    // the raw how; who stopped it
	Used, Finished        bool      // Finished: apps, used and the end audit done
	Apps                  []OpenedApp
}

// ImpersonationSource is the history's impersonation source (contract
// §8.2 Source 4, D44, F22): one entry per impersonation of the person.
//   - Records are the person's kept records (state, F1): an entry per
//     record started in the window, whatever the audit holds (an audit
//     flood can't hide them, Task 7 review I5); nil: none.
//   - Audit reads the person's impersonation.* entries from since to now
//     (newest first), so an end after the page's before still joins. A
//     start (result ok) whose record is gone gives an entry from the
//     audit alone: apps from the end detail's names, own_session false.
//     *Partial{Through} with entries: the audit was read only down to
//     Through, so a start older than that whose record is gone may be
//     missing. The kept records are still shown (a flood can't hide
//     them); the source answers *Incomplete when its answer may lack
//     such a start (fewer than limit entries newer than Through).
//   - Now is the clock (nil: time.Now): a running record past its
//     until (the loop ends it within seconds) reads as ending now.
//
// The live apps function is never run here.
type ImpersonationSource struct {
	Records func(user string) []ImpersonationRecord
	Audit   func(ctx context.Context, user string, since time.Time) ([]directory.AuditEntry, error)
	Now     func() time.Time
}

// impEnd is an end detail's fields.
type impEnd struct {
	how     string
	by      string
	minutes int
	names   []string
}

// parseImpEnd reads "<id> · <how> · <n> min · apps opened: <A, B>|none"
// or "<id> · not_used · 0 min · not used".
func parseImpEnd(e directory.AuditEntry) (id string, end impEnd, ok bool) {
	f := strings.SplitN(e.Detail, impSep, 4)
	if len(f) < 3 || !impIDRe.MatchString(f[0]) {
		return "", impEnd{}, false
	}
	end = impEnd{how: f[1], by: e.Actor}
	if m := impMinRe.FindStringSubmatch(f[2]); m != nil {
		end.minutes, _ = strconv.Atoi(m[1])
	}
	if len(f) == 4 {
		if list, found := strings.CutPrefix(f[3], "apps opened: "); found && list != "none" {
			for _, n := range strings.Split(list, ", ") {
				if n = strings.TrimSpace(n); n != "" {
					end.names = append(end.names, n)
				}
			}
		}
	}
	return f[0], end, true
}

// parseImpStart reads "<id> · <fresh method> · <reason>" (the reason is
// the rest, " · " included).
func parseImpStart(detail string) (id, reason string, ok bool) {
	f := strings.SplitN(detail, impSep, 3)
	if len(f) != 3 || !impIDRe.MatchString(f[0]) {
		return "", "", false
	}
	return f[0], f[2], true
}

// Entries implements Source: the ok starts in [since, before), newest
// first (equal times in the audit's order), at most limit.
func (s ImpersonationSource) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := []Entry{}
	user = strings.ToLower(strings.TrimSpace(user))
	if limit < 1 || user == "" || !since.Before(before) {
		return out, nil
	}
	got, err := s.Audit(ctx, user, since)
	var partial *Partial
	if err != nil && !errors.As(err, &partial) {
		return nil, err
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	type item struct {
		at time.Time
		id string
		e  Entry
	}
	var items []item
	inWindow := func(t time.Time) bool { return !t.Before(since) && t.Before(before) }
	kept := map[string]bool{}
	if s.Records != nil {
		for _, r := range s.Records(user) {
			if !impIDRe.MatchString(r.ID) {
				continue
			}
			kept[r.ID] = true
			if !inWindow(r.Started) {
				continue
			}
			en := Entry{Time: r.Started.UTC(), Kind: KindImpersonation, By: Clean(r.Admin, maxBy), Reason: Clean(r.Reason, maxDetail)}
			switch {
			case r.Ended.IsZero():
				en.Detail = runningDetail(r.Until, now)
			case !r.Finished:
				// Being finished (apps, used, the end audit): shortly known.
				en.Detail = "ended"
			default:
				en.Detail = ImpersonationDetail(impMinutes(r.Started, r.Ended), r.How, r.EndedBy, r.Apps, r.Used)
			}
			items = append(items, item{r.Started, r.ID, en})
		}
	}
	ends := map[string]impEnd{}
	type start struct {
		e      directory.AuditEntry
		id     string
		reason string
	}
	var starts []start
	for _, e := range got {
		if strings.ToLower(strings.TrimSpace(e.Target)) != user || (e.Result != "" && e.Result != "ok") {
			continue
		}
		switch e.Action {
		case ImpersonationEndAction:
			// The audit is newest first: the earliest end of an id wins
			// (a retried end may be audited twice).
			if id, end, ok := parseImpEnd(e); ok {
				ends[id] = end
			}
		case ImpersonationStartAction:
			if !inWindow(e.Time) {
				continue
			}
			if id, reason, ok := parseImpStart(e.Detail); ok && !kept[id] {
				kept[id] = true // one entry per id
				starts = append(starts, start{e, id, reason})
			}
		}
	}
	for _, st := range starts {
		en := Entry{Time: st.e.Time.UTC(), Kind: KindImpersonation, By: Clean(st.e.Actor, maxBy), Reason: Clean(st.reason, maxDetail)}
		if end, ended := ends[st.id]; ended {
			var apps []OpenedApp
			for _, n := range end.names {
				apps = append(apps, OpenedApp{Name: n})
			}
			en.Detail = ImpersonationDetail(end.minutes, end.how, end.by, apps, end.how != "not_used")
		} else {
			// No record and no end: being finished, or its end audit lost.
			en.Detail = "ended"
		}
		items = append(items, item{st.e.Time, st.id, en})
	}
	// Newest first; equal times by id (stable: a larger limit answers a
	// longer prefix of the same list).
	slices.SortFunc(items, func(a, b item) int {
		if c := b.at.Compare(a.at); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})
	for _, it := range items[:min(len(items), limit)] {
		it.e.Detail = Clean(it.e.Detail, maxDetail)
		out = append(out, withScore(it.e))
	}
	if partial != nil && partial.Through.After(since) {
		// A start older than Through (record gone) may be missing; the
		// answer can't hold it when limit entries are newer than Through.
		newer := 0
		for _, e := range out {
			if e.Time.After(partial.Through) {
				newer++
			}
		}
		if newer < limit {
			return out, &Incomplete{Why: partial.Error()}
		}
	}
	return out, nil
}

// runningDetail is "running · ends hh:mm UTC" (past until: now's time,
// the loop ends it within seconds).
func runningDetail(until, now time.Time) string {
	until = until.UTC()
	if until.Before(now) {
		until = now
	}
	return "running · ends " + until.Format("15:04") + " UTC"
}

// impMinutes is the minutes from started to ended, rounded up, at least
// 1 (the end detail's and the notice's rule).
func impMinutes(started, ended time.Time) int {
	d := ended.Sub(started)
	return max(int((d+time.Minute-1)/time.Minute), 1)
}

// ImpersonationDetail is an ended impersonation's history detail (D44,
// contract §8.2): "<n> min · <how> · apps opened: A, B" (or "none"),
// plus " · <app> keeps its own session and may have stayed signed in
// longer" for each own-session app; "not used" when it wasn't. how is
// the record's raw value, shown per D41: stopped → "stopped by
// <endedBy>", expired, switched_off → "switched off", not_used → "not
// used".
func ImpersonationDetail(minutes int, how, endedBy string, apps []OpenedApp, used bool) string {
	if !used || how == "not_used" {
		return "not used"
	}
	shown := how
	switch how {
	case "stopped":
		shown = "stopped by " + Clean(endedBy, maxBy)
	case "switched_off":
		shown = "switched off"
	}
	var names, own []string
	for _, a := range apps {
		n := Clean(a.Name, maxApp)
		if n == "" {
			continue
		}
		names = append(names, n)
		if a.OwnSession {
			own = append(own, n)
		}
	}
	list := "none"
	if len(names) > 0 {
		list = strings.Join(names, ", ")
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(max(minutes, 1)) + " min" + impSep + shown + impSep + "apps opened: " + list)
	for _, n := range own {
		b.WriteString(impSep + n + " keeps its own session and may have stayed signed in longer")
	}
	return b.String()
}
