package signinhistory

import (
	"context"
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

// ImpersonationSource is the history's impersonation source (contract
// §8.2 Source 4, D44, F22): one entry per impersonation of the person,
// from the audit's impersonation.start (result ok) joined with its
// impersonation.end.
//   - Audit reads the person's impersonation.* entries from since to now
//     (newest first), so an end after the page's before still joins.
//   - Stored is the kept record's apps (F1); false (or nil): the end
//     detail's names, own_session false. The live apps function is never
//     run here.
//   - Until is a running record's until (false: not running); nil: none
//     known running.
//   - Now is the clock (nil: time.Now): a running record past its
//     until (the loop ends it within seconds) reads as ending now.
type ImpersonationSource struct {
	Audit  func(ctx context.Context, user string, since time.Time) ([]directory.AuditEntry, error)
	Stored func(id string) ([]OpenedApp, bool)
	Until  func(id string) (time.Time, bool)
	Now    func() time.Time
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
	if err != nil {
		return nil, err
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
			if e.Time.Before(since) || !e.Time.Before(before) {
				continue
			}
			if id, reason, ok := parseImpStart(e.Detail); ok {
				starts = append(starts, start{e, id, reason})
			}
		}
	}
	slices.SortStableFunc(starts, func(a, b start) int { return b.e.Time.Compare(a.e.Time) })
	for _, st := range starts[:min(len(starts), limit)] {
		en := Entry{Time: st.e.Time.UTC(), Kind: KindImpersonation, By: Clean(st.e.Actor, maxBy), Reason: Clean(st.reason, maxDetail)}
		end, ended := ends[st.id]
		switch {
		case ended:
			var apps []OpenedApp
			stored := false
			if s.Stored != nil && end.how != "not_used" {
				apps, stored = s.Stored(st.id)
			}
			if !stored {
				apps = nil
				for _, n := range end.names {
					apps = append(apps, OpenedApp{Name: n})
				}
			}
			en.Detail = ImpersonationDetail(end.minutes, end.how, end.by, apps, end.how != "not_used")
		case s.Until != nil:
			if until, ok := s.Until(st.id); ok {
				now := time.Now().UTC()
				if s.Now != nil {
					now = s.Now().UTC()
				}
				until = until.UTC()
				if until.Before(now) {
					until = now
				}
				en.Detail = "running · ends " + until.Format("15:04") + " UTC"
				break
			}
			en.Detail = "ended"
		default:
			en.Detail = "ended"
		}
		en.Detail = Clean(en.Detail, maxDetail)
		out = append(out, withScore(en))
	}
	return out, nil
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
