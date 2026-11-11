package signinhistory

import (
	"context"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
)

// The Keycloak clients the mapping names.
const (
	FreshAuthClient   = "portcullis-fresh-auth"
	ForwardAuthClient = "portcullis-forward-auth"
)

// The extension's event details (contract §8.1 "History details").
const (
	detailKind    = "pc_kind"
	detailMethods = "pc_methods"
	detailSession = "pc_session"
	detailUA      = "pc_ua"
	detailMethod  = "pc_method"
)

// failureText maps Keycloak's error to the history's text (§8.2).
var failureText = map[string]string{
	"invalid_user_credentials":     "wrong password",
	"user_not_found":               "unknown account",
	"user_disabled":                "account disabled",
	"user_temporarily_disabled":    "too many attempts: wait",
	"invalid_user_certificate":     "certificate refused",
	"different_user_authenticated": "another person's certificate",
	"access_denied":                "access denied",
}

// FailureText is Keycloak error's plain text ("sign-in failed" when it
// isn't in the table).
func FailureText(kcErr string) string {
	if t, ok := failureText[kcErr]; ok {
		return t
	}
	if strings.HasPrefix(kcErr, "certificate_") {
		return "certificate refused"
	}
	return "sign-in failed"
}

// FromEvent maps a LOGIN / LOGIN_ERROR event to an entry (§8.2);
// clientNames are signin-keycloak.json's clients (client id → name). false
// = not part of the history:
//   - LOGIN with client portcullis-fresh-auth → confirmed;
//   - pc_kind sign_in → sign_in (no method: a setup link, detail
//     SetupLinkDetail); step_up → step_up;
//   - pc_kind sso → opened <client name> for a listed client, else
//     dropped (group-gate's log covers the gateway's apps);
//   - LOGIN_ERROR → failed, methods [pc_method], the error's text.
//
// A LOGIN without the extension's pc_kind is kept as a sign-in whose
// methods weren't recorded, never hidden.
func FromEvent(ev keycloak.Event, clientNames map[string]string) (Entry, bool) {
	d := ev.Details
	if d == nil {
		d = map[string]string{}
	}
	e := Entry{Time: ev.Time.UTC(), IP: Clean(ev.IP, maxIP), Browser: Browser(d[detailUA])}
	switch ev.Type {
	case "LOGIN":
		e.Methods = splitMethods(d[detailMethods])
		switch {
		case ev.ClientID == FreshAuthClient:
			e.Kind = KindConfirmed
		case d[detailKind] == "sign_in":
			e.Kind = KindSignIn
			if len(e.Methods) == 0 {
				e.Detail = SetupLinkDetail
			}
		case d[detailKind] == "step_up":
			e.Kind = KindStepUp
		case d[detailKind] == "sso":
			name, ok := clientNames[ev.ClientID]
			if !ok || ev.ClientID == ForwardAuthClient {
				return Entry{}, false
			}
			e.Kind, e.App = KindOpened, Clean(name, maxApp)
			if e.App == "" {
				e.App = Clean(ev.ClientID, maxApp)
			}
			e.Methods = splitMethods(d[detailSession])
		default:
			e.Kind, e.Detail = KindSignIn, "the sign-in's methods weren't recorded"
		}
	case "LOGIN_ERROR":
		e.Kind = KindFailed
		e.Methods = splitMethods(d[detailMethod])
		e.Reason = FailureText(ev.Error)
	default:
		return Entry{}, false
	}
	return withScore(e), true
}

// KeycloakEvents reads a user's login events by username (main:
// keycloak.Client.UserLoginEventsPage), newest first, from the first-th.
type KeycloakEvents func(ctx context.Context, user string, from, to time.Time, first, max int) ([]keycloak.Event, error)

// keycloakPages bounds how many pages of limit+1 events one read takes
// (events newer than before, and dropped ones, are paged past).
const keycloakPages = 20

// KeycloakSource is the Keycloak events source. ClientNames is read once
// per call (nil: no listed client).
type KeycloakSource struct {
	Events      KeycloakEvents
	ClientNames func() map[string]string
}

// Entries pages through the user's events (Keycloak's dateFrom / dateTo
// are whole days, widened by one each way for its zone, so the window is
// filtered here) until it has limit+1 entries in [since, before), the
// events run out or reach past since.
func (s KeycloakSource) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) {
	var names map[string]string
	if s.ClientNames != nil {
		names = s.ClientNames()
	}
	want := limit + 1
	out := []Entry{}
	from, to := since.AddDate(0, 0, -1), before.AddDate(0, 0, 1)
	for page, first := 0, 0; page < keycloakPages && len(out) < want; page++ {
		evs, err := s.Events(ctx, user, from, to, first, want)
		if err != nil {
			return nil, err
		}
		first += len(evs)
		done := len(evs) < want
		for _, ev := range evs {
			if ev.Time.Before(since) {
				done = true // newest first: the rest is older still
				break
			}
			if !ev.Time.Before(before) {
				continue
			}
			if e, ok := FromEvent(ev, names); ok && len(out) < want {
				out = append(out, e)
			}
		}
		if done {
			break
		}
	}
	return out, nil
}
