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
	// detailIdP is Keycloak's own detail on a brokered LOGIN: a setup link
	// signs in through the hidden identity provider InviteIdP (core's
	// enroll), whose post-broker LOGIN carries none of the extension's
	// details.
	detailIdP = "identity_provider"
)

// InviteIdP is the setup links' identity provider (contract §9.4).
const InviteIdP = "portcullis-invite"

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
//   - a brokered LOGIN through InviteIdP (no pc_kind: Keycloak writes the
//     post-broker LOGIN itself) → sign_in, SetupLinkDetail;
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
	e := Entry{Time: ev.Time.UTC(), IP: IP(ev.IP), Browser: Browser(d[detailUA])}
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
		case d[detailIdP] == InviteIdP:
			// A setup link's brokered LOGIN: no method (inv meets nothing).
			e.Kind, e.Methods, e.Detail = KindSignIn, nil, SetupLinkDetail
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

// KeycloakEvents reads a user's login events by username with from <=
// time < to (main: keycloak.Client.UserLoginEventsPage), newest first,
// from the first-th.
type KeycloakEvents func(ctx context.Context, user string, from, to time.Time, first, max int) ([]keycloak.Event, error)

// keycloakPages bounds how many pages of limit events one read takes
// (dropped events — SSO through the gateway — are paged past).
const keycloakPages = 20

// KeycloakSource is the Keycloak events source. ClientNames is read once
// per call (nil: no listed client).
type KeycloakSource struct {
	Events      KeycloakEvents
	ClientNames func() map[string]string
}

// Entries pages through the user's events in [since, before) until it has
// limit entries or the events run out. When the page budget runs out
// first, it answers what it has with *Partial{Through: the oldest event
// read}: the history continues from there.
func (s KeycloakSource) Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error) {
	var names map[string]string
	if s.ClientNames != nil {
		names = s.ClientNames()
	}
	out := []Entry{}
	if limit < 1 || !since.Before(before) {
		return out, nil
	}
	var oldest time.Time
	first := 0
	for page := 0; len(out) < limit; page++ {
		if page == keycloakPages {
			// Keep only what is complete: newer than the oldest read.
			kept := out[:0]
			for _, e := range out {
				if e.Time.After(oldest) {
					kept = append(kept, e)
				}
			}
			return kept, &Partial{Through: oldest, Why: "Keycloak's page budget ran out"}
		}
		evs, err := s.Events(ctx, user, since, before, first, limit)
		if err != nil {
			return nil, err
		}
		first += len(evs)
		for _, ev := range evs {
			if oldest.IsZero() || ev.Time.Before(oldest) {
				oldest = ev.Time
			}
			if ev.Time.Before(since) || !ev.Time.Before(before) {
				continue
			}
			if e, ok := FromEvent(ev, names); ok && len(out) < limit {
				out = append(out, e)
			}
		}
		if len(evs) < limit {
			break
		}
	}
	return out, nil
}
