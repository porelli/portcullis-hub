// Package signinhistory is a person's sign-in history (contract §8.2,
// plan D28), merged at read time from four sources: Keycloak's LOGIN /
// LOGIN_ERROR events (FromEvent), group-gate's opened log (OpenedLog),
// the Hub's audit (FromAudit) and, part 3, the impersonations
// (ImpersonationSource). Nothing is stored here. Every text that
// came from outside (the User-Agent, an IP, an app name, an audit detail)
// is clipped and has its control and bidi characters removed; the pages
// that show it escape it.
package signinhistory

import (
	"context"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mileusna/useragent"

	"github.com/portcullis/hub/internal/signin"
)

// Kind is an entry's kind.
type Kind string

// The kinds (contract §8.2); impersonation is Source 4 (part 3).
const (
	KindSignIn        Kind = "sign_in"
	KindStepUp        Kind = "step_up"
	KindFailed        Kind = "failed"
	KindConfirmed     Kind = "confirmed"
	KindOpened        Kind = "opened"
	KindHelp          Kind = "help"
	KindCertificate   Kind = "certificate"
	KindImpersonation Kind = "impersonation"
)

// Entry is one line of a person's history. Methods is never nil (JSON
// []); Score is ScoreOfSet(Methods), nil when there are none.
type Entry struct {
	Time    time.Time       `json:"time"`
	Kind    Kind            `json:"kind"`
	Methods []signin.Method `json:"methods"`
	Score   *signin.Score   `json:"score"`
	App     string          `json:"app"`
	IP      string          `json:"ip"`
	Browser string          `json:"browser"`
	By      string          `json:"by"`
	Reason  string          `json:"reason"`
	Detail  string          `json:"detail"`
}

// Source is one source of entries: user's entries with since <= time <
// before, newest first (equal times in a stable order: a larger limit
// answers a longer prefix of the same list), at most limit — the history
// passes limit+1 itself, a source adds nothing. An error is the whole
// source's: the history names it unknown and shows the others — except
// *Partial.
type Source interface {
	Entries(ctx context.Context, user string, since, before time.Time, limit int) ([]Entry, error)
}

// Partial is the error of a source that read only the newer part of its
// window (a read budget ran out): the entries it returns with it are
// every entry with Through < time < before, and none older was read. The
// history then ends its page after Through and continues from there,
// never losing what wasn't read.
type Partial struct {
	Through time.Time
	Why     string
}

func (p *Partial) Error() string {
	return "read down to " + p.Through.UTC().Format(time.RFC3339Nano) + " only: " + p.Why
}

// Incomplete is the error of a source that shows what it could tell but
// may be missing entries anywhere in its window (the impersonation
// source when the audit scan didn't reach the oldest start its kept
// records don't cover): the history shows its entries and names it in
// Unknown.
type Incomplete struct{ Why string }

func (e *Incomplete) Error() string { return "possibly incomplete: " + e.Why }

// SetupLinkDetail is the detail of a sign-in through a setup link (a
// LOGIN with pc_kind sign_in and no method: the link signed the person
// in, no method did). Such an entry is never shown as a methodless
// sign-in.
const SetupLinkDetail = "Setup link used"

// Clip limits (runes).
const (
	maxUA     = 256
	maxIP     = 64
	maxApp    = 128
	maxBy     = 128
	maxDetail = 300
)

// Clean is s for display data: control and bidi-formatting characters
// (and invalid UTF-8) removed, at most n runes, trimmed.
func Clean(s string, n int) string {
	var b strings.Builder
	runes := 0
	for _, r := range s {
		if runes >= n {
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			continue
		}
		b.WriteRune(r)
		runes++
	}
	return strings.TrimSpace(b.String())
}

// IP is s as an IP address (normalised, without a zone), "" when it
// isn't one.
func IP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(Clean(s, maxIP)))
	if err != nil {
		return ""
	}
	return a.WithZone("").String()
}

// Browser is the User-Agent's browser and OS ("Firefox · macOS"; the
// name alone when the OS is unknown), or "" when the browser is unknown.
func Browser(ua string) string {
	ua = Clean(ua, maxUA)
	if ua == "" {
		return ""
	}
	p := useragent.Parse(ua)
	name := Clean(p.Name, 64)
	if name == "" {
		return ""
	}
	if os := Clean(p.OS, 64); os != "" {
		return name + " · " + os
	}
	return name
}

// Methods are the method ids of ids that are methods, once each, in the
// method table's order (never nil).
func Methods(ids []string) []signin.Method {
	seen := map[signin.Method]bool{}
	for _, id := range ids {
		if _, ok := signin.InfoOf(signin.Method(strings.TrimSpace(id))); ok {
			seen[signin.Method(strings.TrimSpace(id))] = true
		}
	}
	out := []signin.Method{}
	for _, m := range signin.Methods {
		if seen[m] {
			out = append(out, m)
		}
	}
	return out
}

// splitMethods is a comma-joined pc_methods / pc_session value's methods.
func splitMethods(s string) []signin.Method {
	if s == "" {
		return []signin.Method{}
	}
	return Methods(strings.Split(s, ","))
}

// withScore sets e's score from its methods (and Methods to [] if nil).
func withScore(e Entry) Entry {
	if e.Methods == nil {
		e.Methods = []signin.Method{}
	}
	e.Score = signin.ScoreOfSet(e.Methods)
	return e
}
