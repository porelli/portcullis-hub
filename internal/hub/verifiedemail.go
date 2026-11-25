package hub

import (
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/templates"
)

// The verified_email option type (contract §13.2, §13.7, §9.8): each
// member's verified email, read from the directory snapshot at delivery
// time (Membership.VerifiedEmails: only a record that still holds the
// person's current LLDAP email), into the people section of the data
// files it is delivered to. A member without one is left out of such a
// file entirely (no people entry, no tsv row, out of expanded member
// lists and entries). No admin value exists (hubSetOption). A verification
// or a dropped one changes the directory (OnChange), so the membership
// delivery follows and rewrites the file. The list is personal data: it
// is never logged.

// verifiedEmailOptions are t's verified_email options.
func verifiedEmailOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Type == templates.TypeVerifiedEmail {
			out = append(out, &opts[i])
		}
	}
	return out
}

// targetCarriesVerifiedEmail: a verified_email option delivers into
// target (a data file; never a hook's stdin: the type takes no hook
// delivery).
func targetCarriesVerifiedEmail(t *templates.Template, target docTarget) bool {
	for _, o := range verifiedEmailOptions(t) {
		if len(target.deliveries(o)) > 0 {
			return true
		}
	}
	return false
}

// withVerifiedEmail are the users of members who have a verified email in
// m (order kept, never nil).
func withVerifiedEmail(members []string, m *directory.Membership) []string {
	out := []string{}
	for _, u := range members {
		if m != nil && m.VerifiedEmails[u] != "" {
			out = append(out, u)
		}
	}
	return out
}

// noVerifiedEmailLocked are the members of t's population in m without a
// verified email (sorted usernames; nil when t has no verified_email
// option or m is nil): the panel's population.no_verified_email. Caller
// holds mu (read).
func (h *Hub) noVerifiedEmailLocked(t *templates.Template, m *directory.Membership) []string {
	if m == nil || len(verifiedEmailOptions(t)) == 0 {
		return nil
	}
	out := []string{}
	for _, p := range h.populationLocked(t, m).People {
		if m.VerifiedEmails[p.User] == "" {
			out = append(out, p.User)
		}
	}
	return out
}
