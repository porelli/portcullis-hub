package directory

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

// What the Hub's app settings need from the directory (contract §13,
// spec calls 9, 27–29): who is in which group with which LLDAP group id,
// which memberships have expired but aren't removed yet, and which
// groups may hold privileged values. Read-only; never under the Hub's
// lock (the Hub calls it before taking it).

// MemberGroup is one LLDAP group: its id and its members (lowercase,
// sorted; the Hub's service account excluded).
type MemberGroup struct {
	ID      int
	Members []string
}

// Membership is a snapshot of LLDAP's groups for per-person settings.
type Membership struct {
	// Users: every LLDAP user but the Hub's service account (lowercase)
	// → group name → LLDAP group id (empty for a user in no group).
	Users map[string]map[string]int
	// Groups: group name → id and members.
	Groups map[string]MemberGroup
	// Expired: user → group for the memberships whose expiry (manual
	// expiry, an "added" exception's end, a grace entry) is past but the
	// evaluator hasn't removed yet — group-gate already denies them
	// (the published expiring list, contract §4).
	Expired map[string]map[string]bool
	// Privilege: group → why it can't hold a privileged value
	// (PrivilegeProblem); absent = it may.
	Privilege map[string]string
	// UUIDs: lowercase user → LLDAP account uuid (the service account
	// excluded): a name deleted and re-created gets a new one (spec call
	// 32: a person-entered value is bound to the uuid it was entered
	// under).
	UUIDs map[string]string
	// Emails: lowercase user → LLDAP email (the service account
	// excluded; "" = none). Only the gate file's people (identity_headers,
	// contract §15.4) uses it: identity is the username, never the email.
	Emails map[string]string
	// Pending: user → group → the earliest expiry still ahead of now
	// (contract §15.4 expiring: the gate refuses from that time on, even
	// before the evaluator removes the membership).
	Pending map[string]map[string]time.Time
}

// Membership reads LLDAP and directory.yaml. LLDAP unavailable: 503;
// unreachable: 502; directory.yaml unreadable: 503 (the expiries are
// needed: fail closed). No store: no rule groups, no expiries.
func (s *Service) Membership(ctx context.Context, now time.Time) (*Membership, error) {
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	cfg := &Config{Groups: map[string]*GroupConfig{}, Permissions: map[string]string{}}
	if s.Store != nil {
		var err error
		if cfg, err = s.loadConfig(); err != nil {
			return nil, err
		}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	svc := strings.ToLower(s.serviceUser())
	m := &Membership{Users: map[string]map[string]int{}, Groups: map[string]MemberGroup{}, Expired: map[string]map[string]bool{}, Privilege: map[string]string{}, UUIDs: map[string]string{},
		Emails: map[string]string{}, Pending: map[string]map[string]time.Time{}}
	for id, u := range sn.users {
		if id != svc {
			m.Users[id] = map[string]int{}
			m.UUIDs[id] = u.UUID
			m.Emails[id] = u.Email
		}
	}
	for name, g := range sn.groups {
		mg := MemberGroup{ID: g.ID, Members: []string{}}
		for _, u := range g.Members() {
			u = strings.ToLower(u)
			if u == svc {
				continue
			}
			mg.Members = append(mg.Members, u)
			if m.Users[u] != nil {
				m.Users[u][name] = g.ID
			}
		}
		sort.Strings(mg.Members)
		m.Groups[name] = mg
		if p := privilegeProblem(cfg, name); p != "" {
			m.Privilege[name] = p
		}
	}
	for _, e := range s.publishedExpiring(cfg, sn, now) {
		if e.At.After(now) {
			if m.Pending[e.User] == nil {
				m.Pending[e.User] = map[string]time.Time{}
			}
			if at, ok := m.Pending[e.User][e.Group]; !ok || e.At.Before(at) {
				m.Pending[e.User][e.Group] = e.At
			}
			continue
		}
		if m.Expired[e.User] == nil {
			m.Expired[e.User] = map[string]bool{}
		}
		m.Expired[e.User][e.Group] = true
	}
	return m, nil
}

// PrivilegeProblem says why group can't hold a privileged option's
// per-group value (spec call 9): "" for a manual group or a rule group
// whose rule uses admin-only fields only and doesn't match a person with
// no details. A missing group is a 404; LLDAP unavailable 503.
func (s *Service) PrivilegeProblem(ctx context.Context, group string) (string, error) {
	if err := s.LLDAP.Available(); err != nil {
		return "", &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	cfg := &Config{Groups: map[string]*GroupConfig{}}
	if s.Store != nil {
		var err error
		if cfg, err = s.loadConfig(); err != nil {
			return "", err
		}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return "", err
	}
	if _, err := sn.group(group); err != nil {
		return "", err
	}
	return privilegeProblem(cfg, group), nil
}

// privilegeProblem is PrivilegeProblem on cfg.
func privilegeProblem(cfg *Config, group string) string {
	gc := cfg.Groups[group]
	if gc == nil || gc.Rule == nil {
		return ""
	}
	if bad := nonAdminOnly(cfg, gc.Rule); len(bad) > 0 {
		return "its rule uses fields delegates can edit: " + strings.Join(bad, ", ")
	}
	if matchesEmpty(cfg, gc.Rule) {
		return "its rule matches a person with no details at all (e.g. a new account)"
	}
	return ""
}
