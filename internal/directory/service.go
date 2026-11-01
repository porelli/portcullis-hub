// Package directory is the Hub's user and group management (integration
// contract §9): LLDAP users/groups and passwords through internal/lldap,
// the Keycloak side (import, required actions, passkeys, sessions) through
// internal/keycloak, guardrails, and an append-only audit log.
package directory

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// CoreAdmin is LLDAP's bootstrap admin (core sets LLDAP_LDAP_USER_DN=admin).
// Keycloak's LDAP federation and enroll bind as it with LLDAP_ADMIN_PASSWORD,
// and whoever gets an invite or passkey reset for it owns the root account,
// so the Hub never changes it in any way: it is managed (and recovered)
// from the server only.
const CoreAdmin = "admin"

// DefaultServiceUser is the Hub's own LLDAP account (§9).
const DefaultServiceUser = "portcullis-hub"

// builtinGroups are LLDAP's own groups; the Hub never deletes them.
var builtinGroups = map[string]bool{lldap.AdminGroup: true, "lldap_password_manager": true, "lldap_strict_readonly": true}

// Directory is the LLDAP side (implemented by *lldap.Client).
type Directory interface {
	Available() error
	ServiceUser() string
	ListUsers(ctx context.Context) ([]lldap.User, error)
	ListGroups(ctx context.Context) ([]lldap.Group, error)
	CreateUser(ctx context.Context, id, email, displayName string) error
	UpdateUser(ctx context.Context, id string, email, displayName *string) error
	DeleteUser(ctx context.Context, id string) error
	CreateGroup(ctx context.Context, name string) (int, error)
	DeleteGroup(ctx context.Context, id int) error
	AddUserToGroup(ctx context.Context, user string, group int) error
	RemoveUserFromGroup(ctx context.Context, user string, group int) error
	SetPassword(ctx context.Context, user, password string) error
	UserAttributes(ctx context.Context) ([]lldap.Attribute, error)
	AddUserAttribute(ctx context.Context, name string, isList bool) error
	DeleteUserAttribute(ctx context.Context, name string) error
	SetUserAttributes(ctx context.Context, user string, set map[string][]string, remove []string) error
}

// Keycloak is the Keycloak side (implemented by *keycloak.Client).
type Keycloak interface {
	UserStatuses(ctx context.Context) (map[string]keycloak.UserStatus, error)
	ListedUser(ctx context.Context, username string) (*keycloak.UserStatus, error)
	ImportUser(ctx context.Context, username string) (string, error)
	RequirePasskey(ctx context.Context, username string) error
	SetUserRequiredActions(ctx context.Context, username string, actions []string) error
	RemovePasskeys(ctx context.Context, username string, requireNew bool) (int, error)
	CredentialCount(ctx context.Context, username string) (int, error)
	LogoutUser(ctx context.Context, username string) error
	DeleteUserByID(ctx context.Context, id string) error
}

// Inviter creates one-time onboarding links (implemented by *invite.Client).
type Inviter interface {
	Available() error
	Create(ctx context.Context, username string) (*invite.Invite, error)
}

// App is what the service needs to know about a template.
type App struct {
	ID, Name                string
	Enabled                 bool
	AccessGroup, AdminGroup string
}

// Service implements the user/group operations. Mutations are serialised
// so guardrail checks and the change can't interleave with another change.
type Service struct {
	LLDAP Directory
	KC    Keycloak // nil: Keycloak features unavailable
	// Invites: nil or unavailable means only the password fallback works.
	Invites Inviter
	Audit   *AuditLog
	Apps    func() []App
	// AdminGroups returns the groups whose members are administrators:
	// core refuses to invite them (§9.4) and the Hub asks for a typed
	// confirmation before handing over their sign-in. nil: lldap_admin and
	// lldap_password_manager (see ProtectedGroups).
	AdminGroups func() map[string]bool
	// KeycloakTimeout bounds the Keycloak part of Overview (0:
	// DefaultKeycloakTimeout); past it the page renders without the
	// statuses still missing.
	KeycloakTimeout time.Duration
	// Store for directory.yaml (custom fields, rules, etc.); nil: field
	// operations return 503.
	Store *Store
	// OnChange, if set, is called (outside the service lock) after every
	// successful mutation and every evaluation that changed a membership
	// or pruned directory.yaml, so the Hub republishes expiries and user
	// attributes (contract §4, §4.1) and the Keycloak mappers (§9.6). It
	// must not block: the Hub coalesces calls into one background sync.
	OnChange func()

	mu sync.Mutex
	// ruleState: each rule group's membership (lowercase) after the last
	// evaluation, to tell outside changes from rule changes. Guarded by mu.
	ruleState map[string]map[string]bool
	kickOnce  sync.Once
	kickCh    chan struct{}
	// The snapshot PreviewRule shares for previewTTL (previewSnapshot).
	previewMu sync.Mutex
	previewSn *snapshot
	previewAt time.Time
}

// Error carries an HTTP status for the API layer.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func refuse(format string, a ...interface{}) error {
	return &Error{Status: http.StatusConflict, Msg: fmt.Sprintf(format, a...)}
}
func invalid(format string, a ...interface{}) error {
	return &Error{Status: http.StatusBadRequest, Msg: fmt.Sprintf(format, a...)}
}
func notFound(format string, a ...interface{}) error {
	return &Error{Status: http.StatusNotFound, Msg: fmt.Sprintf(format, a...)}
}

// ── read side ─────────────────────────────────────────────

func (s *Service) adminGroups() map[string]bool {
	if s.AdminGroups != nil {
		return s.AdminGroups()
	}
	return ProtectedGroups("", "")
}

// recoverMsg is shown wherever an administrator would need an invite.
func recoverMsg(user string) string {
	return "administrators are recovered from the server: ./portcullis invite " + user
}

// DefaultKeycloakTimeout bounds the Keycloak part of Overview.
const DefaultKeycloakTimeout = 15 * time.Second

// KeycloakView is a user's Keycloak state. Imported false: Keycloak has
// no copy yet (LDAP users are imported at first sign-in).
type KeycloakView struct {
	Imported        bool     `json:"imported"`
	Enabled         bool     `json:"enabled"`
	RequiredActions []string `json:"required_actions"`
	Passkeys        int      `json:"passkeys"`
	// Error: this user's status couldn't be read (Passkeys unknown); the
	// other rows are unaffected.
	Error string `json:"error,omitempty"`
}

// StaleRecord is a Keycloak user imported from the LDAP federation whose
// LLDAP entry no longer exists (deleted outside the Hub). Keycloak keeps
// the copy and typically answers 404/500 for it.
type StaleRecord struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	Reason   string `json:"reason"`
}

// UserView is one row of the users table.
type UserView struct {
	Username    string        `json:"username"`
	Email       string        `json:"email"`
	DisplayName string        `json:"display_name"`
	Created     string        `json:"created"`
	Groups      []string      `json:"groups"`
	Keycloak    *KeycloakView `json:"keycloak,omitempty"` // nil: Keycloak unreachable (or not an admin's view)
	// Protected: "service" (the Hub's account) or "core-admin" (the
	// bootstrap admin): both read-only here. "" otherwise.
	Protected string `json:"protected,omitempty"`
	Self      bool   `json:"self,omitempty"`
	// Admin: member of an administrator group (AdminGroups). No invites
	// from the Hub (core refuses them); recover with ServerInvite.
	Admin        bool                `json:"admin,omitempty"`
	ServerInvite string              `json:"server_invite,omitempty"`
	Attrs        map[string][]string `json:"attrs,omitempty"` // custom attributes that are defined fields
	// Memberships: one per group in Groups, with how it is held.
	Memberships []Membership `json:"memberships"`
	// CreatedBy: the delegate who invited this account (until an admin
	// takes it over), so rule memberships can say "account created by X".
	CreatedBy string `json:"created_by,omitempty"`
}

// How a membership is held (Membership.How).
const (
	HowManual    = "manual"    // added by hand (manual group), or a rule group member the rule doesn't (yet) explain
	HowRule      = "rule"      // the group's rule matches
	HowException = "exception" // an active "added" exception of a rule group
)

// Membership is one group of a user and how they are in it.
type Membership struct {
	Group  string     `json:"group"`
	How    string     `json:"how"`              // manual | rule | exception
	Reason string     `json:"reason,omitempty"` // exception: its reason
	Until  *time.Time `json:"until,omitempty"`  // manual expiry or exception end (UTC)
}

// RuleView is a rule group's rule, as canonical text and as a tree.
type RuleView struct {
	Text string      `json:"text"`
	Expr *rules.Expr `json:"expr"`
}

// ExceptionView is one exception of a rule group.
type ExceptionView struct {
	User    string     `json:"user"`
	Reason  string     `json:"reason"`
	By      string     `json:"by"`
	Include bool       `json:"include"` // true: added; false: kept out
	Until   *time.Time `json:"until"`   // nil: permanent
	At      time.Time  `json:"at"`
	Expired bool       `json:"expired,omitempty"`
}

// GroupView is one group.
type GroupView struct {
	Name    string   `json:"name"`
	Created string   `json:"created"`
	Members []string `json:"members"`
	Builtin bool     `json:"builtin,omitempty"`
	Admin   bool     `json:"admin,omitempty"` // an administrator group
	UsedBy  []string `json:"used_by"`         // app ids referencing it
	// RuleAllowed: may become rule-based (not built-in, not an
	// administrator group).
	RuleAllowed bool                 `json:"rule_allowed"`
	Rule        *RuleView            `json:"rule"` // nil: manual group
	Exceptions  []ExceptionView      `json:"exceptions"`
	Expiry      map[string]time.Time `json:"expiry"` // manual groups: username -> until (UTC)
	// AddsBlocked: why the evaluator adds nobody to this guarding group
	// ("" if it does), see addsBlocked.
	AddsBlocked string `json:"adds_blocked,omitempty"`
}

// Suggestion is a group of an ENABLED app that doesn't exist yet.
type Suggestion struct {
	Group   string `json:"group"`
	App     string `json:"app"`
	AppName string `json:"app_name"`
	Kind    string `json:"kind"` // "access" or "admin"
}

// Overview is GET /api/directory.
type Overview struct {
	Available     bool         `json:"available"`
	Reason        string       `json:"reason,omitempty"`
	Me            string       `json:"me"`
	ServiceUser   string       `json:"service_user"`
	Users         []UserView   `json:"users"`
	Groups        []GroupView  `json:"groups"`
	Suggestions   []Suggestion `json:"suggestions"`
	Fields        []Field      `json:"fields"`                 // custom fields, sorted by name
	FieldsError   string       `json:"fields_error,omitempty"` // set when loading directory.yaml fails
	KeycloakError string       `json:"keycloak_error,omitempty"`
	// StaleKeycloak lists Keycloak copies of users LLDAP no longer has
	// (RemoveStaleKeycloakUser removes them).
	StaleKeycloak []StaleRecord `json:"stale_keycloak,omitempty"`
	// InvitesError is set when invite links can't be created (admins only).
	InvitesError string `json:"invites_error,omitempty"`
	// InvitesAvailable: invite links can be created.
	InvitesAvailable bool `json:"invites_available"`
	// Admin and Perms describe the caller (Me): admins hold every
	// delegated permission.
	Admin bool     `json:"admin"`
	Perms []string `json:"perms"`
	// Permissions: delegated permission -> group (directory.yaml).
	Permissions map[string]string `json:"permissions"`
	// Cycles: manager loops in the org chart (usernames).
	Cycles [][]string `json:"cycles"`
}

func (s *Service) serviceUser() string {
	if u := s.LLDAP.ServiceUser(); u != "" {
		return u
	}
	return DefaultServiceUser
}

func (s *Service) protection(user string) string {
	switch strings.ToLower(user) {
	case s.serviceUser():
		return "service"
	case CoreAdmin:
		return "core-admin"
	}
	return ""
}

// Overview lists users, groups and suggestions: the administrator's
// view (everything). An unconfigured LLDAP is not an error: Available is
// false and Reason says why.
func (s *Service) Overview(ctx context.Context, me string) (*Overview, error) {
	return s.overview(ctx, me, nil)
}

// OverviewFor is GET /api/directory for c: administrators get everything
// (Overview); anyone else gets people, groups, fields, rules, exceptions,
// permissions and the org chart's cycles, but no Keycloak or passkey
// state, no stale Keycloak records, no invite internals and no setup
// suggestions (contract §9.6: everyone signed in sees everyone's fields).
func (s *Service) OverviewFor(ctx context.Context, c *Caller) (*Overview, error) {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return nil, errNoActor()
	}
	return s.overview(ctx, c.User, c)
}

// overview builds the Overview; c nil = the full (administrator) view
// with Admin/Perms computed for me, otherwise the view c may see.
func (s *Service) overview(ctx context.Context, me string, c *Caller) (*Overview, error) {
	full := c == nil || c.Admin
	ov := &Overview{Me: me, Users: []UserView{}, Groups: []GroupView{}, Suggestions: []Suggestion{}, StaleKeycloak: []StaleRecord{},
		Fields: []Field{}, Permissions: map[string]string{}, Cycles: [][]string{}, Perms: []string{}}
	if err := s.LLDAP.Available(); err != nil {
		ov.Reason = err.Error()
		return ov, nil
	}
	ov.Available = true
	ov.ServiceUser = s.serviceUser()
	if err := s.invitesAvailable(); err != nil {
		if full {
			ov.InvitesError = err.Error()
		}
	} else {
		ov.InvitesAvailable = true
	}

	// Load fields from Store if available
	var cfg *Config
	var fieldNames map[string]bool
	if s.Store != nil {
		var err error
		cfg, err = s.Store.Load()
		if err != nil {
			ov.FieldsError = "directory.yaml could not be read"
			if full {
				ov.FieldsError = err.Error()
			}
			cfg = nil
		}
		if cfg != nil {
			ov.Fields = make([]Field, len(cfg.Fields))
			copy(ov.Fields, cfg.Fields)
			sort.Slice(ov.Fields, func(i, j int) bool {
				return ov.Fields[i].Name < ov.Fields[j].Name
			})
			// Track which fields are defined
			fieldNames = make(map[string]bool)
			for _, f := range cfg.Fields {
				fieldNames[f.Name] = true
			}
			for p, g := range cfg.Permissions {
				if g != "" && containsString(delegatedPerms, p) {
					ov.Permissions[p] = g
				}
			}
		}
	}

	users, err := s.LLDAP.ListUsers(ctx)
	if err != nil {
		return nil, &Error{Status: http.StatusBadGateway, Msg: err.Error()}
	}
	groups, err := s.LLDAP.ListGroups(ctx)
	if err != nil {
		return nil, &Error{Status: http.StatusBadGateway, Msg: err.Error()}
	}
	sn := snapshotOf(users, groups)
	if c != nil {
		ov.Admin = c.Admin
		for p, ok := range c.Perms {
			if ok {
				ov.Perms = append(ov.Perms, p)
			}
		}
	} else if me != "" {
		ov.Admin = memberOf(sn.groups[lldap.AdminGroup], me)
		for p, g := range ov.Permissions {
			if grp, ok := sn.groups[g]; ok && memberOf(grp, me) {
				ov.Perms = append(ov.Perms, p)
			}
		}
	}
	if ov.Admin {
		ov.Perms = append([]string{}, delegatedPerms...) // admins hold every permission
	}
	sort.Strings(ov.Perms)
	var kc map[string]keycloak.UserStatus
	if full {
		kc = s.keycloakStatuses(ctx, ov)
	}
	admins := s.adminGroups()
	inLLDAP := map[string]bool{}
	for _, u := range users {
		inLLDAP[strings.ToLower(u.ID)] = true
		v := UserView{Username: u.ID, Email: u.Email, DisplayName: u.DisplayName, Created: u.CreationDate, Groups: []string{},
			Protected: s.protection(u.ID), Self: me != "" && strings.EqualFold(me, u.ID), Attrs: map[string][]string{}, Memberships: []Membership{}}
		for _, g := range u.Groups {
			v.Groups = append(v.Groups, g.DisplayName)
			v.Admin = v.Admin || admins[g.DisplayName]
		}
		sort.Strings(v.Groups)
		// Populate Attrs with only defined fields
		if fieldNames != nil && len(u.Attributes) > 0 {
			for name, values := range u.Attributes {
				if fieldNames[name] {
					v.Attrs[name] = values
				}
			}
		}
		if cfg != nil {
			for k, by := range cfg.CreatedBy {
				if strings.EqualFold(k, u.ID) {
					v.CreatedBy = by
				}
			}
		}
		if full && v.Admin && v.Protected != "service" {
			v.ServerInvite = "./portcullis invite " + u.ID
		}
		// The service account is excluded from Keycloak's federation: no
		// Keycloak status to show. A user missing from kc was never
		// imported (not signed in yet): Imported false, no error.
		if kc != nil && v.Protected != "service" {
			st, ok := kc[strings.ToLower(u.ID)]
			v.Keycloak = &KeycloakView{Imported: ok, Enabled: st.Enabled, RequiredActions: st.RequiredActions, Passkeys: st.Passkeys, Error: st.Error}
			if v.Keycloak.RequiredActions == nil {
				v.Keycloak.RequiredActions = []string{}
			}
		}
		ov.Users = append(ov.Users, v)
	}
	for name, st := range kc {
		if !st.LDAPFederated || inLLDAP[name] || s.checkTarget(name) != nil {
			continue
		}
		reason := "imported from LDAP, but LLDAP has no such user"
		if st.Error != "" {
			reason += " (Keycloak: " + st.Error + ")"
		}
		ov.StaleKeycloak = append(ov.StaleKeycloak, StaleRecord{Username: st.Username, ID: st.ID, Reason: reason})
	}
	sort.Slice(ov.StaleKeycloak, func(i, j int) bool { return ov.StaleKeycloak[i].Username < ov.StaleKeycloak[j].Username })
	sort.Slice(ov.Users, func(i, j int) bool { return ov.Users[i].Username < ov.Users[j].Username })

	var apps []App
	if s.Apps != nil {
		apps = s.Apps()
	}
	have := map[string]bool{}
	for _, g := range groups {
		gv := GroupView{Name: g.DisplayName, Created: g.CreationDate, Members: g.Members(), Builtin: builtinGroups[g.DisplayName], Admin: admins[g.DisplayName], UsedBy: []string{},
			RuleAllowed: s.ruleGroupAllowed(g.DisplayName, admins), Exceptions: []ExceptionView{}, Expiry: map[string]time.Time{}}
		sort.Strings(gv.Members)
		for _, a := range apps {
			if a.AccessGroup == g.DisplayName || a.AdminGroup == g.DisplayName {
				gv.UsedBy = append(gv.UsedBy, a.ID)
			}
		}
		have[g.DisplayName] = true
		ov.Groups = append(ov.Groups, gv)
	}
	sort.Slice(ov.Groups, func(i, j int) bool { return ov.Groups[i].Name < ov.Groups[j].Name })
	if cfg != nil {
		s.addGroupConfig(ov, cfg, sn, admins, time.Now().UTC())
	}
	if !full {
		return ov, nil
	}
	// Suggest only groups of apps that are enabled: templates you don't use
	// have no business in the directory.
	seen := map[string]bool{}
	for _, a := range apps {
		if !a.Enabled {
			continue
		}
		for _, c := range []struct{ group, kind string }{{a.AccessGroup, "access"}, {a.AdminGroup, "admin"}} {
			if c.group == "" || have[c.group] || seen[c.group] || !lldap.ValidGroupName(c.group) {
				continue
			}
			seen[c.group] = true
			ov.Suggestions = append(ov.Suggestions, Suggestion{Group: c.group, App: a.ID, AppName: a.Name, Kind: c.kind})
		}
	}
	sort.Slice(ov.Suggestions, func(i, j int) bool {
		return ov.Suggestions[i].Group < ov.Suggestions[j].Group
	})
	return ov, nil
}

// addGroupConfig adds what directory.yaml says about groups to ov: each
// group's rule, exceptions and expiries, every user's memberships with
// how they hold them, and the manager cycles of the org chart.
func (s *Service) addGroupConfig(ov *Overview, cfg *Config, sn *snapshot, admins map[string]bool, now time.Time) {
	d := ruleDirectory(cfg, sn)
	if cy := rules.Cycles(d); cy != nil {
		for _, c := range cy {
			ids := make([]string, len(c))
			for i, u := range c {
				ids[i] = u
				if su, ok := sn.users[strings.ToLower(u)]; ok {
					ids[i] = su.ID
				}
			}
			ov.Cycles = append(ov.Cycles, ids)
		}
	}
	guarding := s.guardingGroups(cfg)
	evals := map[string]*groupEval{}
	for i := range ov.Groups {
		gv := &ov.Groups[i]
		gc := cfg.Groups[gv.Name]
		if gc == nil {
			continue
		}
		if gc.Rule != nil {
			gv.Rule = &RuleView{Text: rules.Format(gc.Rule), Expr: gc.Rule}
			gv.AddsBlocked = s.addsBlocked(cfg, guarding, gv.Name, gc)
			if s.ruleGroupAllowed(gv.Name, admins) {
				evals[gv.Name] = s.evalGroup(gc, d, sn, now)
			}
		}
		for _, ex := range gc.Exceptions {
			gv.Exceptions = append(gv.Exceptions, ExceptionView{User: ex.User, Reason: ex.Reason, By: ex.By, Include: ex.Include, Until: ex.Until, At: ex.At,
				Expired: ex.Until != nil && expired(*ex.Until, now)})
		}
		for u, at := range gc.Expiry {
			gv.Expiry[u] = at.UTC()
		}
	}
	for i := range ov.Users {
		uv := &ov.Users[i]
		id := strings.ToLower(uv.Username)
		for _, g := range uv.Groups {
			m := Membership{Group: g, How: HowManual}
			if ge := evals[g]; ge != nil {
				switch {
				case ge.include[id]:
					m.How = HowException
					for _, ex := range ge.kept {
						if ex.Include && strings.EqualFold(ex.User, id) {
							m.Reason, m.Until = ex.Reason, ex.Until
						}
					}
				case ge.matched[id]:
					m.How = HowRule
				}
			} else if gc := cfg.Groups[g]; gc != nil && gc.Rule == nil {
				for u, at := range gc.Expiry {
					if strings.EqualFold(u, id) {
						until := at.UTC()
						m.Until = &until
					}
				}
			}
			uv.Memberships = append(uv.Memberships, m)
		}
	}
}

// keycloakStatuses fetches every Keycloak user's status within the
// Keycloak timeout. Realm-level failures (Keycloak down) set the one
// banner, ov.KeycloakError, and return nil; per-user failures stay in the
// user's status.
func (s *Service) keycloakStatuses(ctx context.Context, ov *Overview) map[string]keycloak.UserStatus {
	if s.KC == nil {
		ov.KeycloakError = "Keycloak admin API not configured"
		return nil
	}
	d := s.KeycloakTimeout
	if d <= 0 {
		d = DefaultKeycloakTimeout
	}
	kctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	kc, err := s.KC.UserStatuses(kctx)
	switch {
	case err != nil:
		ov.KeycloakError = err.Error()
		return nil
	case kctx.Err() != nil:
		ov.KeycloakError = fmt.Sprintf("Keycloak didn't answer within %s: some users' status is missing", d)
	}
	return kc
}

// Recent returns the last n audit entries, newest first.
func (s *Service) Recent(n int) ([]AuditEntry, error) {
	if s.Audit == nil {
		return []AuditEntry{}, nil
	}
	return s.Audit.Recent(n)
}

// ── mutation plumbing ─────────────────────────────────────

// snapshot is the directory state guardrails are checked against.
type snapshot struct {
	users  map[string]lldap.User // by lowercase id
	groups map[string]lldap.Group
}

func (s *Service) load(ctx context.Context) (*snapshot, error) {
	users, err := s.LLDAP.ListUsers(ctx)
	if err != nil {
		return nil, &Error{Status: http.StatusBadGateway, Msg: err.Error()}
	}
	groups, err := s.LLDAP.ListGroups(ctx)
	if err != nil {
		return nil, &Error{Status: http.StatusBadGateway, Msg: err.Error()}
	}
	return snapshotOf(users, groups), nil
}

func snapshotOf(users []lldap.User, groups []lldap.Group) *snapshot {
	sn := &snapshot{users: map[string]lldap.User{}, groups: map[string]lldap.Group{}}
	for _, u := range users {
		sn.users[strings.ToLower(u.ID)] = u
	}
	for _, g := range groups {
		sn.groups[g.DisplayName] = g
	}
	return sn
}

func (sn *snapshot) user(name string) (lldap.User, error) {
	u, ok := sn.users[strings.ToLower(name)]
	if !ok {
		return u, notFound("no such user %q", name)
	}
	return u, nil
}

func (sn *snapshot) group(name string) (lldap.Group, error) {
	g, ok := sn.groups[name]
	if !ok {
		return g, notFound("no such group %q", name)
	}
	return g, nil
}

// humanAdmins are lldap_admin members other than the service account.
func (s *Service) humanAdmins(sn *snapshot) []string {
	var out []string
	for _, m := range sn.groups[lldap.AdminGroup].Members() {
		if !strings.EqualFold(m, s.serviceUser()) {
			out = append(out, strings.ToLower(m))
		}
	}
	return out
}

// checkNotLastAdmin refuses if user is the only human lldap_admin member.
func (s *Service) checkNotLastAdmin(sn *snapshot, user string) error {
	admins := s.humanAdmins(sn)
	for _, a := range admins {
		if a == strings.ToLower(user) && len(admins) == 1 {
			return refuse("%s is the last remaining %s member; add another administrator first", user, lldap.AdminGroup)
		}
	}
	return nil
}

// checkTarget refuses every change to the service account and the
// bootstrap admin. Every operation that targets a user calls it first.
func (s *Service) checkTarget(user string) error {
	switch {
	case strings.EqualFold(user, s.serviceUser()) || strings.EqualFold(user, DefaultServiceUser):
		return refuse("%s is the Hub's own service account and can't be changed here", user)
	case strings.EqualFold(user, CoreAdmin):
		return refuse("%s is the bootstrap LLDAP admin (Keycloak and enroll bind as it) and can't be changed from the Hub; the bootstrap admin is recovered from the server: ./portcullis invite admin", CoreAdmin)
	}
	return nil
}

// isAdmin reports whether user is in an administrator group.
func (s *Service) isAdmin(sn *snapshot, user string) bool {
	for name := range s.adminGroups() {
		for _, m := range sn.groups[name].Members() {
			if strings.EqualFold(m, user) {
				return true
			}
		}
	}
	return false
}

// checkAdminTakeover: a password or passkey reset for ANOTHER
// administrator hands the acting admin that account — allowed, but only
// with the target's name typed again, and flagged in the audit entry.
func (s *Service) checkAdminTakeover(sn *snapshot, actor, user, confirm string, detail *string) error {
	if !s.isAdmin(sn, user) || strings.EqualFold(actor, user) {
		return nil
	}
	*detail = strings.TrimSpace(*detail + " target_is_lldap_admin=true")
	if confirm != user {
		return invalid("%s is an administrator: type the username to confirm", user)
	}
	return nil
}

// checkInvitable: core refuses invites for administrators (§9.4), so
// the Hub doesn't ask — not even for the acting admin themselves.
func (s *Service) checkInvitable(sn *snapshot, user string) error {
	if s.isAdmin(sn, user) {
		return refuse("%s is an administrator; %s", user, recoverMsg(user))
	}
	return nil
}

// inviteErr turns core's 409 into the server-side recovery message.
func inviteErr(user string, err error) error {
	var ae *invite.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict {
		msg := recoverMsg(user)
		if ae.Message != "" {
			msg = ae.Message + " — " + msg
		}
		return refuse("invite refused by core: %s", msg)
	}
	return err
}

func clip(s string) string { return clipN(s, 128) }

// maxAuditDetail bounds an audit entry's detail (bytes).
const maxAuditDetail = 2048

// clipN drops control characters and cuts s to at most n bytes (on a rune
// boundary), marking a cut with "…".
func clipN(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := 0
	for i := range s {
		if i > n {
			break
		}
		cut = i
	}
	return s[:cut] + "…"
}

// run serialises a mutation, checks the caller, availability and the
// caller's permission perm on target (gate; "admin" = admins only), and
// writes the audit entry — refusals included.
func (s *Service) run(ctx context.Context, c *Caller, perm, action, target string, detail *string, fn func() error) error {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return errNoActor()
	}
	defer s.kick() // re-evaluate rule groups after every mutation
	done := false
	defer func() {
		if done {
			s.changed() // runs after the unlock below
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.LLDAP.Available()
	if err != nil {
		err = &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	} else if err = s.gate(ctx, c, perm, target); err == nil {
		err = fn()
		done = err == nil
	}
	if s.Audit != nil {
		e := AuditEntry{Actor: clip(c.User), Action: action, Target: clip(target), Result: "ok"}
		if detail != nil {
			e.Detail = clipN(*detail, maxAuditDetail)
		}
		var de *Error
		switch {
		case errors.As(err, &de) && de.Status < 500:
			e.Result, e.Error = "refused", clip(err.Error())
		case err != nil:
			e.Result, e.Error = "error", clip(err.Error())
		}
		if aerr := s.Audit.Append(e); aerr != nil && err == nil {
			// The change happened; say the audit write failed.
			return fmt.Errorf("%s done, but writing the audit log failed: %v", action, aerr)
		}
	}
	return err
}

// regranted records an admin's explicit (re-)add of user to group: its
// grace entry and its expired exceptions in that group (kept while the
// evaluator doesn't manage the group, see pruneSkipped) go, so access is
// restored; reports whether anything went. No store: nothing to do.
// Caller holds s.mu.
func (s *Service) regranted(group, user string, now time.Time) (bool, error) {
	if s.Store == nil {
		return false, nil
	}
	cfg, err := s.loadConfig()
	if err != nil {
		return false, fmt.Errorf("%s added to %s, but directory.yaml could not be read to end its earlier expiry (it may keep denying): %w", user, group, err)
	}
	changed := cfg.clearGrace(group, user)
	if gc := cfg.Groups[group]; gc != nil {
		kept := []Exception{}
		for _, ex := range gc.Exceptions {
			if strings.EqualFold(ex.User, user) && ex.Until != nil && expired(*ex.Until, now) {
				changed = true
				continue
			}
			kept = append(kept, ex)
		}
		gc.Exceptions = kept
	}
	if !changed {
		return false, nil
	}
	if err := s.saveConfig(cfg); err != nil {
		return false, fmt.Errorf("%s added to %s, but its earlier expiry could not be cleared in directory.yaml (it may keep denying): %w", user, group, err)
	}
	return true, nil
}

// GeneratePassword returns a random password (26 base32 chars, 130 bits).
func GeneratePassword() string { return rand.Text() }

// ── users ─────────────────────────────────────────────────

// Onboarding modes.
const (
	OnboardInvite   = "invite"   // one-time link: register a passkey, signed in
	OnboardPassword = "password" // fallback: the admin hands over a password
)

// CreateRequest is POST /api/directory/users.
type CreateRequest struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
	// Onboarding is "invite" (default) or "password". The password fields
	// apply only to "password".
	Onboarding     string `json:"onboarding"`
	Password       string `json:"password"`          // used if !Generate
	Generate       bool   `json:"generate_password"` // show a random one once
	RequirePasskey bool   `json:"require_passkey"`   // add the registration action
}

// Result reports a one-time invite or generated password (shown once) and
// partial failures.
type Result struct {
	Invite   *invite.Invite `json:"invite,omitempty"`
	Password string         `json:"password,omitempty"`
	// ServerInvite: run this on the server to onboard an administrator.
	ServerInvite string   `json:"server_invite,omitempty"`
	Warnings     []string `json:"warnings"`
	Count        int      `json:"count,omitempty"`
}

func (s *Service) invitesAvailable() error {
	if s.Invites == nil {
		return invite.ErrNotConfigured
	}
	return s.Invites.Available()
}

// newInvite asks core for a link; caller holds s.mu.
func (s *Service) newInvite(ctx context.Context, username string) (*invite.Invite, error) {
	if err := s.invitesAvailable(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	inv, err := s.Invites.Create(ctx, username)
	return inv, inviteErr(username, err)
}

func newResult() *Result { return &Result{Warnings: []string{}} }

// CreateUser creates a user and onboards them: by default with a one-time
// invite link (no password at all), or — fallback — with a password and
// optionally the passkey registration action.
func (s *Service) CreateUser(ctx context.Context, c *Caller, req CreateRequest) (*Result, error) {
	res := newResult()
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Onboarding == "" {
		req.Onboarding = OnboardInvite
	}
	detail := fmt.Sprintf("onboarding=%s email=%s groups=%s", req.Onboarding, req.Email, strings.Join(req.Groups, ","))
	if req.Onboarding == OnboardPassword {
		detail += fmt.Sprintf(" require_passkey=%v generated_password=%v", req.RequirePasskey, req.Generate)
	}
	err := s.run(ctx, c, PermInvite, "user.create", req.Username, &detail, func() error {
		switch {
		case !lldap.ValidUsername(req.Username):
			return invalid("invalid username: use 1-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
		case strings.EqualFold(req.Username, s.serviceUser()) || req.Username == CoreAdmin || req.Username == DefaultServiceUser:
			return invalid("%q is reserved", req.Username)
		case !lldap.ValidEmail(req.Email):
			return invalid("invalid email address")
		case !lldap.ValidDisplayName(req.DisplayName):
			return invalid("display name: at most 128 printable characters")
		}
		if !c.Admin {
			// Delegates onboard by invite only, into no group: group
			// membership is admins only (rule groups do the rest).
			if len(req.Groups) > 0 {
				return invalid("groups can only be set by an administrator")
			}
			if req.Onboarding != OnboardInvite {
				return forbidden("not allowed: delegates onboard with an invite link (password onboarding: admins only)")
			}
		}
		pw := ""
		switch req.Onboarding {
		case OnboardInvite: // availability checked below, once the groups are known
		case OnboardPassword:
			pw = req.Password
			if req.Generate {
				pw = GeneratePassword()
			} else if !lldap.ValidPassword(pw) {
				return invalid("password must be %d-%d characters without control characters", lldap.MinPasswordLen, lldap.MaxPasswordLen)
			}
		default:
			return invalid("onboarding must be %q or %q", OnboardInvite, OnboardPassword)
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		if _, ok := sn.users[req.Username]; ok {
			return refuse("user %q already exists", req.Username)
		}
		if other := emailTaken(sn, req.Email, ""); other != "" {
			return refuse("email %s is already used by %s", req.Email, other)
		}
		var cfg *Config
		if s.Store != nil {
			if cfg, err = s.Store.Load(); err != nil {
				if !c.Admin {
					return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
				}
				res.Warnings = append(res.Warnings, "directory.yaml couldn't be read ("+err.Error()+"): a tombstone for this name, if any, is kept")
				cfg = nil
			}
		}
		if c.Admin && cfg != nil {
			// Leftovers of an earlier account with this name (deleted here
			// or outside the Hub) don't carry over.
			if purged := purgeUser(cfg, req.Username); len(purged) > 0 {
				if err := s.Store.Save(cfg); err != nil {
					return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
				}
				res.Warnings = append(res.Warnings, fmt.Sprintf("purged leftovers naming %s from an earlier account: %s", req.Username, strings.Join(purged, ", ")))
				detail += " purged=" + strings.Join(purged, ",")
			}
		}
		if !c.Admin {
			if cfg == nil {
				return forbidden("not allowed: directory.yaml not configured")
			}
			if _, ok := cfg.Deleted[req.Username]; ok {
				return refuse("%s was deleted; an admin must re-create it", req.Username)
			}
			if g := namedInGroups(cfg, req.Username); g != "" {
				return refuse("%s is still named in the exceptions or expiries of %s; an admin must re-create it", req.Username, g)
			}
			if err := s.checkKeyless(ctx, c, req.Username); err != nil {
				return err
			}
		}
		var groupIDs []int
		admin := false
		admins := s.adminGroups()
		for _, name := range req.Groups {
			g, err := sn.group(name)
			if err != nil {
				return invalid("no such group %q", name)
			}
			groupIDs = append(groupIDs, g.ID)
			admin = admin || admins[name]
		}
		if req.Onboarding == OnboardInvite && !admin {
			if err := s.invitesAvailable(); err != nil {
				return &Error{Status: http.StatusServiceUnavailable, Msg: "can't create invite links (" + err.Error() + "); use the password fallback"}
			}
		}
		if err := s.LLDAP.CreateUser(ctx, req.Username, req.Email, req.DisplayName); err != nil {
			return err
		}
		if cfg != nil {
			changed := false
			if at, ok := cfg.Deleted[req.Username]; ok { // admins only (refused above)
				delete(cfg.Deleted, req.Username)
				changed = true
				res.Warnings = append(res.Warnings, fmt.Sprintf("an earlier %s was deleted on %s; this is a new account", req.Username, at.Format(time.RFC3339)))
			}
			if !c.Admin {
				cfg.CreatedBy[req.Username] = c.User
				changed = true
			}
			if changed {
				if err := s.Store.Save(cfg); err != nil {
					res.Warnings = append(res.Warnings, "saving directory.yaml failed: "+err.Error())
				}
			}
		}
		if pw != "" {
			if err := s.LLDAP.SetPassword(ctx, req.Username, pw); err != nil {
				// Don't leave a half-created account behind.
				if derr := s.LLDAP.DeleteUser(ctx, req.Username); derr != nil {
					return fmt.Errorf("setting the password failed (%v) and removing the new user failed too (%v): delete %s in LLDAP", err, derr, req.Username)
				}
				return fmt.Errorf("setting the password failed, user not created: %v", err)
			}
		}
		graceCleared := false
		for i, id := range groupIDs {
			if err := s.LLDAP.AddUserToGroup(ctx, req.Username, id); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("adding to %s failed: %v", req.Groups[i], err))
			} else if cfg != nil && cfg.clearGrace(req.Groups[i], req.Username) {
				graceCleared = true // granted again
			}
		}
		if graceCleared {
			if err := s.Store.Save(cfg); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("clearing the grace entries of %s in directory.yaml failed (they keep denying for up to %s): %v", req.Username, GracePeriod, err))
			}
		}
		// Import into Keycloak now (LDAP users are otherwise imported on
		// first login) so the invite redemption / required action has a
		// Keycloak user to work on.
		switch {
		case s.KC == nil:
			res.Warnings = append(res.Warnings, "Keycloak admin API not configured: user not pre-imported")
		case req.Onboarding == OnboardPassword && req.RequirePasskey:
			if err := s.KC.RequirePasskey(ctx, req.Username); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("requiring passkey registration failed (retry with \"Require passkey\"): %v", err))
			}
		default:
			if _, err := s.KC.ImportUser(ctx, req.Username); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pre-importing into Keycloak failed (it happens on first use instead): %v", err))
			}
		}
		switch {
		case req.Onboarding == OnboardInvite && admin:
			// Core refuses invites for administrators.
			res.ServerInvite = "./portcullis invite " + req.Username
			res.Warnings = append(res.Warnings, req.Username+" is an administrator: "+recoverMsg(req.Username))
		case req.Onboarding == OnboardInvite:
			inv, err := s.newInvite(ctx, req.Username)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("the user was created but the invite failed (use \"Send new invite\"): %v", err))
				var de *Error
				if errors.As(err, &de) && de.Status == http.StatusConflict {
					res.ServerInvite = "./portcullis invite " + req.Username
				}
			} else {
				res.Invite = inv
			}
		}
		if req.Generate {
			res.Password = pw
		}
		return nil
	})
	return res, err
}

// UpdateUser changes email and/or display name (nil = unchanged).
func (s *Service) UpdateUser(ctx context.Context, c *Caller, username string, email, displayName *string) error {
	detail := ""
	if email != nil {
		*email = strings.TrimSpace(*email)
		detail += "email=" + *email + " "
	}
	if displayName != nil {
		*displayName = strings.TrimSpace(*displayName)
		detail += "display_name=" + *displayName
	}
	return s.run(ctx, c, PermEditDetails, "user.update", username, &detail, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if email == nil && displayName == nil {
			return invalid("nothing to change")
		}
		if email != nil && !lldap.ValidEmail(*email) {
			return invalid("invalid email address")
		}
		if displayName != nil && !lldap.ValidDisplayName(*displayName) {
			return invalid("display name: at most 128 printable characters")
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if email != nil {
			if other := emailTaken(sn, *email, u.ID); other != "" {
				return refuse("email %s is already used by %s", *email, other)
			}
		}
		return s.LLDAP.UpdateUser(ctx, u.ID, email, displayName)
	})
}

// DeleteUser deletes a user from LLDAP and Keycloak. confirm must repeat
// the username.
// The audit detail records what happened to the Keycloak copy; a failure
// there is a warning (the user is gone from LLDAP either way) and the copy
// then shows up under the stale Keycloak records.
func (s *Service) DeleteUser(ctx context.Context, c *Caller, username, confirm string) (*Result, error) {
	res := newResult()
	detail := ""
	err := s.run(ctx, c, PermRemove, "user.delete", username, &detail, func() error {
		if confirm != username {
			return invalid("type the username to confirm")
		}
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if strings.EqualFold(username, c.User) {
			return refuse("you can't delete yourself")
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if err := s.checkNotLastAdmin(sn, u.ID); err != nil {
			return err
		}
		// Tombstone first: if it can't be saved, nothing is deleted. If
		// the LLDAP delete then fails, the tombstone stays (harmless for a
		// name that still exists). Exceptions, expiries and created_by are
		// purged only after the delete succeeded (below).
		if s.Store != nil {
			cfg, err := s.Store.Load()
			if err == nil {
				cfg.Deleted[strings.ToLower(u.ID)] = time.Now().UTC()
				err = s.Store.Save(cfg)
			}
			if err != nil {
				return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml (tombstone): " + err.Error()}
			}
		}
		kcID := ""
		kcErr := ""
		if s.KC == nil {
			detail = "keycloak_copy=unknown (Keycloak admin API not configured)"
		} else {
			id, err := s.KC.ImportUser(ctx, u.ID)
			switch {
			case err == nil:
				kcID = id
			case errors.Is(err, keycloak.ErrUserNotFound):
				detail = "keycloak_copy=none"
			default:
				kcErr = "lookup: " + err.Error()
			}
		}
		if err := s.LLDAP.DeleteUser(ctx, u.ID); err != nil {
			detail = ""
			return err
		}
		if kcID != "" {
			if err := s.KC.DeleteUserByID(ctx, kcID); err != nil {
				kcErr = "delete: " + err.Error()
			} else {
				detail = "keycloak_copy=removed"
			}
		}
		if kcErr != "" {
			detail = "keycloak_copy=FAILED " + kcErr
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s was deleted from LLDAP, but removing the Keycloak copy failed (%s); it is listed under \"Stale Keycloak records\" — remove it there", u.ID, kcErr))
		}
		if s.Store != nil {
			cfg, err := s.Store.Load()
			if err == nil && len(purgeUser(cfg, u.ID)) > 0 {
				err = s.Store.Save(cfg)
			}
			if err != nil {
				detail = strings.TrimSpace(detail + " purge=FAILED")
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s was deleted, but removing them from exceptions, expiries and created_by in directory.yaml failed: %v", u.ID, err))
			}
		}
		return nil
	})
	return res, err
}

// RemoveStaleKeycloakUser deletes the Keycloak copy of a user that was
// imported from the LDAP federation but no longer exists in LLDAP (see
// Overview.StaleKeycloak). confirm must repeat the username. Refused for
// the protected accounts, for anyone LLDAP still has, and for Keycloak
// users not linked to the LDAP federation. Keycloak's federation is
// READ_ONLY, so this never touches LLDAP.
func (s *Service) RemoveStaleKeycloakUser(ctx context.Context, c *Caller, username, confirm string) error {
	detail := ""
	return s.run(ctx, c, permAdmin, "keycloak.remove_stale", username, &detail, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if confirm != username {
			return invalid("type the username to confirm")
		}
		if s.KC == nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "Keycloak admin API not configured"}
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		if _, err := sn.user(username); err == nil {
			return refuse("%s exists in LLDAP: not a stale record (delete the user instead)", username)
		}
		st, err := s.KC.ListedUser(ctx, username)
		if err != nil {
			return &Error{Status: http.StatusBadGateway, Msg: err.Error()}
		}
		if st == nil {
			return notFound("Keycloak has no user %q", username)
		}
		detail = "keycloak_id=" + st.ID
		if !st.LDAPFederated {
			return refuse("%s is not linked to the LDAP federation (a Keycloak-local user): manage it in the Keycloak admin console", username)
		}
		return s.KC.DeleteUserByID(ctx, st.ID)
	})
}

// SetPassword sets (or generates) a user's password and ends their
// Keycloak sessions.
// confirm must repeat the username if the target is another lldap_admin
// member.
func (s *Service) SetPassword(ctx context.Context, c *Caller, username, password string, generate bool, confirm string) (*Result, error) {
	res := newResult()
	detail := fmt.Sprintf("generated=%v", generate)
	err := s.run(ctx, c, permAdmin, "user.password", username, &detail, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if !generate && !lldap.ValidPassword(password) {
			return invalid("password must be %d-%d characters without control characters", lldap.MinPasswordLen, lldap.MaxPasswordLen)
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if err := s.checkAdminTakeover(sn, c.User, u.ID, confirm, &detail); err != nil {
			return err
		}
		if !lldap.ValidUsername(u.ID) {
			return refuse("username %q can't be used in an LDAP DN; change this password in the LLDAP UI", u.ID)
		}
		if err := s.clearCreatedBy(c, u.ID); err != nil {
			return err
		}
		if generate {
			password = GeneratePassword()
		}
		if err := s.LLDAP.SetPassword(ctx, u.ID, password); err != nil {
			return err
		}
		if s.KC != nil {
			if err := s.KC.LogoutUser(ctx, u.ID); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("signing the user out of Keycloak failed: %v", err))
			}
		}
		if generate {
			res.Password = password
		}
		return nil
	})
	return res, err
}

func (s *Service) kcTarget(ctx context.Context, username string) (string, *snapshot, error) {
	if err := s.checkTarget(username); err != nil {
		return "", nil, err
	}
	if s.KC == nil {
		return "", nil, &Error{Status: http.StatusServiceUnavailable, Msg: "Keycloak admin API not configured"}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return "", nil, err
	}
	u, err := sn.user(username)
	return u.ID, sn, err
}

// RequirePasskey adds the passkey registration action (importing the
// user into Keycloak first if needed).
func (s *Service) RequirePasskey(ctx context.Context, c *Caller, username string) error {
	return s.run(ctx, c, permAdmin, "user.require_passkey", username, nil, func() error {
		id, _, err := s.kcTarget(ctx, username)
		if err != nil {
			return err
		}
		if err := s.clearCreatedBy(c, id); err != nil {
			return err
		}
		return s.KC.RequirePasskey(ctx, id)
	})
}

// ClearActions removes every pending required action.
func (s *Service) ClearActions(ctx context.Context, c *Caller, username string) error {
	return s.run(ctx, c, permAdmin, "user.clear_actions", username, nil, func() error {
		id, _, err := s.kcTarget(ctx, username)
		if err != nil {
			return err
		}
		return s.KC.SetUserRequiredActions(ctx, id, nil)
	})
}

// RemovePasskeys deletes the user's WebAuthn credentials and signs them
// out. With withInvite it then creates a new invite link (the invite
// registers the new passkey); otherwise it adds the passkey registration
// action for the next (password) login. confirm must repeat the username.
func (s *Service) RemovePasskeys(ctx context.Context, c *Caller, username, confirm string, withInvite bool) (*Result, error) {
	res := newResult()
	detail := fmt.Sprintf("new_invite=%v", withInvite)
	err := s.run(ctx, c, permAdmin, "user.remove_passkeys", username, &detail, func() error {
		id, sn, err := s.kcTarget(ctx, username)
		if err != nil {
			return err
		}
		// Always confirmed; flagged in the audit entry for another admin.
		if err := s.checkAdminTakeover(sn, c.User, id, confirm, &detail); err != nil {
			return err
		}
		if confirm != username {
			return invalid("type the username to confirm")
		}
		if withInvite {
			// Check before removing anything: an administrator would be
			// left without passkeys and without an invite.
			if err := s.checkInvitable(sn, id); err != nil {
				return err
			}
			if err := s.invitesAvailable(); err != nil {
				return &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
			}
		}
		if err := s.clearCreatedBy(c, id); err != nil {
			return err
		}
		n, err := s.KC.RemovePasskeys(ctx, id, !withInvite)
		res.Count = n
		if err != nil {
			return err
		}
		if withInvite {
			inv, err := s.newInvite(ctx, id)
			if err != nil {
				return fmt.Errorf("passkeys removed (%d), but creating the invite failed (use \"Send new invite\"): %w", n, err)
			}
			res.Invite = inv
		}
		return nil
	})
	return res, err
}

// SendInvite creates a new one-time invite link (earlier unredeemed ones
// stop working, core side). Administrators are refused: core won't invite
// them, they're recovered from the server.
func (s *Service) SendInvite(ctx context.Context, c *Caller, username string) (*Result, error) {
	res := newResult()
	err := s.run(ctx, c, PermInvite, "user.invite", username, nil, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if err := s.checkInvitable(sn, u.ID); err != nil {
			return err
		}
		if err := s.clearCreatedBy(c, u.ID); err != nil {
			return err
		}
		if !c.Admin {
			// Delegates re-invite only accounts a delegate created that
			// have no credential yet (see checkKeyless).
			cfg := &Config{}
			if s.Store != nil {
				if cfg, err = s.Store.Load(); err != nil {
					return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
				}
			}
			if cfg.CreatedBy[strings.ToLower(u.ID)] == "" {
				return forbidden("not allowed: only an admin can re-invite %s", u.ID)
			}
			if err := s.checkKeyless(ctx, c, u.ID); err != nil {
				return err
			}
		}
		inv, err := s.newInvite(ctx, u.ID)
		res.Invite = inv
		return err
	})
	return res, err
}

// ── groups ────────────────────────────────────────────────

// purgeGroup drops everything directory.yaml says about group (its rule,
// exceptions and expiries, its grace entries and every permission granted
// to it), so a group created later with that name inherits nothing.
// fold: match the name case-insensitively. Returns what went, sorted.
func purgeGroup(cfg *Config, group string, fold bool) []string {
	same := func(n string) bool { return n == group || (fold && strings.EqualFold(n, group)) }
	var out []string
	for name, gc := range cfg.Groups {
		if !same(name) {
			continue
		}
		switch {
		case gc == nil || (gc.Rule == nil && len(gc.Exceptions) == 0 && len(gc.Expiry) == 0):
			out = append(out, "empty entry of "+name)
		default:
			if gc.Rule != nil {
				out = append(out, "rule of "+name)
			}
			if len(gc.Exceptions) > 0 {
				out = append(out, fmt.Sprintf("%d exception(s) of %s", len(gc.Exceptions), name))
			}
			if len(gc.Expiry) > 0 {
				out = append(out, fmt.Sprintf("%d expiry(ies) of %s", len(gc.Expiry), name))
			}
		}
		delete(cfg.Groups, name)
	}
	kept := cfg.Grace[:0:0]
	for _, g := range cfg.Grace {
		if same(g.Group) {
			out = append(out, "grace of "+g.User+" in "+g.Group)
		} else {
			kept = append(kept, g)
		}
	}
	cfg.Grace = kept
	for p, g := range cfg.Permissions {
		if g != "" && same(g) {
			delete(cfg.Permissions, p)
			out = append(out, "permission "+p)
		}
	}
	sort.Strings(out)
	return out
}

// logoutAll ends the Keycloak sessions of users (so a removed membership
// stops working at the next token refresh, contract §9.6); failures are
// warnings. Never call it with s.mu held.
func (s *Service) logoutAll(ctx context.Context, users []string, res *Result) {
	if s.KC == nil {
		if len(users) > 0 {
			res.Warnings = append(res.Warnings, "Keycloak admin API not configured: "+strings.Join(users, ", ")+" not signed out (their sessions end on their own)")
		}
		return
	}
	for _, u := range users {
		if err := s.KC.LogoutUser(ctx, u); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("signing %s out of Keycloak failed (their current sessions keep the old groups until they end): %v", u, err))
		}
	}
}

// CreateGroup creates a group. An admin's new group starts clean: leftovers
// in directory.yaml for that name (a group deleted outside the Hub) are
// purged first and listed in a warning.
func (s *Service) CreateGroup(ctx context.Context, c *Caller, name string) (*Result, error) {
	res := newResult()
	name = strings.TrimSpace(name)
	detail := ""
	err := s.run(ctx, c, permAdmin, "group.create", name, &detail, func() error {
		if !lldap.ValidGroupName(name) {
			return invalid("invalid group name: 1-128 letters, digits, '_', '.' or '-', starting with a letter or digit")
		}
		if strings.HasPrefix(strings.ToLower(name), "lldap_") {
			return invalid("lldap_* names are reserved for LLDAP's built-in groups")
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		for existing := range sn.groups {
			if strings.EqualFold(existing, name) {
				return refuse("group %q already exists", existing)
			}
		}
		if s.Store != nil {
			cfg, err := s.loadConfig()
			if err != nil {
				return err
			}
			if purged := purgeGroup(cfg, name, true); len(purged) > 0 {
				if err := s.saveConfig(cfg); err != nil {
					return err
				}
				detail = "purged=" + strings.Join(purged, ",")
				res.Warnings = append(res.Warnings, fmt.Sprintf("purged leftovers of an earlier group %s from directory.yaml: %s", name, strings.Join(purged, ", ")))
			}
		}
		_, err = s.LLDAP.CreateGroup(ctx, name)
		return err
	})
	return res, err
}

// DeleteGroup deletes a group. confirm must repeat the name. The LLDAP
// delete comes first (a failure changes nothing); then its rule,
// exceptions, expiries, grace entries and permission grants go from
// directory.yaml (a failure there is a warning; CreateGroup purges them
// before the name is used again), and its former members are signed out of
// Keycloak.
func (s *Service) DeleteGroup(ctx context.Context, c *Caller, name, confirm string) (*Result, error) {
	res := newResult()
	detail := ""
	var logout []string
	err := s.run(ctx, c, permAdmin, "group.delete", name, &detail, func() error {
		if confirm != name {
			return invalid("type the group name to confirm")
		}
		if builtinGroups[name] {
			return refuse("%s is a built-in LLDAP group", name)
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		g, err := sn.group(name)
		if err != nil {
			return err
		}
		if err := s.LLDAP.DeleteGroup(ctx, g.ID); err != nil {
			return err
		}
		for _, m := range g.Members() {
			if !s.protectedAccount(m) {
				logout = append(logout, m)
			}
		}
		sort.Strings(logout)
		if s.Store != nil {
			cfg, err := s.loadConfig()
			if err == nil {
				if purged := purgeGroup(cfg, name, false); len(purged) > 0 {
					if err = s.saveConfig(cfg); err == nil {
						detail = "purged=" + strings.Join(purged, ",")
					}
				}
			}
			if err != nil {
				detail = "purge=FAILED"
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s was deleted, but removing its rule, exceptions and permissions from directory.yaml failed (they are purged when a group with this name is created again): %v", name, err))
			}
		}
		if len(logout) > 0 {
			detail = strings.TrimSpace(detail + " logout=" + strings.Join(logout, ","))
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	s.logoutAll(ctx, logout, res)
	return res, nil
}

// AddMember adds username to group.
func (s *Service) AddMember(ctx context.Context, c *Caller, group, username string) error {
	return s.run(ctx, c, permAdmin, "group.add_member", group, &username, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		g, err := sn.group(group)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if memberOf(g, u.ID) {
			// Re-adding a member whose temporary access expired (in a group
			// the evaluator doesn't manage) confirms the membership.
			changed, err := s.regranted(group, u.ID, time.Now())
			if err != nil {
				return err
			}
			if !changed {
				return refuse("%s is already a member of %s", u.ID, group)
			}
			return nil
		}
		if err := s.LLDAP.AddUserToGroup(ctx, u.ID, g.ID); err != nil {
			return err
		}
		_, err = s.regranted(group, u.ID, time.Now())
		return err
	})
}

// RemoveMember removes username from group, drops their expiry there and
// their grace entry (a later re-add starts clean), and signs them out of
// Keycloak so the removal takes effect at the next token refresh.
func (s *Service) RemoveMember(ctx context.Context, c *Caller, group, username string) (*Result, error) {
	res := newResult()
	detail := username
	var removed string
	err := s.run(ctx, c, permAdmin, "group.remove_member", group, &detail, func() error {
		if err := s.checkTarget(username); err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		g, err := sn.group(group)
		if err != nil {
			return err
		}
		u, err := sn.user(username)
		if err != nil {
			return err
		}
		if !memberOf(g, u.ID) {
			return notFound("%s is not a member of %s", u.ID, group)
		}
		if group == lldap.AdminGroup {
			if strings.EqualFold(u.ID, c.User) {
				return refuse("you can't remove yourself from %s", lldap.AdminGroup)
			}
			if err := s.checkNotLastAdmin(sn, u.ID); err != nil {
				return err
			}
		}
		if err := s.LLDAP.RemoveUserFromGroup(ctx, u.ID, g.ID); err != nil {
			return err
		}
		removed = u.ID
		if s.Store != nil {
			cfg, err := s.loadConfig()
			if err == nil {
				changed := cfg.clearGrace(group, u.ID)
				if gc := cfg.Groups[group]; gc != nil {
					for k := range gc.Expiry {
						if strings.EqualFold(k, u.ID) {
							delete(gc.Expiry, k)
							changed = true
						}
					}
					tidy(cfg, group)
				}
				if changed {
					if err = s.saveConfig(cfg); err == nil {
						detail += " expiry_dropped=true"
					}
				}
			}
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s was removed from %s, but dropping their expiry there in directory.yaml failed (a re-add may inherit it): %v", u.ID, group, err))
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	s.logoutAll(ctx, []string{removed}, res)
	return res, nil
}
