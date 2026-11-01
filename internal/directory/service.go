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

	mu sync.Mutex
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
	Keycloak    *KeycloakView `json:"keycloak"` // nil: Keycloak unreachable
	// Protected: "service" (the Hub's account) or "core-admin" (the
	// bootstrap admin): both read-only here. "" otherwise.
	Protected string `json:"protected,omitempty"`
	Self      bool   `json:"self,omitempty"`
	// Admin: member of an administrator group (AdminGroups). No invites
	// from the Hub (core refuses them); recover with ServerInvite.
	Admin        bool                `json:"admin,omitempty"`
	ServerInvite string              `json:"server_invite,omitempty"`
	Attrs        map[string][]string `json:"attrs,omitempty"` // custom attributes that are defined fields
}

// GroupView is one group.
type GroupView struct {
	Name    string   `json:"name"`
	Created string   `json:"created"`
	Members []string `json:"members"`
	Builtin bool     `json:"builtin,omitempty"`
	Admin   bool     `json:"admin,omitempty"` // an administrator group
	UsedBy  []string `json:"used_by"`         // app ids referencing it
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
	StaleKeycloak []StaleRecord `json:"stale_keycloak"`
	// InvitesError is set when invite links can't be created.
	InvitesError string `json:"invites_error,omitempty"`
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

// Overview lists users, groups and suggestions. An unconfigured LLDAP is
// not an error: Available is false and Reason says why.
func (s *Service) Overview(ctx context.Context, me string) (*Overview, error) {
	ov := &Overview{Me: me, Users: []UserView{}, Groups: []GroupView{}, Suggestions: []Suggestion{}, StaleKeycloak: []StaleRecord{}}
	if err := s.LLDAP.Available(); err != nil {
		ov.Reason = err.Error()
		return ov, nil
	}
	ov.Available = true
	ov.ServiceUser = s.serviceUser()
	if err := s.invitesAvailable(); err != nil {
		ov.InvitesError = err.Error()
	}

	// Load fields from Store if available
	var cfg *Config
	var fieldNames map[string]bool
	ov.Fields = []Field{}
	if s.Store != nil {
		var err error
		cfg, err = s.Store.Load()
		if err != nil {
			ov.FieldsError = err.Error()
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
	kc := s.keycloakStatuses(ctx, ov)
	admins := s.adminGroups()
	inLLDAP := map[string]bool{}
	for _, u := range users {
		inLLDAP[strings.ToLower(u.ID)] = true
		v := UserView{Username: u.ID, Email: u.Email, DisplayName: u.DisplayName, Created: u.CreationDate, Groups: []string{},
			Protected: s.protection(u.ID), Self: me != "" && strings.EqualFold(me, u.ID), Attrs: map[string][]string{}}
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
		if v.Admin && v.Protected != "service" {
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
		gv := GroupView{Name: g.DisplayName, Created: g.CreationDate, Members: g.Members(), Builtin: builtinGroups[g.DisplayName], Admin: admins[g.DisplayName], UsedBy: []string{}}
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
	sn := &snapshot{users: map[string]lldap.User{}, groups: map[string]lldap.Group{}}
	for _, u := range users {
		sn.users[strings.ToLower(u.ID)] = u
	}
	for _, g := range groups {
		sn.groups[g.DisplayName] = g
	}
	return sn, nil
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

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		return s[:128] + "…"
	}
	return s
}

// run serialises a mutation, checks the actor and availability, and
// writes the audit entry.
func (s *Service) run(actor, action, target string, detail *string, fn func() error) error {
	if strings.TrimSpace(actor) == "" {
		return &Error{Status: http.StatusForbidden, Msg: "no signed-in user (X-Forwarded-User) — refusing an unattributable change"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.LLDAP.Available()
	if err != nil {
		err = &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	} else {
		err = fn()
	}
	if s.Audit != nil {
		e := AuditEntry{Actor: clip(actor), Action: action, Target: clip(target), Result: "ok"}
		if detail != nil {
			e.Detail = clip(*detail)
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
func (s *Service) CreateUser(ctx context.Context, actor string, req CreateRequest) (*Result, error) {
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
	err := s.run(actor, "user.create", req.Username, &detail, func() error {
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
		if pw != "" {
			if err := s.LLDAP.SetPassword(ctx, req.Username, pw); err != nil {
				// Don't leave a half-created account behind.
				if derr := s.LLDAP.DeleteUser(ctx, req.Username); derr != nil {
					return fmt.Errorf("setting the password failed (%v) and removing the new user failed too (%v): delete %s in LLDAP", err, derr, req.Username)
				}
				return fmt.Errorf("setting the password failed, user not created: %v", err)
			}
		}
		for i, id := range groupIDs {
			if err := s.LLDAP.AddUserToGroup(ctx, req.Username, id); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("adding to %s failed: %v", req.Groups[i], err))
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
func (s *Service) UpdateUser(ctx context.Context, actor, username string, email, displayName *string) error {
	detail := ""
	if email != nil {
		*email = strings.TrimSpace(*email)
		detail += "email=" + *email + " "
	}
	if displayName != nil {
		*displayName = strings.TrimSpace(*displayName)
		detail += "display_name=" + *displayName
	}
	return s.run(actor, "user.update", username, &detail, func() error {
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
		return s.LLDAP.UpdateUser(ctx, u.ID, email, displayName)
	})
}

// DeleteUser deletes a user from LLDAP and Keycloak. confirm must repeat
// the username.
// The audit detail records what happened to the Keycloak copy; a failure
// there is a warning (the user is gone from LLDAP either way) and the copy
// then shows up under the stale Keycloak records.
func (s *Service) DeleteUser(ctx context.Context, actor, username, confirm string) (*Result, error) {
	res := newResult()
	detail := ""
	err := s.run(actor, "user.delete", username, &detail, func() error {
		if confirm != username {
			return invalid("type the username to confirm")
		}
		if err := s.checkTarget(username); err != nil {
			return err
		}
		if strings.EqualFold(username, actor) {
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
func (s *Service) RemoveStaleKeycloakUser(ctx context.Context, actor, username, confirm string) error {
	detail := ""
	return s.run(actor, "keycloak.remove_stale", username, &detail, func() error {
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
func (s *Service) SetPassword(ctx context.Context, actor, username, password string, generate bool, confirm string) (*Result, error) {
	res := newResult()
	detail := fmt.Sprintf("generated=%v", generate)
	err := s.run(actor, "user.password", username, &detail, func() error {
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
		if err := s.checkAdminTakeover(sn, actor, u.ID, confirm, &detail); err != nil {
			return err
		}
		if !lldap.ValidUsername(u.ID) {
			return refuse("username %q can't be used in an LDAP DN; change this password in the LLDAP UI", u.ID)
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
func (s *Service) RequirePasskey(ctx context.Context, actor, username string) error {
	return s.run(actor, "user.require_passkey", username, nil, func() error {
		id, _, err := s.kcTarget(ctx, username)
		if err != nil {
			return err
		}
		return s.KC.RequirePasskey(ctx, id)
	})
}

// ClearActions removes every pending required action.
func (s *Service) ClearActions(ctx context.Context, actor, username string) error {
	return s.run(actor, "user.clear_actions", username, nil, func() error {
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
func (s *Service) RemovePasskeys(ctx context.Context, actor, username, confirm string, withInvite bool) (*Result, error) {
	res := newResult()
	detail := fmt.Sprintf("new_invite=%v", withInvite)
	err := s.run(actor, "user.remove_passkeys", username, &detail, func() error {
		id, sn, err := s.kcTarget(ctx, username)
		if err != nil {
			return err
		}
		// Always confirmed; flagged in the audit entry for another admin.
		if err := s.checkAdminTakeover(sn, actor, id, confirm, &detail); err != nil {
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
func (s *Service) SendInvite(ctx context.Context, actor, username string) (*Result, error) {
	res := newResult()
	err := s.run(actor, "user.invite", username, nil, func() error {
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
		inv, err := s.newInvite(ctx, u.ID)
		res.Invite = inv
		return err
	})
	return res, err
}

// ── groups ────────────────────────────────────────────────

// CreateGroup creates a group.
func (s *Service) CreateGroup(ctx context.Context, actor, name string) error {
	name = strings.TrimSpace(name)
	return s.run(actor, "group.create", name, nil, func() error {
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
		_, err = s.LLDAP.CreateGroup(ctx, name)
		return err
	})
}

// DeleteGroup deletes a group. confirm must repeat the name.
func (s *Service) DeleteGroup(ctx context.Context, actor, name, confirm string) error {
	return s.run(actor, "group.delete", name, nil, func() error {
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
		return s.LLDAP.DeleteGroup(ctx, g.ID)
	})
}

// AddMember adds username to group.
func (s *Service) AddMember(ctx context.Context, actor, group, username string) error {
	return s.run(actor, "group.add_member", group, &username, func() error {
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
		for _, m := range g.Members() {
			if strings.EqualFold(m, u.ID) {
				return refuse("%s is already a member of %s", u.ID, group)
			}
		}
		return s.LLDAP.AddUserToGroup(ctx, u.ID, g.ID)
	})
}

// RemoveMember removes username from group.
func (s *Service) RemoveMember(ctx context.Context, actor, group, username string) error {
	return s.run(actor, "group.remove_member", group, &username, func() error {
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
		member := false
		for _, m := range g.Members() {
			member = member || strings.EqualFold(m, u.ID)
		}
		if !member {
			return notFound("%s is not a member of %s", u.ID, group)
		}
		if group == lldap.AdminGroup {
			if strings.EqualFold(u.ID, actor) {
				return refuse("you can't remove yourself from %s", lldap.AdminGroup)
			}
			if err := s.checkNotLastAdmin(sn, u.ID); err != nil {
				return err
			}
		}
		return s.LLDAP.RemoveUserFromGroup(ctx, u.ID, g.ID)
	})
}
