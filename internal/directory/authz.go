package directory

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/lldap"
)

// Delegated permissions (Config.Permissions maps each to a group). Holders
// are "delegates": they may run the matching operations on ordinary users
// only. Everything else is for administrators (lldap_admin members).
const (
	PermEditDetails = "edit_details" // UpdateUser (email, display name)
	PermInvite      = "invite"       // CreateUser (invite, no groups), SendInvite
	PermRemove      = "remove"       // DeleteUser
	// permAdmin marks an operation as admins only; it is never granted
	// through Config.Permissions.
	permAdmin = "admin"
)

// delegatedPerms are the only permissions Config.Permissions can grant.
var delegatedPerms = []string{PermEditDetails, PermInvite, PermRemove}

// Caller is who is making a request, resolved once per request by
// CallerFor. Admin: member of lldap_admin. Perms: the delegated
// permissions whose group they are in.
type Caller struct {
	User  string
	Admin bool
	Perms map[string]bool
}

func forbidden(format string, a ...interface{}) error {
	return &Error{Status: http.StatusForbidden, Msg: fmt.Sprintf(format, a...)}
}

func errNoActor() error {
	return forbidden("no signed-in user (X-Forwarded-User) — refusing an unattributable change")
}

func memberOf(g lldap.Group, user string) bool {
	for _, m := range g.Members() {
		if strings.EqualFold(m, user) {
			return true
		}
	}
	return false
}

// CallerFor resolves user (X-Forwarded-User) against LLDAP and
// directory.yaml. An empty user is refused (403); a user LLDAP doesn't
// know gets no permissions. Without a Store nobody holds a delegated
// permission (admins are unaffected).
func (s *Service) CallerFor(ctx context.Context, user string) (*Caller, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, errNoActor()
	}
	c := &Caller{User: user, Perms: map[string]bool{}}
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := sn.users[strings.ToLower(user)]; !ok {
		return c, nil
	}
	c.Admin = memberOf(sn.groups[lldap.AdminGroup], user)
	if c.Admin || s.Store == nil {
		return c, nil
	}
	cfg, err := s.Store.Load()
	if err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
	}
	for _, p := range delegatedPerms {
		if g, ok := sn.groups[cfg.Permissions[p]]; ok && cfg.Permissions[p] != "" && memberOf(g, user) {
			c.Perms[p] = true
		}
	}
	return c, nil
}

// gate is the authorization step of every mutation (called by run, inside
// the audited section). Admins pass without loading anything, so their
// behaviour is unchanged; delegates are checked against a fresh snapshot.
func (s *Service) gate(ctx context.Context, c *Caller, perm, target string) error {
	if c.Admin {
		return nil
	}
	if perm == permAdmin || !c.Perms[perm] {
		return s.authorize(c, perm, target, nil, nil)
	}
	sn, err := s.load(ctx)
	if err != nil {
		return err
	}
	cfg := &Config{}
	if s.Store != nil {
		if cfg, err = s.Store.Load(); err != nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
		}
	}
	// The Caller was resolved before the lock: confirm the permission
	// still holds against this snapshot.
	if g, ok := sn.groups[cfg.Permissions[perm]]; !ok || !memberOf(g, c.User) {
		return forbidden("not allowed: needs %s", perm)
	}
	return s.authorize(c, perm, target, sn, cfg)
}

// authorize decides whether c may run an operation needing perm on the
// user target. perm "admin" means admins only. A delegate never targets
// themselves, the protected accounts, administrators or members of any
// permission group. sn and cfg may be nil only when no target check is
// reached (admin, or a missing permission).
func (s *Service) authorize(c *Caller, perm, target string, sn *snapshot, cfg *Config) error {
	switch {
	case c.Admin:
		return nil
	case perm == permAdmin:
		return forbidden("not allowed: admins only")
	case !c.Perms[perm]:
		return forbidden("not allowed: needs %s", perm)
	case sn == nil || cfg == nil:
		return forbidden("not allowed: can't check %s", target)
	}
	return s.checkDelegateTarget(c, target, sn, cfg)
}

// checkDelegateTarget is checkTarget for delegates: on top of the
// protected accounts, administrators, permission-group members and the
// caller themselves are admins only.
func (s *Service) checkDelegateTarget(c *Caller, target string, sn *snapshot, cfg *Config) error {
	target = strings.TrimSpace(target)
	switch {
	case target == "":
		return forbidden("not allowed: no target user")
	case strings.EqualFold(target, c.User):
		return forbidden("not allowed: you can't do this to your own account; ask an administrator")
	case s.checkTarget(target) != nil:
		return forbidden("not allowed: %s is a protected account (admins only)", target)
	case s.isAdmin(sn, target) || memberOf(sn.groups[lldap.AdminGroup], target) || memberOf(sn.groups["lldap_password_manager"], target):
		return forbidden("not allowed: %s is an administrator (admins only)", target)
	}
	for _, g := range cfg.Permissions {
		if g != "" && memberOf(sn.groups[g], target) {
			return forbidden("not allowed: %s holds a delegated permission (member of %s; admins only)", target, g)
		}
	}
	return nil
}
