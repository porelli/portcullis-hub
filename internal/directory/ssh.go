package directory

// SSH access's directory checks (contract §9.6, §18.12): who may grant
// SSH access to which group, on a fresh snapshot.

import (
	"context"
	"net/http"

	"github.com/portcullis/hub/internal/lldap"
)

// TextSSHOwnGroup is the refusal for a delegate granting to their own group.
const TextSSHOwnGroup = "you can't grant access to a group you're in"

// CheckSSHGrantGroup decides, on a fresh snapshot, whether c may make an
// SSH grant to group, and answers the group's LLDAP id. Administrators
// may grant to any existing group. An ssh_access holder may not grant to
// a group they are in or that a rule would put them in, to a permission
// group, an administrator or protected group, or a group with a
// privileged SSH grant (403).
func (s *Service) CheckSSHGrantGroup(ctx context.Context, c *Caller, group string) (int, error) {
	if c == nil {
		return 0, errNoActor()
	}
	if err := s.LLDAP.Available(); err != nil {
		return 0, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return 0, err
	}
	g, ok := sn.groups[group]
	if !ok {
		return 0, notFound("no group %s", group)
	}
	if c.Admin {
		if !memberOf(sn.groups[lldap.AdminGroup], c.User) {
			return 0, forbidden("not allowed: admins only (%s is no longer in %s)", c.User, lldap.AdminGroup)
		}
		return g.ID, nil
	}
	cfg := &Config{}
	if s.Store != nil {
		if cfg, err = s.Store.Load(); err != nil {
			return 0, &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
		}
	}
	if pg, ok := sn.groups[cfg.Permissions[PermSSHAccess]]; !c.Perms[PermSSHAccess] || !ok || !memberOf(pg, c.User) {
		return 0, forbidden("not allowed: needs %s", PermSSHAccess)
	}
	if memberOf(g, c.User) {
		return 0, forbidden(TextSSHOwnGroup)
	}
	if gc, ok := cfg.Groups[group]; ok && gc.Rule != nil && s.matching(cfg, sn, gc.Rule)[c.User] {
		return 0, forbidden(TextSSHOwnGroup)
	}
	for _, pg := range cfg.Permissions {
		if pg == group {
			return 0, forbidden("not allowed: %s holds a delegated permission (admins only)", group)
		}
	}
	if s.adminGroups()[group] || group == lldap.AdminGroup || group == "lldap_password_manager" {
		return 0, forbidden("not allowed: %s is an administrator or protected group (admins only)", group)
	}
	if s.SSHGroups != nil {
		for _, pg := range s.SSHGroups().Privileged {
			if pg == group {
				return 0, forbidden("not allowed: %s has a privileged SSH grant (admins only)", group)
			}
		}
	}
	return g.ID, nil
}
