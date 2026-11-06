package directory

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// App instance groups (contract §11.2, §11.4): the Hub creates an
// instance's users_<id> / admin_<id> groups and deletes its access and
// admin groups on a guarded delete. Both go through the same audited,
// admin-only operations as the Users & Groups page (CreateGroup /
// DeleteGroup: a deleted group's directory.yaml entries are purged and its
// former members signed out), as actor.

// keptGroupReason says why name must survive an instance delete ("" =
// it may go): built-in LLDAP groups, administrator groups (§9.4) and
// delegated-permission groups. Caller holds no lock.
func (s *Service) keptGroupReason(name string) (string, error) {
	if builtinGroups[name] {
		return "it is a built-in LLDAP group", nil
	}
	for g := range s.adminGroups() {
		if strings.EqualFold(g, name) {
			return "it is an administrator group", nil
		}
	}
	if s.Store != nil {
		cfg, err := s.loadConfig()
		if err != nil {
			return "", err
		}
		for p, g := range cfg.Permissions {
			if g != "" && strings.EqualFold(g, name) {
				return "it is the " + p + " permission group", nil
			}
		}
		for g, gc := range cfg.Groups {
			if gc != nil && gc.Rule != nil && strings.EqualFold(g, name) {
				return "it is a rule group (its members come from a rule an admin set)", nil
			}
		}
	}
	return "", nil
}

// ResolveActor checks that actor can run the instance group operations:
// an LLDAP administrator (as CallerFor resolves it). Users & Groups not
// available is no error (the group steps are warnings then).
func (s *Service) ResolveActor(ctx context.Context, actor Actor) error {
	if s.LLDAP.Available() != nil {
		return nil
	}
	c, err := s.CallerFor(ctx, actor.User)
	if err != nil {
		return err
	}
	if !c.Admin {
		return forbidden("%s is not an administrator", actor.User)
	}
	return nil
}

// DeleteInstanceGroup deletes group name for an instance delete, as
// actor. Missing = nothing to do (retries). A protected or permission
// group is kept, with a warning. Users & Groups not configured (no LLDAP
// credentials) is a warning too: the group stays in LLDAP.
func (s *Service) DeleteInstanceGroup(ctx context.Context, actor Actor, name string) (warnings []string, err error) {
	if name == "" {
		return nil, nil
	}
	if aerr := s.LLDAP.Available(); aerr != nil {
		return []string{fmt.Sprintf("group %s was kept: users & groups is not available (%v) — delete it on the Users & Groups page", name, aerr)}, nil
	}
	why, err := s.keptGroupReason(name)
	if err != nil {
		return nil, err
	}
	if why != "" {
		return []string{fmt.Sprintf("group %s was kept: %s", name, why)}, nil
	}
	c, err := s.CallerFor(ctx, actor.User)
	if err != nil {
		return nil, err
	}
	res, err := s.DeleteGroup(ctx, c, name, name)
	var de *Error
	if errors.As(err, &de) && de.Status == http.StatusNotFound {
		return nil, nil
	}
	if res != nil {
		warnings = append(warnings, res.Warnings...)
	}
	return warnings, err
}

// CreateInstanceGroup creates an instance's (empty, manual) group as
// actor. An existing group is kept as it is, with a warning (its members
// get access to the instance). created reports that this call created
// the group (its warnings, e.g. purged leftovers, don't change that): an
// undo deletes exactly the groups created.
func (s *Service) CreateInstanceGroup(ctx context.Context, actor Actor, name string) (created bool, warnings []string, err error) {
	if name == "" {
		return false, nil, nil
	}
	if aerr := s.LLDAP.Available(); aerr != nil {
		return false, []string{fmt.Sprintf("group %s was not created: users & groups is not available (%v)", name, aerr)}, nil
	}
	c, err := s.CallerFor(ctx, actor.User)
	if err != nil {
		return false, nil, err
	}
	res, err := s.CreateGroup(ctx, c, name)
	var de *Error
	if errors.As(err, &de) && de.Status == http.StatusConflict && strings.Contains(de.Msg, "already exists") {
		return false, []string{fmt.Sprintf("group %s already exists and was kept with its members: they can use the instance", name)}, nil
	}
	if res != nil {
		warnings = append(warnings, res.Warnings...)
	}
	return err == nil, warnings, err
}

// MissingInstanceGroups returns the names (in order, deduplicated) that
// are no LLDAP group (compared case-insensitively). Read-only: the
// Hub's "missing groups" check before an enable and on the Apps page.
func (s *Service) MissingInstanceGroups(ctx context.Context, names []string) ([]string, error) {
	if err := s.LLDAP.Available(); err != nil {
		return nil, fmt.Errorf("users & groups is not available: %w", err)
	}
	groups, err := s.LLDAP.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing LLDAP groups: %w", err)
	}
	have := map[string]bool{}
	for _, g := range groups {
		have[strings.ToLower(g.DisplayName)] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(n)
		if n == "" || seen[k] {
			continue
		}
		seen[k] = true
		if !have[k] {
			out = append(out, n)
		}
	}
	return out, nil
}
