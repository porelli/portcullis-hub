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
	why, err := s.privilegedGroupReason(name)
	if why != "" || err != nil {
		return why, err
	}
	if s.Store != nil {
		cfg, err := s.loadConfig()
		if err != nil {
			return "", err
		}
		for g, gc := range cfg.Groups {
			if gc != nil && gc.Rule != nil && strings.EqualFold(g, name) {
				return "it is a rule group (its members come from a rule an admin set)", nil
			}
		}
	}
	return "", nil
}

// privilegedGroupReason says why name is a privileged group ("" = it
// isn't): a built-in LLDAP group, an administrator group (§9.4) or a
// delegated-permission group (§9.6). The one classification behind
// keptGroupReason and CheckBindGroups. Caller holds no lock.
func (s *Service) privilegedGroupReason(name string) (string, error) {
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
	}
	return "", nil
}

// CheckBindGroups checks the groups an instance is bound to (contract
// §11.9 groups mode "existing"; "" = none of that kind) and answers
// them as LLDAP names them (matched case-insensitively): an unknown
// group is 400 "unknown group <name>"; the users group may not be a
// built-in, administrator or permission group (privilegedGroupReason,
// built-ins matched case-insensitively too) — 400; the admins group may
// be any existing group, lldap_admin included. Users & Groups not
// configured or not answering, or directory.yaml unreadable, is 503.
// Read-only.
func (s *Service) CheckBindGroups(ctx context.Context, users, admins string) (string, string, error) {
	if err := s.LLDAP.Available(); err != nil {
		return "", "", &Error{Status: http.StatusServiceUnavailable, Msg: "users & groups is not available: " + err.Error()}
	}
	groups, err := s.LLDAP.ListGroups(ctx)
	if err != nil {
		return "", "", &Error{Status: http.StatusServiceUnavailable, Msg: "listing LLDAP groups: " + err.Error()}
	}
	byName := map[string]string{}
	for _, g := range groups {
		byName[strings.ToLower(g.DisplayName)] = g.DisplayName
	}
	resolve := func(n string) (string, error) {
		if n == "" {
			return "", nil
		}
		if g, ok := byName[strings.ToLower(n)]; ok {
			return g, nil
		}
		return "", invalid("unknown group %s", n)
	}
	u, err := resolve(users)
	if err != nil {
		return "", "", err
	}
	a, err := resolve(admins)
	if err != nil {
		return "", "", err
	}
	if u != "" {
		why, err := s.privilegedGroupReason(u)
		if err != nil {
			return "", "", &Error{Status: http.StatusServiceUnavailable, Msg: "reading directory.yaml: " + err.Error()}
		}
		for b := range builtinGroups {
			if strings.EqualFold(b, u) {
				why = "it is a built-in LLDAP group"
			}
		}
		if why != "" {
			return "", "", invalid("the users group can't be a built-in or administrator group (%s: %s)", u, why)
		}
	}
	return u, a, nil
}

// ResolveActor checks that actor can run the instance group operations:
// an LLDAP administrator (as CallerAs resolves it). Users & Groups not
// available is no error (the group steps are warnings then).
func (s *Service) ResolveActor(ctx context.Context, actor Actor) error {
	if s.LLDAP.Available() != nil {
		return nil
	}
	c, err := s.CallerAs(ctx, actor)
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
// group is kept, with a warning: decided, nothing to retry. Users &
// Groups not configured or not answering (no LLDAP credentials, LLDAP
// down) keeps the group too, but undecided: a *KeptUnavailableError
// (errors.Is ErrKeptUnavailable), whose text is the warning for people —
// a delete shows it as one, an enable's Stop fails its undo step (Stop
// again retries).
func (s *Service) DeleteInstanceGroup(ctx context.Context, actor Actor, name string) (warnings []string, err error) {
	if name == "" {
		return nil, nil
	}
	if aerr := s.LLDAP.Available(); aerr != nil {
		return nil, &KeptUnavailableError{Group: name, Cause: aerr}
	}
	why, err := s.keptGroupReason(name)
	if err != nil {
		return nil, err
	}
	if why != "" {
		return []string{fmt.Sprintf("group %s was kept: %s", name, why)}, nil
	}
	c, err := s.CallerAs(ctx, actor)
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

// ErrKeptUnavailable: DeleteInstanceGroup kept the group only because
// Users & Groups didn't answer — nothing was decided (an enable's Stop
// retries it), unlike a group kept because it is protected or shared (a
// warning). Matched with errors.Is on a *KeptUnavailableError.
var ErrKeptUnavailable = errors.New("users & groups is not available")

// KeptUnavailableError is DeleteInstanceGroup's answer when Users &
// Groups didn't answer: Group was kept, Cause is why. Its text is the
// warning shown to people.
type KeptUnavailableError struct {
	Group string
	Cause error
}

func (e *KeptUnavailableError) Error() string {
	return fmt.Sprintf("group %s was kept: %s (%v) — delete it on the Users & Groups page", e.Group, ErrKeptUnavailable, e.Cause)
}

// Is: errors.Is(err, ErrKeptUnavailable).
func (e *KeptUnavailableError) Is(target error) bool { return target == ErrKeptUnavailable }

func (e *KeptUnavailableError) Unwrap() error { return e.Cause }

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
	c, err := s.CallerAs(ctx, actor)
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
