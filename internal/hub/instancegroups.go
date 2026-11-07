package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/templates"
)

// Instance groups on enable (contract §11.2): enabling an instance —
// the default instance of a template included — creates its missing
// access / admin groups through the Users & Groups guardrails
// (Groups.CreateInstanceGroup, audited there as the enabling admin),
// as CreateInstanceAs does. Only the derived names are created
// (users_<id> / admin_<id>: an instance's always, a default instance's
// when the manifest declares exactly those); a manifest group with any
// other name (a shared or core group) is never created by the Hub, only
// reported. Existing groups are left alone. MissingGroups lists the
// enabled instances whose groups are missing (the Apps banner, "Create
// missing groups"); CreateMissingGroups creates them.

// instanceGroup is one access / admin group of an instance.
type instanceGroup struct {
	Name string
	// Derived: users_<id> / admin_<id> — the Hub may create it.
	Derived bool
}

// instanceGroups lists t's access and admin groups.
func instanceGroups(t *templates.Template) []instanceGroup {
	n := t.NamesFor(t.ID)
	var out []instanceGroup
	if n.AccessGroup != "" {
		out = append(out, instanceGroup{Name: n.AccessGroup, Derived: n.AccessGroup == "users_"+t.ID})
	}
	if n.AdminGroup != "" && n.AdminGroup != n.AccessGroup {
		out = append(out, instanceGroup{Name: n.AdminGroup, Derived: n.AdminGroup == "admin_"+t.ID})
	}
	return out
}

// EnableResult is what an enable answers: the groups it created and any
// warnings (Users & Groups unavailable, a group it may not create).
type EnableResult struct {
	GroupsCreated []string `json:"groups_created,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// EnableAs is Enable as actor, run to its end: StartEnable's code (the
// same lock, op record, steps and Stop) waited for (runOpSync). First
// the instance's missing derived groups are created as actor (who must
// resolve as an LLDAP admin; else nothing happens), then the instance is
// enabled. A group created before a failed enable stays (empty; the
// instance needs it anyway) — only a Stop removes it. Without an actor
// (no X-Forwarded-User) no group is created: a warning. A failure after
// the enable was accepted is an *OpError (its record); a busy instance
// a *BusyError carrying the running record.
func (h *Hub) EnableAs(id string, actor directory.Actor) (*EnableResult, error) {
	res := &EnableResult{}
	_, _, err := h.runOpSync(id, OpEnable, actor, h.enablePlan(id), func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		r, err := h.runEnable(ctx, id, actor, ready)
		res = r
		return nil, r.Warnings, err
	})
	// The synchronous enable route answers an unknown instance 400, as it
	// always did (StartEnable's is 404, contract §11.7).
	var se *StatusError
	var oe *OpError
	if !errors.As(err, &oe) && errors.As(err, &se) && se.Status == 404 {
		err = &StatusError{Status: 400, Err: se.Err}
	}
	return res, err
}

// ensureGroups creates id's missing derived groups as actor; a missing
// group the Hub may not create is a warning. Caller holds id's lock.
func (h *Hub) ensureGroups(ctx context.Context, id string, groups []instanceGroup, actor directory.Actor) (created, warnings []string, err error) {
	todo, warnings, err := h.planGroups(ctx, id, groups, actor)
	if err != nil || len(todo) == 0 {
		return nil, warnings, err
	}
	created, w, err := h.createGroups(ctx, nil, id, todo, actor)
	return created, append(warnings, w...), err
}

// planGroups is the read-only half of ensureGroups: the derived groups
// to create (todo) — the actor resolved when there are any (else the
// error: nothing was changed) — and the warnings (not checked, a missing
// group the Hub may not create).
func (h *Hub) planGroups(ctx context.Context, id string, groups []instanceGroup, actor directory.Actor) (todo, warnings []string, err error) {
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	if groupsAPI == nil {
		return nil, []string{fmt.Sprintf("groups %s were not checked: users & groups is not available — create them in Users & Groups if they are missing", strings.Join(names, ", "))}, nil
	}
	if strings.TrimSpace(actor.User) == "" {
		return nil, []string{fmt.Sprintf("groups %s were not checked: no signed-in user to create them as", strings.Join(names, ", "))}, nil
	}
	missing, err := groupsAPI.MissingInstanceGroups(ctx, names)
	if err != nil {
		return nil, []string{fmt.Sprintf("groups %s were not checked: %v — use \"Create missing groups\" on the Apps page once users & groups answers", strings.Join(names, ", "), err)}, nil
	}
	if len(missing) == 0 {
		return nil, nil, nil
	}
	isMissing := map[string]bool{}
	for _, g := range missing {
		isMissing[g] = true
	}
	for _, g := range groups {
		switch {
		case !isMissing[g.Name]:
		case g.Derived:
			todo = append(todo, g.Name)
		default:
			warnings = append(warnings, fmt.Sprintf("group %s is missing and is not the instance's own (users_%s / admin_%s): create it in Users & Groups — until then nobody can use it to sign in", g.Name, id, id))
		}
	}
	if len(todo) == 0 {
		return nil, warnings, nil
	}
	if err := groupsAPI.ResolveActor(ctx, actor); err != nil {
		return nil, warnings, fmt.Errorf("the acting admin %q can't create the missing groups %s of %s — nothing was changed: %w", actor.User, strings.Join(todo, ", "), id, err)
	}
	return todo, warnings, nil
}

// createGroups creates todo as actor, each one written to p's Created
// ledger the moment it exists (a Stop deletes exactly those). A Stop
// (stopCtx cancelled) ends it before the next group with stopCtx's
// error; nil: never stopped. LLDAP calls run on their own context.
func (h *Hub) createGroups(stopCtx context.Context, p *Progress, id string, todo []string, actor directory.Actor) (created, warnings []string, err error) {
	if len(todo) == 0 {
		return nil, nil, nil
	}
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI == nil {
		return nil, nil, statusErr(503, "users & groups is not available")
	}
	for _, g := range todo {
		if stopCtx != nil && stopCtx.Err() != nil {
			return created, warnings, stopCtx.Err()
		}
		made, w, err := groupsAPI.CreateInstanceGroup(context.Background(), actor, g)
		warnings = append(warnings, w...)
		if made {
			created = append(created, g)
			p.Created(CreatedGroups, g)
		}
		if err != nil {
			return created, warnings, fmt.Errorf("creating group %s of %s: %w", g, id, err)
		}
	}
	if len(created) > 0 {
		log.Printf("instance %s: groups %s created by %s", id, strings.Join(created, ", "), actor.User)
	}
	return created, warnings, nil
}

// MissingGroup is an enabled instance whose access / admin groups are
// missing in LLDAP: Creatable ones "Create missing groups" makes, Other
// ones (not the instance's derived names) only an admin can create in
// Users & Groups.
type MissingGroup struct {
	Instance  string   `json:"instance"`
	Creatable []string `json:"creatable,omitempty"`
	Other     []string `json:"other,omitempty"`
}

// MissingGroupsReport answers GET /api/instances/missing-groups. Error:
// users & groups didn't answer (or isn't configured): nothing is known.
type MissingGroupsReport struct {
	Instances []MissingGroup `json:"instances"`
	Error     string         `json:"error,omitempty"`
}

// enabledGroups lists every enabled instance's groups.
func (h *Hub) enabledGroups() (map[string][]instanceGroup, Groups) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[string][]instanceGroup{}
	for _, id := range h.st.Enabled {
		if t := h.findLocked(id); t != nil {
			if gs := instanceGroups(t); len(gs) > 0 {
				out[id] = gs
			}
		}
	}
	return out, h.groups
}

// MissingGroups reports the enabled instances whose groups are missing.
func (h *Hub) MissingGroups(ctx context.Context) MissingGroupsReport {
	rep := MissingGroupsReport{Instances: []MissingGroup{}}
	byID, groupsAPI := h.enabledGroups()
	if groupsAPI == nil {
		rep.Error = "users & groups is not available"
		return rep
	}
	var names []string
	for _, gs := range byID {
		for _, g := range gs {
			names = append(names, g.Name)
		}
	}
	if len(names) == 0 {
		return rep
	}
	missing, err := groupsAPI.MissingInstanceGroups(ctx, names)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	isMissing := map[string]bool{}
	for _, g := range missing {
		isMissing[g] = true
	}
	for id, gs := range byID {
		m := MissingGroup{Instance: id}
		for _, g := range gs {
			switch {
			case !isMissing[g.Name]:
			case g.Derived:
				m.Creatable = append(m.Creatable, g.Name)
			default:
				m.Other = append(m.Other, g.Name)
			}
		}
		if len(m.Creatable)+len(m.Other) > 0 {
			rep.Instances = append(rep.Instances, m)
		}
	}
	sort.Slice(rep.Instances, func(i, j int) bool { return rep.Instances[i].Instance < rep.Instances[j].Instance })
	return rep
}

// CreateGroupsResult is one instance's part of CreateMissingGroups.
type CreateGroupsResult struct {
	Instance string   `json:"instance"`
	Created  []string `json:"created,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// CreateMissingGroups creates the missing derived groups of the enabled
// instances ids (empty: all of them) as actor, each under its instance's
// lock. A busy or unknown instance is reported, not fatal; the actor must
// resolve as an LLDAP admin (else nothing is created: the error).
func (h *Hub) CreateMissingGroups(ctx context.Context, ids []string, actor directory.Actor) ([]CreateGroupsResult, error) {
	if strings.TrimSpace(actor.User) == "" {
		return nil, statusErr(400, "no signed-in user to create the groups as")
	}
	byID, groupsAPI := h.enabledGroups()
	if groupsAPI == nil {
		return nil, statusErr(503, "users & groups is not available")
	}
	if err := groupsAPI.ResolveActor(ctx, actor); err != nil {
		return nil, fmt.Errorf("the acting admin %q can't create groups — nothing was changed: %w", actor.User, err)
	}
	if len(ids) == 0 {
		for id := range byID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]CreateGroupsResult, 0, len(ids))
	for _, id := range ids {
		r := CreateGroupsResult{Instance: id}
		if !templates.ValidID(id) && !templates.InstanceIDRe.MatchString(id) {
			r.Error = "invalid instance id"
			out = append(out, r)
			continue
		}
		unlock, err := h.lockApp(id)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		h.mu.RLock()
		var gs []instanceGroup
		enabled := h.st.IsEnabled(id)
		if t := h.findLocked(id); t != nil && enabled {
			gs = instanceGroups(t)
		}
		h.mu.RUnlock()
		if !enabled {
			r.Error = "not an enabled instance"
		} else if len(gs) > 0 {
			created, warnings, err := h.ensureGroups(ctx, id, gs, actor)
			r.Created, r.Warnings = created, warnings
			if err != nil {
				r.Error = err.Error()
			}
			h.seedSettings(id)
			h.reseedPlaceholderRows(id, created)
			r.Warnings = append(r.Warnings, h.bindPlaceholderRows(ctx, id)...)
		}
		unlock()
		out = append(out, r)
	}
	return out, nil
}
