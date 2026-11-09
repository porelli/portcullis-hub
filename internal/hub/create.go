package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/templates"
)

// Creating an instance from the API (contract §11.1–11.3, §11.7).

// CreateResult is what POST /api/instances answers: the new instance and
// any warnings (an existing group kept, Users & Groups unavailable).
type CreateResult struct {
	InstanceView
	Warnings []string `json:"warnings,omitempty"`
}

// OpCreate is an instance create (POST /api/instances; contract §11.7):
// steps instance, groups.
const OpCreate = "create"

// CreateInstanceAs creates instance id of templateID (CreateInstance:
// state "created", not enabled; hosts nil = the defaults on the main
// domain) as actor, then its empty access / admin groups users_<id> /
// admin_<id> through the Users & Groups guardrails (Groups, as actor). The
// actor must resolve as an LLDAP admin before anything is created. A group
// that already exists is kept with a warning (its members get access);
// without Users & Groups the groups are a warning. A failure creating a
// group removes the instance and the groups created so far. Takes the
// per-instance lock; audited as instance.create. StartCreate's operation
// run to its end (runOpSync: the same lock, record, steps and Stop; the
// record is id's).
func (h *Hub) CreateInstanceAs(req CreateRequest, actor directory.Actor) (res *CreateResult, err error) {
	res = &CreateResult{}
	_, _, err = h.runOpSync(req.ID, OpCreate, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		var cerr error
		res, cerr = h.createInstance(ctx, req, actor, ready)
		return createResult(res, req.ID, cerr)
	})
	return res, err
}

// StartCreate starts CreateInstanceAs in the background (202, op create,
// the record is id's): every refusal before the instance exists — a bad
// or taken id, its collisions, the actor — is answered at once, nothing
// recorded. The result holds "instance", the warnings are the record's.
func (h *Hub) StartCreate(req CreateRequest, actor directory.Actor) (*AsyncOp, error) {
	return h.startAsync(req.ID, OpCreate, actor, []Step{}, func(ctx context.Context, ready func()) (map[string]string, []string, error) {
		res, err := h.createInstance(ctx, req, actor, ready)
		return createResult(res, req.ID, err)
	})
}

// createResult is a create's op record result ("instance" once it
// succeeded) and warnings.
func createResult(res *CreateResult, id string, err error) (map[string]string, []string, error) {
	if err != nil {
		return nil, res.Warnings, err
	}
	return map[string]string{"instance": id}, res.Warnings, nil
}

// createInstance is the create CreateInstanceAs and StartCreate run: the
// request checked (label §11.9, groups choice, an "existing" binding
// against LLDAP), the instance step (createEntry) before ready — its
// refusals are the synchronous answer —, then the groups step: for mode
// "new" the derived groups created (each into the record's Created
// ledger; a default instance's manifest group with another name is only
// a warning), for "existing" nothing created ("bound to <users>,
// <admins>"). A Stop accepted before the commit (the groups done)
// removes the instance and exactly the groups created (settleOp →
// undoCreate).
func (h *Hub) createInstance(ctx context.Context, req CreateRequest, actor directory.Actor, ready func()) (res *CreateResult, err error) {
	templateID, id := req.Template, req.ID
	res = &CreateResult{}
	defer func() {
		detail := "template=" + templateID
		if len(res.Hosts) > 0 {
			detail += " hosts=" + hostList(res.Hosts)
		}
		if req.Groups.Mode == GroupsExisting {
			detail += " groups=existing"
		}
		if len(req.Setup) > 0 {
			detail += " setup=" + strings.Join(slices.Sorted(maps.Keys(req.Setup)), ",")
		}
		if len(res.Warnings) > 0 {
			detail += fmt.Sprintf(" warnings=%d", len(res.Warnings))
		}
		h.auditOp(actor, "instance.create", id, detail, err)
	}()
	if strings.TrimSpace(actor.User) == "" {
		return res, statusErr(400, "no signed-in user to audit the change as")
	}
	if id != templateID {
		if !templates.InstanceIDRe.MatchString(id) {
			return res, statusErr(400, "instance id %q must match %s", id, templates.InstanceIDRe)
		}
		if err := templates.CheckIDShape(id); err != nil {
			return res, statusErr(400, "instance %v", err)
		}
	}
	if err := CheckLabel(req.Label); err != nil {
		return res, err
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, h.busyErr(id, err)
	}
	defer unlock()

	h.mu.RLock()
	groupsAPI := h.groups
	var names templates.InstanceNames
	t := h.catalogLocked(templateID)
	req.setupGen = h.catalogGen
	var choiceErr error
	if t != nil {
		names = t.NamesFor(id)
		choiceErr = checkGroupChoice(t, req.Groups)
	}
	h.mu.RUnlock()
	if t == nil {
		return res, statusErr(404, "template not found: %s", templateID)
	}
	if choiceErr != nil {
		return res, choiceErr
	}
	// The setup choices (§11.9, §13.18): checked like a settings save's
	// values before anything is created, against the catalog read above;
	// createEntry stores exactly this result (409 if the catalog changed).
	if req.setup, err = h.parseSetup(context.Background(), t, req.Setup); err != nil {
		return res, err
	}
	req.checked = true
	bound := req.Groups.Mode == GroupsExisting
	var users, admins string
	groups := []string{}
	if bound {
		if users, admins, err = h.bindGroups(context.Background(), req.Groups); err != nil {
			return res, err
		}
	} else {
		for _, g := range []string{names.AccessGroup, names.AdminGroup} {
			switch {
			case g == "":
			case g == "users_"+id || g == "admin_"+id:
				groups = append(groups, g)
			default:
				// A default instance's manifest group with another name
				// (§11.2): someone's on purpose, never created here.
				res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was not created: it isn't named users_%s / admin_%s (create it in Users & Groups if it is missing)", g, id, id))
			}
		}
	}
	if groupsAPI != nil && (len(groups) > 0 || bound) {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return res, fmt.Errorf("the acting admin %q can't create the instance's groups — nothing was created: %w", actor.User, err)
		}
	}
	p := progressFrom(ctx)
	p.AddStep(StepInstance, "Creating the instance")
	if len(groups) > 0 || bound {
		p.AddStep(StepGroups, "Groups")
	}
	// The instance step before the operation is accepted: its refusals
	// (an id taken, its collisions) are the synchronous answer.
	p.Start(StepInstance)
	if bound {
		req.recheck = func() error {
			u, a, err := h.bindGroups(context.Background(), req.Groups)
			if err == nil && (u != users || a != admins) {
				err = statusErr(409, "the groups to bind changed meanwhile (%s, %s): retry", u, a)
			}
			return err
		}
	}
	prior, err := h.createEntry(req, users, admins)
	if err != nil {
		return res, err
	}
	p.setPriorSettings(prior)
	p.Done(StepInstance)
	ready()
	if bound {
		p.Start(StepGroups)
		p.Detail(StepGroups, "bound to "+boundList(users, admins))
	}
	err = h.createSteps(ctx, p, templateID, id, groups, groupsAPI, actor, res)
	return res, h.settleOp(id, OpCreate, p, err)
}

// boundList is "<users>, <admins>" (the ones there are).
func boundList(users, admins string) string {
	var out []string
	for _, g := range []string{users, admins} {
		if g != "" {
			out = append(out, g)
		}
	}
	return strings.Join(out, ", ")
}

// createSteps is a create's groups step and commit (caller holds id's
// lock): a failure creating a group removes the instance and the groups
// created so far, unless a Stop was accepted first (its undo does).
func (h *Hub) createSteps(ctx context.Context, p *Progress, templateID, id string, groups []string, groupsAPI Groups, actor directory.Actor, res *CreateResult) error {
	var created []string
	undo := func(cause error) error {
		if !p.CloseStop() {
			return fmt.Errorf("%v: %w", cause, context.Canceled)
		}
		var errs []error
		var kept []string
		for _, g := range created {
			_, err := groupsAPI.DeleteInstanceGroup(context.Background(), actor, g)
			// Kept because Users & Groups didn't answer: the group stays
			// in LLDAP (a warning, as restore-as's undo treats it), not a
			// failed removal of the instance.
			if errors.Is(err, directory.ErrKeptUnavailable) {
				kept = append(kept, err.Error())
				res.Warnings = append(res.Warnings, err.Error())
				continue
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		if err := h.removeNewInstance(id, p.priorSettings()); err != nil {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("%w — removing the new instance %s again failed too: %v", cause, id, err)
		}
		if len(kept) > 0 {
			return fmt.Errorf("%w — the new instance %s was removed again (%s)", cause, id, strings.Join(kept, "; "))
		}
		return fmt.Errorf("%w — the new instance %s was removed again", cause, id)
	}
	if len(groups) > 0 {
		p.Start(StepGroups)
	}
	for _, g := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if groupsAPI == nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was not created: users & groups is not available", g))
			continue
		}
		made, w, err := groupsAPI.CreateInstanceGroup(context.Background(), actor, g)
		res.Warnings = append(res.Warnings, w...)
		if made {
			created = append(created, g)
			// Written at once: a Stop — also after a Hub restart — deletes
			// exactly the groups this create made.
			p.Created(CreatedGroups, g)
		}
		if err != nil {
			return undo(fmt.Errorf("creating group %s: %w", g, err))
		}
	}
	if len(groups) > 0 {
		p.Detail(StepGroups, groupsDetail(nil, created, groups))
	}
	// The commit gate: a Stop accepted until here removes the instance.
	if !p.CloseStop() {
		return context.Canceled
	}
	if p.Has(StepGroups) {
		p.Done(StepGroups)
	}
	// The template's starting rows (seeded by CreateInstance), bound to
	// the groups just created.
	res.Warnings = append(res.Warnings, h.bindPlaceholderRows(context.Background(), id)...)
	if v, ok := h.InstanceView(id); ok {
		res.InstanceView = v
	}
	log.Printf("instance %s of %s created by %s", id, templateID, actor.User)
	return nil
}

// InstanceView returns one instance as GET /api/instances lists it. A
// default instance the list leaves out (never enabled, no state, no op
// record) is built from its catalog view; false only for an unknown id.
func (h *Hub) InstanceView(id string) (InstanceView, bool) {
	for _, v := range h.Instances() {
		if v.ID == id {
			return v, true
		}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil {
		return InstanceView{}, false
	}
	v := h.instanceViewLocked(t)
	v.State = StateDisabled
	if t.Enabled {
		v.State = StateEnabled
	}
	return v, true
}

// hostList renders hosts for the audit log: "router=host,…", sorted.
func hostList(hosts map[string]string) string {
	out := make([]string, 0, len(hosts))
	for r, v := range hosts {
		out = append(out, r+"="+v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// InstanceDomain is a domain the hostname editor offers (§11.3): the main
// domain or an enrolled one; Assignable = new hostnames may go on it (an
// enrolled domain only in state ready).
type InstanceDomain struct {
	Name       string `json:"name"`
	Main       bool   `json:"main"`
	State      string `json:"state,omitempty"`
	Assignable bool   `json:"assignable"`
}

// InstanceDomains lists the main domain first, then the enrolled domains
// (the cached known list: no network call), sorted.
func (h *Hub) InstanceDomains() []InstanceDomain {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []InstanceDomain{{Name: NormalizeHost(h.cfg.Domain), Main: true, Assignable: true}}
	enrolled := h.enrolledLocked()
	sort.Slice(enrolled, func(i, j int) bool { return enrolled[i].Name < enrolled[j].Name })
	for _, d := range enrolled {
		out = append(out, InstanceDomain{Name: d.Name, State: d.State, Assignable: d.State == DomainReady})
	}
	return out
}

// HostRouter describes one host router of a template for the hostname
// editor: its default subdomain and whether its hostname is fixed once the
// instance exists (hosts.immutable).
type HostRouter struct {
	Router    string `json:"router"`
	Subdomain string `json:"subdomain"`
	Immutable bool   `json:"immutable"`
}

// HostRouters lists a template's host routers, sorted (nil, false for an
// unknown template); legacy reports a template whose hostnames are fixed
// (${PORTCULLIS_DOMAIN} rules).
func (h *Hub) HostRouters(templateID string) (routers []HostRouter, multi, legacy, ok bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.catalogLocked(templateID)
	if t == nil {
		return nil, false, false, false
	}
	for r, sub := range t.HostRouters {
		routers = append(routers, HostRouter{Router: r, Subdomain: sub, Immutable: t.Manifest.ImmutableHost(r)})
	}
	sort.Slice(routers, func(i, j int) bool { return routers[i].Router < routers[j].Router })
	return routers, t.Manifest.Multi(), t.HostForm == templates.FormLegacy, true
}
