package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// Creating an instance from the API (contract §11.1–11.3, §11.7).

// CreateResult is what POST /api/instances answers: the new instance and
// any warnings (an existing group kept, Users & Groups unavailable).
type CreateResult struct {
	InstanceView
	Warnings []string `json:"warnings,omitempty"`
}

// CreateInstanceAs creates instance id of templateID (CreateInstance:
// state "created", not enabled; hosts nil = the defaults on the main
// domain) as actor, then its empty access / admin groups users_<id> /
// admin_<id> through the Users & Groups guardrails (Groups, as actor). The
// actor must resolve as an LLDAP admin before anything is created. A group
// that already exists is kept with a warning (its members get access);
// without Users & Groups the groups are a warning. A failure creating a
// group removes the instance and the groups created so far. Takes the
// per-instance lock; audited as instance.create.
func (h *Hub) CreateInstanceAs(templateID, id string, hosts map[string]string, actor string) (res *CreateResult, err error) {
	res = &CreateResult{}
	defer func() {
		detail := "template=" + templateID
		if len(res.Hosts) > 0 {
			detail += " hosts=" + hostList(res.Hosts)
		}
		if len(res.Warnings) > 0 {
			detail += fmt.Sprintf(" warnings=%d", len(res.Warnings))
		}
		h.auditOp(actor, "instance.create", id, detail, err)
	}()
	if strings.TrimSpace(actor) == "" {
		return res, statusErr(400, "no signed-in user to audit the change as")
	}
	if !templates.InstanceIDRe.MatchString(id) {
		return res, statusErr(400, "instance id %q must match %s", id, templates.InstanceIDRe)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return res, err
	}
	defer unlock()

	h.mu.RLock()
	groupsAPI := h.groups
	var names templates.InstanceNames
	if t := h.catalogLocked(templateID); t != nil {
		names = t.NamesFor(id)
	}
	h.mu.RUnlock()
	groups := []string{}
	for _, g := range []string{names.AccessGroup, names.AdminGroup} {
		if g != "" {
			groups = append(groups, g)
		}
	}
	if groupsAPI != nil && len(groups) > 0 {
		if err := groupsAPI.ResolveActor(context.Background(), actor); err != nil {
			return res, fmt.Errorf("the acting admin %q can't create the instance's groups — nothing was created: %w", actor, err)
		}
	}
	if err := h.CreateInstance(templateID, id, hosts); err != nil {
		return res, err
	}

	var created []string
	undo := func(cause error) error {
		var errs []error
		for _, g := range created {
			if _, err := groupsAPI.DeleteInstanceGroup(context.Background(), actor, g); err != nil {
				errs = append(errs, err)
			}
		}
		h.mu.Lock()
		delete(h.st.Instances, id)
		h.rebuildLocked()
		saveErr := h.st.Save(h.statePath())
		h.mu.Unlock()
		if err := errors.Join(append(errs, saveErr)...); err != nil {
			return fmt.Errorf("%w — removing the new instance %s again failed too: %v", cause, id, err)
		}
		return fmt.Errorf("%w — the new instance %s was removed again", cause, id)
	}
	for _, g := range groups {
		if groupsAPI == nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("group %s was not created: users & groups is not available", g))
			continue
		}
		w, err := groupsAPI.CreateInstanceGroup(context.Background(), actor, g)
		res.Warnings = append(res.Warnings, w...)
		if err != nil {
			return res, undo(fmt.Errorf("creating group %s: %w", g, err))
		}
		if len(w) == 0 {
			created = append(created, g)
		}
	}
	if v, ok := h.InstanceView(id); ok {
		res.InstanceView = v
	}
	log.Printf("instance %s of %s created by %s", id, templateID, actor)
	return res, nil
}

// InstanceView returns one instance as GET /api/instances lists it.
func (h *Hub) InstanceView(id string) (InstanceView, bool) {
	for _, v := range h.Instances() {
		if v.ID == id {
			return v, true
		}
	}
	return InstanceView{}, false
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
