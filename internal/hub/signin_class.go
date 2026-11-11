package hub

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// What the Portcullis MCP's sign-in tools need for their per-call classes
// (contract §15.10): a plain read of the sign-in state, the twin route's
// refusals before any confirmation, and who a change newly blocks.

// SignInState is the sign-in view without touching the inventory (no
// load, no refresh): the people counts come from the cache, -1 while there
// is none.
func (h *Hub) SignInState() *SignInView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.signInViewLocked()
}

// SignInDraft is one planned sign-in change: exactly one of a method
// switch (Method, On), a template save (Template, Name, Rule, Create), the
// default (Default), a core page's pick (CoreKey, Core: "" = the default)
// or an instance's pick (Instance, Pick: "" = the default).
// It is also the body of POST /api/signin/impact.
type SignInDraft struct {
	Method   signin.Method `json:"method,omitempty"`
	On       bool          `json:"on,omitempty"`
	Template string        `json:"template,omitempty"`
	Name     string        `json:"name,omitempty"`
	Rule     *signin.Node  `json:"rule,omitempty"`
	Create   bool          `json:"create,omitempty"`
	Default  *string       `json:"default,omitempty"`
	CoreKey  string        `json:"core_page,omitempty"`
	Core     *string       `json:"core,omitempty"`
	Instance string        `json:"instance,omitempty"`
	Pick     *string       `json:"pick,omitempty"`
}

// SignInImpact is who a draft newly blocks: people its uses apply to who
// meet their template with the switches before and not after, per use
// (Affected, sorted like affectedLocked). Unknown says why that couldn't be
// worked out ("" = it was): Users & Groups or the inventory unreadable, or
// people whose methods the inventory doesn't have.
type SignInImpact struct {
	Affected []AffectedApp `json:"affected"`
	Unknown  string        `json:"unknown"`
}

// PrecheckSignIn refuses a draft its twin route would refuse for its
// names and rule, with the route's status and text: an unknown method
// (404), a bad template id, name or rule
// (400), an existing id on create (409), an unknown one on update (404),
// an enabled template left unmeetable (409), an unknown core key (400),
// an unknown or disabled template pick (404 / 409), an unknown instance
// (404) or one that takes no template (400). Nothing is stored.
func (h *Hub) PrecheckSignIn(d SignInDraft) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	si := h.st.SignIn
	switch {
	case d.Method != "":
		if _, ok := signin.InfoOf(d.Method); !ok {
			return statusErr(http.StatusNotFound, "unknown sign-in method %q", clip(string(d.Method), 64))
		}
	case d.Template != "" || d.Name != "" || d.Rule != nil || d.Create:
		if err := checkTemplateID(d.Template); err != nil {
			return err
		}
		if d.Rule == nil {
			return statusErr(http.StatusBadRequest, "rule is required")
		}
		if err := checkTemplateInput(TemplateInput{Name: d.Name, Rule: *d.Rule}); err != nil {
			return err
		}
		old, exists := si.Templates[d.Template]
		switch {
		case d.Create && exists:
			return statusErr(http.StatusConflict, "a template with id %s already exists", d.Template)
		case !d.Create && !exists:
			return statusErr(http.StatusNotFound, "no sign-in template %s", d.Template)
		}
		if d.Create || old.Enabled {
			if _, err := signin.Compile(*d.Rule, si.MethodsOn()); err != nil {
				return statusErr(http.StatusConflict, "%q can't be met with the sign-in methods that are switched on (%v): switch on a method it names or change the rule", d.Name, err)
			}
		}
	case d.Default != nil:
		return pickable(si, *d.Default)
	case d.Core != nil:
		if !slices.Contains(state.CoreSignInKeys, d.CoreKey) {
			return statusErr(http.StatusBadRequest, "%q is not a core page that takes a template (%s)", clip(d.CoreKey, 64), strings.Join(state.CoreSignInKeys, ", "))
		}
		if *d.Core != "" {
			return pickable(si, *d.Core)
		}
	case d.Pick != nil:
		t := h.findLocked(d.Instance)
		if t == nil {
			return ErrNotFound
		}
		native := h.st.SignInMode[d.Instance] == state.SignInNative
		if *d.Pick != "" && !configCapability(t, native).Templates {
			return statusErr(http.StatusBadRequest, "sign-in template: this app takes none (auth method %s: Portcullis doesn't sign people in to it, or its client certificate is its sign-in)", configCapability(t, native).Enforcement)
		}
		return pickableLocked(si, d.Pick)
	default:
		return statusErr(http.StatusBadRequest, "no sign-in change")
	}
	return nil
}

// NewlyBlocked works out who draft d newly blocks, judged like the
// preview (PreviewTemplate's affectedLocked): every core page and enabled
// instance that takes a template, with their people, the membership and
// the cached inventory (read once when there is none; never a forced
// refresh). A use whose compiled rule and switches don't change is
// skipped. A person the inventory doesn't have — or whose certificates
// are unknown while either rule names a YubiKey certificate — makes the
// impact Unknown (fail closed: nothing about them is known), and so does
// an enabled instance without a view (its template is missing: its
// people and rule can't be judged, never "nobody blocked").
func (h *Hub) NewlyBlocked(ctx context.Context, d SignInDraft) *SignInImpact {
	m, inv, why := h.signInPeople(ctx)
	if why != "" {
		return &SignInImpact{Affected: []AffectedApp{}, Unknown: why}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	cur := h.st.SignIn
	next := cur.Clone()
	switch {
	case d.Method != "":
		if next.Methods == nil {
			next.Methods = map[string]bool{}
		}
		next.Methods[string(d.Method)] = d.On
	case d.Template != "":
		if d.Rule == nil {
			return &SignInImpact{Affected: []AffectedApp{}, Unknown: "no rule"}
		}
		t, ok := next.Templates[d.Template]
		if !ok {
			t = state.SignInTemplate{Enabled: true}
		}
		t.Rule = state.CloneNode(*d.Rule)
		if next.Templates == nil {
			next.Templates = map[string]state.SignInTemplate{}
		}
		next.Templates[d.Template] = t
	case d.Default != nil:
		next.Default = *d.Default
	case d.Core != nil:
		if next.Core == nil {
			next.Core = map[string]string{}
		}
		next.Core[d.CoreKey] = *d.Core
	}
	onB, onA := cur.MethodsOn(), next.MethodsOn()
	imp := &SignInImpact{Affected: []AffectedApp{}}
	var unknown []string
	judge := func(kind, key, name string, users []string, before, after *signin.Node) {
		b, a := signin.Node{}, signin.Node{}
		if before != nil {
			b = *before
		}
		if after != nil {
			a = *after
		}
		if (before == nil) == (after == nil) && sameRule(b, a) && sameMethods(onB, onA) {
			return
		}
		certs := namesCert(b) || namesCert(a)
		var blocked []Blocked
		seen := map[string]bool{}
		for _, u := range slices.Sorted(slices.Values(users)) {
			u = strings.ToLower(u)
			if seen[u] {
				continue
			}
			seen[u] = true
			pm, known := inv.People[u]
			if !known || (certs && !pm.CertsKnown) {
				if !slices.Contains(unknown, u) {
					unknown = append(unknown, u)
				}
				continue
			}
			if meets(pm, b, onB) && !meets(pm, a, onA) {
				blocked = append(blocked, Blocked{User: u, Why: blockedWhy(pm, true)})
			}
		}
		if len(blocked) > 0 {
			imp.Affected = append(imp.Affected, AffectedApp{Kind: kind, Instance: key, Name: name, Blocked: blocked})
		}
	}
	for _, k := range state.CoreSignInKeys {
		pb, pa := cur.Core[k], next.Core[k]
		if pb == "" {
			pb = cur.Default
		}
		if pa == "" {
			pa = next.Default
		}
		judge(UseCore, k, coreSignInLabels[k], coreSignInUsers(k, m), compiledPtr(cur, pb), compiledPtr(next, pa))
	}
	viewed := map[string]bool{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		viewed[t.ID] = true
		pick, mode := h.st.Instances[t.ID].SignInTemplate, h.st.SignInMode[t.ID]
		pickA := pick
		if d.Pick != nil && t.ID == d.Instance {
			pickA = *d.Pick
		}
		accB, accA := h.accessWith(t, cur, pick, mode), h.accessWith(t, next, pickA, mode)
		if !accB.Capability.Templates || !accA.Capability.Templates {
			continue
		}
		judge(UseInstance, t.ID, instanceName(t), instanceSignInUsers(t, m), accB.Rule, accA.Rule)
	}
	var missing []string
	for _, id := range h.st.Enabled {
		if !viewed[id] && !slices.Contains(missing, id) {
			missing = append(missing, id)
		}
	}
	slices.Sort(missing)
	var whys []string
	if len(unknown) > 0 {
		whys = append(whys, fmt.Sprintf("the sign-in methods of %s aren't known", strings.Join(clipList(unknown, 10), ", ")))
	}
	if len(missing) > 0 {
		whys = append(whys, fmt.Sprintf("the template of enabled app %s is missing", strings.Join(clipList(missing, 10), ", ")))
	}
	imp.Unknown = strings.Join(whys, "; ")
	return imp
}

// InheritingDefault lists what uses the default template without a pick
// of its own: core pages without a pick and instances that take a
// template and pick none (enabled or not).
func (h *Hub) InheritingDefault() []UseRef {
	h.mu.RLock()
	defer h.mu.RUnlock()
	si := h.st.SignIn
	out := []UseRef{}
	for _, k := range state.CoreSignInKeys {
		if si.Core[k] == "" {
			out = append(out, UseRef{Kind: UseCore, ID: k, Name: coreSignInLabels[k]})
		}
	}
	for i := range h.instances {
		t := &h.instances[i]
		acc := h.accessLocked(t)
		if acc.Capability.Templates && acc.Inherits {
			out = append(out, UseRef{Kind: UseInstance, ID: t.ID, Name: instanceName(t)})
		}
	}
	return out
}

// compiledPtr is compiledIn as a pointer (nil = no rule: nobody gets in).
func compiledPtr(si state.SignIn, id string) *signin.Node {
	c, ok := compiledIn(si, id)
	if !ok {
		return nil
	}
	return &c
}

func sameMethods(a, b map[signin.Method]bool) bool {
	for _, m := range signin.Methods {
		if a[m] != b[m] {
			return false
		}
	}
	return true
}

// namesCert reports whether compiled rule n has an alternative with a
// certificate method (an unreadable rule counts: fail closed).
func namesCert(n signin.Node) bool {
	if n.Op == "" && n.Leaf == "" {
		return false
	}
	alts, err := signin.Alternatives(n)
	if err != nil {
		return true
	}
	for _, alt := range alts {
		if slices.Contains(alt, signin.YubiKeyCert) || slices.Contains(alt, signin.BrowserCert) {
			return true
		}
	}
	return false
}

// clipList is the first n of list, "and N more" after them.
func clipList(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(slices.Clone(list[:n]), fmt.Sprintf("%d more", len(list)-n))
}
