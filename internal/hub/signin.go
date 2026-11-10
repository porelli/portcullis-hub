package hub

// Settings → Sign-in (contract §8.1, plan D1–D3, D11, D12): the methods,
// the templates, the default and the core pages' picks, with the "in use"
// and "method needed" refusals. Writers plan on a copy of state.SignIn under
// the read lock, plan again under the write lock (the result must be the
// same: instance picks change outside signInMu), save once (a failed save
// is undone in memory), write the policy file and audit after mu.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Blocked is a person who can't meet a template, and why: "no method yet"
// or "<Short> + <Short> only" (blockedFor).
type Blocked struct {
	User string `json:"user"`
	Why  string `json:"why"`
}

// UseRef is one use of a template: the default, a core page or an
// instance's own pick.
type UseRef struct {
	Kind string `json:"kind"` // UseDefault | UseCore | UseInstance
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UseRef kinds.
const (
	UseDefault  = "default"
	UseCore     = "core"
	UseInstance = "instance"
)

// SignInMethodView is one method row of Settings → Sign-in.
type SignInMethodView struct {
	ID        signin.Method `json:"id"`
	Label     string        `json:"label"`
	Tenths    int           `json:"tenths"`
	On        bool          `json:"on"`
	Available bool          `json:"available"`
	// People who have it set up (the inventory, signin_people.go); -1
	// while unknown.
	People int `json:"people"`
}

// SignInTemplateView is one template of Settings → Sign-in. Sentence and
// Score describe the rule as the switches leave it; Problem says why it
// can't be met ("" when it can).
type SignInTemplateView struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Rule     signin.Node  `json:"rule"`
	Sentence string       `json:"sentence"`
	Score    signin.Score `json:"score"`
	Problem  string       `json:"problem,omitempty"`
	Enabled  bool         `json:"enabled"`
	BuiltIn  bool         `json:"built_in"`
	UsedBy   []UseRef     `json:"used_by"`
}

// SignInView is Settings → Sign-in (GET /api/signin).
type SignInView struct {
	Methods     []SignInMethodView   `json:"methods"`
	Templates   []SignInTemplateView `json:"templates"`
	Default     string               `json:"default"`
	Core        map[string]string    `json:"core"`
	AddStronger bool                 `json:"add_stronger"`
}

// TemplateInput is a template save or preview: its name and source rule.
type TemplateInput struct {
	Name string      `json:"name"`
	Rule signin.Node `json:"rule"`
}

// SignInChange is a committed sign-in change: the new view, the enabled
// instances whose TLS option moved (tierChangesLocked: their override is
// rendered again and they restart) and warnings.
type SignInChange struct {
	View     *SignInView `json:"view"`
	Restarts []string    `json:"restarts"`
	Warnings []string    `json:"warnings"`
}

// TemplatePreview is a template draft's sentence, score and who it would
// affect (the people of the apps and core pages using it who can't meet
// the draft, signin_people.go); nothing is stored.
type TemplatePreview struct {
	Sentence string        `json:"sentence"`
	Score    signin.Score  `json:"score"`
	Affected []AffectedApp `json:"affected"`
	Problem  string        `json:"problem,omitempty"`
	// PeopleUnknown says why Affected couldn't be worked out ("" = it
	// was).
	PeopleUnknown string `json:"people_unknown,omitempty"`
}

// AffectedApp is an app (Kind UseInstance, Instance its id) or a core
// page (Kind UseCore, Instance its key) whose people can't all meet a
// template.
type AffectedApp struct {
	Kind     string    `json:"kind"`
	Instance string    `json:"instance"`
	Name     string    `json:"name"`
	Blocked  []Blocked `json:"blocked"`
}

// coreSignInLabels name the core pages (state.CoreSignInKeys).
var coreSignInLabels = map[string]string{
	"portal": "Portal", "hub": "Hub", "people": "People", "directory": "Directory",
	"enroll": "Enroll", "metrics": "Metrics", "traefik": "Traefik",
}

// ── reads ────────────────────────────────────────────────

// SignInView is Settings → Sign-in.
func (h *Hub) SignInView(ctx context.Context) (*SignInView, error) {
	// The people counts: the cached inventory (read once if there is
	// none yet); unknown stays -1.
	_, _ = h.inventoryBase(ctx, false)
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.signInViewLocked(), nil
}

// compiledLocked is template id's compiled rule while it is enabled and
// can be met with the switched-on methods; every writer of a published
// rule goes through it (fail closed: anything else is no rule).
func (h *Hub) compiledLocked(id string) (signin.Node, bool) {
	return compiledIn(h.st.SignIn, id)
}

// compiledIn is compiledLocked under sign-in section si.
func compiledIn(si state.SignIn, id string) (signin.Node, bool) {
	t, ok := si.Templates[id]
	if !ok || !t.Enabled {
		return signin.Node{}, false
	}
	c, err := signin.Compile(t.Rule, si.MethodsOn())
	if err != nil {
		return signin.Node{}, false
	}
	return c, true
}

// templateForInstanceLocked is instance t's template: its own pick, else
// the default.
func (h *Hub) templateForInstanceLocked(t *templates.Template) string {
	if pick := h.st.Instances[t.ID].SignInTemplate; pick != "" {
		return pick
	}
	return h.st.SignIn.Default
}

func (h *Hub) signInViewLocked() *SignInView {
	si := h.st.SignIn
	on := si.MethodsOn()
	people := h.methodPeopleLocked()
	v := &SignInView{Default: si.Default, Core: maps.Clone(si.Core), AddStronger: si.AddStronger}
	for _, m := range signin.Methods {
		info, _ := signin.InfoOf(m)
		v.Methods = append(v.Methods, SignInMethodView{ID: m, Label: info.Label, Tenths: info.Tenths, On: on[m], Available: info.Available, People: people[m]})
	}
	for _, id := range templateOrder(si) {
		t := si.Templates[id]
		sentence, score, problem := describeRule(t.Rule, on)
		v.Templates = append(v.Templates, SignInTemplateView{ID: id, Name: t.Name, Rule: t.Rule, Sentence: sentence, Score: score, Problem: problem,
			Enabled: t.Enabled, BuiltIn: t.BuiltIn, UsedBy: h.usesLocked(si, id)})
	}
	return v
}

// describeRule is a source rule's sentence and score with the switches
// as they are, and why it can't be met ("" when it can).
func describeRule(rule signin.Node, on map[signin.Method]bool) (string, signin.Score, string) {
	u, err := signin.Usable(rule, on)
	switch {
	case errors.Is(err, signin.ErrUnmeetable):
		return signin.Sentence(rule), signin.ScoreOf(rule, on), "it can't be met with the sign-in methods that are switched on"
	case err != nil:
		return signin.Sentence(rule), signin.ScoreOf(rule, on), "the rule isn't valid: " + err.Error()
	}
	return signin.Sentence(u), signin.ScoreOf(rule, on), ""
}

// templateOrder lists the templates: the built-ins in their order, then
// the admins' own by id.
func templateOrder(si state.SignIn) []string {
	var out []string
	for _, b := range signin.Builtins() {
		if _, ok := si.Templates[b.ID]; ok {
			out = append(out, b.ID)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(si.Templates)) {
		if !si.Templates[id].BuiltIn {
			out = append(out, id)
		}
	}
	return out
}

// usesLocked lists what uses template id under si: the default, core pages
// that pick it, and every instance (enabled or not) whose own pick it is —
// or whose pre-restore pick it is while a restore runs.
func (h *Hub) usesLocked(si state.SignIn, id string) []UseRef {
	out := []UseRef{}
	if si.Default == id {
		out = append(out, UseRef{Kind: UseDefault, ID: "default", Name: "the default"})
	}
	for _, k := range state.CoreSignInKeys {
		if si.Core[k] == id {
			out = append(out, UseRef{Kind: UseCore, ID: k, Name: coreSignInLabels[k]})
		}
	}
	for _, iid := range slices.Sorted(maps.Keys(h.st.Instances)) {
		e := h.st.Instances[iid]
		// A restoring instance's pre-restore pick too: its rollback puts
		// it back.
		if e.SignInTemplate != id && !(e.State == state.InstanceRestoring && e.PreRestorePick == id) {
			continue
		}
		name := iid
		if t := h.findLocked(iid); t != nil {
			name = instanceName(t)
		}
		out = append(out, UseRef{Kind: UseInstance, ID: iid, Name: name})
	}
	return out
}

func useNames(uses []UseRef) string {
	names := make([]string, len(uses))
	for i, u := range uses {
		names[i] = u.Name
	}
	return strings.Join(names, ", ")
}

// ── writers ──────────────────────────────────────────────

// signInPlan is a planned change: the next sign-in section and the audit
// detail; changed false = nothing to do (no save, no audit).
type signInPlan struct {
	next    state.SignIn
	detail  string
	changed bool
}

// changeSignIn runs a sign-in writer (see the file comment). plan reads
// h.st under mu (either lock) and never changes it; attempt is the audit
// detail of a refusal.
func (h *Hub) changeSignIn(actor directory.Actor, action, target, attempt string, plan func() (signInPlan, error)) (ch *SignInChange, err error) {
	detail := ""
	defer func() {
		if err != nil {
			h.auditSignIn(actor, action, target, attempt, err)
		} else if detail != "" {
			h.auditSignIn(actor, action, target, detail, nil)
		}
	}()
	if actor.User == "" {
		return nil, statusErr(http.StatusUnauthorized, "changing the sign-in settings needs a signed-in admin")
	}
	h.signInMu.Lock()
	defer h.signInMu.Unlock()
	h.mu.RLock()
	p, err := plan()
	if err == nil && !p.changed {
		v := h.signInViewLocked()
		h.mu.RUnlock()
		return &SignInChange{View: v, Restarts: []string{}, Warnings: []string{}}, nil
	}
	var aiOff map[string][]string
	var cur state.SignIn
	if err == nil {
		aiOff = h.signInAIOffLocked(p.next)
		cur = h.st.SignIn.Clone()
	}
	h.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	// The lockout guard (D17), outside mu, before anything changes: a
	// refusal leaves AI support as it is and commits nothing.
	lockWarn, err := h.lockoutCheck(context.Background(), cur, p.next)
	if err != nil {
		return nil, err
	}
	// AI support goes off first where the change makes an instance's
	// template certificate-only (contract §8.1, G43; audited ai.disable):
	// a switch-off that fails refuses the change, nothing saved.
	warnings := lockoutWarnings(lockWarn)
	if warnings == nil {
		warnings = []string{}
	}
	for _, id := range slices.Sorted(maps.Keys(aiOff)) {
		if err := h.switchAIOff(context.Background(), id, aiOff[id], actor, aiCertOffDetail); err != nil {
			var oe *OpError
			if !errors.As(err, &oe) {
				return nil, fmt.Errorf("the sign-in settings were not changed: switching AI support off on %s first failed: %w", id, err)
			}
			// Off in state and in the gate already; the rest is recorded.
			warnings = append(warnings, fmt.Sprintf("%s: switching AI support off: %s", id, h.redactUnitError(id, err)))
		}
		warnings = append(warnings, aiOffWarning(id, aiOff[id]))
	}
	h.mu.Lock()
	again, err := plan()
	if err != nil {
		h.mu.Unlock()
		return nil, err
	}
	// Password records change outside signInMu (RecordPassword): the
	// commit keeps the current ones, whatever the plan copied.
	p.next.Passwords = maps.Clone(h.st.SignIn.Passwords)
	if p.next.Passwords == nil {
		p.next.Passwords = map[string]state.PasswordRecord{}
	}
	again.next.Passwords = p.next.Passwords
	if !reflect.DeepEqual(again, p) {
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "the sign-in settings changed meanwhile: try again")
	}
	// Never commit a certificate-only template with a companion on.
	if on := h.signInAIOffLocked(p.next); len(on) > 0 {
		h.mu.Unlock()
		return nil, statusErr(http.StatusConflict, "AI support was switched on meanwhile for %s, whose sign-in template the change would make certificate-only: try again", strings.Join(slices.Sorted(maps.Keys(on)), ", "))
	}
	prev := h.st.SignIn
	restarts := h.tierChangesLocked(prev, p.next)
	h.st.SignIn = p.next
	if err := h.saveStateLocked(); err != nil {
		h.st.SignIn = prev
		h.mu.Unlock()
		return nil, err
	}
	// The TLS option moved (D18): the override now, the restart through
	// the delivery engine (owed, background).
	for _, id := range restarts {
		if t := h.findLocked(id); t != nil {
			if err := h.generateOverrideLocked(t, h.st.Settings[id]); err != nil {
				log.Printf("signin: %s: override: %v", id, err)
				warnings = append(warnings, fmt.Sprintf("%s: the override couldn't be written: %s", id, h.redactUnitError(id, err)))
			}
		}
	}
	v := h.signInViewLocked()
	h.mu.Unlock()
	detail = p.detail
	ch = &SignInChange{View: v, Restarts: restarts, Warnings: warnings}
	if werr := h.WritePolicy(); werr != nil {
		log.Printf("signin: %s: policy file: %v", action, werr)
		ch.Warnings = append(ch.Warnings, "the policy file couldn't be written: "+werr.Error())
	}
	for _, id := range restarts {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
	return ch, nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// SetMethod switches method m on or off for the whole server: 404 for an
// unknown method, 409 for browser_cert (not available yet) and while an
// enabled template needs m (D3; the refusal lists them and their uses).
func (h *Hub) SetMethod(ctx context.Context, m signin.Method, on bool, actor directory.Actor) (*SignInChange, error) {
	// A refusal is audited as the switch it would have made; an unknown
	// method has no state to come from: only the attempted one.
	attempt := onOff(!on) + " -> " + onOff(on)
	if _, ok := signin.InfoOf(m); !ok {
		attempt = onOff(on)
	}
	return h.changeSignIn(actor, "signin.method", clip(string(m), 64), attempt, func() (signInPlan, error) {
		info, ok := signin.InfoOf(m)
		if !ok {
			return signInPlan{}, statusErr(http.StatusNotFound, "unknown sign-in method %q", clip(string(m), 64))
		}
		if !info.Available && on {
			return signInPlan{}, statusErr(http.StatusConflict, "browser certificates aren't available yet")
		}
		cur := h.st.SignIn
		if cur.Methods[string(m)] == on {
			return signInPlan{}, nil
		}
		if !on {
			methods := cur.MethodsOn()
			var needers []string
			for _, id := range templateOrder(cur) {
				t := cur.Templates[id]
				if !t.Enabled || !slices.Contains(signin.Needs(t.Rule, methods), m) {
					continue
				}
				uses := h.usesLocked(cur, id)
				if len(uses) == 0 {
					needers = append(needers, fmt.Sprintf("%q (not in use: disable it)", t.Name))
				} else {
					needers = append(needers, fmt.Sprintf("%q (used by %s)", t.Name, useNames(uses)))
				}
			}
			if len(needers) > 0 {
				return signInPlan{}, statusErr(http.StatusConflict, "%s can't be switched off: no way in would be left for %s; change them first", info.Label, strings.Join(needers, ", "))
			}
		}
		next := cur.Clone()
		next.Methods[string(m)] = on
		return signInPlan{next: next, detail: onOff(!on) + " -> " + onOff(on), changed: true}, nil
	})
}

// checkTemplateName is the template name rule (D12, state.CheckSignInName:
// the one Load applies too).
func checkTemplateName(name string) error {
	if why := state.CheckSignInName(name); why != "" {
		return statusErr(http.StatusBadRequest, "template name: %s (%s)", why, VisibleText(clipRunes(name, 64)))
	}
	return nil
}

func checkTemplateID(id string) error {
	if !state.SignInTemplateIDRe.MatchString(id) {
		return statusErr(http.StatusBadRequest, "template id %q: lowercase letters, digits and -, starting with a letter, at most 32", clip(id, 64))
	}
	return nil
}

func checkTemplateInput(in TemplateInput) error {
	if err := checkTemplateName(in.Name); err != nil {
		return err
	}
	if err := signin.Validate(in.Rule); err != nil {
		return statusErr(http.StatusBadRequest, "rule: %v", err)
	}
	return nil
}

func sameRule(a, b signin.Node) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// SaveTemplate creates (create) or updates template id: 400 for a bad id,
// name or rule, 409 for an existing id on create, 404 for an unknown one
// on update, 409 when an enabled template (a new one is enabled) would be
// left with no way in.
func (h *Hub) SaveTemplate(ctx context.Context, id string, in TemplateInput, create bool, actor directory.Actor) (*SignInChange, error) {
	attempt := "update"
	if create {
		attempt = "create"
	}
	return h.changeSignIn(actor, "signin.template", clip(id, 64), attempt, func() (signInPlan, error) {
		if err := checkTemplateID(id); err != nil {
			return signInPlan{}, err
		}
		if err := checkTemplateInput(in); err != nil {
			return signInPlan{}, err
		}
		cur := h.st.SignIn
		old, exists := cur.Templates[id]
		switch {
		case create && exists:
			return signInPlan{}, statusErr(http.StatusConflict, "a template with id %s already exists", id)
		case !create && !exists:
			return signInPlan{}, statusErr(http.StatusNotFound, "no sign-in template %s", id)
		}
		t := old
		if create {
			t = state.SignInTemplate{Enabled: true}
		}
		t.Name, t.Rule = in.Name, state.CloneNode(in.Rule)
		if t.Enabled {
			if _, err := signin.Compile(t.Rule, cur.MethodsOn()); err != nil {
				return signInPlan{}, statusErr(http.StatusConflict, "%q can't be met with the sign-in methods that are switched on (%v): switch on a method it names or change the rule", t.Name, err)
			}
		}
		var parts []string
		if create {
			parts = append(parts, "created: "+signin.Sentence(t.Rule))
		} else {
			if old.Name != t.Name {
				parts = append(parts, fmt.Sprintf("name %q -> %q", old.Name, t.Name))
			}
			if !sameRule(old.Rule, t.Rule) {
				parts = append(parts, fmt.Sprintf("rule %q -> %q", signin.Sentence(old.Rule), signin.Sentence(t.Rule)))
			}
			if len(parts) == 0 {
				return signInPlan{}, nil
			}
		}
		next := cur.Clone()
		next.Templates[id] = t
		return signInPlan{next: next, detail: strings.Join(parts, "; "), changed: true}, nil
	})
}

// SetTemplateEnabled enables or disables template id: 404 unknown; off
// is 409 while it is in use, on is 409 while it can't be met.
func (h *Hub) SetTemplateEnabled(ctx context.Context, id string, on bool, actor directory.Actor) (*SignInChange, error) {
	return h.changeSignIn(actor, "signin.template_enabled", clip(id, 64), onOff(!on)+" -> "+onOff(on), func() (signInPlan, error) {
		cur := h.st.SignIn
		t, ok := cur.Templates[id]
		if !ok {
			return signInPlan{}, statusErr(http.StatusNotFound, "no sign-in template %s", clip(id, 64))
		}
		if t.Enabled == on {
			return signInPlan{}, nil
		}
		if !on {
			if uses := h.usesLocked(cur, id); len(uses) > 0 {
				return signInPlan{}, statusErr(http.StatusConflict, "%q is in use by %s: pick another template there first", t.Name, useNames(uses))
			}
		} else if _, err := signin.Compile(t.Rule, cur.MethodsOn()); err != nil {
			return signInPlan{}, statusErr(http.StatusConflict, "%q can't be met with the sign-in methods that are switched on (%v): switch on a method it names or change the rule", t.Name, err)
		}
		next := cur.Clone()
		t.Enabled = on
		next.Templates[id] = t
		return signInPlan{next: next, detail: onOff(!on) + " -> " + onOff(on), changed: true}, nil
	})
}

// DeleteTemplate deletes an admin's template: 404 unknown, 409 for a
// built-in or a template in use.
func (h *Hub) DeleteTemplate(ctx context.Context, id string, actor directory.Actor) error {
	_, err := h.changeSignIn(actor, "signin.template_delete", clip(id, 64), "delete", func() (signInPlan, error) {
		cur := h.st.SignIn
		t, ok := cur.Templates[id]
		if !ok {
			return signInPlan{}, statusErr(http.StatusNotFound, "no sign-in template %s", clip(id, 64))
		}
		if t.BuiltIn {
			return signInPlan{}, statusErr(http.StatusConflict, "%q is a built-in template: it can be disabled, not deleted", t.Name)
		}
		if uses := h.usesLocked(cur, id); len(uses) > 0 {
			return signInPlan{}, statusErr(http.StatusConflict, "%q is in use by %s: pick another template there first", t.Name, useNames(uses))
		}
		next := cur.Clone()
		delete(next.Templates, id)
		return signInPlan{next: next, detail: fmt.Sprintf("deleted %q: %s", t.Name, signin.Sentence(t.Rule)), changed: true}, nil
	})
	return err
}

// pickable refuses a template id that can't be picked: 404
// unknown, 409 disabled.
func pickable(si state.SignIn, id string) error {
	t, ok := si.Templates[id]
	if !ok {
		return statusErr(http.StatusNotFound, "no sign-in template %s", clip(id, 64))
	}
	if !t.Enabled {
		return statusErr(http.StatusConflict, "%q is disabled: enable it first", t.Name)
	}
	return nil
}

// SetDefaultTemplate makes template id the default: 404 unknown, 409
// disabled.
func (h *Hub) SetDefaultTemplate(ctx context.Context, id string, actor directory.Actor) (*SignInChange, error) {
	return h.changeSignIn(actor, "signin.default", "default", "-> "+clip(id, 64), func() (signInPlan, error) {
		cur := h.st.SignIn
		if err := pickable(cur, id); err != nil {
			return signInPlan{}, err
		}
		if cur.Default == id {
			return signInPlan{}, nil
		}
		next := cur.Clone()
		next.Default = id
		return signInPlan{next: next, detail: cur.Default + " -> " + id, changed: true}, nil
	})
}

func coreName(id string) string {
	if id == "" {
		return "default"
	}
	return id
}

// SetCoreTemplate sets core page key's template (id "" = the default): 400
// for an unknown key, 404 unknown template, 409 disabled.
func (h *Hub) SetCoreTemplate(ctx context.Context, key, id string, actor directory.Actor) (*SignInChange, error) {
	return h.changeSignIn(actor, "signin.core", clip(key, 64), "-> "+coreName(clip(id, 64)), func() (signInPlan, error) {
		if !slices.Contains(state.CoreSignInKeys, key) {
			return signInPlan{}, statusErr(http.StatusBadRequest, "%q is not a core page that takes a template (%s)", clip(key, 64), strings.Join(state.CoreSignInKeys, ", "))
		}
		cur := h.st.SignIn
		if id != "" {
			if err := pickable(cur, id); err != nil {
				return signInPlan{}, err
			}
		}
		if cur.Core[key] == id {
			return signInPlan{}, nil
		}
		next := cur.Clone()
		next.Core[key] = id
		return signInPlan{next: next, detail: coreName(cur.Core[key]) + " -> " + coreName(id), changed: true}, nil
	})
}

// SetAddStronger sets the "adding a stronger method" switch.
func (h *Hub) SetAddStronger(on bool, actor directory.Actor) error {
	_, err := h.changeSignIn(actor, "signin.add_stronger", "add_stronger", onOff(!on)+" -> "+onOff(on), func() (signInPlan, error) {
		cur := h.st.SignIn
		if cur.AddStronger == on {
			return signInPlan{}, nil
		}
		next := cur.Clone()
		next.AddStronger = on
		return signInPlan{next: next, detail: onOff(!on) + " -> " + onOff(on), changed: true}, nil
	})
	return err
}

// PreviewTemplate is a draft's sentence and score with the switches as
// they are (id and name optional; checked when given). Nothing is stored.
func (h *Hub) PreviewTemplate(ctx context.Context, id string, in TemplateInput) (*TemplatePreview, error) {
	if id != "" {
		if err := checkTemplateID(id); err != nil {
			return nil, err
		}
	}
	if in.Name != "" {
		if err := checkTemplateName(in.Name); err != nil {
			return nil, err
		}
	}
	if err := signin.Validate(in.Rule); err != nil {
		return nil, statusErr(http.StatusBadRequest, "rule: %v", err)
	}
	// Who it affects: the uses of template id (none for a new one),
	// judged against the draft as the switches compile it.
	var m *directory.Membership
	var inv *Inventory
	why := ""
	if id != "" {
		m, inv, why = h.signInPeople(ctx)
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	si := h.st.SignIn
	on := si.MethodsOn()
	sentence, score, problem := describeRule(in.Rule, on)
	p := &TemplatePreview{Sentence: sentence, Score: score, Affected: []AffectedApp{}, Problem: problem}
	if _, exists := si.Templates[id]; id == "" || !exists {
		return p, nil
	}
	if why != "" {
		p.PeopleUnknown = why
		return p, nil
	}
	compiled, err := signin.Compile(in.Rule, on)
	if err != nil {
		compiled = signin.Node{} // no way in: everybody is blocked
	}
	p.Affected = h.affectedLocked(si, id, compiled, m, inv)
	return p, nil
}

// ensureSignIn fills a state's missing sign-in defaults (Init) and saves
// them when anything was missing, or when state.yaml has no sign_in
// section yet (the seeded built-ins are persisted).
func (h *Hub) ensureSignIn() {
	h.mu.Lock()
	defer h.mu.Unlock()
	before := h.st.SignIn.Clone()
	h.st.EnsureSignIn()
	if h.st.SignInMissing() || !reflect.DeepEqual(before, h.st.SignIn) {
		if err := h.saveStateLocked(); err != nil {
			log.Printf("signin: %v", err)
		}
	}
}
