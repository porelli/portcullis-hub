package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Instance labels and group binding (contract §11.9). The label is
// display text only (`<App> · <label>`); nothing keys on it. The group
// binding (groups mode "existing") replaces the derived access / admin
// group names everywhere: instanceGroupsLocked is the one place that
// answers an instance's groups, and stampInstanceLocked writes its
// answer onto every instance view (Manifest.Auth, InstanceEnv), so the
// policy file, population, placeholders, env, access role, views,
// missing-groups, enable and delete all follow it.

// LabelMaxRunes caps an instance label (§11.9).
const LabelMaxRunes = 64

// Group modes of the create body (§11.9).
const (
	GroupsNew      = "new"
	GroupsExisting = "existing"
)

// GroupChoice is the create body's groups: Mode "new" (or "": the
// derived groups, created empty) or "existing" (bound to Users / Admins,
// nothing created).
type GroupChoice struct {
	Mode   string `json:"mode"`
	Users  string `json:"users,omitempty"`
	Admins string `json:"admins,omitempty"`
}

// CreateRequest is POST /api/instances's body (§11.9 "Create body"):
// Template, ID and Label are required; Hosts nil = the defaults on the
// main domain; Setup the template's setup options' values (option key →
// JSON value, parsed like a settings save's values; an omitted one takes
// its default).
type CreateRequest struct {
	Template string
	ID       string
	Label    string
	Hosts    map[string]string
	Groups   GroupChoice
	Setup    map[string]json.RawMessage
	// recheck, if set, runs right before the create commits (outside
	// mu): an "existing" binding checked again against the directory.
	recheck func() error
	// setup is Setup parsed (parseSetup), stored by createEntry.
	setup *parsedSettings
}

// CheckLabel refuses (400) a label §11.9 doesn't allow: 1–64 runes, one
// line, no control characters (templates.HasControlChars), none of the
// invisible or format characters VisibleText escapes (hasHiddenText),
// not blank, no leading or trailing white space.
func CheckLabel(label string) error {
	switch {
	case strings.TrimSpace(label) == "" && !hasHiddenText(label) && !templates.HasControlChars(label):
		return statusErr(400, "a label is required (1–%d characters)", LabelMaxRunes)
	case templates.HasControlChars(label) || hasHiddenText(label):
		return statusErr(400, "the label must be one line of visible text: no control, invisible or format characters (%s)", VisibleText(label))
	case utf8.RuneCountInString(label) > LabelMaxRunes:
		return statusErr(400, "the label is longer than %d characters", LabelMaxRunes)
	case strings.TrimSpace(label) != label:
		return statusErr(400, "the label may not start or end with white space")
	}
	return nil
}

// instanceLabel is t's label: the stored one, else the manifest's name
// for a default instance and the id for any other (§11.9 "Default").
func instanceLabel(t *templates.Template) string {
	switch {
	case t.Label != "":
		return t.Label
	case t.IsDefault():
		return t.Manifest.Name
	}
	return t.ID
}

// instanceName is how the Hub names instance t to people (§10 name,
// §11.9 "Where it shows"): `<App> · <label>`, the default instance
// included.
func instanceName(t *templates.Template) string {
	return t.Manifest.Name + " · " + instanceLabel(t)
}

// instanceGroupsLocked is the one answer to instance t's access (users)
// and admin groups (§11.9 "One answer"): its binding when it is bound to
// existing groups, else the derived names (§11.2: users_<id> /
// admin_<id>, a default instance's manifest groups). "" = the manifest
// has no such group. t is an instance view (or a catalog entry: its
// default instance). Caller holds mu.
func (h *Hub) instanceGroupsLocked(t *templates.Template) (users, admins string) {
	n := t.NamesFor(t.ID)
	users, admins = n.AccessGroup, n.AdminGroup
	e, ok := h.st.Instances[t.ID]
	tid := templateIDOf(t)
	if !ok || e.Template != tid {
		return users, admins
	}
	if users != "" && e.UsersGroup != "" {
		users = e.UsersGroup
	}
	if admins != "" && e.AdminsGroup != "" {
		admins = e.AdminsGroup
	}
	return users, admins
}

// instanceBoundLocked reports whether instance id is bound to existing
// groups. Caller holds mu.
func (h *Hub) instanceBoundLocked(id string) bool {
	return h.st.Instances[id].Bound()
}

// stampInstanceLocked writes instance view v's label and groups
// (instanceGroupsLocked) onto it: Label, Manifest.Auth's access / admin
// group and the PORTCULLIS_ACCESS_GROUP / _ADMIN_GROUP instance
// variables, and marks it Stamped. Every view the Hub builds goes
// through it (newViewLocked). Caller holds mu.
func (h *Hub) stampInstanceLocked(v *templates.Template) {
	if e, ok := h.st.Instances[v.ID]; ok && e.Template == templateIDOf(v) {
		v.Label = e.Label
	}
	users, admins := h.instanceGroupsLocked(v)
	v.Manifest.Auth.AccessGroup, v.Manifest.Auth.AdminGroup = users, admins
	if v.InstanceEnv != nil {
		v.InstanceEnv[templates.VarAccessGroup] = users
		v.InstanceEnv[templates.VarAdminGroup] = admins
	}
	v.Stamped = true
}

// newViewLocked is THE way the Hub builds an instance view: t's view for
// instance id on hosts (InstanceOn on the main domain, the enrolled
// domains' hosts as extra), stamped with its label and groups
// (stampInstanceLocked). TestInstanceViewsStamped allows InstanceOn
// nowhere else. Caller holds mu.
func (h *Hub) newViewLocked(t *templates.Template, id string, hosts map[string]string, extra func(string) bool) (templates.Template, error) {
	v, err := t.InstanceOn(id, hosts, h.cfg.Domain, extra)
	if err != nil {
		return v, err
	}
	h.stampInstanceLocked(&v)
	return v, nil
}

// groupsMode is GroupsExisting for a bound instance, else GroupsNew.
func groupsMode(e state.Instance) string {
	if e.Bound() {
		return GroupsExisting
	}
	return GroupsNew
}

// templateIDOf is t's template id (a catalog entry's is its ID).
func templateIDOf(t *templates.Template) string {
	if t.TemplateID != "" {
		return t.TemplateID
	}
	return t.ID
}

// checkGroupChoice checks gc against template t (§11.9): the mode,
// and for "existing" users when the manifest has an access group and
// admins when it has an admin group (a field for a group it doesn't
// have is 400). The groups themselves are checked against LLDAP later
// (bindGroups).
func checkGroupChoice(t *templates.Template, gc GroupChoice) error {
	tid := templateIDOf(t)
	raw := t.NamesFor(tid)
	switch gc.Mode {
	case "", GroupsNew:
		if gc.Users != "" || gc.Admins != "" {
			return statusErr(400, "groups: users and admins are only for mode %q", GroupsExisting)
		}
		return nil
	case GroupsExisting:
	default:
		return statusErr(400, "groups: mode must be %q or %q", GroupsNew, GroupsExisting)
	}
	switch {
	case raw.AccessGroup == "" && gc.Users != "":
		return statusErr(400, "groups: template %s has no access group: leave users out", tid)
	case raw.AdminGroup == "" && gc.Admins != "":
		return statusErr(400, "groups: template %s has no admin group: leave admins out", tid)
	case raw.AccessGroup != "" && strings.TrimSpace(gc.Users) == "":
		return statusErr(400, "groups: users (the group whose people can use it) is required")
	case raw.AdminGroup != "" && strings.TrimSpace(gc.Admins) == "":
		return statusErr(400, "groups: admins (the group whose people administer it) is required")
	}
	return nil
}

// bindGroups resolves an "existing" choice against LLDAP (Groups.
// CheckBindGroups: each must exist, 400 "unknown group <name>"; the
// users group may not be built-in, an administrator or a permission
// group; the directory down is 503) and returns the names as LLDAP has
// them. Never under mu.
func (h *Hub) bindGroups(ctx context.Context, gc GroupChoice) (users, admins string, err error) {
	h.mu.RLock()
	groupsAPI := h.groups
	h.mu.RUnlock()
	if groupsAPI == nil {
		return "", "", statusErr(503, "users & groups is not available: the groups to bind can't be checked")
	}
	users, admins, err = groupsAPI.CheckBindGroups(ctx, strings.TrimSpace(gc.Users), strings.TrimSpace(gc.Admins))
	var de *directory.Error
	switch {
	case errors.As(err, &de):
		return "", "", &StatusError{Status: de.Status, Err: err}
	case errors.Is(err, directory.ErrUnknownGroup):
		return "", "", &StatusError{Status: 400, Err: err}
	}
	return users, admins, err
}

// checkBoundUsersGroup refuses (409) to start instance id while the
// users group it is bound to has become a built-in, administrator or
// permission group since its create (§11.9, fail closed); a bound group
// that is gone only denies (missing-groups lists it). Users & Groups
// not available is 503: the binding can't be checked. Unbound: nil.
// Never under mu.
func (h *Hub) checkBoundUsersGroup(ctx context.Context, id string) error {
	h.mu.RLock()
	e := h.st.Instances[id]
	groupsAPI := h.groups
	h.mu.RUnlock()
	if e.UsersGroup == "" {
		return nil
	}
	if groupsAPI == nil {
		return statusErr(503, "instance %s is bound to group %s, which can't be checked: users & groups is not available", id, e.UsersGroup)
	}
	_, _, err := groupsAPI.CheckBindGroups(ctx, e.UsersGroup, "")
	var de *directory.Error
	switch {
	case err == nil, errors.Is(err, directory.ErrUnknownGroup):
		return nil
	case errors.As(err, &de) && de.Status == 400:
		return statusErr(409, "instance %s can't start: %v", id, err)
	case errors.As(err, &de):
		return &StatusError{Status: de.Status, Err: err}
	}
	var se *StatusError
	if errors.As(err, &se) && se.Status == 400 {
		return statusErr(409, "instance %s can't start: %v", id, err)
	}
	return err
}

// PlannedGroups is the access and admin group instance id of templateID
// would use when created with gc (the Portcullis MCP's create_instance
// class): for "existing" the names exactly as the create would bind
// them (bindGroups: the directory's resolution, §11.9), else the derived
// ones. ok false: unknown template, or a binding the create would refuse
// or can't check (ambiguous, unknown, privileged, directory down) — the
// caller fails closed.
func (h *Hub) PlannedGroups(ctx context.Context, templateID, id string, gc GroupChoice) (users, admins string, ok bool) {
	h.mu.RLock()
	t := h.catalogLocked(templateID)
	var n templates.InstanceNames
	var choiceErr error
	if t != nil {
		n = t.NamesFor(id)
		choiceErr = checkGroupChoice(t, gc)
	}
	h.mu.RUnlock()
	if t == nil || choiceErr != nil {
		return "", "", false
	}
	if gc.Mode == GroupsExisting {
		users, admins, err := h.bindGroups(ctx, gc)
		if err != nil {
			return "", "", false
		}
		return users, admins, true
	}
	return n.AccessGroup, n.AdminGroup, true
}

// InstanceGroups is instance id's access and admin group
// (instanceGroupsLocked); ok false: unknown instance.
func (h *Hub) InstanceGroups(id string) (users, admins string, ok bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil {
		return "", "", false
	}
	users, admins = h.instanceGroupsLocked(t)
	return users, admins, true
}

// SetLabel changes instance id's label (§11.9 "Display only", PUT
// /api/instances/{id}/label): 400 invalid, 404 unknown, 409 while
// deleting / restoring or busy. Under the instance's lock and its AI
// lifecycle lock (lockApp → aiLock, as SetHosts), it first re-asserts the
// consent text of the instance's companion mcp:* scopes in Keycloak
// (ensureAIScopes, under aiKCMu as moveAIScopes): a failure is 502 and
// the label is unchanged (the scopes put back). Then it saves the label
// and rewrites portal-apps.json. An unchanged label is a no-op, not
// audited; a change is audited instance.update "label <a> -> <b>".
func (h *Hub) SetLabel(ctx context.Context, id, label string, actor directory.Actor) (err error) {
	detail := ""
	var deliveryErr error // committed, but portal-apps.json not written
	defer func() {
		var busy ErrBusy
		if detail != "" && !errors.As(err, &busy) {
			if deliveryErr != nil {
				// As a settings save: the change ok, then one delivery
				// entry carrying the failure.
				h.auditOp(actor, "instance.update", id, detail, nil)
				h.auditOp(actor, "instance.update", id, "delivery", deliveryErr)
				return
			}
			h.auditOp(actor, "instance.update", id, detail, err)
		}
	}()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(400, "no signed-in user to audit the change as")
	}
	detail = "label (refused)"
	if err := CheckLabel(label); err != nil {
		return err
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return h.busyErr(id, err)
	}
	defer unlock()
	defer h.lifecycleAILock(id)() // lockApp → aiLock (G35)

	h.mu.Lock()
	cur := h.findLocked(id)
	if cur == nil {
		_, broken := h.brokenInstances[id]
		h.mu.Unlock()
		if broken {
			return statusErr(409, "instance %s can't be resolved (%s): fix its template first", id, h.brokenReason(id))
		}
		return statusErr(404, "instance not found: %s", id)
	}
	if err := h.pendingLocked(id); err != nil {
		h.mu.Unlock()
		return err
	}
	if _, has := h.st.Instances[id]; !has && !h.st.IsEnabled(id) {
		// An implicit default instance (never created, not running): a
		// label would store an entry that blocks its first create
		// (§11.9 "First instance").
		h.mu.Unlock()
		return statusErr(404, "instance %s doesn't exist yet: create the instance first", id)
	}
	before := instanceLabel(cur)
	if before == label {
		h.mu.Unlock()
		detail = ""
		return nil
	}
	detail = "label " + before + " -> " + label
	next := *cur
	next.Label = label
	oldScopes, newScopes := map[string]keycloak.MCPScope{}, map[string]keycloak.MCPScope{}
	h.instanceScopesLocked(cur, oldScopes)
	h.instanceScopesLocked(&next, newScopes)
	h.mu.Unlock()

	// The consent text first (§8): the scope passes (aiKCMu) wait until
	// the label is saved or the text is put back.
	scopeUnlock := func() {}
	if len(newScopes) > 0 {
		h.aiKCMu.Lock()
		scopeUnlock = sync.OnceFunc(h.aiKCMu.Unlock)
		defer scopeUnlock()
		if err := h.relabelAIScopes(ctx, id, before, newScopes, oldScopes); err != nil {
			return err
		}
	}

	h.mu.Lock()
	e, had := h.st.Instances[id]
	if h.findLocked(id) == nil || h.pendingLocked(id) != nil {
		h.mu.Unlock()
		h.putBackAIScopes(ctx, id, oldScopes)
		return statusErr(409, "instance %s changed meanwhile: retry", id)
	}
	prev := e
	if !had {
		e = state.Instance{ID: id, Template: cur.TemplateID}
	}
	e.Label = label
	h.st.Instances[id] = e
	if serr := h.st.Save(h.statePath()); serr != nil {
		if had {
			h.st.Instances[id] = prev
		} else {
			delete(h.st.Instances, id)
		}
		h.mu.Unlock()
		h.putBackAIScopes(ctx, id, oldScopes)
		return statusErr(500, "saving state.yaml failed — the label is unchanged: %v", serr)
	}
	h.rebuildLocked()
	h.mu.Unlock()
	scopeUnlock()
	log.Printf("instance %s: %s", id, detail)
	if perr := h.WritePolicy(); perr != nil {
		deliveryErr = statusErr(500, "the label was saved, but writing portal-apps.json failed (the next policy write retries it): %v", perr)
		return deliveryErr
	}
	return nil
}

// relabelAIScopes re-asserts scopes' consent texts (ensureAIScopes); a
// failure puts the old ones back (best effort) and is a 502: the label
// stays unchanged. Caller holds aiKCMu.
func (h *Hub) relabelAIScopes(ctx context.Context, id, before string, scopes, old map[string]keycloak.MCPScope) error {
	kc := h.aiKeycloak()
	var errs []error
	if kc == nil {
		errs = []error{errors.New("Keycloak: the AI scope calls are not configured")}
	} else {
		errs = ensureAIScopes(ctx, kc, scopes)
	}
	if len(errs) == 0 {
		return nil
	}
	h.putBackAIScopes(ctx, id, old)
	return &StatusError{Status: 502, Err: fmt.Errorf("%w — nothing changed, the label of %s stays %q", errors.Join(errs...), id, before)}
}

// putBackAIScopes re-asserts old (the scopes with the current label),
// best effort. Caller holds aiKCMu when there are any.
func (h *Hub) putBackAIScopes(ctx context.Context, id string, old map[string]keycloak.MCPScope) {
	if len(old) == 0 {
		return
	}
	if kc := h.aiKeycloak(); kc != nil {
		for _, err := range ensureAIScopes(ctx, kc, old) {
			log.Printf("instance %s: putting an AI scope's consent text back failed (the next scope pass retries): %v", id, err)
		}
	}
}

// brokenReason is why instance id can't be resolved. Caller holds no
// lock.
func (h *Hub) brokenReason(id string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.brokenInstances[id]
}
