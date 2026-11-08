package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
	"github.com/portcullis/hub/internal/templates"
)

// The Portcullis MCP's users and groups tools (plan 4 Task 18; contract
// §9, §15.10, spec call 25): twins of /api/directory/*. Each Run calls the
// same Server work its handler calls (directory.go: createUser,
// addMember, …: the same directory.Service method with a Caller from
// CallerFor + Via "ai" + the AI client, plus the confirmation a D call
// consumed), so every guardrail (checkTarget, the last admin, delegate
// rules, administrators' invites) and every audit entry — refusals
// included — are the directory's own. No new Service method.
//
// G37 (ruling 2): the calls that can widen access are D per call, decided
// from the directory's own definitions (Membership.Guarding /
// GuardedFields / Administrators — never a second list) and D whenever
// they can't be read or the group is unknown (fail closed).
//
// G39 (ruling 3): no result carries an invite link, a password or the
// server-invite internals: an invite is reported as created (with its
// expiry), a server invite as "run ./portcullis invite <user> on the
// server".

// dirClassTimeout bounds the directory read a per-call class makes.
const dirClassTimeout = 10 * time.Second

// maxAuditScan / maxAuditPage bound audit_recent (ruling 7).
const (
	maxAuditScan = 10000
	maxAuditPage = 200
)

// serverInviteText is G39's fixed replacement of a server invite.
func serverInviteText(user string) string {
	return "run ./portcullis invite " + user + " on the server"
}

// inviteNote is what replaces an invite link.
func (s *Server) inviteNote(user string) string {
	return "the one-time invite link is never shown to the AI; to hand one to " + user + ", open " +
		s.mcpScope(ScopeAdmin).home + "#users/" + url.PathEscape(user) + "?invite (a new link replaces this one)"
}

// safeInvite is an invite as the AI sees it: created, and when it expires.
func (s *Server) safeInvite(user string, created bool, expires time.Time) map[string]any {
	if !created {
		return nil
	}
	return map[string]any{"created": true, "expires_at": expires, "note": s.inviteNote(user)}
}

// safeResult is a directory.Result without Invite, Password and
// ServerInvite (G39).
func (s *Server) safeResult(user, status string, r *directory.Result) map[string]any {
	out := map[string]any{"status": status, "username": user, "warnings": []string{}}
	if r == nil {
		return out
	}
	if r.Warnings != nil {
		out["warnings"] = r.Warnings
	}
	if r.Count > 0 {
		out["count"] = r.Count
	}
	if r.Invite != nil {
		out["invite"] = s.safeInvite(user, true, r.Invite.ExpiresAt)
	}
	if r.ServerInvite != "" {
		out["server_invite"] = serverInviteText(user)
	}
	return out
}

// safeOverview is the overview with every server invite as G39's text.
func safeOverview(ov *directory.Overview) *directory.Overview {
	if ov == nil {
		return nil
	}
	c := *ov
	c.Users = slices.Clone(ov.Users)
	for i := range c.Users {
		if c.Users[i].ServerInvite != "" {
			c.Users[i].ServerInvite = serverInviteText(c.Users[i].Username)
		}
	}
	return &c
}

// errNoUserManagement is a tool's answer without Users & Groups.
var errNoUserManagement = &hub.StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("user management not configured")}

// dirTool is an admin-scope directory tool whose Run decodes T and gets
// the directory Caller: the tool's (via ai, the client), re-resolved with
// CallerAs(toolActor) when a D call consumed a confirmation — so its audit
// entry carries "confirmation <id>" (§15.6).
func dirTool[T any](s *Server, name, desc string, class ToolClass, twin, audit string,
	run func(ctx context.Context, c *directory.Caller, in T) (any, error)) Tool {
	var zero T
	return Tool{Name: name, Description: desc, Class: class, Scope: ScopeAdmin, Twin: twin, Audit: audit, In: zero,
		Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
			if s.Directory == nil {
				return nil, errNoUserManagement
			}
			in, err := decode[T](args)
			if err != nil {
				return nil, badArg("invalid arguments")
			}
			if confirmationID(ctx) != "" {
				if c, err = s.Directory.CallerAs(ctx, toolActor(ctx, c)); err != nil {
					return nil, err
				}
			}
			return run(ctx, c, in)
		}}
}

// dirD is a D directory tool (its typed check and consequences).
func dirD(t Tool, typed func(json.RawMessage) string, consequences func(context.Context, json.RawMessage) []string) Tool {
	t.Class, t.Typed, t.Consequences = ClassDestructive, typed, consequences
	return t
}

// loadGuards reads the directory's view of who and what guards access
// (nil: it can't be read — the caller fails closed).
func (s *Server) loadGuards() *directory.Membership {
	if s.Directory == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dirClassTimeout)
	defer cancel()
	m, err := s.Directory.Membership(ctx, time.Now().UTC())
	if err != nil {
		log.Printf("mcp: directory class: %v", err)
		return nil
	}
	return m
}

// guards is loadGuards read once per tools/call (callMemo: the class,
// the consequences and Run of one call see the same snapshot).
func (s *Server) guards(ctx context.Context) *directory.Membership {
	m := memoOf(ctx)
	if m == nil {
		return s.loadGuards()
	}
	m.once.Do(func() { m.m = s.loadGuards() })
	return m.m
}

// groupGuard: why changing group's members, rule or exceptions can widen
// access ("" = it can't); ok false = can't decide (directory unreadable,
// group unknown).
func groupGuard(m *directory.Membership, group string) (why string, ok bool) {
	if m == nil {
		return "", false
	}
	known := false
	for g := range m.Groups {
		if strings.EqualFold(g, group) {
			known = true
		}
	}
	for g, w := range m.Guarding {
		if strings.EqualFold(g, group) {
			return w, true
		}
	}
	return "", known
}

// membersOf is group's current members (case-insensitive name).
func membersOf(m *directory.Membership, group string) []string {
	if m == nil {
		return nil
	}
	for g, mg := range m.Groups {
		if strings.EqualFold(g, group) {
			return mg.Members
		}
	}
	return nil
}

// groupClass: W for a known group that guards nothing, else D (G37).
func (s *Server) groupClass(ctx context.Context, args json.RawMessage) ToolClass {
	if why, ok := groupGuard(s.guards(ctx), argField(args, "group")); ok && why == "" {
		return ClassWrite
	}
	return ClassDestructive
}

// peopleList words a list of usernames ("nobody" when empty).
func peopleList(us []string) string {
	if len(us) == 0 {
		return "nobody"
	}
	return strings.Join(us, ", ")
}

// groupConsequences names the group, why it widens access and its
// current members; rule, when given, adds who it matches now.
func (s *Server) groupConsequences(ctx context.Context, args json.RawMessage, line string, rule string) []string {
	g := argField(args, "group")
	m := s.guards(ctx)
	why, ok := groupGuard(m, g)
	if why == "" && ok {
		why = s.instanceGroupOf(g)
	}
	switch {
	case !ok:
		return []string{line, "The directory couldn't say whether " + g + " grants rights: treat it as one that does."}
	case why == "":
		return []string{line}
	}
	lines := []string{line, g + " is " + why + ": its members get rights through it. Members now: " + peopleList(membersOf(m, g)) + "."}
	if rule != "" {
		lines = append(lines, s.ruleMatches(ctx, rule))
	}
	return lines
}

// ruleMatches is who rule matches right now (PreviewRule as the caller).
func (s *Server) ruleMatches(ctx context.Context, text string) string {
	memo := memoOf(ctx)
	rule, err := parseRuleText(text)
	if err != nil || memo == nil || memo.c == nil || s.Directory == nil {
		return "Who the rule matches couldn't be computed."
	}
	people, err := s.Directory.PreviewRule(ctx, memo.c, rule)
	if err != nil {
		return "Who the rule matches couldn't be computed."
	}
	return "The rule matches now: " + peopleList(people) + "."
}

// fieldGroups: the guarding groups whose rules use field.
func fieldGroups(m *directory.Membership, field string) []string {
	for f, gs := range m.GuardedFields {
		if strings.EqualFold(f, field) {
			return gs
		}
	}
	return nil
}

// attrsWiden: why setting attrs can change a guarding group ("" = it
// can't); ok false = the directory can't say.
func (s *Server) attrsWiden(ctx context.Context, attrs map[string][]string) (string, bool) {
	if len(attrs) == 0 {
		return "", true
	}
	m := s.guards(ctx)
	if m == nil {
		return "", false
	}
	for f := range attrs {
		if gs := fieldGroups(m, f); len(gs) > 0 {
			return "the rules of " + strings.Join(gs, ", ") + " use " + f, true
		}
		// A rule of an instance's access or admin group (final review I1).
		for rf, gs := range m.RuleFields {
			if !strings.EqualFold(rf, f) {
				continue
			}
			for _, g := range gs {
				if why := s.instanceGroupOf(g); why != "" {
					return "the rule of " + g + " (" + why + ") uses " + f, true
				}
			}
		}
	}
	return "", true
}

// isAdministrator: user is in an administrator group (unknown = true:
// the consequences then warn).
func (s *Server) isAdministrator(ctx context.Context, user string) bool {
	m := s.guards(ctx)
	return m == nil || m.Administrators[strings.ToLower(user)]
}

// personConsequences: the action on user, and that user is another
// administrator (§9.5: the typed check is their name, plus the passkey).
func (s *Server) personConsequences(what string) func(context.Context, json.RawMessage) []string {
	return func(ctx context.Context, args json.RawMessage) []string {
		u := argField(args, "username")
		lines := []string{fmt.Sprintf(what, u)}
		if s.isAdministrator(ctx, u) {
			lines = append(lines, u+" is an administrator (or couldn't be checked): this hands their account to whoever acts next — confirm only if you meant "+u+".")
		}
		return lines
	}
}

// prestaged: the groups instance id of t would use (its access / admin
// group: users_<id> / admin_<id>, or a default instance's manifest
// groups) that already have people → those people (T18 fix round 1: an
// AI that pre-staged admin_foo and then creates foo hands them the app's
// admin rights). People = current members ∪ who directory.yaml puts in
// it before the evaluator runs (Membership.Staged: rule matches, include
// exceptions — final review I1); a group with a rule counts as staged
// even when it matches nobody yet. ok false = can't say (no template, the
// directory unreadable): fail closed.
func (s *Server) prestaged(ctx context.Context, t *templates.Template, id string) (map[string][]string, bool) {
	if t == nil {
		return nil, false
	}
	m := s.guards(ctx)
	if m == nil {
		return nil, false
	}
	n := t.NamesFor(id)
	out := map[string][]string{}
	for _, g := range []string{n.AccessGroup, n.AdminGroup} {
		if g == "" {
			continue
		}
		people := slices.Clone(membersOf(m, g))
		staged, has := stagedOf(m, g)
		people = append(people, staged...)
		slices.Sort(people)
		people = slices.Compact(people)
		if len(people) > 0 || has {
			out[g] = people
		}
	}
	return out, true
}

// stagedOf is Membership.Staged for group (case-insensitive); has: the
// group has a rule or include exceptions.
func stagedOf(m *directory.Membership, group string) (people []string, has bool) {
	for g, ps := range m.Staged {
		if strings.EqualFold(g, group) {
			people = append(people, ps...)
			has = true
		}
	}
	return people, has
}

// instanceGroupOf: why group is an existing instance's derived group
// (its access or admin group; "" = it isn't). Adding people to one by a
// rule or an exception hands them that app at once (final review I1).
func (s *Server) instanceGroupOf(group string) string {
	if group == "" {
		return ""
	}
	for _, a := range s.Hub.DirectoryApps() {
		switch {
		case a.AdminGroup != "" && strings.EqualFold(a.AdminGroup, group):
			return "the admin group of app " + a.ID
		case a.AccessGroup != "" && strings.EqualFold(a.AccessGroup, group):
			return "the access group of app " + a.ID
		}
	}
	return ""
}

// ruleClass: set_group_rule, convert_group, add_exception and
// remove_exception — groupClass, and D on an instance's access or admin
// group (a rule or an exception adds people there without a member
// call).
func (s *Server) ruleClass(ctx context.Context, args json.RawMessage) ToolClass {
	if s.instanceGroupOf(argField(args, "group")) != "" {
		return ClassDestructive
	}
	return s.groupClass(ctx, args)
}

// prestagedLines are prestaged's consequences.
func (s *Server) prestagedLines(ctx context.Context, t *templates.Template, id string) []string {
	pre, ok := s.prestaged(ctx, t, id)
	if !ok {
		return []string{"Who is already in " + id + "'s groups couldn't be read: treat them as holding its access and admin rights."}
	}
	var lines []string
	for _, g := range slices.Sorted(maps.Keys(pre)) {
		lines = append(lines, g+" already exists with members "+peopleList(pre[g])+" (current members, rule matches and include exceptions): they get what it gives in "+id+" at once, and whoever its rule matches later too.")
	}
	return lines
}

// inviteForm is the Hub page that issues (and shows) user's invite.
func (s *Server) inviteForm(user string) string {
	return s.mcpScope(ScopeAdmin).home + "#users/" + url.PathEscape(user) + "?invite"
}

// inviteTTL is core's invite lifetime (§9.4).
const inviteTTL = 72 * time.Hour

// lastInvite is the newest ok invite of user in the audit log (a
// user.invite, or an invite-mode user.create; any case), made by actor
// ("" = by anyone); nil when there is none (or no log).
func (s *Server) lastInvite(user, actor string) *directory.AuditEntry {
	l := s.auditLog()
	if l == nil {
		return nil
	}
	list, err := l.Recent(1000)
	if err != nil {
		return nil
	}
	for i := range list {
		e := list[i]
		if !strings.EqualFold(e.Target, user) || e.Result != "ok" || (actor != "" && !strings.EqualFold(e.Actor, actor)) {
			continue
		}
		if e.Action == "user.invite" || (e.Action == "user.create" && strings.HasPrefix(e.Detail, "onboarding=invite")) {
			return &list[i]
		}
	}
	return nil
}

// inviteState is what the Hub knows about user's invite (send_invite's
// and create_person's Run; never the client's accept): the newest ok
// user.invite / invite-mode user.create entry of the audit log, and
// whether they have passkeys now. pending = an invite younger than core's
// 72 h and no passkey yet — evidence, not proof (core keeps invites in
// memory: a restart of enroll drops them).
func (s *Server) inviteState(ctx context.Context, c *directory.Caller, user string) map[string]any {
	out := map[string]any{"username": user, "last_invite": nil, "pending": false,
		"note": "from the audit log and Keycloak; core keeps invites in memory, so a restarted enroll drops them"}
	last := s.lastInvite(user, "")
	if last != nil {
		out["last_invite"] = map[string]any{"time": last.Time, "actor": last.Actor, "via": last.Via, "action": last.Action}
		out["expires_at"] = last.Time.Add(inviteTTL)
	}
	if s.Directory == nil {
		return out
	}
	ov, err := s.Directory.OverviewFor(ctx, c)
	if err != nil {
		out["pending"] = "unknown"
		return out
	}
	for _, u := range ov.Users {
		if !strings.EqualFold(u.Username, user) {
			continue
		}
		out["exists"] = true
		if u.Admin {
			out["server_invite"] = serverInviteText(u.Username)
		}
		if u.Keycloak == nil || u.Keycloak.Error != "" {
			out["pending"] = "unknown"
			return out
		}
		out["passkeys"] = u.Keycloak.Passkeys
		out["pending"] = last != nil && time.Now().Before(last.Time.Add(inviteTTL)) && u.Keycloak.Passkeys == 0
		return out
	}
	out["exists"] = false
	return out
}

// parseRuleText is the rule body's text form (400 as the route answers).
func parseRuleText(text string) (*rules.Expr, error) {
	if strings.TrimSpace(text) == "" {
		return nil, badArg("a rule (text) is required")
	}
	e, err := rules.Parse(text)
	if err != nil {
		return nil, badArg(fmt.Sprintf("%s (column %d)", err.Error(), rules.ErrorColumn(err)))
	}
	return e, nil
}

// parseUntil is an RFC 3339 end ("" / nil = none).
func parseUntil(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, badArg("until must be an RFC 3339 time, e.g. 2026-12-31T18:00:00Z")
	}
	return &t, nil
}

// Argument types.
type (
	personArgs struct {
		Username string `json:"username" jsonschema:"the person's LLDAP username"`
	}
	createPersonArgs struct {
		Username    string   `json:"username" jsonschema:"the new LLDAP username (lowercase letters, digits, . _ -)"`
		Email       string   `json:"email" jsonschema:"their email address (contact only, never an identity)"`
		DisplayName string   `json:"display_name" jsonschema:"their display name"`
		Groups      []string `json:"groups,omitempty" jsonschema:"groups to add them to (needs your confirmation in the browser)"`
	}
	updatePersonArgs struct {
		Username    string  `json:"username" jsonschema:"the person's username"`
		Email       *string `json:"email,omitempty" jsonschema:"the new email address"`
		DisplayName *string `json:"display_name,omitempty" jsonschema:"the new display name"`
	}
	detailsArgs struct {
		Username string              `json:"username" jsonschema:"the person's username"`
		Attrs    map[string][]string `json:"attrs" jsonschema:"custom field → values ([] clears it); fields not named are kept"`
	}
	removePasskeysArgs struct {
		Username string `json:"username" jsonschema:"the person's username"`
		Invite   bool   `json:"invite,omitempty" jsonschema:"also create a new invite (never for administrators; the link is never shown to the AI)"`
	}
	createGroupArgs struct {
		Name string `json:"name" jsonschema:"the new group's name"`
	}
	groupRefArgs struct {
		Group string `json:"group" jsonschema:"the group's name"`
	}
	memberArgs struct {
		Group    string `json:"group" jsonschema:"the group's name"`
		Username string `json:"username" jsonschema:"the person's username"`
	}
	addMemberArgs struct {
		Group    string  `json:"group" jsonschema:"the group's name"`
		Username string  `json:"username" jsonschema:"the person's username"`
		Reason   string  `json:"reason,omitempty" jsonschema:"why (required on a rule group: they are added by hand, shown and audited; ignored on a manual group)"`
		Until    *string `json:"until,omitempty" jsonschema:"RFC 3339 end of the membership or of the added-by-hand entry (absent = no end)"`
	}
	expiryArgs struct {
		Group    string  `json:"group" jsonschema:"the manual group's name"`
		Username string  `json:"username" jsonschema:"the member's username"`
		Until    *string `json:"until,omitempty" jsonschema:"RFC 3339 end of the membership (absent = no end)"`
	}
	ruleArgs struct {
		Rule string `json:"rule" jsonschema:"the rule as text, e.g. department = \"Engineering\""`
	}
	groupRuleArgs struct {
		Group  string `json:"group" jsonschema:"the rule group's name"`
		Rule   string `json:"rule,omitempty" jsonschema:"the new rule as text"`
		Manual bool   `json:"manual,omitempty" jsonschema:"drop the rule: the group becomes manual (current members stay)"`
	}
	convertPreviewArgs struct {
		Group string `json:"group" jsonschema:"the manual group's name"`
		Rule  string `json:"rule" jsonschema:"the rule as text"`
	}
	convertArgs struct {
		Group   string                   `json:"group" jsonschema:"the manual group's name"`
		Rule    string                   `json:"rule" jsonschema:"the rule as text (the one previewed)"`
		Keep    []string                 `json:"keep,omitempty" jsonschema:"members the rule doesn't match who stay as added exceptions"`
		Preview directory.ConvertPreview `json:"preview" jsonschema:"convert_group_preview's answer, as reviewed"`
	}
	exceptionArgs struct {
		Group   string  `json:"group" jsonschema:"the rule group's name"`
		User    string  `json:"user" jsonschema:"the person's username"`
		Reason  string  `json:"reason" jsonschema:"why (required, shown and audited)"`
		Include bool    `json:"include,omitempty" jsonschema:"true: add them although they don't match; false: keep them out although they match"`
		Until   *string `json:"until,omitempty" jsonschema:"RFC 3339 end of the exception (absent = permanent)"`
	}
	fieldArgs struct {
		Name          string               `json:"name" jsonschema:"the field's name (lowercase, _ between words)"`
		Label         *string              `json:"label,omitempty" jsonschema:"its label"`
		Kind          *directory.FieldKind `json:"kind,omitempty" jsonschema:"text, list or person"`
		Values        []string             `json:"values,omitempty" jsonschema:"list kind: the allowed values, in order"`
		Multi         *bool                `json:"multi,omitempty" jsonschema:"allow several values"`
		ShareWithApps *bool                `json:"share_with_apps,omitempty" jsonschema:"send it to apps (default true on create)"`
		AdminOnly     *bool                `json:"admin_only,omitempty" jsonschema:"only administrators may edit it"`
	}
	fieldRefArgs struct {
		Name string `json:"name" jsonschema:"the field's name"`
	}
	permissionArgs struct {
		Perm  string `json:"perm" jsonschema:"edit_details, invite or remove"`
		Group string `json:"group" jsonschema:"the group holding it (\"\" = nobody)"`
	}
	importReviewArgs struct {
		Header []string   `json:"header" jsonschema:"the column names (one is username; others display_name, email and custom fields)"`
		Rows   [][]string `json:"rows" jsonschema:"the rows, one cell per column"`
	}
	importRow struct {
		User        string              `json:"user" jsonschema:"the username"`
		Create      bool                `json:"create,omitempty" jsonschema:"create the person (invited)"`
		Remove      bool                `json:"remove,omitempty" jsonschema:"delete the person"`
		Attrs       map[string][]string `json:"attrs,omitempty" jsonschema:"custom field → values"`
		DisplayName string              `json:"display_name,omitempty" jsonschema:"display name (create or change)"`
		Email       string              `json:"email,omitempty" jsonschema:"email (create or change)"`
	}
	importApplyArgs struct {
		Rows []importRow `json:"rows" jsonschema:"the reviewed rows to apply"`
	}
	auditArgs struct {
		Limit  int    `json:"limit,omitempty" jsonschema:"entries per page, 1-200 (default 50)"`
		Offset int    `json:"offset,omitempty" jsonschema:"entries to skip, newest first (next_offset of the previous page)"`
		Via    string `json:"via,omitempty" jsonschema:"ai: only entries made through the Portcullis MCP"`
	}
)

func init() {
	for k, why := range map[string]string{
		"set_details.attrs":         "custom field name → values: field names the admin chose, never judged by name (§15.10)",
		"import_apply.rows[].attrs": "custom field name → values: field names the admin chose, never judged by name (§15.10)",
	} {
		mcpFreeFormAllow[k] = why
	}
}

func (b fieldArgs) body() fieldBody {
	return fieldBody{Name: &b.Name, Label: b.Label, Kind: b.Kind, Values: b.Values, Multi: b.Multi, ShareWithApps: b.ShareWithApps, AdminOnly: b.AdminOnly}
}

func (r importRow) apply() directory.ApplyRow {
	return directory.ApplyRow{User: r.User, Create: r.Create, Remove: r.Remove, Attrs: r.Attrs, DisplayName: r.DisplayName, Email: r.Email}
}

var usernameOf = argReader("username")

// createForm is the Hub's new-person form, pre-filled (create_person).
// Only plain groups are pre-ticked (final review I2): an administrator,
// permission or other guarding group — or one the directory can't judge
// (unknown, directory down) — is left out of the link, so one click on a
// dialog the person doesn't re-read never creates an admin; the AI adds
// those with add_member (D) afterwards.
func (s *Server) createForm(a createPersonArgs) string {
	q := url.Values{}
	q.Set("username", a.Username)
	q.Set("email", a.Email)
	q.Set("display_name", a.DisplayName)
	if gs := plainGroups(s.loadGuards(), a.Groups); len(gs) > 0 {
		q.Set("groups", strings.Join(gs, ","))
	}
	return s.mcpScope(ScopeAdmin).home + "#users?create&" + q.Encode()
}

// plainGroups: the groups of gs that are known and guard nothing
// (groupGuard; m nil = none).
func plainGroups(m *directory.Membership, gs []string) []string {
	var out []string
	for _, g := range gs {
		if why, ok := groupGuard(m, g); ok && why == "" && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// registerDirectoryTools registers the users and groups tools.
func (s *Server) registerDirectoryTools() {
	for _, t := range []Tool{
		// ── Read ──
		dirTool(s, "directory_overview", "Users & Groups: every person (groups, how each membership is held, Keycloak status, custom field values), every group (rules, exceptions, expiries), the fields, the delegated permissions and stale Keycloak records. Invite links and passwords are never shown.",
			ClassRead, "GET /api/directory", "", func(ctx context.Context, c *directory.Caller, _ noArgs) (any, error) {
				ov, err := s.Directory.OverviewFor(ctx, c)
				return safeOverview(ov), err
			}),
		dirTool(s, "get_person", "One person: email, display name, groups and how each is held, Keycloak status (passkeys, pending actions), custom field values, whether they are an administrator.",
			ClassRead, "GET /api/directory", "", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				ov, err := s.Directory.OverviewFor(ctx, c)
				if err != nil {
					return nil, err
				}
				for _, u := range safeOverview(ov).Users {
					if strings.EqualFold(u.Username, in.Username) {
						return map[string]any{"person": u, "fields": ov.Fields}, nil
					}
				}
				return nil, &directory.Error{Status: http.StatusNotFound, Msg: "no such user " + in.Username}
			}),
		dirTool(s, "preview_rule", "Who a group rule (text) matches right now, and the rule in both forms; nothing changes.",
			ClassRead, "POST /api/directory/rules/preview", "", func(ctx context.Context, c *directory.Caller, in ruleArgs) (any, error) {
				rule, err := parseRuleText(in.Rule)
				if err != nil {
					return nil, err
				}
				people, err := s.Directory.PreviewRule(ctx, c, rule)
				if err != nil {
					return nil, err
				}
				out := ruleJSON(rule)
				out["users"] = people
				return out, nil
			}),
		dirTool(s, "convert_group_preview", "What turning a manual group into a rule group would do: who the rule matches, which members don't match (they can stay as exceptions), who joins, whose expiry is dropped. Pass the answer to convert_group.",
			ClassRead, "POST /api/directory/groups/{group}/convert-preview", "", func(ctx context.Context, c *directory.Caller, in convertPreviewArgs) (any, error) {
				rule, err := parseRuleText(in.Rule)
				if err != nil {
					return nil, err
				}
				return s.Directory.ConvertPreview(ctx, c, in.Group, rule)
			}),
		// The JSON form of the CSV import's review (the upload itself is
		// a browser route, noToolRoutes): the same NormalizeImport and
		// ImportReview the route's JSON branch calls. Its twin is the
		// import's route.
		dirTool(s, "import_review", "Review an import of people (the CSV's columns and rows as JSON; one column is username): per row new / changed / missing / same, problems, and the effect on groups. Nothing changes; apply the reviewed rows with import_apply.",
			ClassRead, "POST /api/directory/import/apply", "", func(ctx context.Context, c *directory.Caller, in importReviewArgs) (any, error) {
				if !c.CanImport() {
					return nil, &directory.Error{Status: http.StatusForbidden, Msg: "not allowed: needs edit_details, invite or remove"}
				}
				header, rows, err := directory.NormalizeImport(in.Header, in.Rows)
				if err != nil {
					return nil, err
				}
				rev, err := s.Directory.ImportReview(ctx, c, header, rows)
				if err != nil {
					return nil, err
				}
				return map[string]any{"header": header, "rows": rows, "review": rev}, nil
			}),
		dirTool(s, "audit_recent", "The Users & Groups audit log (every change, refusals too), newest first, at most 200 per call: page with offset / next_offset. Entries made through the Portcullis MCP carry via \"ai\" and the AI client; via=ai shows only those.",
			ClassRead, "GET /api/directory/audit", "", func(_ context.Context, _ *directory.Caller, in auditArgs) (any, error) {
				return s.auditRecent(in)
			}),
		// ── People ──
		// create_person is U (fix round 1 ruling): the Service has no
		// onboarding without an invite or a password, and both are
		// secrets the AI never sees — the person is created on the Hub's
		// pre-filled form, where the admin reviews it (groups included)
		// and the invite link is shown.
		{Name: "create_person", Description: "Create a person: the Hub's new-person form opens pre-filled with these details (and groups that grant no rights: administrator, permission and other guarding groups are never pre-ticked — add them with add_member afterwards); you review it and create them there, where their one-time invite link is shown (administrators: ./portcullis invite <user> on the server). Afterwards this reports whether they exist.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "POST /api/directory/users", In: createPersonArgs{},
			SecretForm: func(args json.RawMessage) string {
				a, _ := decode[createPersonArgs](args)
				return s.createForm(a)
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				// The accept is the client's word: what the directory says.
				if s.Directory == nil {
					return nil, errNoUserManagement
				}
				a, _ := decode[createPersonArgs](args)
				out := s.inviteState(ctx, c, a.Username)
				out["invite_form"] = s.inviteForm(a.Username)
				return out, nil
			}},
		dirTool(s, "update_person", "Change a person's email or display name.",
			ClassWrite, "PUT /api/directory/users/{username}", "user.update", func(ctx context.Context, c *directory.Caller, in updatePersonArgs) (any, error) {
				if err := s.updateUser(ctx, c, in.Username, in.Email, in.DisplayName); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}),
		perCallCtx(dirTool(s, "set_details", "Set a person's custom field values (rule groups follow). A field a guarding group's rule uses needs your confirmation in the browser.",
			ClassWrite, "PUT /api/directory/users/{username}/details", "user.details", func(ctx context.Context, c *directory.Caller, in detailsArgs) (any, error) {
				if in.Attrs == nil {
					return nil, badArg("attrs is required")
				}
				if err := s.setDetails(ctx, c, in.Username, in.Attrs); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}), s.detailsClass, usernameOf, s.detailsConsequences),
		dirD(dirTool(s, "require_passkey", "Ask a person to register a passkey at their next sign-in. Needs your confirmation in the browser.",
			ClassWrite, "POST /api/directory/users/{username}/require-passkey", "user.require_passkey", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				if err := s.requirePasskey(ctx, c, in.Username); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}), usernameOf, s.personConsequences("Makes %s register a new passkey at their next sign-in.")),
		dirD(dirTool(s, "remove_passkeys", "Remove all of a person's passkeys and sign them out everywhere. Needs your confirmation in the browser. A new invite is given on the Hub's page (invite_form; administrators from the server).",
			ClassWrite, "POST /api/directory/users/{username}/remove-passkeys", "user.remove_passkeys", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				// The typed check (the name) was the confirmation page's;
				// never an invite here (fix round 1 ruling).
				res, err := s.removePasskeys(ctx, c, in.Username, in.Username, false)
				if err != nil {
					return nil, err
				}
				out := s.safeResult(in.Username, "removed", res)
				if m := s.guards(ctx); m != nil && m.Administrators[strings.ToLower(in.Username)] {
					out["server_invite"] = serverInviteText(in.Username)
				} else {
					out["invite_form"] = s.inviteForm(in.Username)
				}
				return out, nil
			}), usernameOf, s.personConsequences("Removes every passkey of %s and signs them out everywhere.")),
		{Name: "set_password", Description: "Set a person's fallback password: it is typed (or generated and shown once) on the Hub's page, never in the chat. After you did it there, this reports the last password change the audit log records.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "POST /api/directory/users/{username}/password", In: personArgs{},
			SecretForm: func(args json.RawMessage) string {
				return s.mcpScope(ScopeAdmin).home + "#users/" + url.PathEscape(usernameOf(args)) + "?password"
			},
			Run: func(_ context.Context, _ *directory.Caller, args json.RawMessage) (any, error) {
				// The accept is the client's word: what the audit log says.
				u := usernameOf(args)
				if !lldap.ValidUsername(u) {
					return nil, badArg("invalid username")
				}
				out := map[string]any{"username": u, "last_set": nil,
					"note": "the newest user.password entry of the audit log; it doesn't prove the change was just now"}
				if e := s.lastAudit("user.password", u); e != nil {
					out["last_set"] = map[string]any{"time": e.Time, "actor": e.Actor, "result": e.Result, "via": e.Via}
				}
				return out, nil
			}},
		// send_invite is U (fix round 1 ruling): the link is a secret, so
		// the admin issues it on the Hub's page, where it is shown; Run
		// only reports what the Hub knows.
		{Name: "send_invite", Description: "Give a person a new one-time invite: it is issued on the Hub's page, where the link is shown (earlier unused ones stop working; administrators are invited from the server). Afterwards this reports whether an invite is pending.",
			Class: ClassSecret, Scope: ScopeAdmin, Twin: "POST /api/directory/users/{username}/invite", In: personArgs{},
			SecretForm: func(args json.RawMessage) string { return s.inviteForm(usernameOf(args)) },
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				if s.Directory == nil {
					return nil, errNoUserManagement
				}
				u := usernameOf(args)
				if !lldap.ValidUsername(u) {
					return nil, badArg("invalid username")
				}
				return s.inviteState(ctx, c, u), nil
			}},
		dirTool(s, "clear_actions", "Clear a person's pending Keycloak required actions.",
			ClassWrite, "POST /api/directory/users/{username}/clear-actions", "user.clear_actions", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				if err := s.clearActions(ctx, c, in.Username); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}),
		dirD(dirTool(s, "delete_person", "Delete a person from LLDAP and Keycloak for good (their exceptions, expiries and app values go too). Needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/users/{username}", "user.delete", func(ctx context.Context, c *directory.Caller, in personArgs) (any, error) {
				res, err := s.deleteUser(ctx, c, in.Username, in.Username)
				if err != nil {
					return nil, err
				}
				return s.safeResult(in.Username, "deleted", res), nil
			}), usernameOf, s.personConsequences("Deletes %s from LLDAP and Keycloak; this can't be undone.")),
		// ── Groups ──
		dirTool(s, "create_group", "Create a (manual) group.",
			ClassWrite, "POST /api/directory/groups", "group.create", func(ctx context.Context, c *directory.Caller, in createGroupArgs) (any, error) {
				res, err := s.createGroup(ctx, c, in.Name)
				if err != nil {
					return nil, err
				}
				return map[string]any{"status": "created", "warnings": res.Warnings}, nil
			}),
		dirD(dirTool(s, "delete_group", "Delete a group (its rule, exceptions, expiries, permission grants and app setting rows go too). Needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/groups/{group}", "group.delete", func(ctx context.Context, c *directory.Caller, in groupRefArgs) (any, error) {
				res, err := s.deleteGroup(ctx, c, in.Group, in.Group)
				if err != nil {
					return nil, err
				}
				return map[string]any{"status": "deleted", "warnings": res.Warnings}, nil
			}), argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			g := argField(args, "group")
			return []string{"Deletes group " + g + ": its members (" + peopleList(membersOf(s.guards(ctx), g)) + ") lose what it gives, and its rule, exceptions, expiries, permission grants and app setting rows are removed."}
		}),
		perCallCtx(dirTool(s, "add_member", "Add a person to a group, optionally until a date. On a rule group they are added by hand (an include exception, kept whether or not the rule matches them) and a reason is required. Into an administrator, permission or other guarding group it needs your confirmation in the browser.",
			ClassWrite, "POST /api/directory/groups/{group}/members", "group.add_member", func(ctx context.Context, c *directory.Caller, in addMemberArgs) (any, error) {
				until, err := parseUntil(in.Until)
				if err != nil {
					return nil, err
				}
				st, err := s.addMember(ctx, c, in.Group, directory.MemberAdd{Username: in.Username, Reason: in.Reason, Until: until})
				if err != nil {
					return nil, err
				}
				return st.with(map[string]any{"status": "added"}), nil
			}), s.groupClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			line := "Adds " + argField(args, "username") + " to " + argField(args, "group")
			if u := argField(args, "until"); u != "" {
				line += " until " + q(u)
			}
			if r := argField(args, "reason"); r != "" {
				line += ", reason " + q(r)
			}
			return s.groupConsequences(ctx, args, line+".", "")
		}),
		// remove_member is D from a guarding group (fix round 1 ruling).
		perCallCtx(dirTool(s, "remove_member", "Remove a person from a group (they are signed out of Keycloak). On a rule group it removes their \"added by hand\" entry; someone in by the rule alone is refused (keep them out with add_exception instead). From an administrator, permission or other guarding group it needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/groups/{group}/members/{username}", "group.remove_member", func(ctx context.Context, c *directory.Caller, in memberArgs) (any, error) {
				res, st, err := s.removeMember(ctx, c, in.Group, in.Username)
				if err != nil {
					return nil, err
				}
				return st.with(map[string]any{"status": "removed", "warnings": res.Warnings}), nil
			}), s.groupClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			return s.groupConsequences(ctx, args, "Removes "+argField(args, "username")+" from "+argField(args, "group")+" and signs them out of Keycloak.", "")
		}),
		perCallCtx(dirTool(s, "set_member_expiry", "Set or remove when a person's membership of a manual group ends. On an administrator, permission or other guarding group it needs your confirmation in the browser.",
			ClassWrite, "PUT /api/directory/groups/{group}/members/{username}/expiry", "group.expiry", func(ctx context.Context, c *directory.Caller, in expiryArgs) (any, error) {
				until, err := parseUntil(in.Until)
				if err != nil {
					return nil, err
				}
				st, err := s.setMemberExpiry(ctx, c, in.Group, in.Username, until)
				if err != nil {
					return nil, err
				}
				return st.with(map[string]any{"status": "saved"}), nil
			}), s.groupClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			until := "no end"
			if u := argField(args, "until"); u != "" {
				until = q(u)
			}
			return s.groupConsequences(ctx, args, "Sets the end of "+argField(args, "username")+"'s membership of "+argField(args, "group")+" to "+until+".", "")
		}),
		perCallCtx(dirTool(s, "set_group_rule", "Change a rule group's rule (text), or make it manual again. On a guarding group it needs your confirmation in the browser.",
			ClassWrite, "PUT /api/directory/groups/{group}/rule", "group.rule", func(ctx context.Context, c *directory.Caller, in groupRuleArgs) (any, error) {
				var rule *rules.Expr
				if in.Manual {
					if in.Rule != "" {
						return nil, badArg("manual takes no rule")
					}
				} else {
					var err error
					if rule, err = parseRuleText(in.Rule); err != nil {
						return nil, err
					}
				}
				st, err := s.setGroupRule(ctx, c, in.Group, rule)
				if err != nil {
					return nil, err
				}
				if rule == nil {
					return st.with(map[string]any{"status": "saved", "text": "", "expr": nil}), nil
				}
				out := ruleJSON(rule)
				out["status"] = "saved"
				return st.with(out), nil
			}), s.ruleClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			r := argField(args, "rule")
			line := "Sets the rule of " + argField(args, "group") + " to " + q(r) + ": whoever it matches joins."
			if r == "" {
				line = "Makes " + argField(args, "group") + " manual: its current members stay."
			}
			return s.groupConsequences(ctx, args, line, r)
		}),
		perCallCtx(dirTool(s, "convert_group", "Turn a manual group into a rule group as reviewed with convert_group_preview (send its answer back; a change since is refused). On a guarding group it needs your confirmation in the browser.",
			ClassWrite, "POST /api/directory/groups/{group}/convert", "group.rule", func(ctx context.Context, c *directory.Caller, in convertArgs) (any, error) {
				rule, err := parseRuleText(in.Rule)
				if err != nil {
					return nil, err
				}
				st, err := s.convertGroup(ctx, c, in.Group, rule, in.Keep, &in.Preview)
				if err != nil {
					return nil, err
				}
				out := ruleJSON(rule)
				out["status"] = "saved"
				return st.with(out), nil
			}), s.ruleClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			a, _ := decode[convertArgs](args)
			return s.groupConsequences(ctx, args, "Makes "+a.Group+" a rule group ("+q(a.Rule)+"): joining "+peopleList(a.Preview.Joining)+".", a.Rule)
		}),
		perCallCtx(dirTool(s, "add_exception", "Add an exception to a rule group: a person added although the rule doesn't match them (include), or kept out although it does; a reason is required. On a guarding group it needs your confirmation in the browser.",
			ClassWrite, "POST /api/directory/groups/{group}/exceptions", "group.exception", func(ctx context.Context, c *directory.Caller, in exceptionArgs) (any, error) {
				until, err := parseUntil(in.Until)
				if err != nil {
					return nil, err
				}
				st, err := s.addException(ctx, c, in.Group, directory.Exception{User: in.User, Reason: in.Reason, Include: in.Include, Until: until})
				if err != nil {
					return nil, err
				}
				return st.with(map[string]any{"status": "saved"}), nil
			}), s.ruleClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			return s.groupConsequences(ctx, args, "Adds an exception for "+argField(args, "user")+" to "+argField(args, "group")+".", "")
		}),
		perCallCtx(dirTool(s, "remove_exception", "Remove a person's exception from a rule group (a kept-out person the rule matches joins). On a guarding group it needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/groups/{group}/exceptions/{username}", "group.exception", func(ctx context.Context, c *directory.Caller, in memberArgs) (any, error) {
				st, err := s.removeException(ctx, c, in.Group, in.Username)
				if err != nil {
					return nil, err
				}
				return st.with(map[string]any{"status": "removed"}), nil
			}), s.ruleClass, argReader("group"), func(ctx context.Context, args json.RawMessage) []string {
			return s.groupConsequences(ctx, args, "Removes "+argField(args, "username")+"'s exception from "+argField(args, "group")+" (kept out: they join if the rule matches).", "")
		}),
		dirD(dirTool(s, "set_permission", "Grant a delegated permission (edit_details, invite, remove) to a group, or to nobody (group \"\"). Always needs your confirmation in the browser.",
			ClassWrite, "PUT /api/directory/permissions/{perm}", "permission.set", func(ctx context.Context, c *directory.Caller, in permissionArgs) (any, error) {
				if err := s.setPermission(ctx, c, in.Perm, in.Group); err != nil {
					return nil, err
				}
				return map[string]string{"status": "saved"}, nil
			}), argReader("perm"), func(ctx context.Context, args json.RawMessage) []string {
			g := argField(args, "group")
			if g == "" {
				return []string{"Takes permission " + q(argField(args, "perm")) + " from everybody."}
			}
			m := s.guards(ctx)
			who := "Members now: " + peopleList(membersOf(m, g)) + "."
			if m == nil {
				who = "Its members couldn't be read."
			}
			return []string{"Grants permission " + q(argField(args, "perm")) + " to every member of " + g + " (now and later).", who}
		}),
		// ── Fields ──
		dirTool(s, "create_field", "Create a custom person field (text, list or person; shared with apps unless share_with_apps is false).",
			ClassWrite, "POST /api/directory/fields", "field.create", func(ctx context.Context, c *directory.Caller, in fieldArgs) (any, error) {
				f := in.body().apply(directory.Field{ShareWithApps: true})
				if err := s.createField(ctx, c, f); err != nil {
					return nil, err
				}
				return map[string]any{"status": "created", "name": f.Name}, nil
			}),
		// update_field is D on a guarded field when it changes what the
		// rules read (fix round 1, security hook).
		perCallCtx(dirTool(s, "update_field", "Change a custom field (label, kind, list values, multi, sharing, admin-only); what isn't given is kept. On a field a guarding group's rule uses, changing its kind, values, multi or turning admin-only off needs your confirmation in the browser.",
			ClassWrite, "PUT /api/directory/fields/{name}", "field.update", func(ctx context.Context, c *directory.Caller, in fieldArgs) (any, error) {
				f, err := s.patchField(ctx, c, in.Name, directory.FieldPatch{Label: in.Label, Kind: in.Kind, Values: in.Values, Multi: in.Multi,
					ShareWithApps: in.ShareWithApps, AdminOnly: in.AdminOnly})
				if err != nil {
					return nil, err
				}
				return map[string]any{"status": "saved", "field": f}, nil
			}), s.fieldClass, nameOf, s.fieldConsequences),
		dirD(dirTool(s, "delete_field", "Delete a custom field and everyone's values of it. Needs your confirmation in the browser.",
			ClassWrite, "DELETE /api/directory/fields/{name}", "field.delete", func(ctx context.Context, c *directory.Caller, in fieldRefArgs) (any, error) {
				if err := s.deleteField(ctx, c, in.Name, in.Name); err != nil {
					return nil, err
				}
				return map[string]string{"status": "deleted"}, nil
			}), nameOf, func(_ context.Context, args json.RawMessage) []string {
			return []string{"Deletes field " + nameOf(args) + " and every person's value of it."}
		}),
		// ── Import ──
		perCallCtx(dirTool(s, "import_apply", "Apply reviewed import rows (import_review): change details or delete people. New people are created with create_person (their invites are given on the Hub's page). Deleting people, or setting a field a guarding group's rule uses, needs your confirmation in the browser.",
			ClassWrite, "POST /api/directory/import/apply", "user.update", func(ctx context.Context, c *directory.Caller, in importApplyArgs) (any, error) {
				req := directory.ApplyRequest{Rows: make([]directory.ApplyRow, len(in.Rows))}
				for i, r := range in.Rows {
					if r.Create {
						// Fix round 1: no invite through the AI (a dead link).
						return nil, badArg("row " + r.User + ": people are created with create_person (the Hub's form gives their invite), not through the AI's import")
					}
					req.Rows[i] = r.apply()
				}
				res, err := s.importApply(ctx, c, req)
				if err != nil {
					return nil, err
				}
				rows := make([]map[string]any, len(res.Rows))
				for i, r := range res.Rows {
					row := map[string]any{"user": r.User, "ok": r.OK}
					if r.Error != "" {
						row["error"] = r.Error
					}
					if r.Invite != nil {
						row["invite"] = s.safeInvite(r.User, true, r.Invite.ExpiresAt)
					}
					rows[i] = row
				}
				return map[string]any{"rows": rows}, nil
			}), s.importClass, func(json.RawMessage) string { return "import" }, s.importConsequences),
	} {
		s.registerTool(t)
	}
}

// detailsClass: D when a field a guarding group's rule uses is set
// (deviation, G37's intent), or the directory can't say.
func (s *Server) detailsClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[detailsArgs](args)
	if err != nil {
		return ClassDestructive
	}
	if why, ok := s.attrsWiden(ctx, a.Attrs); ok && why == "" {
		return ClassWrite
	}
	return ClassDestructive
}

func (s *Server) detailsConsequences(ctx context.Context, args json.RawMessage) []string {
	a, _ := decode[detailsArgs](args)
	why, ok := s.attrsWiden(ctx, a.Attrs)
	if !ok {
		why = "the directory couldn't say which groups these fields decide"
	}
	return []string{"Sets " + a.Username + "'s details: " + why + ", so this can put them into those groups."}
}

// fieldChangesRules: the update changes what rules read of the field
// (kind, values, multi) or lets delegates edit it (admin_only false).
func fieldChangesRules(a fieldArgs) bool {
	return (a.AdminOnly != nil && !*a.AdminOnly) || a.Kind != nil || a.Values != nil || a.Multi != nil
}

// fieldClass is update_field's class: D for a guarded field whose rules
// the change affects, or when the directory can't say; else W.
func (s *Server) fieldClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[fieldArgs](args)
	if err != nil {
		return ClassDestructive
	}
	m := s.guards(ctx)
	if m == nil || (len(fieldGroups(m, a.Name)) > 0 && fieldChangesRules(a)) {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) fieldConsequences(ctx context.Context, args json.RawMessage) []string {
	a, _ := decode[fieldArgs](args)
	m := s.guards(ctx)
	if m == nil {
		return []string{"Changes field " + a.Name + " (the directory couldn't say which guarding groups use it)."}
	}
	return []string{"Changes field " + a.Name + ", which the rules of " + strings.Join(fieldGroups(m, a.Name), ", ") + " use: who is in them can change."}
}

// importClass: D when a row deletes a person or sets a field a guarding
// group's rule uses (or the directory can't say). Create rows are
// refused on the tool path.
func (s *Server) importClass(ctx context.Context, args json.RawMessage) ToolClass {
	a, err := decode[importApplyArgs](args)
	if err != nil {
		return ClassDestructive
	}
	attrs := map[string][]string{}
	for _, r := range a.Rows {
		if r.Create || r.Remove {
			return ClassDestructive
		}
		for f, v := range r.Attrs {
			attrs[f] = v
		}
	}
	if why, ok := s.attrsWiden(ctx, attrs); ok && why == "" {
		return ClassWrite
	}
	return ClassDestructive
}

func (s *Server) importConsequences(ctx context.Context, args json.RawMessage) []string {
	a, _ := decode[importApplyArgs](args)
	var removed, changed []string
	attrs := map[string][]string{}
	for _, r := range a.Rows {
		switch {
		case r.Remove:
			removed = append(removed, r.User)
		default:
			changed = append(changed, r.User)
			for f, v := range r.Attrs {
				attrs[f] = v
			}
		}
	}
	var lines []string
	if len(removed) > 0 {
		lines = append(lines, "Deletes "+strings.Join(removed, ", ")+" from LLDAP and Keycloak; this can't be undone.")
	}
	if len(changed) > 0 {
		line := "Changes the details of " + strings.Join(changed, ", ") + " (rule groups follow)."
		if why, ok := s.attrsWiden(ctx, attrs); !ok || why != "" {
			if !ok {
				why = "the directory couldn't say which groups these fields decide"
			}
			line += " " + why + "."
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		lines = []string{"Applies an empty import."}
	}
	return lines
}

// auditRecent is audit_recent: the route's Service.Recent, filtered by
// via, one page of at most maxAuditPage entries, newest first.
func (s *Server) auditRecent(in auditArgs) (any, error) {
	limit := in.Limit
	if limit == 0 {
		limit = 50
	}
	switch {
	case limit < 1 || limit > maxAuditPage:
		return nil, badArg(fmt.Sprintf("limit must be 1-%d", maxAuditPage))
	case in.Offset < 0 || in.Offset > maxAuditScan:
		return nil, badArg(fmt.Sprintf("offset must be 0-%d", maxAuditScan))
	case in.Via != "" && in.Via != directory.ViaAI:
		return nil, badArg(`via must be "ai" or absent`)
	}
	all, err := s.Directory.Recent(maxAuditScan)
	if err != nil {
		return nil, &hub.StatusError{Status: http.StatusInternalServerError, Err: errors.New("read audit log: " + err.Error())}
	}
	if in.Via != "" {
		all = slices.DeleteFunc(all, func(e directory.AuditEntry) bool { return e.Via != in.Via })
	}
	out := map[string]any{"offset": in.Offset, "entries": []directory.AuditEntry{}}
	if in.Offset < len(all) {
		end := min(in.Offset+limit, len(all))
		out["entries"] = all[in.Offset:end]
		if end < len(all) {
			out["next_offset"] = end
		}
	}
	return out, nil
}

// checkNameArgs (final review M3; the security review of the final fix;
// scoped re-review N2): the usernames, group names, field names, ids and
// fingerprints a tool that may ask for a confirmation takes are valid
// (lldap.ValidUsername / ValidGroupName, the directory's field-name rule,
// appIDOK, fpOK) or known to the directory, before any confirmation page
// could show them; "" is left to the tool; 400 (or the id rule's 404)
// otherwise. Only the tool's schema paths are judged — the fields of its
// argument type (In), followed into nested structs and lists of them
// (import rows, convert_group's preview), and attrs' keys — never the
// keys or values of a data map (save_settings' values, person rows…).
func (s *Server) checkNameArgs(ctx context.Context, tool string, in any, args json.RawMessage) error {
	var v any
	if in == nil || json.Unmarshal(args, &v) != nil {
		return nil // checkArgs decoded them already
	}
	nameIs := ""
	switch tool {
	case "create_field", "update_field", "delete_field":
		nameIs = "field"
	case "create_group":
		nameIs = "group"
	}
	var bad error
	check := func(kind, key string, x any) {
		if bad != nil {
			return
		}
		var list []string
		switch y := x.(type) {
		case string:
			list = []string{y}
		case []any:
			for _, e := range y {
				if str, ok := e.(string); ok {
					list = append(list, str)
				}
			}
		}
		for _, n := range list {
			if n == "" || bad != nil {
				continue
			}
			switch kind {
			case "user":
				if !lldap.ValidUsername(strings.ToLower(n)) && !knownUser(s.guards(ctx), n) {
					bad = badArg(key + " is not a valid username")
				}
			case "group":
				if !lldap.ValidGroupName(n) && !knownGroup(s.guards(ctx), n) {
					bad = badArg(key + " is not a valid group name")
				}
			case "field":
				if !directory.IsFieldName(n) {
					bad = badArg(key + " is not a valid field name")
				}
			case "id":
				bad = appIDOK(n)
			case "fp":
				bad = fpOK(n)
			}
		}
	}
	kindOf := func(key string) string {
		switch key {
		case "username", "user", "keep", "matching", "joining", "kept_as_exception", "expiry_dropped":
			return "user"
		case "group", "groups":
			return "group"
		case "id", "template":
			return "id"
		case "fp":
			return "fp"
		case "name":
			return nameIs
		}
		return ""
	}
	var walk func(t reflect.Type, v any)
	walk = func(t reflect.Type, v any) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Struct:
			obj, ok := v.(map[string]any)
			if !ok {
				return
			}
			for _, f := range reflect.VisibleFields(t) {
				if f.Anonymous || !f.IsExported() {
					continue
				}
				key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if key == "" || key == "-" {
					continue
				}
				e, present := obj[key]
				if !present {
					continue
				}
				ft := f.Type
				for ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if k := kindOf(key); k != "" && (ft.Kind() == reflect.String || ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String) {
					check(k, key, e)
					continue
				}
				if key == "attrs" && ft.Kind() == reflect.Map {
					if m, ok := e.(map[string]any); ok {
						for name := range m {
							check("field", "attrs", name)
						}
					}
					continue
				}
				walk(ft, e)
			}
		case reflect.Slice, reflect.Array:
			if list, ok := v.([]any); ok {
				for _, e := range list {
					walk(t.Elem(), e)
				}
			}
		}
		// Maps (data maps) and scalars: not judged.
	}
	walk(reflect.TypeOf(in), v)
	return bad
}
func knownUser(m *directory.Membership, u string) bool {
	if m == nil {
		return false
	}
	_, ok := m.Users[strings.ToLower(u)]
	return ok
}

func knownGroup(m *directory.Membership, g string) bool {
	if m == nil {
		return false
	}
	_, ok := m.Groups[g]
	return ok
}

// validTyped: a confirmation's typed check is a name the person can read
// and type exactly — an instance / template / folder id, a username, a
// group name, a hostname — or one the directory knows (a group whose
// name predates the Hub's rule). Anything else is refused (400) before
// a confirmation is created.
func (s *Server) validTyped(ctx context.Context, typed string) bool {
	switch {
	case templates.ValidID(typed), lldap.ValidUsername(typed), lldap.ValidGroupName(typed), templates.ValidHostname(typed):
		return true
	}
	return knownGroup(s.guards(ctx), typed) || knownUser(s.guards(ctx), typed)
}
