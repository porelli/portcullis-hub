package directory

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// RulesActor is the audit actor of the evaluator's membership changes.
const RulesActor = "portcullis-hub (rules)"

// Causes of evaluator changes (Change.Cause, audit detail after +/-).
const (
	CauseRule             = "rule"
	CauseException        = "exception"
	CauseExceptionExpired = "exception expired"
	CauseMembershipExpire = "membership expired"
	CauseOutsideChange    = "reverted: outside change"
)

// Change is one membership change made by Evaluate.
type Change struct {
	Group, User string
	Add         bool
	Cause       string
}

// EvalReport is the result of one evaluation.
type EvalReport struct {
	Changes []Change
	Cycles  [][]string // manager cycles (for the UI to flag)
	Errors  []string   // per-group / per-change problems; the run continued
	pruned  bool       // expired entries were dropped from directory.yaml
	// groupErrs: the Errors that concern one group (lowercase name), for
	// Settle's why — never another group's.
	groupErrs map[string][]string
}

// addErr reports a problem of group (also in Errors).
func (r *EvalReport) addErr(group, msg string) {
	r.Errors = append(r.Errors, msg)
	if r.groupErrs == nil {
		r.groupErrs = map[string][]string{}
	}
	g := strings.ToLower(group)
	r.groupErrs[g] = append(r.groupErrs[g], msg)
}

// ErrorsOf: the reported problems of the given groups.
func (r *EvalReport) ErrorsOf(groups ...string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, r.groupErrs[strings.ToLower(g)]...)
	}
	return out
}

// Expiring is a membership that ends at At (manual-group expiry or an
// "added" exception with an end date).
type Expiring struct {
	User, Group string
	At          time.Time
}

// expired: an item whose time is <= now is over.
func expired(t time.Time, now time.Time) bool { return !t.After(now) }

// ruleDirectory builds the rules view of the people: only defined fields,
// text and person values lowercased, list values as they are.
func ruleDirectory(cfg *Config, sn *snapshot) *rules.Directory {
	d := &rules.Directory{People: make(map[string]rules.Person, len(sn.users))}
	for _, f := range cfg.Fields {
		if f.Name == "manager" && f.Kind == FieldKindPerson {
			d.ManagerField = "manager"
		}
	}
	for id, u := range sn.users {
		p := rules.Person{User: id, Attrs: map[string][]string{}}
		for _, f := range cfg.Fields {
			if reservedAttr(f.Name) {
				continue // a Hub setting attribute: never a rule input
			}
			vals, ok := u.Attributes[f.Name]
			if !ok || len(vals) == 0 {
				continue
			}
			out := make([]string, len(vals))
			for i, v := range vals {
				if f.Kind == FieldKindList {
					out[i] = v
				} else {
					out[i] = strings.ToLower(v)
				}
			}
			p.Attrs[f.Name] = out
		}
		d.People[id] = p
	}
	return d
}

// protectedAccount: the service account and the bootstrap admin are never
// managed by rules (neither added nor removed).
func (s *Service) protectedAccount(user string) bool { return s.checkTarget(user) != nil }

// ruleGroupAllowed: built-in and administrator groups are never rule
// groups.
func (s *Service) ruleGroupAllowed(name string, admin map[string]bool) bool {
	return !builtinGroups[name] && !admin[name]
}

// addsBlocked: a guarding group (administrator, permission or app admin
// group) whose rule uses a field delegates can edit, or matches a person
// with no details at all (matchesEmpty: every new account), gets no
// additions — editing that field or creating an account must never grant
// rights. It can happen when a group becomes guarding after its rule was
// set (e.g. an app enabled later with it as admin_group). Removals still
// apply. Returns the reason ("" if not blocked).
func (s *Service) addsBlocked(cfg *Config, guarding map[string]string, name string, gc *GroupConfig) string {
	why, ok := guarding[name]
	if !ok || gc == nil || gc.Rule == nil {
		return ""
	}
	if bad := nonAdminOnly(cfg, gc.Rule); len(bad) > 0 {
		return fmt.Sprintf("%s is %s but its rule uses fields that aren't admin-only (%s): nobody is added until the rule uses only admin-only fields", name, why, strings.Join(bad, ", "))
	}
	if matchesEmpty(cfg, gc.Rule) {
		return fmt.Sprintf("%s is %s but its rule matches a person with no details at all (e.g. a new account): nobody is added until the rule no longer does", name, why)
	}
	return ""
}

// groupEval is the computed state of one rule group.
type groupEval struct {
	desired     map[string]bool // lowercase usernames
	matched     map[string]bool
	include     map[string]bool // active "added" exceptions
	exclude     map[string]bool // active "kept out" exceptions
	expiredIncl map[string]bool
	expiredExcl map[string]bool
	kept        []Exception // exceptions still active
}

func (s *Service) evalGroup(gc *GroupConfig, d *rules.Directory, sn *snapshot, now time.Time) *groupEval {
	ge := &groupEval{desired: map[string]bool{}, matched: map[string]bool{}, include: map[string]bool{},
		exclude: map[string]bool{}, expiredIncl: map[string]bool{}, expiredExcl: map[string]bool{}}
	for _, ex := range gc.Exceptions {
		u := strings.ToLower(ex.User)
		switch {
		case ex.Until != nil && expired(*ex.Until, now) && ex.Include:
			ge.expiredIncl[u] = true
		case ex.Until != nil && expired(*ex.Until, now):
			ge.expiredExcl[u] = true
		case ex.Include:
			ge.include[u] = true
			ge.kept = append(ge.kept, ex)
		default:
			ge.exclude[u] = true
			ge.kept = append(ge.kept, ex)
		}
	}
	for id := range sn.users {
		if s.protectedAccount(id) {
			continue
		}
		m := rules.Eval(gc.Rule, id, d)
		if m {
			ge.matched[id] = true
		}
		if (m || ge.include[id]) && !ge.exclude[id] {
			ge.desired[id] = true
		}
	}
	return ge
}

// Desired computes the membership of every rule group (lowercase
// usernames) from cfg and the LLDAP snapshot at now. Pure: no I/O. Built-in
// and administrator groups are left out; protected accounts never appear.
func (s *Service) Desired(cfg *Config, sn *snapshot, now time.Time) map[string]map[string]bool {
	d := ruleDirectory(cfg, sn)
	admin := s.adminGroups()
	guarding := s.guardingGroups(cfg)
	out := map[string]map[string]bool{}
	for name, gc := range cfg.Groups {
		if gc == nil || gc.Rule == nil || !s.ruleGroupAllowed(name, admin) {
			continue
		}
		desired := s.evalGroup(gc, d, sn, now).desired
		if s.addsBlocked(cfg, guarding, name, gc) != "" {
			// Removals only: keep just the current members.
			for u := range desired {
				if !memberOf(sn.groups[name], u) {
					delete(desired, u)
				}
			}
		}
		if _, ok := guarding[name]; ok {
			for u := range desired {
				if createdByDelegate(cfg, u) && !memberOf(sn.groups[name], u) {
					delete(desired, u)
				}
			}
		}
		out[name] = desired
	}
	return out
}

// createdByDelegate: user's account was created by a delegate and no admin
// has taken it over yet (Config.CreatedBy; an admin credential action
// clears it).
func createdByDelegate(cfg *Config, user string) bool {
	for u, by := range cfg.CreatedBy {
		if by != "" && strings.EqualFold(u, user) {
			return true
		}
	}
	return false
}

// dropDelegateCreated removes from adds (lowercase usernames) the accounts
// a delegate created: the evaluator never adds them to a guarding group
// (administrator, permission or app admin group) until an admin has acted
// on the account. Each one is reported.
func dropDelegateCreated(rep *EvalReport, cfg *Config, sn *snapshot, name, why string, adds []string) []string {
	kept := adds[:0:0]
	for _, u := range adds {
		if createdByDelegate(cfg, u) {
			rep.addErr(name, fmt.Sprintf("%s is %s: %s was created by a delegate and isn't added until an admin acts on the account (password, invite, passkeys)", name, why, sn.users[u].ID))
			continue
		}
		kept = append(kept, u)
	}
	return kept
}

// Pending lists every membership end recorded in directory.yaml — manual
// group expiries and "added" exceptions with an end date, past or future
// (a past one is still there because its removal hasn't succeeded yet;
// group-gate denies it either way) — plus the grace entries of memberships
// already removed on expiry whose grace hasn't ended at now. Sorted by (At,
// Group, User), usernames lowercase; a membership may appear twice (the
// Hub keeps the earliest).
func (s *Service) Pending(cfg *Config, now time.Time) []Expiring {
	out := []Expiring{}
	for name, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		for u, at := range gc.Expiry {
			out = append(out, Expiring{User: strings.ToLower(u), Group: name, At: at.UTC()})
		}
		for _, ex := range gc.Exceptions {
			if ex.Include && ex.Until != nil {
				out = append(out, Expiring{User: strings.ToLower(ex.User), Group: name, At: ex.Until.UTC()})
			}
		}
	}
	for _, g := range cfg.Grace {
		if g.Until.After(now) {
			out = append(out, Expiring{User: strings.ToLower(g.User), Group: g.Group, At: g.At.UTC()})
		}
	}
	sortExpiring(out)
	return out
}

// sortExpiring sorts by (At, Group, User).
func sortExpiring(out []Expiring) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.User < b.User
	})
}

// Evaluate turns rule groups, exceptions and expiries into LLDAP group
// membership, prunes what has expired from directory.yaml, audits every
// change (actor RulesActor, action group.sync) and logs removed people out
// of Keycloak. Idempotent. Per-group problems go into the report's Errors.
func (s *Service) Evaluate(ctx context.Context, now time.Time) (*EvalReport, error) {
	if s.Store == nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: "directory store not configured"}
	}
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	rep, removed, err := s.evaluateLocked(ctx, now)
	if err != nil {
		return nil, err
	}
	if len(rep.Changes) > 0 || rep.pruned {
		s.changed()
	}
	// Keycloak only after releasing s.mu. A failed logout stays pending
	// and every evaluation retries it (LLDAP is already consistent, so no
	// later run would see the removal again).
	failed := s.logoutUsers(ctx, removed)
	names := make([]string, 0, len(failed))
	for u := range failed {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		err := failed[u]
		msg := fmt.Sprintf("log out %s: %v", u, err)
		groups := []string{}
		for _, c := range rep.Changes {
			if !c.Add && strings.EqualFold(c.User, u) && !slices.Contains(groups, c.Group) {
				groups = append(groups, c.Group)
			}
		}
		if len(groups) == 0 {
			rep.Errors = append(rep.Errors, msg) // a retried earlier removal
		}
		for _, g := range groups {
			rep.addErr(g, msg)
		}
	}
	return rep, nil
}

func (s *Service) evaluateLocked(ctx context.Context, now time.Time) (*EvalReport, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := &EvalReport{Changes: []Change{}, Cycles: [][]string{}, Errors: []string{}}
	cfg, err := s.Store.Load()
	if err != nil {
		return nil, nil, err
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	d := ruleDirectory(cfg, sn)
	if c := rules.Cycles(d); c != nil {
		rep.Cycles = c
	}
	admin := s.adminGroups()
	guarding := s.guardingGroups(cfg)
	newState := map[string]map[string]bool{} // replaces s.ruleState: only current rule groups
	dirty := cfg.dropEndedGrace(now)

	names := make([]string, 0, len(cfg.Groups))
	for name := range cfg.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var removed []string
	seenRemoved := map[string]bool{}
	apply := func(group string, gid int, id string, add bool, cause string) bool {
		var err error
		if add {
			err = s.LLDAP.AddUserToGroup(ctx, id, gid)
		} else {
			err = s.LLDAP.RemoveUserFromGroup(ctx, id, gid)
		}
		sign := "+"
		if !add {
			sign = "-"
		}
		e := AuditEntry{Actor: RulesActor, Action: "group.sync", Target: clip(group + ":" + id), Detail: sign + cause, Result: "ok"}
		if err != nil {
			e.Result, e.Error = "error", clip(err.Error())
			rep.addErr(group, fmt.Sprintf("%s %s %s: %v", group, sign, id, err))
		}
		if s.Audit != nil {
			if aerr := s.Audit.Append(e); aerr != nil {
				rep.addErr(group, fmt.Sprintf("audit %s:%s: %v", group, id, aerr))
			}
		}
		if err != nil {
			return false
		}
		rep.Changes = append(rep.Changes, Change{Group: group, User: id, Add: add, Cause: cause})
		if !add && !seenRemoved[strings.ToLower(id)] {
			seenRemoved[strings.ToLower(id)] = true
			removed = append(removed, id)
		}
		return true
	}

	for _, name := range names {
		gc := cfg.Groups[name]
		if gc == nil {
			continue
		}
		g, exists := sn.groups[name]

		if gc.Rule == nil {
			// Manual group: drop expired memberships.
			users := make([]string, 0, len(gc.Expiry))
			for u, at := range gc.Expiry {
				if expired(at, now) {
					users = append(users, u)
				}
			}
			sort.Strings(users)
			for _, u := range users {
				member := ""
				if exists {
					for _, m := range g.Members() {
						if strings.EqualFold(m, u) {
							member = m
						}
					}
				}
				protected := member != "" && s.protectedAccount(member)
				if member != "" && !protected {
					if !apply(name, g.ID, member, false, CauseMembershipExpire) {
						continue // keep the entry (still published): retried next run
					}
				}
				if !protected {
					cfg.addGrace(u, name, gc.Expiry[u], now)
				}
				delete(gc.Expiry, u)
				dirty = true
			}
			continue
		}

		if !s.ruleGroupAllowed(name, admin) {
			rep.addErr(name, fmt.Sprintf("%s is a built-in or administrator group and can't be rule-based; rule ignored", name))
			if pruneSkipped(rep, name, gc, now, g, exists) {
				dirty = true
			}
			continue
		}
		if !exists {
			rep.addErr(name, fmt.Sprintf("rule group %s does not exist in LLDAP; create it first", name))
			if pruneSkipped(rep, name, gc, now, g, exists) {
				dirty = true
			}
			continue
		}

		ge := s.evalGroup(gc, d, sn, now)
		last := s.ruleState[name]
		current := map[string]string{} // lowercase -> LLDAP id
		for _, m := range g.Members() {
			current[strings.ToLower(m)] = m
		}

		var adds, dels []string
		for u := range ge.desired {
			if _, ok := current[u]; !ok {
				adds = append(adds, u)
			}
		}
		for u := range current {
			if !ge.desired[u] && !s.protectedAccount(u) {
				dels = append(dels, u)
			}
		}
		if why := s.addsBlocked(cfg, guarding, name, gc); why != "" {
			rep.addErr(name, why)
			adds = nil
		}
		if why, ok := guarding[name]; ok {
			adds = dropDelegateCreated(rep, cfg, sn, name, why, adds)
		}
		sort.Strings(adds)
		sort.Strings(dels)

		state := map[string]bool{}
		for u := range current {
			state[u] = true
		}
		for _, u := range adds {
			cause := CauseRule
			switch {
			case ge.include[u] && !ge.matched[u]:
				cause = CauseException
			case ge.expiredExcl[u]:
				cause = CauseExceptionExpired
			case last != nil && last[u]:
				cause = CauseOutsideChange
			}
			if apply(name, g.ID, sn.users[u].ID, true, cause) {
				state[u] = true
				if cfg.clearGrace(name, u) {
					dirty = true
				}
			}
		}
		for _, u := range dels {
			cause := CauseRule
			switch {
			case ge.exclude[u] && ge.matched[u]:
				cause = CauseException
			case ge.expiredIncl[u]:
				cause = CauseExceptionExpired
			case last != nil && !last[u]:
				cause = CauseOutsideChange
			}
			if apply(name, g.ID, current[u], false, cause) {
				delete(state, u)
			}
		}
		// Expired "added" exceptions go only once the membership is gone
		// (a failed removal keeps the entry, so it stays published), or
		// when the rule itself grants it.
		exs := ge.kept
		for _, ex := range gc.Exceptions {
			u := strings.ToLower(ex.User)
			if !ex.Include || ex.Until == nil || !expired(*ex.Until, now) {
				continue
			}
			switch {
			case ge.desired[u] || s.protectedAccount(u):
				// Still a member by rule (or never touched): nothing to publish.
			case state[u]:
				exs = append(exs, ex) // removal failed or blocked: retried next run
				continue
			default:
				cfg.addGrace(u, name, *ex.Until, now)
			}
		}
		if len(exs) != len(gc.Exceptions) {
			gc.Exceptions = exs
			dirty = true
		}
		newState[name] = state
	}
	s.ruleState = newState

	if dirty {
		if err := s.Store.Save(cfg); err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("save %s: %v", s.Store.Path, err))
		} else {
			rep.pruned = true
		}
	}
	return rep, removed, nil
}

// pruneSkipped handles the expired exceptions of a rule group the
// evaluator skips (it changes no membership there). An expired "added"
// exception of a user who is still a member of the existing LLDAP group is
// kept, so it stays published and group-gate keeps denying, and reported
// every run; it goes once they are no longer a member (or an admin re-adds
// them explicitly: AddMember). Other expired exceptions are dropped: those
// of non-members, "kept out" ones, and all of a group missing in LLDAP
// (nobody is a member). No grace entries.
func pruneSkipped(rep *EvalReport, name string, gc *GroupConfig, now time.Time, g lldap.Group, exists bool) bool {
	kept := []Exception{}
	for _, ex := range gc.Exceptions {
		if ex.Until == nil || !expired(*ex.Until, now) {
			kept = append(kept, ex)
			continue
		}
		if ex.Include && exists && memberOf(g, ex.User) {
			rep.addErr(name, fmt.Sprintf("%s: %s's temporary access expired but the evaluator doesn't manage this group; remove them or re-add them explicitly", name, ex.User))
			kept = append(kept, ex)
		}
	}
	if len(kept) == len(gc.Exceptions) {
		return false
	}
	gc.Exceptions = kept
	return true
}

// changed calls OnChange. Never call it with s.mu held.
func (s *Service) changed() {
	s.invalidatePreview()
	if s.OnChange != nil {
		s.OnChange()
	}
}

// Published is what the Hub publishes from the directory for group-gate
// (contract §4 expiring, §4.1 user attributes) and Keycloak (§9.6).
type Published struct {
	// Expiring: Pending at the time of the call, without the ends of "added"
	// exceptions the rule grants anyway (publishedExpiring).
	Expiring []Expiring
	// Fields: the fields shared with apps (ShareWithApps), sorted by name.
	Fields []Field
	// Users: every LLDAP user except the service account (lowercase), with
	// their values of the shared fields only (users without any omitted).
	Users map[string]map[string][]string
	// Membership is the same read as Membership (plan 4 T11: the Hub's
	// gate file uses it, so it never disagrees with the policy file).
	Membership *Membership
}

// SharedFields returns the fields shared with apps, sorted by name.
func (s *Service) SharedFields() ([]Field, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	return sharedFields(cfg), nil
}

func sharedFields(cfg *Config) []Field {
	out := []Field{}
	for _, f := range cfg.Fields {
		if f.ShareWithApps && !reservedAttr(f.Name) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Publish reads directory.yaml and LLDAP and returns what the Hub
// publishes. Any failure is an error: the caller keeps what it published
// last (fail closed) rather than publishing a partial view.
func (s *Service) Publish(ctx context.Context, now time.Time) (*Published, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := &Published{Expiring: s.publishedExpiring(cfg, sn, now), Fields: sharedFields(cfg), Users: map[string]map[string][]string{},
		Membership: s.membershipOf(cfg, sn, now)}
	svc := strings.ToLower(s.serviceUser())
	for id, u := range sn.users {
		if id == svc {
			continue
		}
		vals := map[string][]string{}
		for _, f := range out.Fields {
			if v := u.Attributes[f.Name]; len(v) > 0 {
				vals[f.Name] = append([]string{}, v...)
			}
		}
		if len(vals) > 0 {
			out.Users[id] = vals
		}
	}
	return out, nil
}

// publishedExpiring is Pending, except for the end of an "added"
// exception whose user stays in the group by rule anyway: the user is a
// current member of the LLDAP group, the rule matches them and they are in
// the evaluator's real desired set (a managed rule group whose adds aren't
// blocked, not a delegate-created account in a guarding group). Only those
// exception ends are dropped; manual expiries and grace entries are always
// published (fail closed).
func (s *Service) publishedExpiring(cfg *Config, sn *snapshot, now time.Time) []Expiring {
	desired := s.Desired(cfg, sn, now)
	guarding := s.guardingGroups(cfg)
	d := ruleDirectory(cfg, sn)
	out := []Expiring{}
	for name, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		for u, at := range gc.Expiry {
			out = append(out, Expiring{User: strings.ToLower(u), Group: name, At: at.UTC()})
		}
		g, exists := sn.groups[name]
		var ge *groupEval
		if gc.Rule != nil && exists && desired[name] != nil && s.addsBlocked(cfg, guarding, name, gc) == "" {
			ge = s.evalGroup(gc, d, sn, now)
		}
		_, guards := guarding[name]
		for _, ex := range gc.Exceptions {
			if !ex.Include || ex.Until == nil {
				continue
			}
			u := strings.ToLower(ex.User)
			if ge != nil && ge.matched[u] && desired[name][u] && memberOf(g, u) && !(guards && createdByDelegate(cfg, u)) {
				continue // kept by rule: the end doesn't end the membership
			}
			out = append(out, Expiring{User: u, Group: name, At: ex.Until.UTC()})
		}
	}
	for _, g := range cfg.Grace {
		if g.Until.After(now) {
			out = append(out, Expiring{User: strings.ToLower(g.User), Group: g.Group, At: g.At.UTC()})
		}
	}
	sortExpiring(out)
	return out
}

// kickChan is the coalesced trigger of RunEvaluator.
func (s *Service) kickChan() chan struct{} {
	s.kickOnce.Do(func() { s.kickCh = make(chan struct{}, 1) })
	return s.kickCh
}

// kick requests an evaluation soon (non-blocking, coalesced).
func (s *Service) kick() {
	s.invalidatePreview()
	select {
	case s.kickChan() <- struct{}{}:
	default:
	}
}

// settleTimeout bounds how long Settle waits for its evaluation
// (contract §9.7: ≤ 5 s); a var so tests can shorten it.
var settleTimeout = 5 * time.Second

// settleEvalBound bounds the evaluation Settle starts. It runs on a
// context detached from the caller's (context.WithoutCancel): a timed-out
// wait or a client that went away never cuts it between an LLDAP removal
// and its Keycloak logout.
var settleEvalBound = 2 * time.Minute

// settleWhyMax: Settle's why is clipped to this many runes.
const settleWhyMax = 200

// Fixed whys (never a path, a URL or another group's problem).
const (
	whyLLDAPDown = "stored, but not applied: Users & Groups (LLDAP) is unavailable; it applies at the next evaluation"
	whyNoStore   = "stored, but not applied: the directory store (directory.yaml) isn't configured"
	whyEvalError = "stored, but not applied: the evaluation failed (see the Hub log); it applies at the next evaluation"
	whyGone      = "stored; the request ended before it was applied: it applies in the background"
)

// Settle runs the evaluator once, synchronously, so a membership,
// exception, rule, convert or expiry change the caller just made is in
// LLDAP when its answer goes back (contract §9.7 applied / why). Call it
// only after the mutation's run returned (s.mu released) and only when
// it succeeded. groups are the groups the change concerns: only their
// report errors reach why.
//
// applied = the evaluation returned without error within settleTimeout.
// Otherwise why is a fixed text (LLDAP unavailable, store not
// configured, a failed evaluation — logged in full —, the timeout, the
// request gone) or a refusal's own message (*Error below 500). A run with
// errors of groups is applied with them, joined, as why. Clipped to
// settleWhyMax runes.
//
// Concurrent Settles share runs (joinSettle): with none in flight a
// Settle starts one; one arriving while a run is in flight waits for the
// single run queued after it (that run starts after this Settle was
// called, so it sees the caller's change), which every other Settle
// arriving meanwhile shares — N parallel Settles evaluate at most twice.
//
// The evaluation itself runs to its end (settleEvalBound) on a detached
// context whatever the wait does. The background loop may evaluate at
// the same time: both go through evaluateLocked, which holds s.mu, so the
// runs are serialised and the second sees the first's changes — a
// removal (and its Keycloak logout) is made by one run only; a failed
// logout is retried by every later run (logoutUsers). The kick the
// mutation's run sent still follows (RunEvaluator unchanged).
func (s *Service) Settle(ctx context.Context, groups ...string) (applied bool, why string) {
	r := s.joinSettle(ctx)
	wait := time.NewTimer(settleTimeout)
	defer wait.Stop()
	select {
	case <-r.done:
	case <-wait.C:
		why = fmt.Sprintf("stored, but applying it took over %s: it goes on in the background (timed out waiting)", settleTimeout)
		log.Printf("rules: settle: %s", why)
		return false, why
	case <-ctx.Done():
		return false, whyGone
	}
	if r.err != nil {
		var de *Error
		switch {
		case errors.As(r.err, &de) && de.Status == http.StatusServiceUnavailable && s.Store == nil:
			return false, whyNoStore
		case errors.As(r.err, &de) && de.Status == http.StatusServiceUnavailable:
			return false, whyLLDAPDown
		case errors.As(r.err, &de) && de.Status < 500:
			return false, clipRunes("stored, but not applied: "+de.Msg, settleWhyMax)
		}
		return false, whyEvalError
	}
	if errs := r.rep.ErrorsOf(groups...); len(errs) > 0 {
		return true, clipRunes(strings.Join(errs, "; "), settleWhyMax)
	}
	return true, ""
}

// settleRun is one evaluation Settles share: done is closed once rep and
// err are set.
type settleRun struct {
	done chan struct{}
	rep  *EvalReport
	err  error
}

// joinSettle answers the run a Settle called now waits for: a new one
// started at once when none is in flight, else the run queued after the
// in-flight one (created by the first Settle to need it; it starts when
// the in-flight run ends). ctx's values only (WithoutCancel) reach the
// run it starts.
func (s *Service) joinSettle(ctx context.Context) *settleRun {
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	if s.settleCur == nil {
		s.settleCur = &settleRun{done: make(chan struct{})}
		go s.runSettle(context.WithoutCancel(ctx), s.settleCur)
		return s.settleCur
	}
	if s.settleNext == nil {
		s.settleNext = &settleRun{done: make(chan struct{})}
		s.settleNextCtx = context.WithoutCancel(ctx)
	}
	return s.settleNext
}

// runSettle evaluates for r (bounded by settleEvalBound, never by a
// waiter), then starts the queued run, if any.
func (s *Service) runSettle(ctx context.Context, r *settleRun) {
	for r != nil {
		evalCtx, cancel := context.WithTimeout(ctx, settleEvalBound)
		eval := s.Evaluate
		if s.settleEval != nil {
			eval = s.settleEval
		}
		rep, err := eval(evalCtx, time.Now().UTC())
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			var de *Error
			if !errors.As(err, &de) || de.Status != http.StatusServiceUnavailable {
				log.Printf("rules: evaluation failed: %v", err)
			}
		} else if err == nil && (len(rep.Changes) > 0 || len(rep.Errors) > 0) {
			log.Printf("rules: %d membership change(s), %d error(s)%s", len(rep.Changes), len(rep.Errors), firstErr(rep.Errors))
		}
		r.rep, r.err = rep, err
		close(r.done)
		s.settleMu.Lock()
		r, ctx = s.settleNext, s.settleNextCtx
		s.settleCur, s.settleNext, s.settleNextCtx = r, nil, nil
		s.settleMu.Unlock()
	}
}

// logoutUsers signs users and every still-pending earlier logout out of
// Keycloak (outside s.mu), returning the failures. A failure stays in
// pendingLogout (deduplicated by lowercase user, its attempts counted and
// logged) until a later call succeeds; a missing Keycloak user is a
// success (LogoutUser). Without Keycloak nothing is kept.
func (s *Service) logoutUsers(ctx context.Context, users []string) map[string]error {
	if s.KC == nil {
		return nil
	}
	s.logoutMu.Lock()
	todo := map[string]string{} // lowercase -> name to log out
	for u := range s.pendingLogout {
		todo[u] = u
	}
	s.logoutMu.Unlock()
	for _, u := range users {
		todo[strings.ToLower(u)] = u
	}
	keys := make([]string, 0, len(todo))
	for k := range todo {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var failed map[string]error
	for _, k := range keys {
		err := s.KC.LogoutUser(ctx, todo[k])
		s.logoutMu.Lock()
		if err == nil {
			delete(s.pendingLogout, k)
			s.logoutMu.Unlock()
			continue
		}
		if s.pendingLogout == nil {
			s.pendingLogout = map[string]int{}
		}
		s.pendingLogout[k]++
		n := s.pendingLogout[k]
		s.logoutMu.Unlock()
		log.Printf("directory: signing %s out of Keycloak failed (attempt %d; retried at the next evaluation): %v", todo[k], n, err)
		if failed == nil {
			failed = map[string]error{}
		}
		failed[todo[k]] = err
	}
	return failed
}

// PendingLogouts: the users whose Keycloak logout failed and is retried
// (lowercase, sorted).
func (s *Service) PendingLogouts() []string {
	s.logoutMu.Lock()
	defer s.logoutMu.Unlock()
	out := make([]string, 0, len(s.pendingLogout))
	for u := range s.pendingLogout {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// clipRunes keeps the first n runes of s (control characters dropped),
// "…" when cut.
func clipRunes(s string, n int) string {
	r := []rune(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n-1]) + "…"
}

// evaluatorDebounce coalesces bursts of mutations into one evaluation.
const evaluatorDebounce = time.Second

// RunEvaluator evaluates once at start, every interval and after each
// mutation (kick, debounced), until ctx is done.
func (s *Service) RunEvaluator(ctx context.Context, interval time.Duration) {
	kick := s.kickChan()
	s.evaluateAndLog(ctx)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-kick:
			select {
			case <-ctx.Done():
				return
			case <-time.After(evaluatorDebounce):
			}
			select {
			case <-kick:
			default:
			}
		}
		s.evaluateAndLog(ctx)
	}
}

// evaluateAndLog runs one evaluation and logs it; OnEvaluated follows
// on every path (success, error, unavailable).
func (s *Service) evaluateAndLog(ctx context.Context) {
	if s.OnEvaluated != nil {
		defer s.OnEvaluated()
	}
	rep, err := s.Evaluate(ctx, time.Now().UTC())
	if err != nil {
		var de *Error
		if errors.As(err, &de) && de.Status == http.StatusServiceUnavailable {
			return // LLDAP or store not configured: nothing to do
		}
		log.Printf("rules: evaluation failed: %v", err)
		return
	}
	if len(rep.Changes) > 0 || len(rep.Errors) > 0 {
		log.Printf("rules: %d membership change(s), %d error(s)%s", len(rep.Changes), len(rep.Errors), firstErr(rep.Errors))
	}
}

func firstErr(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	return "; first: " + errs[0]
}
