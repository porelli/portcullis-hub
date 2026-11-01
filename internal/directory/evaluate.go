package directory

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
// group) whose rule uses a field delegates can edit gets no additions —
// editing that field must never grant rights. It can happen when a group
// becomes guarding after its rule was set (e.g. an app enabled later with
// it as admin_group). Removals still apply. Returns the reason ("" if
// not blocked).
func (s *Service) addsBlocked(cfg *Config, guarding map[string]string, name string, gc *GroupConfig) string {
	why, ok := guarding[name]
	if !ok || gc == nil || gc.Rule == nil {
		return ""
	}
	bad := nonAdminOnly(cfg, gc.Rule)
	if len(bad) == 0 {
		return ""
	}
	return fmt.Sprintf("%s is %s but its rule uses fields that aren't admin-only (%s): nobody is added until the rule uses only admin-only fields", name, why, strings.Join(bad, ", "))
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
		out[name] = desired
	}
	return out
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
	return out
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
	// Keycloak only after releasing s.mu.
	if s.KC != nil {
		for _, u := range removed {
			if err := s.KC.LogoutUser(ctx, u); err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("log out %s: %v", u, err))
			}
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
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s %s %s: %v", group, sign, id, err))
		}
		if s.Audit != nil {
			if aerr := s.Audit.Append(e); aerr != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("audit %s:%s: %v", group, id, aerr))
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
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s is a built-in or administrator group and can't be rule-based; rule ignored", name))
			if pruneSkipped(rep, name, gc, now, g, exists) {
				dirty = true
			}
			continue
		}
		if !exists {
			rep.Errors = append(rep.Errors, fmt.Sprintf("rule group %s does not exist in LLDAP; create it first", name))
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
			rep.Errors = append(rep.Errors, why)
			adds = nil
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
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %s's temporary access expired but the evaluator doesn't manage this group; remove them or re-add them explicitly", name, ex.User))
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
	// Expiring: Pending at the time of the call.
	Expiring []Expiring
	// Fields: the fields shared with apps (ShareWithApps), sorted by name.
	Fields []Field
	// Users: every LLDAP user except the service account (lowercase), with
	// their values of the shared fields only (users without any omitted).
	Users map[string]map[string][]string
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
		if f.ShareWithApps {
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
	out := &Published{Expiring: s.Pending(cfg, now), Fields: sharedFields(cfg), Users: map[string]map[string][]string{}}
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

func (s *Service) evaluateAndLog(ctx context.Context) {
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
