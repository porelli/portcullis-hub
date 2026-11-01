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
	out := map[string]map[string]bool{}
	for name, gc := range cfg.Groups {
		if gc == nil || gc.Rule == nil || !s.ruleGroupAllowed(name, admin) {
			continue
		}
		out[name] = s.evalGroup(gc, d, sn, now).desired
	}
	return out
}

// Pending lists every membership that is still to expire: manual-group
// expiries and "added" exceptions with an end date, sorted by (At, Group,
// User), usernames lowercase.
func (s *Service) Pending(cfg *Config, now time.Time) []Expiring {
	out := []Expiring{}
	for name, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		for u, at := range gc.Expiry {
			if !expired(at, now) {
				out = append(out, Expiring{User: strings.ToLower(u), Group: name, At: at.UTC()})
			}
		}
		for _, ex := range gc.Exceptions {
			if ex.Include && ex.Until != nil && !expired(*ex.Until, now) {
				out = append(out, Expiring{User: strings.ToLower(ex.User), Group: name, At: ex.Until.UTC()})
			}
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
	newState := map[string]map[string]bool{} // replaces s.ruleState: only current rule groups

	names := make([]string, 0, len(cfg.Groups))
	for name := range cfg.Groups {
		names = append(names, name)
	}
	sort.Strings(names)

	dirty := false
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
				if member != "" && !s.protectedAccount(member) {
					if !apply(name, g.ID, member, false, CauseMembershipExpire) {
						continue // keep the entry: retried next run
					}
				}
				delete(gc.Expiry, u)
				dirty = true
			}
			continue
		}

		if !s.ruleGroupAllowed(name, admin) {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s is a built-in or administrator group and can't be rule-based; rule ignored", name))
			continue
		}
		if !exists {
			rep.Errors = append(rep.Errors, fmt.Sprintf("rule group %s does not exist in LLDAP; create it first", name))
			continue
		}

		ge := s.evalGroup(gc, d, sn, now)
		if len(ge.kept) != len(gc.Exceptions) {
			gc.Exceptions = ge.kept
			dirty = true
		}
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
		newState[name] = state
	}
	s.ruleState = newState

	if dirty {
		if err := s.Store.Save(cfg); err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("save %s: %v", s.Store.Path, err))
		}
	}
	return rep, removed, nil
}

// kickChan is the coalesced trigger of RunEvaluator.
func (s *Service) kickChan() chan struct{} {
	s.kickOnce.Do(func() { s.kickCh = make(chan struct{}, 1) })
	return s.kickCh
}

// kick requests an evaluation soon (non-blocking, coalesced).
func (s *Service) kick() {
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
