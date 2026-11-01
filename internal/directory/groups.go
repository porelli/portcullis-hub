package directory

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// maxReasonRunes bounds an exception's reason.
const maxReasonRunes = 500

// ConvertPreview is the review step of turning a manual group into a
// rule group: who the rule matches, which current members don't match
// (offered to stay as "added" exceptions) and who would join. Usernames
// as in LLDAP, sorted; protected accounts never appear. ExpiryDropped:
// members the rule matches whose manual expiry would be dropped (they
// then stay by rule, without an end).
type ConvertPreview struct {
	Matching        []string `json:"matching"`
	KeptAsException []string `json:"kept_as_exception"`
	Joining         []string `json:"joining"`
	ExpiryDropped   []string `json:"expiry_dropped"`
}

// sameAs: p and q list the same people as kept, joining and expiry
// dropped (case-insensitive, any order). Matching is implied by them.
func (p *ConvertPreview) sameAs(q *ConvertPreview) bool {
	eq := func(a, b []string) bool {
		set := map[string]int{}
		for _, x := range a {
			set[strings.ToLower(x)]++
		}
		for _, x := range b {
			set[strings.ToLower(x)]--
		}
		for _, n := range set {
			if n != 0 {
				return false
			}
		}
		return true
	}
	return eq(p.KeptAsException, q.KeptAsException) && eq(p.Joining, q.Joining) && eq(p.ExpiryDropped, q.ExpiryDropped)
}

func errNoStore() error {
	return &Error{Status: http.StatusServiceUnavailable, Msg: "directory store not configured"}
}

func (s *Service) loadConfig() (*Config, error) {
	if s.Store == nil {
		return nil, errNoStore()
	}
	cfg, err := s.Store.Load()
	if err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
	}
	if cfg.Groups == nil {
		cfg.Groups = map[string]*GroupConfig{}
	}
	if cfg.Permissions == nil {
		cfg.Permissions = map[string]string{}
	}
	return cfg, nil
}

// guardingGroups maps each group whose rule may use only admin-only
// fields to why: administrator groups, permission groups and app admin
// groups.
func (s *Service) guardingGroups(cfg *Config) map[string]string {
	out := map[string]string{}
	if s.Apps != nil {
		for _, a := range s.Apps() {
			if a.AdminGroup != "" {
				out[a.AdminGroup] = "the admin group of app " + a.ID
			}
		}
	}
	perms := make([]string, 0, len(cfg.Permissions))
	for p := range cfg.Permissions {
		perms = append(perms, p)
	}
	sort.Strings(perms)
	for _, p := range perms {
		if g := cfg.Permissions[p]; g != "" {
			out[g] = "the " + p + " permission group"
		}
	}
	for g := range s.adminGroups() {
		out[g] = "an administrator group"
	}
	return out
}

// checkRule is the 400 part of rule validation: well-formed, only defined
// fields, reports_to only on a person-kind "manager" (rules.Eval follows
// ManagerField "manager").
func checkRule(cfg *Config, rule *rules.Expr) error {
	if rule == nil {
		return invalid("rule is required")
	}
	if err := rules.Validate(rule); err != nil {
		return invalid("invalid rule: %v", err)
	}
	kinds := map[string]FieldKind{}
	for _, f := range cfg.Fields {
		kinds[f.Name] = f.Kind
	}
	for _, f := range rules.Fields(rule) {
		if _, ok := kinds[f]; !ok {
			return invalid("rule uses %q, which is not a defined field", f)
		}
	}
	var walk func(e *rules.Expr) error
	walk = func(e *rules.Expr) error {
		if e.Op == rules.OpReportsTo {
			if e.Field != "manager" {
				return invalid("reports-to works only on the field \"manager\", not %q", e.Field)
			}
			if kinds["manager"] != FieldKindPerson {
				return invalid("reports-to needs \"manager\" to be a person field")
			}
		}
		for _, it := range e.Items {
			if err := walk(it); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(rule)
}

// nonAdminOnly returns the fields rule uses that delegates could edit.
func nonAdminOnly(cfg *Config, rule *rules.Expr) []string {
	adminOnly := map[string]bool{}
	for _, f := range cfg.Fields {
		adminOnly[f.Name] = f.AdminOnly
	}
	var out []string
	for _, f := range rules.Fields(rule) {
		if !adminOnly[f] {
			out = append(out, f)
		}
	}
	return out
}

// checkRuleFor validates rule for group: checkRule (400), never on
// built-in or administrator groups (409), and guarding groups only on
// admin-only fields (409) — otherwise editing a field could grant admin
// rights or a delegated permission.
func (s *Service) checkRuleFor(cfg *Config, group string, rule *rules.Expr) error {
	if !s.ruleGroupAllowed(group, s.adminGroups()) {
		return refuse("%s is a built-in or administrator group and can't be rule-based", group)
	}
	if err := checkRule(cfg, rule); err != nil {
		return err
	}
	if why, ok := s.guardingGroups(cfg)[group]; ok {
		if bad := nonAdminOnly(cfg, rule); len(bad) > 0 {
			return refuse("%s is %s: its rule may use only admin-only fields, not %s", group, why, strings.Join(bad, ", "))
		}
		if matchesEmpty(cfg, rule) {
			return refuse("%s is %s: its rule must not match a person with no details at all (e.g. a new account), but %s does", group, why, rules.Format(rule))
		}
	}
	return nil
}

// matchesEmpty reports whether rule matches a person with no field values
// at all (and no manager) — every brand-new account. A guarding group's
// rule must not: anyone who can create an account would grant rights.
func matchesEmpty(cfg *Config, rule *rules.Expr) bool {
	const nobody = "\x00empty"
	d := &rules.Directory{People: map[string]rules.Person{nobody: {User: nobody, Attrs: map[string][]string{}}}}
	for _, f := range cfg.Fields {
		if f.Name == "manager" && f.Kind == FieldKindPerson {
			d.ManagerField = "manager"
		}
	}
	return rules.Eval(rule, nobody, d)
}

// ruleBased reports whether cfg makes group a rule group.
func ruleBased(cfg *Config, group string) bool {
	gc := cfg.Groups[group]
	return gc != nil && gc.Rule != nil
}

// tidy drops an empty group entry.
func tidy(cfg *Config, group string) {
	if gc := cfg.Groups[group]; gc != nil && gc.Rule == nil && len(gc.Exceptions) == 0 && len(gc.Expiry) == 0 {
		delete(cfg.Groups, group)
	}
}

func (s *Service) saveConfig(cfg *Config) error {
	if err := s.Store.Save(cfg); err != nil {
		return &Error{Status: http.StatusServiceUnavailable, Msg: "save directory.yaml: " + err.Error()}
	}
	return nil
}

func formatUntil(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// matching returns the (lowercase) people rule matches, protected
// accounts left out — the evaluator's own view.
func (s *Service) matching(cfg *Config, sn *snapshot, rule *rules.Expr) map[string]bool {
	return s.evalGroup(&GroupConfig{Rule: rule}, ruleDirectory(cfg, sn), sn, time.Now().UTC()).matched
}

func idsOf(sn *snapshot, set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, sn.users[u].ID)
	}
	sort.Strings(out)
	return out
}

// preview computes the convert review for group (manual, existing).
func (s *Service) preview(cfg *Config, sn *snapshot, g lldap.Group, rule *rules.Expr) *ConvertPreview {
	matched := s.matching(cfg, sn, rule)
	members := map[string]bool{}
	for _, m := range g.Members() {
		if u := strings.ToLower(m); !s.protectedAccount(u) {
			if _, ok := sn.users[u]; ok {
				members[u] = true
			}
		}
	}
	kept, joining, dropped := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var expiry map[string]time.Time
	if gc := cfg.Groups[g.DisplayName]; gc != nil {
		expiry = gc.Expiry
	}
	for u := range members {
		if !matched[u] {
			kept[u] = true
			continue
		}
		for k := range expiry {
			if strings.EqualFold(k, u) {
				dropped[u] = true
			}
		}
	}
	for u := range matched {
		if !members[u] {
			joining[u] = true
		}
	}
	return &ConvertPreview{Matching: idsOf(sn, matched), KeptAsException: idsOf(sn, kept), Joining: idsOf(sn, joining), ExpiryDropped: idsOf(sn, dropped)}
}

// convertCheck loads what ConvertPreview and ConvertApply need and
// refuses anything but an existing manual group and an acceptable rule.
func (s *Service) convertCheck(ctx context.Context, group string, rule *rules.Expr) (*Config, *snapshot, lldap.Group, error) {
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, nil, lldap.Group{}, err
	}
	if !s.ruleGroupAllowed(group, s.adminGroups()) {
		return nil, nil, lldap.Group{}, s.checkRuleFor(cfg, group, rule)
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, nil, lldap.Group{}, err
	}
	g, err := sn.group(group)
	if err != nil {
		return nil, nil, lldap.Group{}, err
	}
	if ruleBased(cfg, group) {
		return nil, nil, lldap.Group{}, refuse("%s is already rule-based; change its rule instead", group)
	}
	if err := s.checkRuleFor(cfg, group, rule); err != nil {
		return nil, nil, lldap.Group{}, err
	}
	return cfg, sn, g, nil
}

// ConvertPreview shows what turning the manual group into a rule group
// would do. Nothing changes. Admins only.
func (s *Service) ConvertPreview(ctx context.Context, c *Caller, group string, rule *rules.Expr) (*ConvertPreview, error) {
	detail := "rule=" + rules.Format(rule)
	var out *ConvertPreview
	err := s.run(ctx, c, permAdmin, "group.convert_preview", group, &detail, func() error {
		cfg, sn, g, err := s.convertCheck(ctx, group, rule)
		if err != nil {
			return err
		}
		out = s.preview(cfg, sn, g, rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConvertApply turns the manual group into a rule group. keep (a subset
// of the preview's KeptAsException) stay as "added" exceptions, carrying
// any manual expiry; the evaluator then removes the other non-matching
// members. Admins only.
func (s *Service) ConvertApply(ctx context.Context, c *Caller, group string, rule *rules.Expr, keep []string) error {
	return s.ConvertApplyReviewed(ctx, c, group, rule, keep, nil)
}

// ConvertApplyReviewed is ConvertApply after a review: if reviewed is not
// nil and the preview computed now (inside the lock) differs from it in
// who is kept, who joins or whose expiry is dropped, nothing changes and
// the error is a 409 (the admin must review again).
func (s *Service) ConvertApplyReviewed(ctx context.Context, c *Caller, group string, rule *rules.Expr, keep []string, reviewed *ConvertPreview) error {
	detail := "convert rule=" + rules.Format(rule)
	return s.run(ctx, c, permAdmin, "group.rule", group, &detail, func() error {
		cfg, sn, g, err := s.convertCheck(ctx, group, rule)
		if err != nil {
			return err
		}
		p := s.preview(cfg, sn, g, rule)
		if reviewed != nil && !p.sameAs(reviewed) {
			detail += " (stale review)"
			return refuse("%s changed since the review: review the conversion again", group)
		}
		offered := map[string]string{}
		for _, u := range p.KeptAsException {
			offered[strings.ToLower(u)] = u
		}
		gc := cfg.Groups[group]
		if gc == nil {
			gc = &GroupConfig{}
		}
		now := time.Now().UTC()
		reason := fmt.Sprintf("member before the rule (set by %s on %s)", c.User, now.Format("2006-01-02"))
		var exs []Exception
		var kept []string
		seen := map[string]bool{}
		for _, k := range keep {
			k = strings.ToLower(strings.TrimSpace(k))
			id, ok := offered[k]
			if !ok {
				return invalid("%q can't be kept: only current members the rule doesn't match can stay as exceptions", k)
			}
			if seen[k] {
				continue
			}
			seen[k] = true
			ex := Exception{User: id, Reason: reason, By: c.User, Include: true, At: now}
			for u, at := range gc.Expiry {
				if strings.EqualFold(u, id) {
					until := at.UTC()
					ex.Until = &until
				}
			}
			exs = append(exs, ex)
			kept = append(kept, id)
			cfg.clearGrace(group, id) // granted again
		}
		sort.Strings(kept)
		cfg.Groups[group] = &GroupConfig{Rule: rule, Exceptions: exs}
		detail += " keep=" + strings.Join(kept, ",")
		if len(p.ExpiryDropped) > 0 {
			detail += " dropped_expiry=" + strings.Join(p.ExpiryDropped, ",")
		}
		return s.saveConfig(cfg)
	})
}

// SetGroupRule changes the rule of a rule group; nil makes it manual
// again (current members stay, exceptions are dropped). A manual group
// becomes rule-based only through ConvertPreview/ConvertApply (the
// review step). Admins only.
func (s *Service) SetGroupRule(ctx context.Context, c *Caller, group string, rule *rules.Expr) error {
	detail := "manual"
	if rule != nil {
		detail = "rule=" + rules.Format(rule)
	}
	return s.run(ctx, c, permAdmin, "group.rule", group, &detail, func() error {
		cfg, err := s.loadConfig()
		if err != nil {
			return err
		}
		if rule != nil && !s.ruleGroupAllowed(group, s.adminGroups()) {
			return s.checkRuleFor(cfg, group, rule)
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		g, err := sn.group(group)
		if err != nil {
			return err
		}
		if rule == nil {
			if !ruleBased(cfg, group) {
				detail = "manual (unchanged)"
				return nil
			}
			gc := cfg.Groups[group]
			if n := len(gc.Exceptions); n > 0 {
				detail += fmt.Sprintf(" dropped_exceptions=%d", n)
			}
			// Temporary access stays temporary: an active "added"
			// exception with an end becomes the member's manual expiry.
			now := time.Now().UTC()
			var kept []string
			for _, ex := range gc.Exceptions {
				if !ex.Include || ex.Until == nil || expired(*ex.Until, now) || !memberOf(g, ex.User) {
					continue
				}
				if gc.Expiry == nil {
					gc.Expiry = map[string]time.Time{}
				}
				gc.Expiry[ex.User] = ex.Until.UTC()
				kept = append(kept, ex.User+"@"+formatUntil(ex.Until))
			}
			if len(kept) > 0 {
				sort.Strings(kept)
				detail += " expiry=" + strings.Join(kept, ",")
			}
			gc.Rule = nil
			cfg.Groups[group].Exceptions = nil
			tidy(cfg, group)
			return s.saveConfig(cfg)
		}
		if !ruleBased(cfg, group) {
			return refuse("%s is a manual group: turn it into a rule group with the review step (convert)", group)
		}
		if err := s.checkRuleFor(cfg, group, rule); err != nil {
			return err
		}
		cfg.Groups[group].Rule = rule
		return s.saveConfig(cfg)
	})
}

// AddException adds (Include) or keeps out a person of a rule group,
// with a required reason and an optional end. It replaces the person's
// existing exception. Admins only.
func (s *Service) AddException(ctx context.Context, c *Caller, group string, e Exception) error {
	e.User = strings.TrimSpace(e.User)
	e.Reason = strings.TrimSpace(e.Reason)
	detail := fmt.Sprintf("add user=%s include=%v until=%s reason=%s", e.User, e.Include, formatUntil(e.Until), e.Reason)
	return s.run(ctx, c, permAdmin, "group.exception", group, &detail, func() error {
		if err := s.checkTarget(e.User); err != nil {
			return err
		}
		if e.Reason == "" {
			return invalid("a reason is required")
		}
		if utf8.RuneCountInString(e.Reason) > maxReasonRunes {
			return invalid("the reason must be at most %d characters", maxReasonRunes)
		}
		now := time.Now().UTC()
		if e.Until != nil {
			if !e.Until.After(now) {
				return invalid("the end of the exception must be in the future")
			}
			until := e.Until.UTC()
			e.Until = &until
		}
		cfg, err := s.loadConfig()
		if err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		if _, err := sn.group(group); err != nil {
			return err
		}
		u, err := sn.user(e.User)
		if err != nil {
			return err
		}
		if !ruleBased(cfg, group) || !s.ruleGroupAllowed(group, s.adminGroups()) {
			return refuse("%s is not a rule group: exceptions apply only to rule groups (use membership and expiry instead)", group)
		}
		e.User, e.By, e.At = u.ID, c.User, now
		detail = fmt.Sprintf("add user=%s include=%v until=%s reason=%s", e.User, e.Include, formatUntil(e.Until), e.Reason)
		gc := cfg.Groups[group]
		exs := []Exception{}
		for _, ex := range gc.Exceptions {
			if !strings.EqualFold(ex.User, u.ID) {
				exs = append(exs, ex)
			}
		}
		gc.Exceptions = append(exs, e)
		if e.Include {
			cfg.clearGrace(group, u.ID) // granted again
		}
		return s.saveConfig(cfg)
	})
}

// RemoveException removes user's exception from group (404 if none).
// The group need not exist in LLDAP any more. Admins only.
func (s *Service) RemoveException(ctx context.Context, c *Caller, group, user string) error {
	user = strings.TrimSpace(user)
	detail := "remove user=" + user
	return s.run(ctx, c, permAdmin, "group.exception", group, &detail, func() error {
		if err := s.checkTarget(user); err != nil {
			return err
		}
		cfg, err := s.loadConfig()
		if err != nil {
			return err
		}
		gc := cfg.Groups[group]
		if gc == nil {
			return notFound("%s has no exception for %s", group, user)
		}
		exs := []Exception{}
		found := false
		for _, ex := range gc.Exceptions {
			if strings.EqualFold(ex.User, user) {
				found = true
				detail += fmt.Sprintf(" include=%v until=%s", ex.Include, formatUntil(ex.Until))
			} else {
				exs = append(exs, ex)
			}
		}
		if !found {
			return notFound("%s has no exception for %s", group, user)
		}
		gc.Exceptions = exs
		tidy(cfg, group)
		return s.saveConfig(cfg)
	})
}

// SetMemberExpiry sets (or with nil, removes) when user's membership of
// the manual group ends. Not on lldap_admin (the evaluator would bypass
// the last-admin guardrail). Admins only.
func (s *Service) SetMemberExpiry(ctx context.Context, c *Caller, group, user string, until *time.Time) error {
	user = strings.TrimSpace(user)
	detail := fmt.Sprintf("user=%s until=%s", user, formatUntil(until))
	return s.run(ctx, c, permAdmin, "group.expiry", group, &detail, func() error {
		if err := s.checkTarget(user); err != nil {
			return err
		}
		if group == lldap.AdminGroup {
			return refuse("membership of %s can't expire; remove administrators explicitly", lldap.AdminGroup)
		}
		if until != nil && !until.After(time.Now()) {
			return invalid("the expiry must be in the future")
		}
		cfg, err := s.loadConfig()
		if err != nil {
			return err
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		g, err := sn.group(group)
		if err != nil {
			return err
		}
		u, err := sn.user(user)
		if err != nil {
			return err
		}
		detail = fmt.Sprintf("user=%s until=%s", u.ID, formatUntil(until))
		if ruleBased(cfg, group) {
			return refuse("%s is a rule group: use an exception with an end date instead", group)
		}
		if !memberOf(g, u.ID) {
			return refuse("%s is not a member of %s", u.ID, group)
		}
		gc := cfg.Groups[group]
		if gc == nil {
			gc = &GroupConfig{}
			cfg.Groups[group] = gc
		}
		for k := range gc.Expiry {
			if strings.EqualFold(k, u.ID) {
				delete(gc.Expiry, k)
			}
		}
		if until != nil {
			if gc.Expiry == nil {
				gc.Expiry = map[string]time.Time{}
			}
			gc.Expiry[u.ID] = until.UTC()
		}
		cfg.clearGrace(group, u.ID) // a current member: any grace is stale
		tidy(cfg, group)
		return s.saveConfig(cfg)
	})
}

// SetPermission grants perm to group; "" grants it to nobody. Not to
// built-in or administrator groups, and a rule group only if its rule
// uses admin-only fields. Admins only.
func (s *Service) SetPermission(ctx context.Context, c *Caller, perm, group string) error {
	group = strings.TrimSpace(group)
	detail := "group=" + group
	if group == "" {
		detail = "group=(nobody)"
	}
	return s.run(ctx, c, permAdmin, "permission.set", perm, &detail, func() error {
		if !containsString(delegatedPerms, perm) {
			return invalid("unknown permission %q: use %s", perm, strings.Join(delegatedPerms, ", "))
		}
		cfg, err := s.loadConfig()
		if err != nil {
			return err
		}
		if group == "" {
			delete(cfg.Permissions, perm)
			return s.saveConfig(cfg)
		}
		if builtinGroups[group] || s.adminGroups()[group] {
			return refuse("%s is a built-in or administrator group; grant %s to an ordinary group", group, perm)
		}
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		if _, ok := sn.groups[group]; !ok {
			return refuse("group %q does not exist in LLDAP; create it first", group)
		}
		if ruleBased(cfg, group) {
			if bad := nonAdminOnly(cfg, cfg.Groups[group].Rule); len(bad) > 0 {
				return refuse("%s's rule uses fields that aren't admin-only (%s): a permission group's rule may use only admin-only fields", group, strings.Join(bad, ", "))
			}
			if matchesEmpty(cfg, cfg.Groups[group].Rule) {
				return refuse("%s's rule matches a person with no details at all (e.g. a new account): a permission group's rule must not", group)
			}
		}
		cfg.Permissions[perm] = group
		return s.saveConfig(cfg)
	})
}

// PreviewRule lists, sorted, who rule matches right now. Any signed-in
// caller; read-only, not audited.
func (s *Service) PreviewRule(ctx context.Context, c *Caller, rule *rules.Expr) ([]string, error) {
	if c == nil || strings.TrimSpace(c.User) == "" {
		return nil, errNoActor()
	}
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	if err := checkRule(cfg, rule); err != nil {
		return nil, err
	}
	sn, err := s.previewSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return idsOf(sn, s.matching(cfg, sn, rule)), nil
}

// previewTTL: PreviewRule reuses one LLDAP snapshot for this long (the
// rule editor previews as the admin types); any mutation or evaluation
// change drops it (invalidatePreview).
const previewTTL = 2 * time.Second

// previewSnapshot returns the shared preview snapshot, loading a new one
// when it is older than previewTTL or was invalidated.
func (s *Service) previewSnapshot(ctx context.Context) (*snapshot, error) {
	s.previewMu.Lock()
	defer s.previewMu.Unlock()
	if s.previewSn != nil && time.Since(s.previewAt) < previewTTL {
		return s.previewSn, nil
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	s.previewSn, s.previewAt = sn, time.Now()
	return sn, nil
}

// invalidatePreview drops the preview snapshot.
func (s *Service) invalidatePreview() {
	s.previewMu.Lock()
	s.previewSn = nil
	s.previewMu.Unlock()
}
