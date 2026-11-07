package directory

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/rules"
)

// Delegated permissions (Config.Permissions maps each to a group). Holders
// are "delegates": they may run the matching operations on ordinary users
// only. Everything else is for administrators (lldap_admin members).
const (
	PermEditDetails = "edit_details" // UpdateUser (email, display name)
	PermInvite      = "invite"       // CreateUser (invite, no groups), SendInvite
	PermRemove      = "remove"       // DeleteUser
	// permAdmin marks an operation as admins only; it is never granted
	// through Config.Permissions.
	permAdmin = "admin"
)

// delegatedPerms are the only permissions Config.Permissions can grant.
var delegatedPerms = []string{PermEditDetails, PermInvite, PermRemove}

// Caller is who is making a request, resolved once per request by
// CallerFor. Admin: member of lldap_admin. Perms: the delegated
// permissions whose group they are in. Via / Client: the AI attribution
// (Actor), set only by CallerAs from the MCP listener's identity.
type Caller struct {
	User   string
	Admin  bool
	Perms  map[string]bool
	Via    string
	Client string
	// Confirmation: the confirmation a Portcullis MCP class-D call
	// consumed (Actor.Confirmation; set only by CallerAs).
	Confirmation string
}

// Actor is who an audited change is attributed to: the person (User, the
// LLDAP username) and, for changes made through the Portcullis MCP, Via
// ViaAI and Client (the AI client, the token's azp). Stored or displayed
// actors (op records, created_by, logs) use User only.
type Actor struct {
	User, Via, Client string
	// Confirmation is the id of the confirmation a Portcullis MCP class-D
	// call consumed (§15.6), set only on that tool path: every audit
	// entry of the call carries "confirmation <id>" in its detail
	// (AuditDetail). Never part of the attribution checks.
	Confirmation string
}

// AuditDetail is detail as a's audit entry holds it: with
// "confirmation <id>" appended when a carries a consumed confirmation.
func (a Actor) AuditDetail(detail string) string {
	if a.Confirmation == "" {
		return detail
	}
	if detail == "" {
		return "confirmation " + a.Confirmation
	}
	return detail + "; confirmation " + a.Confirmation
}

// ViaAI is Actor.Via / AuditEntry.Via for changes made through the AI.
const ViaAI = "ai"

// Human is the actor of a request made by a person in a browser (or the
// Hub itself): no AI attribution.
func Human(user string) Actor { return Actor{User: user} }

// Actor returns c's attribution (zero for a nil Caller).
func (c *Caller) Actor() Actor {
	if c == nil {
		return Actor{}
	}
	return Actor{User: c.User, Via: c.Via, Client: c.Client, Confirmation: c.Confirmation}
}

// Check refuses (403) an actor without a user, a Via other than "" or
// ViaAI, an AI actor without a client and a client without Via.
func (a Actor) Check() error {
	switch {
	case strings.TrimSpace(a.User) == "":
		return errNoActor()
	case a.Via != "" && a.Via != ViaAI:
		return forbidden("unknown attribution via %q", clip(a.Via))
	case a.Via == ViaAI && strings.TrimSpace(a.Client) == "":
		return forbidden("an AI change without its AI client — refusing an unattributable change")
	case a.Via == "" && a.Client != "":
		return forbidden("an AI client without via ai — refusing a mis-attributed change")
	}
	return nil
}

func forbidden(format string, a ...interface{}) error {
	return &Error{Status: http.StatusForbidden, Msg: fmt.Sprintf(format, a...)}
}

func errNoActor() error {
	return forbidden("no signed-in user (X-Forwarded-User) — refusing an unattributable change")
}

func memberOf(g lldap.Group, user string) bool {
	for _, m := range g.Members() {
		if strings.EqualFold(m, user) {
			return true
		}
	}
	return false
}

// CallerFor resolves user (X-Forwarded-User) against LLDAP and
// directory.yaml. An empty user is refused (403); a user LLDAP doesn't
// know gets no permissions. Without a Store nobody holds a delegated
// permission (admins are unaffected).
func (s *Service) CallerFor(ctx context.Context, user string) (*Caller, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, errNoActor()
	}
	c := &Caller{User: user, Perms: map[string]bool{}}
	if err := s.LLDAP.Available(); err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	sn, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := sn.users[strings.ToLower(user)]; !ok {
		return c, nil
	}
	c.Admin = memberOf(sn.groups[lldap.AdminGroup], user)
	if c.Admin || s.Store == nil {
		return c, nil
	}
	cfg, err := s.Store.Load()
	if err != nil {
		return nil, &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
	}
	for _, p := range delegatedPerms {
		if g, ok := sn.groups[cfg.Permissions[p]]; ok && cfg.Permissions[p] != "" && memberOf(g, user) {
			c.Perms[p] = true
		}
	}
	return c, nil
}

// CallerAs is CallerFor for an Actor (the MCP listener's identity): the
// permissions are resolved from a.User exactly as CallerFor does, and the
// Caller keeps a.Via / a.Client so every audit entry of the request is
// attributed to the AI client. An invalid actor is refused (Actor.Check).
func (s *Service) CallerAs(ctx context.Context, a Actor) (*Caller, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	c, err := s.CallerFor(ctx, a.User)
	if err != nil {
		return nil, err
	}
	c.Via, c.Client, c.Confirmation = a.Via, a.Client, a.Confirmation
	return c, nil
}

// gate is the authorization step of every mutation (called by run, inside
// the lock and the audited section). The Caller was resolved before the
// lock, so admin membership and delegated permissions are re-checked
// against a fresh snapshot (a just-demoted admin is refused).
func (s *Service) gate(ctx context.Context, c *Caller, perm, target string) error {
	if c.Admin {
		sn, err := s.load(ctx)
		if err != nil {
			return err
		}
		if !memberOf(sn.groups[lldap.AdminGroup], c.User) {
			return forbidden("not allowed: admins only (%s is no longer in %s)", c.User, lldap.AdminGroup)
		}
		return nil
	}
	if perm == permAdmin || !c.Perms[perm] {
		return s.authorize(c, perm, target, nil, nil)
	}
	sn, err := s.load(ctx)
	if err != nil {
		return err
	}
	cfg := &Config{}
	if s.Store != nil {
		if cfg, err = s.Store.Load(); err != nil {
			return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml: " + err.Error()}
		}
	}
	// The Caller was resolved before the lock: confirm the permission
	// still holds against this snapshot.
	if g, ok := sn.groups[cfg.Permissions[perm]]; !ok || !memberOf(g, c.User) {
		return forbidden("not allowed: needs %s", perm)
	}
	return s.authorize(c, perm, target, sn, cfg)
}

// CheckDelegate is gate's decision for perm on target, read only (no
// lock, no audit, nothing changed): nil when c may run the operation
// now, else the refusal the operation itself would answer (403). The
// Portcullis MCP's delegate tools ask it before a confirmation, so a
// refused target never gets one; the operation still runs gate itself.
// perm must be a delegated permission.
func (s *Service) CheckDelegate(ctx context.Context, c *Caller, perm, target string) error {
	if c == nil {
		return errNoActor()
	}
	if !slices.Contains(delegatedPerms, perm) {
		return forbidden("not allowed: admins only")
	}
	if err := s.LLDAP.Available(); err != nil {
		return &Error{Status: http.StatusServiceUnavailable, Msg: err.Error()}
	}
	if err := s.gate(ctx, c, perm, target); err != nil {
		return err
	}
	return s.checkTarget(target)
}

// authorize decides whether c may run an operation needing perm on the
// user target. perm "admin" means admins only. A delegate never targets
// themselves, the protected accounts, administrators or members of any
// permission group. sn and cfg may be nil only when no target check is
// reached (admin, or a missing permission).
func (s *Service) authorize(c *Caller, perm, target string, sn *snapshot, cfg *Config) error {
	switch {
	case c.Admin:
		return nil
	case perm == permAdmin:
		return forbidden("not allowed: admins only")
	case !c.Perms[perm]:
		return forbidden("not allowed: needs %s", perm)
	case sn == nil || cfg == nil:
		return forbidden("not allowed: can't check %s", target)
	}
	return s.checkDelegateTarget(c, target, sn, cfg)
}

// checkDelegateTarget is checkTarget for delegates: on top of the
// protected accounts, administrators, permission-group members and the
// caller themselves are admins only.
func (s *Service) checkDelegateTarget(c *Caller, target string, sn *snapshot, cfg *Config) error {
	target = strings.TrimSpace(target)
	switch {
	case target == "":
		return forbidden("not allowed: no target user")
	case strings.EqualFold(target, c.User):
		return forbidden("not allowed: you can't do this to your own account; ask an administrator")
	case s.checkTarget(target) != nil:
		return forbidden("not allowed: %s is a protected account (admins only)", target)
	case s.isAdmin(sn, target) || memberOf(sn.groups[lldap.AdminGroup], target) || memberOf(sn.groups["lldap_password_manager"], target):
		return forbidden("not allowed: %s is an administrator (admins only)", target)
	}
	for _, g := range cfg.Permissions {
		if g != "" && memberOf(sn.groups[g], target) {
			return forbidden("not allowed: %s holds a delegated permission (member of %s; admins only)", target, g)
		}
	}
	return nil
}

// checkKeyless: a delegate may invite only someone with no Keycloak
// credential of any type (password, OTP, passkey, ...) — an invite for an
// account that can already sign in would hand the delegate that account.
// Keycloak missing or failing refuses (fail closed). Admins aren't
// limited. Client certificates aren't Keycloak credentials: see the
// CLAUDE.md permissions rule.
func (s *Service) checkKeyless(ctx context.Context, c *Caller, user string) error {
	if c.Admin {
		return nil
	}
	if s.KC == nil {
		return forbidden("not allowed: Keycloak admin API not configured, so %s's credentials can't be checked; ask an administrator", user)
	}
	n, err := s.KC.CredentialCount(ctx, user)
	if err != nil {
		return forbidden("not allowed: couldn't check %s's credentials (%v); ask an administrator", user, err)
	}
	if n > 0 {
		return forbidden("not allowed: %s already has sign-in credentials; only an admin can send them an invite", user)
	}
	return nil
}

// namedInGroups returns a group whose exceptions or expiries name user
// ("" if none).
func namedInGroups(cfg *Config, user string) string {
	for name, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		for _, ex := range gc.Exceptions {
			if strings.EqualFold(ex.User, user) {
				return name
			}
		}
		for u := range gc.Expiry {
			if strings.EqualFold(u, user) {
				return name
			}
		}
	}
	return ""
}

// purgeUser drops user from every group's exceptions and expiries, from
// CreatedBy and from Grace, so an account with that name inherits nothing; it
// returns what was removed (for warnings and audit), sorted.
func purgeUser(cfg *Config, user string) []string {
	var out []string
	for name, gc := range cfg.Groups {
		if gc == nil {
			continue
		}
		kept := gc.Exceptions[:0]
		for _, ex := range gc.Exceptions {
			if strings.EqualFold(ex.User, user) {
				out = append(out, "exception in "+name)
			} else {
				kept = append(kept, ex)
			}
		}
		gc.Exceptions = kept
		for u := range gc.Expiry {
			if strings.EqualFold(u, user) {
				delete(gc.Expiry, u)
				out = append(out, "expiry in "+name)
			}
		}
	}
	for u := range cfg.CreatedBy {
		if strings.EqualFold(u, user) {
			delete(cfg.CreatedBy, u)
			out = append(out, "created_by")
		}
	}
	kept := cfg.Grace[:0:0]
	for _, g := range cfg.Grace {
		if strings.EqualFold(g.User, user) {
			out = append(out, "grace in "+g.Group)
		} else {
			kept = append(kept, g)
		}
	}
	cfg.Grace = kept
	sort.Strings(out)
	return out
}

// clearCreatedBy: an admin acted on user's sign-in (password, invite,
// passkeys), so the account is no longer "created by a delegate, never
// used" and delegates can't re-invite it any more. Saved before the
// action (fail closed: 503 if it can't be). Store nil or delegates: no-op.
func (s *Service) clearCreatedBy(c *Caller, user string) error {
	if !c.Admin || s.Store == nil {
		return nil
	}
	cfg, err := s.Store.Load()
	if err == nil {
		found := false
		for u := range cfg.CreatedBy {
			if strings.EqualFold(u, user) {
				delete(cfg.CreatedBy, u)
				found = true
			}
		}
		if !found {
			return nil
		}
		err = s.Store.Save(cfg)
	}
	if err != nil {
		return &Error{Status: http.StatusServiceUnavailable, Msg: "directory.yaml (created_by): " + err.Error()}
	}
	return nil
}

// emailTaken returns the user (other than self) whose email is email.
func emailTaken(sn *snapshot, email, self string) string {
	for _, u := range sn.users {
		if !strings.EqualFold(u.ID, self) && strings.EqualFold(strings.TrimSpace(u.Email), strings.TrimSpace(email)) {
			return u.ID
		}
	}
	return ""
}

// referencesTo lists what still names user after the account is gone:
// other people whose person fields hold user, and rules that name user in
// reports-to or in a person-field comparison (they now match nobody
// through user). Sorted; for the delete warning.
func referencesTo(cfg *Config, sn *snapshot, user string) []string {
	person := map[string]bool{}
	for _, f := range cfg.Fields {
		if f.Kind == FieldKindPerson && !reservedAttr(f.Name) {
			person[f.Name] = true
		}
	}
	var out []string
	for _, u := range sn.users {
		if strings.EqualFold(u.ID, user) {
			continue
		}
		for name := range person {
			for _, v := range u.Attributes[name] {
				if strings.EqualFold(v, user) {
					out = append(out, fmt.Sprintf("%s of %s", name, u.ID))
				}
			}
		}
	}
	for name, gc := range cfg.Groups {
		if gc == nil || gc.Rule == nil {
			continue
		}
		var names func(e *rules.Expr) bool
		names = func(e *rules.Expr) bool {
			if e.Op == rules.OpReportsTo || person[e.Field] {
				for _, v := range e.Values {
					if strings.EqualFold(v, user) {
						return true
					}
				}
			}
			for _, it := range e.Items {
				if names(it) {
					return true
				}
			}
			return false
		}
		if names(gc.Rule) {
			out = append(out, "rule of "+name)
		}
	}
	sort.Strings(out)
	return out
}
