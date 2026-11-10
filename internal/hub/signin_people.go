package hub

// Who has which sign-in method (contract §8.1 "Inventory and warnings",
// plan D13, D16): passkeys from Keycloak (credential type → kind),
// YubiKey certificates from enroll, passwords from the Hub's own records.
// A source that fails leaves its methods unknown, and unknown never
// counts: not in the blocked lists, not in the lockout guard. The policy
// file's `people` (page text only) comes from here too.

import (
	"context"
	"errors"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// PersonMethods is one person's set-up sign-in methods, canonical order.
// CertsKnown false: their YubiKey certificates couldn't be read (none
// counted).
type PersonMethods struct {
	User       string          `json:"user"`
	Methods    []signin.Method `json:"methods"`
	CertsKnown bool            `json:"certs_known"`
}

// Inventory is everyone's set-up methods as of At (the last good
// Keycloak read). A person absent from People is not known: no method
// counts for them.
type Inventory struct {
	At     time.Time                `json:"at"`
	People map[string]PersonMethods `json:"people"`
}

// SignInSources are where the inventory comes from (SetSignInSources):
// Keycloak's passkeys (keycloak.Client.SignInCredentials) and enroll's
// certificates (invite.Client.Certificates). nil Passkeys: not known at
// all (the lockout guard answers 503); nil Certificates: certificates
// unknown.
type SignInSources struct {
	Passkeys     func(ctx context.Context) (map[string][]keycloak.PasskeyCredential, error)
	Certificates func(ctx context.Context) ([]invite.CertRecord, error)
}

// SetSignInSources wires the inventory's sources (main: Keycloak and
// enroll). The cached inventory is dropped.
func (h *Hub) SetSignInSources(src SignInSources) {
	c := &h.signInInv
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.src, c.base, c.err, c.tried = src, nil, nil, time.Time{}
}

// inventoryMinAge: an on-demand refresh runs at most once per 30 s (D16).
const inventoryMinAge = 30 * time.Second

// inventoryTimeout bounds one refresh (both sources).
const inventoryTimeout = 20 * time.Second

// inventoryCache is the last refresh. refreshMu serialises refreshes
// (held across the Keycloak and enroll calls, never with h.mu); mu is a
// leaf lock over the fields, taken under h.mu by peopleMethodsLocked.
type inventoryCache struct {
	refreshMu sync.Mutex
	mu        sync.Mutex
	src       SignInSources
	base      *invBase
	err       error     // the last refresh's error (nil: it worked)
	tried     time.Time // when the last refresh ran
	now       func() time.Time
}

// invBase is a refresh's result without the passwords (those are read
// from state.yaml whenever the inventory is used, so a recorded password
// counts at once).
type invBase struct {
	at         time.Time
	passkeys   map[string][]signin.Method // every user Keycloak listed with readable credentials
	certs      map[string]bool            // users with an unexpired, unrevoked YubiKey certificate
	certsKnown bool
}

func (c *inventoryCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// noPasswordAccounts never sign in with a password (the extension's
// password form refuses them, D5/D13): the Hub never counts one.
var noPasswordAccounts = map[string]bool{"admin": true, "portcullis-hub": true}

// errInventoryUnknown: no Keycloak source is wired.
var errInventoryUnknown = errors.New("Keycloak isn't configured")

// SignInInventory is everyone's set-up methods. fresh: refreshed unless
// the last refresh ran less than 30 s ago (its result, or its error, is
// returned then); else the cached inventory, refreshed only when there is
// none yet. An error means Keycloak couldn't be read: nothing is known.
func (h *Hub) SignInInventory(ctx context.Context, fresh bool) (*Inventory, error) {
	base, err := h.inventoryBase(ctx, fresh)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return composeInventory(base, h.st.SignIn.Passwords), nil
}

// inventoryBase is SignInInventory without the passwords.
func (h *Hub) inventoryBase(ctx context.Context, fresh bool) (*invBase, error) {
	c := &h.signInInv
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	base, err, tried, src := c.base, c.err, c.tried, c.src
	c.mu.Unlock()
	now := c.clock()
	recent := !tried.IsZero() && now.Sub(tried) < inventoryMinAge
	switch {
	case fresh && recent, !fresh && base != nil:
		if err != nil && fresh {
			return nil, err
		}
		if base == nil {
			return nil, err
		}
		return base, nil
	case !fresh && recent:
		return nil, err
	}
	base, err = loadInventory(ctx, src, now)
	c.mu.Lock()
	c.tried, c.err = now, err
	if err == nil {
		c.base = base
	}
	c.mu.Unlock()
	if err != nil {
		log.Printf("signin: who has which method is unknown: %v", err)
		return nil, err
	}
	return base, nil
}

// loadInventory reads both sources (no lock held).
func loadInventory(ctx context.Context, src SignInSources, now time.Time) (*invBase, error) {
	if src.Passkeys == nil {
		return nil, errInventoryUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	keys, err := src.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	b := &invBase{at: now.UTC(), passkeys: map[string][]signin.Method{}, certs: map[string]bool{}}
	for u, list := range keys {
		ms := []signin.Method{}
		for _, pk := range list {
			m := signin.Method(pk.Type)
			if _, ok := signin.InfoOf(m); ok && !slices.Contains(ms, m) {
				ms = append(ms, m)
			}
		}
		b.passkeys[strings.ToLower(u)] = ms
	}
	if src.Certificates != nil {
		certs, cerr := src.Certificates(ctx)
		switch {
		case cerr == nil:
			b.certsKnown = true
			for _, r := range certs {
				if !r.Revoked && r.NotAfter.After(now) {
					b.certs[strings.ToLower(r.User)] = true
				}
			}
		case errors.Is(cerr, invite.ErrNoCertAPI):
			log.Printf("signin: enroll has no certificates API: YubiKey certificates are unknown (they never count)")
		default:
			log.Printf("signin: YubiKey certificates are unknown (they never count): %v", cerr)
		}
	}
	return b, nil
}

// composeInventory is base plus the Hub's password records (never for
// noPasswordAccounts).
func composeInventory(b *invBase, passwords map[string]state.PasswordRecord) *Inventory {
	inv := &Inventory{At: b.at, People: map[string]PersonMethods{}}
	have := map[string]map[signin.Method]bool{}
	add := func(u string, m signin.Method) {
		if have[u] == nil {
			have[u] = map[signin.Method]bool{}
		}
		if m != "" {
			have[u][m] = true
		}
	}
	for u, ms := range b.passkeys {
		add(u, "")
		for _, m := range ms {
			add(u, m)
		}
	}
	for u := range b.certs {
		add(u, signin.YubiKeyCert)
	}
	for u := range passwords {
		if lu := strings.ToLower(u); !noPasswordAccounts[lu] {
			add(lu, signin.Password)
		}
	}
	for u, set := range have {
		pm := PersonMethods{User: u, Methods: []signin.Method{}, CertsKnown: b.certsKnown}
		for _, m := range signin.Methods {
			if set[m] {
				pm.Methods = append(pm.Methods, m)
			}
		}
		inv.People[u] = pm
	}
	return inv
}

// peopleMethodsLocked is each known person's switched-on set-up methods
// (the policy file's people, page text only); nil = not known, nobody
// listed. Caller holds mu (takes the inventory's leaf lock).
func (h *Hub) peopleMethodsLocked() map[string][]signin.Method {
	c := &h.signInInv
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	if base == nil {
		return nil
	}
	on := h.st.SignIn.MethodsOn()
	out := map[string][]signin.Method{}
	for u, pm := range composeInventory(base, h.st.SignIn.Passwords).People {
		ms := []signin.Method{}
		for _, m := range pm.Methods {
			if on[m] {
				ms = append(ms, m)
			}
		}
		out[u] = ms
	}
	return out
}

// methodPeopleLocked is how many known people have each method set up:
// -1 while unknown (no inventory; yubikey_cert while certificates are
// unknown). Caller holds mu.
func (h *Hub) methodPeopleLocked() map[signin.Method]int {
	out := map[signin.Method]int{}
	c := &h.signInInv
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	for _, m := range signin.Methods {
		out[m] = -1
	}
	if base == nil {
		return out
	}
	for _, m := range signin.Methods {
		out[m] = 0
	}
	if !base.certsKnown {
		out[signin.YubiKeyCert] = -1
	}
	for _, pm := range composeInventory(base, h.st.SignIn.Passwords).People {
		for _, m := range pm.Methods {
			if out[m] >= 0 {
				out[m]++
			}
		}
	}
	return out
}

// ── warnings ─────────────────────────────────────────────

// blockedWhy says what a blocked person has: "no method yet", or their
// methods' short names, "password + synced passkey only".
func blockedWhy(ms []signin.Method) string {
	if len(ms) == 0 {
		return "no method yet"
	}
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		info, _ := signin.InfoOf(m)
		names = append(names, info.Short)
	}
	return strings.Join(names, " + ") + " only"
}

// blockedFor lists, sorted, the users who can't meet compiled with the
// methods they have set up that are switched on (on); a person the
// inventory doesn't know (or a nil inventory) has none (unknown never
// counts).
func blockedFor(inv *Inventory, users []string, compiled signin.Node, on map[signin.Method]bool) []Blocked {
	out := []Blocked{}
	seen := map[string]bool{}
	for _, u := range slices.Sorted(slices.Values(users)) {
		u = strings.ToLower(u)
		if seen[u] {
			continue
		}
		seen[u] = true
		var ms []signin.Method
		if inv != nil {
			ms = inv.People[u].Methods
		}
		have := map[signin.Method]bool{}
		for _, m := range ms {
			if on[m] {
				have[m] = true
			}
		}
		if !signin.Satisfied(compiled, have) {
			out = append(out, Blocked{User: u, Why: blockedWhy(ms)})
		}
	}
	return out
}

// unexpiredMembers is group g's members in m without expired memberships.
func unexpiredMembers(m *directory.Membership, g string) []string {
	var out []string
	for _, u := range m.Groups[g].Members {
		if !m.Expired[u][g] {
			out = append(out, u)
		}
	}
	return out
}

// instanceSignInUsers are the people instance t's template applies to:
// the unexpired members of its access and admin groups (every user when
// it has no access group).
func instanceSignInUsers(t *templates.Template, m *directory.Membership) []string {
	var out []string
	if g := accessGroupOf(t); g == "" {
		out = slices.Collect(maps.Keys(m.Users))
	} else {
		out = unexpiredMembers(m, g)
	}
	if a := t.Manifest.Auth.AdminGroup; a != "" && t.Stamped {
		out = append(out, unexpiredMembers(m, a)...)
	}
	return out
}

// coreSignInUsers are the people core page key's template applies to:
// lldap_admin for the consoles, everyone for the portal and people.
func coreSignInUsers(key string, m *directory.Membership) []string {
	switch key {
	case "people", "portal":
		return slices.Collect(maps.Keys(m.Users))
	}
	return unexpiredMembers(m, lldap.AdminGroup)
}

// TemplateChoice is a template an instance can pick.
type TemplateChoice struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Sentence string       `json:"sentence"`
	Score    signin.Score `json:"score"`
	Default  bool         `json:"default"`
}

// InstanceSignInView is an instance's Settings → sign-in part (GET
// /api/instances/{id}/signin): its template (own pick, else the
// default: Inherits), what it can pick, and who can't meet it.
// TakesTemplate false: the app has no Portcullis sign-in template (its
// own login, a client certificate or no sign-in), nothing else is set.
// PeopleUnknown says why Blocked couldn't be worked out ("" = it was).
type InstanceSignInView struct {
	Instance      string           `json:"instance"`
	Name          string           `json:"name"`
	TakesTemplate bool             `json:"takes_template"`
	Template      string           `json:"template"`
	Inherits      bool             `json:"inherits"`
	Default       string           `json:"default"`
	Choices       []TemplateChoice `json:"choices"`
	Blocked       []Blocked        `json:"blocked"`
	PeopleUnknown string           `json:"people_unknown,omitempty"`
}

// signInPeople is the membership and inventory the warnings need, read
// outside mu; why is "" when both were read.
func (h *Hub) signInPeople(ctx context.Context) (*directory.Membership, *Inventory, string) {
	m, err := h.membership(ctx)
	if err != nil {
		return nil, nil, "Users & Groups can't be read: " + err.Error()
	}
	inv, err := h.SignInInventory(ctx, false)
	if err != nil {
		return m, nil, "the sign-in methods people have set up can't be read: " + err.Error()
	}
	return m, inv, ""
}

// InstanceSignIn is instance id's sign-in view: 404 for an unknown
// instance.
func (h *Hub) InstanceSignIn(ctx context.Context, id string) (*InstanceSignInView, error) {
	h.mu.RLock()
	known := h.findLocked(id) != nil
	h.mu.RUnlock()
	if !known {
		return nil, statusErr(http.StatusNotFound, "no instance %s", clip(id, 64))
	}
	m, inv, why := h.signInPeople(ctx)
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if t == nil {
		return nil, statusErr(http.StatusNotFound, "no instance %s", clip(id, 64))
	}
	si := h.st.SignIn
	on := si.MethodsOn()
	v := &InstanceSignInView{Instance: id, Name: instanceName(t), Default: si.Default, Choices: []TemplateChoice{}, Blocked: []Blocked{}}
	acc := h.accessLocked(t)
	if !acc.Capability.Templates {
		return v, nil
	}
	v.TakesTemplate, v.Template, v.Inherits = true, acc.Template, acc.Inherits
	for _, tid := range templateOrder(si) {
		tm := si.Templates[tid]
		if _, ok := compiledIn(si, tid); !ok {
			continue
		}
		sentence, score, _ := describeRule(tm.Rule, on)
		v.Choices = append(v.Choices, TemplateChoice{ID: tid, Name: tm.Name, Sentence: sentence, Score: score, Default: tid == si.Default})
	}
	switch {
	case why != "":
		v.PeopleUnknown = why
	case acc.Rule == nil:
		// Unpublishable: nobody gets in (fail closed).
		v.Blocked = blockedFor(inv, instanceSignInUsers(t, m), signin.Node{}, on)
	default:
		v.Blocked = blockedFor(inv, instanceSignInUsers(t, m), *acc.Rule, on)
	}
	return v, nil
}

// affectedLocked lists the apps and core pages that use template id under
// si (enabled instances that take a template, explicitly or through the
// default; core pages) whose people can't all meet compiled. Caller holds
// mu.
func (h *Hub) affectedLocked(si state.SignIn, id string, compiled signin.Node, m *directory.Membership, inv *Inventory) []AffectedApp {
	out := []AffectedApp{}
	on := si.MethodsOn()
	for _, k := range state.CoreSignInKeys {
		pick := si.Core[k]
		if pick == "" {
			pick = si.Default
		}
		if pick != id {
			continue
		}
		if b := blockedFor(inv, coreSignInUsers(k, m), compiled, on); len(b) > 0 {
			out = append(out, AffectedApp{Kind: UseCore, Instance: k, Name: coreSignInLabels[k], Blocked: b})
		}
	}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		acc := h.accessWith(t, si, h.st.Instances[t.ID].SignInTemplate, h.st.SignInMode[t.ID])
		if !acc.Capability.Templates || acc.Template != id {
			continue
		}
		if b := blockedFor(inv, instanceSignInUsers(t, m), compiled, on); len(b) > 0 {
			out = append(out, AffectedApp{Kind: UseInstance, Instance: t.ID, Name: instanceName(t), Blocked: b})
		}
	}
	return out
}

// ── password records ─────────────────────────────────────

// RecordPassword records that actor set user's LLDAP password through the
// Hub (directory.Service.PasswordSet; D13: only these count). The
// bootstrap admin and the service account are never recorded (password
// sign-in is refused for them). Never given the password.
func (h *Hub) RecordPassword(user, actor string) error {
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "" || noPasswordAccounts[u] {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, had := h.st.SignIn.Passwords[u]
	if h.st.SignIn.Passwords == nil {
		h.st.SignIn.Passwords = map[string]state.PasswordRecord{}
	}
	h.st.SignIn.Passwords[u] = state.PasswordRecord{SetAt: h.signInInv.clock().UTC(), SetBy: actor}
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.SignIn.Passwords[u] = prev
		} else {
			delete(h.st.SignIn.Passwords, u)
		}
		return err
	}
	return nil
}

// forgetPassword drops user's password record (the account was deleted:
// a new account under the name has no Hub-set password).
func (h *Hub) forgetPassword(user string) []string {
	u := strings.ToLower(user)
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, ok := h.st.SignIn.Passwords[u]
	if !ok {
		return nil
	}
	delete(h.st.SignIn.Passwords, u)
	if err := h.saveStateLocked(); err != nil {
		h.st.SignIn.Passwords[u] = prev
		return []string{"forgetting " + u + "'s password record failed: " + err.Error()}
	}
	return nil
}

// ── refresh with the directory sync ──────────────────────

// TriggerInventoryRefresh asks runInventorySync for a refresh soon
// (non-blocking, coalesced; RunDirectorySync calls it after every policy
// write).
func (h *Hub) TriggerInventoryRefresh() {
	select {
	case h.invKick <- struct{}{}:
	default:
	}
}

// runInventorySync refreshes the inventory on each kick, at most once per
// inventoryMinAge (a kick inside it waits for the rest), and rewrites the
// policy file when the published people changed. It never delays a
// policy write: the directory sync only kicks it.
func (h *Hub) runInventorySync(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.invKick:
		}
		c := &h.signInInv
		c.mu.Lock()
		tried := c.tried
		c.mu.Unlock()
		if wait := inventoryMinAge - c.clock().Sub(tried); !tried.IsZero() && wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		h.mu.RLock()
		before := h.peopleMethodsLocked()
		h.mu.RUnlock()
		if _, err := h.inventoryBase(ctx, true); err != nil {
			continue
		}
		h.mu.RLock()
		after := h.peopleMethodsLocked()
		h.mu.RUnlock()
		if !maps.EqualFunc(before, after, slices.Equal) || (before == nil) != (after == nil) {
			h.writePolicyLogged()
		}
	}
}

// PasswordMethodOn reports whether the password sign-in method is switched
// on (directory.Service.PasswordMethodOn: password onboarding is refused
// while it is off).
func (h *Hub) PasswordMethodOn() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.SignIn.MethodsOn()[signin.Password]
}
