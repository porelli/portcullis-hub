package hub

// The admin lockout guard (contract §8.1 "Lockout guard", plan D17): a
// Settings → Sign-in save that would take the number of unexpired
// lldap_admin members who can meet the Hub's compiled template from more
// than 0 to 0 is refused; at 0 already it goes through with a warning.
// Recovery is the CLI's `signin reset-core` (internal/signinreset).

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// noAdminWarning is the warning of a save made while no administrator
// can meet the Hub's template.
const noAdminWarning = "No administrator can meet the Hub's template"

// hubTemplateIn is the Hub's own template under si: its core pick, else
// the default.
func hubTemplateIn(si state.SignIn) string {
	if id := si.Core["hub"]; id != "" {
		return id
	}
	return si.Default
}

// lockoutCheck is the guard for a change from section before to after
// (never under mu: it reads Keycloak, enroll and LLDAP). When whoever
// meets the Hub's template before still meets it after (signin.Implies),
// nobody can lose the Hub and nothing is read. Otherwise the inventory
// (fresh, at most 30 s old) and the membership are read: unreadable =
// 503; unknown methods never count.
func (h *Hub) lockoutCheck(ctx context.Context, before, after state.SignIn) (warning string, err error) {
	bID, aID := hubTemplateIn(before), hubTemplateIn(after)
	bRule, bOK := compiledIn(before, bID)
	aRule, aOK := compiledIn(after, aID)
	if bOK && aOK && signin.Implies(bRule, aRule) {
		return "", nil
	}
	inv, err := h.SignInInventory(ctx, true)
	if err != nil {
		return "", statusErr(http.StatusServiceUnavailable, "the change can't be checked: who can still sign in to the Hub is unknown (%v); try again once Keycloak is reachable", err)
	}
	m, err := h.membership(ctx)
	if err != nil {
		return "", statusErr(http.StatusServiceUnavailable, "the change can't be checked: the administrators can't be read from Users & Groups (%v); try again", err)
	}
	admins := unexpiredMembers(m, lldap.AdminGroup)
	able := func(si state.SignIn, rule signin.Node, ok bool) (int, []Blocked) {
		if !ok {
			return 0, blockedFor(inv, admins, signin.Node{}, si.MethodsOn())
		}
		blocked := blockedFor(inv, admins, rule, si.MethodsOn())
		return len(admins) - len(blocked), blocked
	}
	nBefore, _ := able(before, bRule, bOK)
	nAfter, blocked := able(after, aRule, aOK)
	switch {
	case nAfter > 0:
		return "", nil
	case nBefore == 0:
		return noAdminWarning, nil
	}
	name := aID
	if t, ok := after.Templates[aID]; ok {
		name = t.Name
	}
	who := make([]string, len(blocked))
	for i, b := range blocked {
		who[i] = b.User + " (" + b.Why + ")"
	}
	return "", statusErr(http.StatusConflict, "this change would leave no administrator able to sign in to the Hub: none of them can meet %q afterwards — %s; set up a method it accepts first (recovery: ./portcullis signin reset-core)", name, strings.Join(who, ", "))
}

// lockoutWarnings is a guard warning as a SignInChange warning list entry.
func lockoutWarnings(w string) []string {
	if w == "" {
		return nil
	}
	return []string{fmt.Sprintf("%s: set up a method it accepts for an administrator, or recover with ./portcullis signin reset-core", w)}
}
