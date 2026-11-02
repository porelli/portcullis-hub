package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Access role (contract §8): native-OIDC instances whose app can't
// restrict sign-in to the access group (templates.Manifest.
// AccessRoleEnforced) get it enforced in Keycloak. Enable sets it up (and
// refuses to start the app if it can't); SyncClientAccess keeps every
// enabled instance consistent (directory changes, a periodic pass — the
// access group may be created after the instance, core may rebuild its
// browser flow); RemoveInstanceAccess undoes it on delete.

// instanceHosts are t's hosts, sorted (keycloak MayReconcile).
func instanceHosts(t *templates.Template) []string {
	hosts := make([]string, 0, len(t.Hosts))
	for _, h := range t.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func accessSpec(t *templates.Template, c templates.KeycloakClient) keycloak.AccessSpec {
	return keycloak.AccessSpec{ClientID: c.ClientID, TemplateID: t.ID, AllowedHosts: instanceHosts(t), Group: t.Manifest.Auth.AccessGroup}
}

// ensureAccess sets up the access role of every client of t, if t's
// template needs it. A missing access group is logged (fail closed: the
// client denies everybody until it exists, and the sync maps it then);
// anything else is a StatusError (409 for a foreign client, else 502).
func (h *Hub) ensureAccess(ctx context.Context, t *templates.Template) error {
	if h.idp == nil || !t.Manifest.AccessRoleEnforced() {
		return nil
	}
	for _, c := range t.Manifest.Clients {
		err := h.idp.EnsureClientAccess(ctx, accessSpec(t, c))
		var conflict *keycloak.ConflictError
		switch {
		case err == nil:
		case errors.Is(err, keycloak.ErrGroupNotFound):
			log.Printf("Warning: instance %s: %v", t.ID, err)
		case errors.As(err, &conflict):
			return &StatusError{Status: 409, Err: err}
		default:
			return &StatusError{Status: 502, Err: fmt.Errorf("Keycloak: restricting sign-in to client %s to group %s failed — not starting an app anyone could sign in to: %w", c.ClientID, t.Manifest.Auth.AccessGroup, err)}
		}
	}
	return nil
}

// RemoveInstanceAccess removes the access role, its group mapping and the
// access flow binding of every client of instance view t (guarded delete,
// contract §11.4 step 4: call it before or after deleting the clients —
// it unbinds the flow before deleting the role and deletes the Hub's
// access flows either way). Idempotent; a client the instance doesn't
// own is left alone.
func (h *Hub) RemoveInstanceAccess(ctx context.Context, t *templates.Template) error {
	if h.idp == nil {
		return nil
	}
	var errs []error
	for _, c := range t.Manifest.Clients {
		if err := h.idp.RemoveClientAccess(ctx, c.ClientID, t.ID, instanceHosts(t)); err != nil {
			errs = append(errs, fmt.Errorf("client %s: %w", c.ClientID, err))
		}
	}
	return errors.Join(errs...)
}

// SyncClientAccess makes every enabled instance's Keycloak clients match
// its template: the access role set up where AccessRoleEnforced, removed
// where not (a template that no longer needs it). An instance with a
// lifecycle operation in progress is skipped this round (reported, so the
// caller retries). Errors are joined. A missing access group is only
// logged: the client denies everybody meanwhile (fail closed), and the
// group appearing is a directory change (or the periodic pass) that runs
// the sync again — it is no reason for the caller's quick retry (an LDAP
// group sync each time).
func (h *Hub) SyncClientAccess(ctx context.Context) error {
	if h.idp == nil {
		return nil
	}
	h.mu.RLock()
	var views []templates.Template
	for _, id := range h.st.Enabled {
		if e, ok := h.st.Instances[id]; ok && e.State == state.InstanceDeleting {
			continue
		}
		if t := h.findLocked(id); t != nil {
			views = append(views, *t)
		}
	}
	h.mu.RUnlock()
	var errs []error
	var callbacks []string
	for i := range views {
		t := &views[i]
		unlock, err := h.lockApp(t.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("instance %s: busy, access role sync skipped", t.ID))
			continue
		}
		// Re-read under the lock: it may have been disabled or deleted.
		h.mu.RLock()
		cur := h.findLocked(t.ID)
		still := cur != nil && h.st.IsEnabled(t.ID)
		if still {
			*t = *cur
		}
		h.mu.RUnlock()
		if still {
			h.mu.RLock()
			callbacks = append(callbacks, callbackURIs(h.signInExtraHostsLocked(t))...)
			h.mu.RUnlock()
			for _, c := range t.Manifest.Clients {
				var err error
				if t.Manifest.AccessRoleEnforced() {
					err = h.idp.EnsureClientAccess(ctx, accessSpec(t, c))
				} else {
					err = h.idp.RemoveClientAccess(ctx, c.ClientID, t.ID, instanceHosts(t))
				}
				switch {
				case errors.Is(err, keycloak.ErrGroupNotFound):
					log.Printf("Warning: instance %s: %v", t.ID, err)
				case err != nil:
					errs = append(errs, fmt.Errorf("instance %s: %w", t.ID, err))
				}
			}
		}
		unlock()
	}
	// The running instances' extra-domain sign-in callbacks (contract §5)
	// are re-asserted too: core's keycloak configure may reset the
	// portcullis-forward-auth client's redirect URIs.
	if len(callbacks) > 0 {
		if err := h.idp.UpdateForwardAuthCallbacks(ctx, callbacks, nil); err != nil {
			errs = append(errs, fmt.Errorf("%s callbacks: %w", keycloak.ForwardAuthClient, err))
		}
	}
	return errors.Join(errs...)
}
