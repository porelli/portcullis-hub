package hub

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sort"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
)

// DirectoryState returns what the policy writer publishes from the
// directory: the pending membership expiries (contract §4 expiring) and the
// user-attributes.json document (§4.1; nil: no file). An error makes the
// writer keep the last published expiries and the existing attributes file
// (fail closed).
type DirectoryState func(ctx context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error)

// directoryStateTimeout bounds one DirectoryState call.
const directoryStateTimeout = 30 * time.Second

// SetDirectory wires the directory into the Hub: state feeds WritePolicy,
// attrSync (Keycloak attribute mappers, may be nil) runs after each
// directory-triggered policy write. Call before Init and RunDirectorySync.
func (h *Hub) SetDirectory(state DirectoryState, attrSync func(ctx context.Context) error) {
	h.policyWriteMu.Lock()
	defer h.policyWriteMu.Unlock()
	h.dirState, h.attrSync = state, attrSync
}

// directoryState runs the hook for WritePolicy (caller holds
// policyWriteMu). keepAttrs: leave user-attributes.json as it is.
func (h *Hub) directoryState() (expiring []policy.Expiring, attrs *policy.UserAttributesDocument, keepAttrs bool) {
	if h.dirState == nil {
		return []policy.Expiring{}, nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), directoryStateTimeout)
	defer cancel()
	exp, attrs, err := h.dirState(ctx)
	if err != nil {
		log.Printf("auth-policy: directory unavailable, keeping the last published membership expiries and user attributes: %v", err)
		return h.publishedExpiring(), nil, true
	}
	return normalizeExpiring(exp), attrs, false
}

// publishedExpiring is the expiring list last written: in memory, else
// from the policy file on disk (after a restart), else empty.
func (h *Hub) publishedExpiring() []policy.Expiring {
	if h.lastExpiring != nil {
		return h.lastExpiring
	}
	var doc struct {
		Expiring []policy.Expiring `json:"expiring"`
	}
	if b, err := os.ReadFile(h.policyPath()); err == nil && json.Unmarshal(b, &doc) == nil && doc.Expiring != nil {
		return doc.Expiring
	}
	return []policy.Expiring{}
}

// normalizeExpiring keeps one entry per (user, group): the earliest. Sorted
// by (at, group, user); never nil.
func normalizeExpiring(in []policy.Expiring) []policy.Expiring {
	type key struct{ user, group string }
	earliest := map[key]policy.Expiring{}
	at := map[key]time.Time{}
	for _, e := range in {
		t, err := time.Parse(time.RFC3339, e.At)
		if err != nil {
			continue // never written by DirectoryStateOf
		}
		k := key{e.User, e.Group}
		if old, ok := at[k]; !ok || t.Before(old) {
			at[k], earliest[k] = t, e
		}
	}
	out := make([]policy.Expiring, 0, len(earliest))
	for _, e := range earliest {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ta, tb := at[key{a.User, a.Group}], at[key{b.User, b.Group}]
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.User < b.User
	})
	return out
}

// DirectoryStateOf adapts the directory service to DirectoryState.
func DirectoryStateOf(d *directory.Service) DirectoryState {
	return func(ctx context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		pub, err := d.Publish(ctx, time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		exp := make([]policy.Expiring, 0, len(pub.Expiring))
		for _, e := range pub.Expiring {
			exp = append(exp, policy.Expiring{User: e.User, Group: e.Group, At: e.At.UTC().Format(time.RFC3339)})
		}
		fields := make([]policy.AttrField, 0, len(pub.Fields))
		for _, f := range pub.Fields {
			fields = append(fields, policy.AttrField{Name: f.Name, Multi: f.Multi})
		}
		doc := policy.BuildUserAttributes(fields, pub.Users)
		return exp, &doc, nil
	}
}

// TriggerDirectorySync asks RunDirectorySync for a policy write and an
// attribute-mapper sync soon. Non-blocking and coalesced: safe to call
// from directory.Service.OnChange.
func (h *Hub) TriggerDirectorySync() {
	select {
	case h.dirKick <- struct{}{}:
	default:
	}
}

const (
	directorySyncDebounce = time.Second
	directorySyncRetry    = time.Minute
	attrSyncTimeout       = 2 * time.Minute
)

// RunDirectorySync writes the policy and syncs the attribute mappers once
// at start and after each TriggerDirectorySync (debounced), until ctx is
// done. A failed mapper sync is logged and retried after a minute; it
// never holds up the policy write.
func (h *Hub) RunDirectorySync(ctx context.Context) {
	var retry <-chan time.Time
	for {
		h.syncDirectory(ctx, &retry)
		select {
		case <-ctx.Done():
			return
		case <-retry:
			retry = nil
		case <-h.dirKick:
			select {
			case <-ctx.Done():
				return
			case <-time.After(directorySyncDebounce):
			}
			select {
			case <-h.dirKick:
			default:
			}
		}
	}
}

func (h *Hub) syncDirectory(ctx context.Context, retry *<-chan time.Time) {
	h.writePolicyLogged()
	h.policyWriteMu.Lock()
	sync := h.attrSync
	h.policyWriteMu.Unlock()
	if sync == nil {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, attrSyncTimeout)
	defer cancel()
	if err := sync(sctx); err != nil {
		if ctx.Err() == nil {
			log.Printf("keycloak: attribute mapper sync failed (retrying in %s): %v", directorySyncRetry, err)
			*retry = time.After(directorySyncRetry)
		}
	}
}

// DirectoryApps lists every template's groups for the Users page
// (group suggestions and "used by").
func (h *Hub) DirectoryApps() []directory.App {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]directory.App, 0, len(h.templates))
	for i := range h.templates {
		t := &h.templates[i]
		out = append(out, directory.App{ID: t.ID, Name: t.Manifest.Name, Enabled: t.Enabled,
			AccessGroup: t.Manifest.Auth.AccessGroup, AdminGroup: t.Manifest.Auth.AdminGroup})
	}
	return out
}
