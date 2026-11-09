package hub

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/types"

	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Setup choices and compose profiles (contract §11.9 "Create body",
// §13.18). Validation and the pre-up safety checks always load every
// profile (loadRendered); the runtime views — pre-pull, status, drift,
// readiness, the create's volume ledger — follow the instance's selected
// profiles (loadRuntime, inactiveServicesLocked).

// SetupView is an instance view's setup part (§11.7): Locked once the
// instance's first start succeeded (its fixed_after_start choices can't
// change any more).
type SetupView struct {
	Locked bool `json:"locked"`
}

// setupViewLocked is instance id's SetupView. Caller holds mu.
func (h *Hub) setupViewLocked(id string) SetupView {
	return SetupView{Locked: h.st.Settings[id].FirstStartedAt != nil}
}

// stampFirstStartLocked records instance id's first successful start
// (InstanceSettings.FirstStartedAt, §13.18) unless one is recorded;
// reports whether it did (the caller saves). Caller holds mu (write).
func (h *Hub) stampFirstStartLocked(id string) bool {
	s := h.st.Settings[id]
	if s.FirstStartedAt != nil {
		return false
	}
	s = s.Clone()
	now := time.Now().UTC()
	s.FirstStartedAt = &now
	h.st.Settings[id] = s
	return true
}

// profilesLocked are instance t's compose profiles (templates.ProfilesFor
// over its effective instance values: the stored value, else the
// default). Caller holds mu.
func (h *Hub) profilesLocked(t *templates.Template) []string {
	return h.profilesIn(t, h.st.Settings[t.ID])
}

// profilesIn are t's compose profiles for settings s. Caller holds mu.
func (h *Hub) profilesIn(t *templates.Template, s state.InstanceSettings) []string {
	if len(t.ProfiledServices) == 0 {
		return nil
	}
	vals := map[string]any{}
	for k, v := range h.instanceValuesLocked(t, s) {
		vals[k] = v
	}
	return templates.ProfilesFor(t, vals)
}

// composeProfilesEnv is COMPOSE_PROFILES' value for t under settings s:
// its profiles comma-joined ("" = none, written too: a stale or
// hand-written value never stays). Caller holds mu.
func (h *Hub) composeProfilesEnv(t *templates.Template, s state.InstanceSettings) string {
	return strings.Join(h.profilesIn(t, s), ",")
}

// inactiveServicesLocked are t's compose services the instance's setup
// choices leave off: services with compose profiles: none of which is
// selected. Never nil. Caller holds mu.
func (h *Hub) inactiveServicesLocked(t *templates.Template) map[string]bool {
	out := map[string]bool{}
	if len(t.ProfiledServices) == 0 {
		return out
	}
	selected := h.profilesLocked(t)
	for s, ps := range t.ProfiledServices {
		active := false
		for _, p := range ps {
			if slices.Contains(selected, p) {
				active = true
				break
			}
		}
		if !active {
			out[s] = true
		}
	}
	return out
}

// inactiveServices is inactiveServicesLocked under the read lock.
func (h *Hub) inactiveServices(t *templates.Template) map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.inactiveServicesLocked(t)
}

// loadRuntime loads t's project as compose runs it for the instance's
// setup choices: loadRendered with only the selected profiles (an
// unselected profile's services are DisabledServices). For the runtime
// views only — the safety checks use loadRendered (every profile), so a
// profile never hides a service from them. Outside mu.
func (h *Hub) loadRuntime(ctx context.Context, t *templates.Template) (*types.Project, error) {
	h.mu.RLock()
	profiles := h.profilesLocked(t)
	h.mu.RUnlock()
	if profiles == nil {
		profiles = []string{}
	}
	return loadRenderedWith(ctx, h.project(t), h.cfg.ProjectDir, profiles)
}

// checkSetupKeys refuses (400, naming it) a create body setup key that
// isn't one of t's setup options (§11.9).
func checkSetupKeys(t *templates.Template, setup map[string]json.RawMessage) error {
	for _, k := range slices.Sorted(maps.Keys(setup)) {
		o := optionByKey(t, k)
		if o == nil || !o.Setup {
			return statusErr(http.StatusBadRequest, "setup: %s is not a setup option of template %s", clip(k, 64), t.TemplateID)
		}
	}
	return nil
}

// parseSetup checks a create body's setup values against t (§11.9):
// only setup options (checkSetupKeys), each parsed and checked exactly
// like a settings save's values (configCheck: canonical values, the
// type's constraints; folderSaveCheck, gidRangeSaveCheck and the Docker
// root rule as SaveSettings runs them) — 400 (409) naming the option.
// required / requires are checked against the stored result by
// createEntry (nextSettingsLocked). nil without setup values. Outside mu.
func (h *Hub) parseSetup(ctx context.Context, t *templates.Template, setup map[string]json.RawMessage) (*parsedSettings, error) {
	if len(setup) == 0 {
		return nil, nil
	}
	if err := checkSetupKeys(t, setup); err != nil {
		return nil, err
	}
	h.mu.RLock()
	folders := h.folderSourceLocked()
	defs := maps.Clone(h.st.Folders)
	h.mu.RUnlock()
	u := SettingsUpdate{Values: setup}
	if err := folderSaveCheck(t, state.InstanceSettings{}, defs, u); err != nil {
		return nil, err
	}
	parsed, problems := configCheck(t, h.kinds, folders, u, false)
	if len(problems) > 0 {
		return nil, problems[0]
	}
	if err := gidRangeSaveCheck(t, parsed); err != nil {
		return nil, err
	}
	if err := h.dockerRootValuesRule(ctx, t, parsed.values); err != nil {
		return nil, err
	}
	return parsed, nil
}

// fixedAfterStartErr is the 409 of a change to fixed_after_start option
// o once the instance has started (§13.18).
func fixedAfterStartErr(o *templates.Option) error {
	label := o.Label
	if label == "" {
		label = o.Key
	}
	return statusErr(http.StatusConflict, "%s is fixed after the first start: changing it would mean moving the data (create a new instance and restore a backup into it)", label)
}
