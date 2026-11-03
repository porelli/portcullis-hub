package hub

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// My apps (Task 15, contract §5.1): what the people listener's
// GET /api/me/apps shows a signed-in person — their own resolved
// per-person values for the enabled apps whose population holds them.
// Never instance options, secrets, other people or the losing rows
// (Reason.Others); a reason names only the caller's own groups.

// MyReason is how the caller's value was picked: the source and only the
// caller's own groups (never Others).
type MyReason struct {
	Source string   `json:"source"`
	Group  string   `json:"group,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// MyValue is one person option's value for the caller (Display form).
type MyValue struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Value   string   `json:"value"`
	Applies string   `json:"applies"`
	Reason  MyReason `json:"reason"`
}

// MyInfoLine is one label/value line of a credential.
type MyInfoLine struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// MyCredential is a per-person credential (empty list in project 1;
// project 3 fills it).
type MyCredential struct {
	Key    string       `json:"key"`
	Label  string       `json:"label"`
	Status string       `json:"status"`
	Since  *time.Time   `json:"since,omitempty"`
	Reason string       `json:"reason,omitempty"`
	Info   []MyInfoLine `json:"info,omitempty"`
}

// MyEntry is a person-entered value (Task 15A fills it).
type MyEntry struct{}

// EntryInput is what a person-entered value's input needs (Task 15A).
type EntryInput struct{}

// MyApp is one app on the caller's My apps tab. Entries and Credentials
// are always [] (never null).
type MyApp struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Icon        string         `json:"icon"`
	URL         string         `json:"url"`
	Values      []MyValue      `json:"values"`
	Entries     []MyEntry      `json:"entries"`
	Credentials []MyCredential `json:"credentials"`
}

// MyApps lists user's (any case) apps: enabled instances whose
// population holds them, with their self-visible person options'
// resolved values; an app with none is left out. The directory snapshot
// is taken before mu; an unavailable directory is the membership error.
func (h *Hub) MyApps(ctx context.Context, user string) ([]MyApp, error) {
	user = strings.ToLower(user)
	m, err := h.membership(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []MyApp{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		var groups map[string]int
		for _, p := range h.populationLocked(t, m).People {
			if p.User == user {
				groups = p.Groups
				break
			}
		}
		if groups == nil {
			continue
		}
		resolved := h.resolvePeopleLocked(t, m)[user]
		app := MyApp{ID: t.ID, Name: instanceName(t), Icon: t.Manifest.Icon, Values: []MyValue{}, Entries: []MyEntry{}, Credentials: []MyCredential{}}
		if len(t.Manifest.URLs) > 0 {
			app.URL = t.Manifest.URLs[0].URL
		}
		opts := t.Manifest.Options()
		for j := range opts {
			o := &opts[j]
			if o.EffectiveScope() != templates.ScopePerson || o.Type == templates.TypeSecret || (o.SelfVisible != nil && !*o.SelfVisible) {
				continue
			}
			r, ok := resolved[o.Key]
			if !ok {
				continue
			}
			if v, ok := myValueOf(h.kinds, o, r, groups); ok {
				app.Values = append(app.Values, v)
			}
		}
		if len(app.Values) > 0 {
			out = append(out, app)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// myValueOf is r as the caller sees it: UNRESOLVED (nil value) is left
// out (ok false); the reason keeps only groups in mine (the caller's).
func myValueOf(kinds *settings.Registry, o *templates.Option, r settings.Resolved, mine map[string]int) (MyValue, bool) {
	if r.Value == nil {
		return MyValue{}, false
	}
	reason := MyReason{Source: r.Reason.Source}
	if _, ok := mine[r.Reason.Group]; ok && r.Reason.Group != "" {
		reason.Group = r.Reason.Group
	}
	for _, g := range r.Reason.Groups {
		if _, ok := mine[g]; ok {
			reason.Groups = append(reason.Groups, g)
		}
	}
	return MyValue{Key: o.Key, Label: o.Label, Value: kinds.Display(o, r.Value), Applies: o.EffectiveApplies(), Reason: reason}, true
}
