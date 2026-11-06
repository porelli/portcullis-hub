package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// AppSettingsView is an instance's policy, sign-in and public-access
// part of the settings panel (SettingsPanel embeds it).
type AppSettingsView struct {
	// PortDefinitions are the template's declared ports (the stored
	// values are SettingsPanel.Ports).
	PortDefinitions []templates.Port `json:"port_definitions"`
	// EffectivePolicy is what applies: the configured policy (override or
	// global default) intersected with what the app can enforce.
	EffectivePolicy policy.AuthPolicy `json:"effective_policy"`
	DefaultPolicy   policy.AuthPolicy `json:"default_policy"`
	SafetyScore     float64           `json:"safety_score"`
	// AuthPolicy is the app's override (nil: it inherits the default).
	AuthPolicy *policy.AuthPolicy `json:"auth_policy,omitempty"`
	// Method is the auth method as deployed (a custom app behind
	// Portcullis sign-in is forward-auth); Capability what it can enforce.
	Method      string            `json:"method"`
	Capability  policy.Capability `json:"capability"`
	Resolution  policy.Resolution `json:"resolution"`
	PolicyNotes []string          `json:"policy_notes"`
	Tier        string            `json:"tier"`
	// SignIn is set for apps with their own login (auth.native_login).
	SignIn *SignInView `json:"sign_in,omitempty"`
	// PublicAccess is set when the manifest declares auth.public_access.
	PublicAccess *PublicAccessView `json:"public_access,omitempty"`
	// Secrets: every secret option, set or not (write-only: never a
	// value).
	Secrets map[string]SecretView `json:"secrets"`
}

// SignInView is the "Sign-in" setting of an app with its own login.
type SignInView struct {
	Mode                string `json:"mode"` // SignInGateway or SignInNative
	AllowWithoutGateway bool   `json:"allow_without_gateway"`
	Note                string `json:"note,omitempty"`
	AccessGroup         string `json:"access_group,omitempty"` // "" = any signed-in user
	Blocked             string `json:"blocked,omitempty"`
}

// AppSettings returns an app's settings and policy.
func (h *Hub) AppSettings(id string) (*AppSettingsView, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	acc := h.accessLocked(t)
	eff := acc.Resolved.Policy
	legacy := h.st.LegacyPassword[id]
	if acc.Inherits {
		legacy = h.st.LegacyPassword[""]
	}
	pub := h.publicLocked(t, t.Public)
	v := &AppSettingsView{
		PortDefinitions: t.Manifest.Ports,
		EffectivePolicy: eff,
		DefaultPolicy:   h.st.Default(),
		SafetyScore:     policy.SafetyScore(eff),
		Method:          acc.Method,
		Capability:      acc.Capability,
		Resolution:      acc.Resolved,
		PolicyNotes:     policyNotes(acc, legacy),
		Tier:            policy.HostTier(eff, pub.Active()),
	}
	if p, ok := h.st.AuthPolicies[id]; ok {
		v.AuthPolicy = &p
	}
	if acc.SignIn != "" {
		nl := t.Manifest.Auth.NativeLogin
		v.SignIn = &SignInView{Mode: acc.SignIn, AllowWithoutGateway: nl.AllowWithoutGateway, Note: nl.Note, Blocked: acc.Blocked}
		if t.Manifest.Auth.GroupAccess {
			v.SignIn.AccessGroup = t.Manifest.Auth.AccessGroup
		}
	}
	v.PublicAccess = h.publicViewLocked(t, eff)
	v.Secrets = h.secretViewsLocked(t)
	return v, nil
}

// SignInMode returns an app's sign-in mode ("" for apps without their own
// login, or unknown apps).
func (h *Hub) SignInMode(id string) string {
	t := h.Template(id)
	if t == nil {
		return ""
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.accessLocked(t).SignIn
}

// parsedSettings is a validated SettingsUpdate's settings part: canonical
// values (nil = back to the default), ports as given, and the per-person
// and per-group changes (rows not bound to group ids).
type parsedSettings struct {
	ports  map[string]string // nil = unchanged
	values map[string]any
	person map[string]state.PersonSetting
	groups map[string][]state.GroupValue
	// secrets: the secret changes (a value given or generated, or a
	// clear). Never logged or echoed.
	secrets map[string]secretOp
	// sentIDs: option key → lowercase group → the group id the panel
	// sent with the row (GroupValueInput.GroupID; absent = a new row).
	sentIDs map[string]map[string]int
	// groupIDs: instance group / groups values (F3) → group name → the
	// directory's id, filled by bindRowsWith; a nil map = not bound yet
	// (stored unbound: grants nothing), an empty one = no group.
	groupIDs map[string]map[string]int
	// sentValueIDs: SettingsUpdate.ValueGroupIDs of the parsed values.
	sentValueIDs map[string]map[string]int
}

// secretOp is one parsed secret change.
type secretOp struct {
	value            string
	clear, generated bool
}

// ValidateSettings checks a settings update against template t: ports
// keep their rules (declared keys and <KEY>_BIND only, 1-65535 or a
// low-high range, a bind IP), and every option value must be a declared
// option of the right scope that parses as its type (kinds) and renders
// for each of its env deliveries. Shared folders (folder:…) are refused:
// no FolderSource.
func ValidateSettings(t *templates.Template, kinds *settings.Registry, u SettingsUpdate) error {
	_, err := parseSettings(t, kinds, nil, u)
	return err
}

// optionByKey is t's option key, or nil.
func optionByKey(t *templates.Template, key string) *templates.Option {
	opts := t.Manifest.Options()
	for i := range opts {
		if opts[i].Key == key {
			return &opts[i]
		}
	}
	return nil
}

// decodeRaw decodes one JSON value (numbers as json.Number, so int64s
// stay exact); empty or null = nil.
func decodeRaw(raw json.RawMessage) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("not a JSON value: %v", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("not a single JSON value")
	}
	return v, nil
}

// folderPrefix marks a shared-folder path value (contract §13.15).
const folderPrefix = settings.FolderRefPrefix

// folderHostPath resolves a folder:… value through folders (nil: shared
// folders aren't available).
func folderHostPath(folders FolderSource, v string) (string, error) {
	if folders == nil {
		return "", fmt.Errorf("%q names a shared folder, but shared folders aren't available", v)
	}
	id, sub, ok, err := settings.ParseFolderRef(v)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%q is not a shared folder (folder:<id>[/<subpath>])", v)
	}
	p, err := folders.FolderHostPath(id, sub)
	if err != nil {
		return "", fmt.Errorf("shared folder %s: %w", id, err)
	}
	// The source's answer is checked like any host path: it ends up in a
	// "<host>:<container>" volume entry.
	if err := templates.ValidatePathSetting(p); err != nil {
		return "", fmt.Errorf("shared folder %s: %w", id, err)
	}
	if !path.IsAbs(p) || path.Clean(p) == "/" {
		return "", fmt.Errorf("shared folder %s: host path %q must be an absolute directory other than /", id, p)
	}
	return path.Clean(p), nil
}

// parseValue parses raw as a value of o: a path's folder:… value through
// folders, anything else through its kind.
func parseValue(kinds *settings.Registry, folders FolderSource, o *templates.Option, raw any) (any, error) {
	if s, ok := raw.(string); ok && o.Type == templates.TypePath && strings.HasPrefix(s, folderPrefix) {
		if _, err := folderHostPath(folders, s); err != nil {
			return nil, err
		}
		return s, nil
	}
	return kinds.Parse(o, raw)
}

// storedValue is a canonical value as state stores it (unlimited as its
// text).
func storedValue(v any) any {
	if v == (settings.Unlimited{}) {
		return settings.UnlimitedText
	}
	return v
}

// validRowGroup: a row's group is an LLDAP group name or a placeholder.
func validRowGroup(g string) bool {
	return g == templates.PlaceholderAccessGroup || g == templates.PlaceholderAdminGroup || lldap.ValidGroupName(g)
}

// parseRows checks one option's per-group rows (person rows or group
// records): a valid group name or placeholder each, no group twice
// (duplicate rows are invalid configuration: refused at save, P-T5), and
// a value of o each (canonical). Group ids are kept as given (rows from
// an archive); the save path binds them (Task 8).
func parseRows(kinds *settings.Registry, folders FolderSource, o *templates.Option, rows []state.GroupValue) ([]state.GroupValue, error) {
	seen := map[string]bool{}
	out := make([]state.GroupValue, 0, len(rows))
	for i, r := range rows {
		if !validRowGroup(r.Group) {
			return nil, statusErr(400, "setting %s: row %d: %q is not a group name", o.Key, i+1, r.Group)
		}
		if seen[strings.ToLower(r.Group)] {
			return nil, statusErr(400, "setting %s: group %s has more than one row (one value per group)", o.Key, r.Group)
		}
		seen[strings.ToLower(r.Group)] = true
		if r.Value == nil {
			return nil, statusErr(400, "setting %s: group %s: no value", o.Key, r.Group)
		}
		v, err := parseValue(kinds, folders, o, r.Value)
		if err != nil {
			return nil, statusErr(400, "setting %s: group %s: %v", o.Key, r.Group, err)
		}
		out = append(out, state.GroupValue{Group: r.Group, GroupID: r.GroupID, Value: storedValue(v)})
	}
	return out, nil
}

// rowsFromInput turns API rows into state rows (unbound: id 0).
func rowsFromInput(o *templates.Option, in []GroupValueInput) ([]state.GroupValue, error) {
	out := make([]state.GroupValue, 0, len(in))
	for i, r := range in {
		v, err := decodeRaw(r.Value)
		if err != nil {
			return nil, statusErr(400, "setting %s: row %d: %v", o.Key, i+1, err)
		}
		out = append(out, state.GroupValue{Group: r.Group, Value: v})
	}
	return out, nil
}

// parsePerson checks a per-person option's configuration: a default of
// o (required, stored canonical), a rule the template offers, valid rows.
func parsePerson(kinds *settings.Registry, folders FolderSource, o *templates.Option, p state.PersonSetting) (state.PersonSetting, error) {
	if p.Default == nil {
		return p, statusErr(400, "setting %s: a per-person option needs a default", o.Key)
	}
	def, err := parseValue(kinds, folders, o, p.Default)
	if err != nil {
		return p, statusErr(400, "setting %s: default: %v", o.Key, err)
	}
	if p.Resolve != "" && p.Resolve != o.Resolve && !slices.Contains(o.ResolveChoices, p.Resolve) {
		return p, statusErr(400, "setting %s: resolve %q is not one the template offers", o.Key, p.Resolve)
	}
	rows, err := parseRows(kinds, folders, o, p.Rows)
	if err != nil {
		return p, err
	}
	return state.PersonSetting{Default: storedValue(def), Resolve: p.Resolve, Rows: rows}, nil
}

// parseSettings validates u's settings part against t (ValidateSettings)
// and returns it canonical.
func parseSettings(t *templates.Template, kinds *settings.Registry, folders FolderSource, u SettingsUpdate) (*parsedSettings, error) {
	out := &parsedSettings{values: map[string]any{}, person: map[string]state.PersonSetting{}, groups: map[string][]state.GroupValue{}, secrets: map[string]secretOp{}, sentIDs: map[string]map[string]int{}, groupIDs: map[string]map[string]int{}}
	sent := func(key string, in []GroupValueInput) {
		for _, r := range in {
			if r.GroupID == 0 {
				continue
			}
			if out.sentIDs[key] == nil {
				out.sentIDs[key] = map[string]int{}
			}
			out.sentIDs[key][strings.ToLower(r.Group)] = r.GroupID
		}
	}
	if u.Ports != nil {
		if err := validatePorts(t, u.Ports); err != nil {
			return nil, err
		}
		out.ports = u.Ports
	}
	scoped := func(key, scope string) (*templates.Option, error) {
		o := optionByKey(t, key)
		if o == nil {
			return nil, statusErr(400, "unknown setting %q", clip(key, 64))
		}
		if hubSetOption(o) {
			// Per-person values the Hub computes (F5): no admin value.
			return nil, statusErr(400, "setting %s is set by the Hub for each person: it takes no admin value", key)
		}
		if o.EffectiveScope() != scope {
			return nil, statusErr(400, "setting %s is a %s option, not %s", key, o.EffectiveScope(), scope)
		}
		return o, nil
	}
	for _, k := range slices.Sorted(maps.Keys(u.Values)) {
		o, err := scoped(k, templates.ScopeInstance)
		if err != nil {
			return nil, err
		}
		if o.Type == templates.TypeSecret {
			// Write-only secrets (contract §13.10) have their own store;
			// a secret is never taken as a plain value.
			return nil, statusErr(400, "setting %s is a secret: secret values are write-only and can't be set as a plain value", k)
		}
		raw, err := decodeRaw(u.Values[k])
		if err != nil {
			return nil, statusErr(400, "setting %s: %v", k, err)
		}
		if raw == nil {
			out.values[k] = nil
			if isGroupOption(o) {
				out.groupIDs[k] = map[string]int{}
			}
			continue
		}
		v, err := parseValue(kinds, folders, o, raw)
		if err != nil {
			return nil, statusErr(400, "setting %s: %v", k, err)
		}
		if _, err := renderOptionEnv(o, v); err != nil {
			return nil, statusErr(400, "setting %s: %v", k, err)
		}
		out.values[k] = v
		if isGroupOption(o) {
			if ids := u.ValueGroupIDs[k]; len(ids) > 0 {
				if out.sentValueIDs == nil {
					out.sentValueIDs = map[string]map[string]int{}
				}
				out.sentValueIDs[k] = ids
			}
			out.groupIDs[k] = nil // bound by bindRowsWith
			if len(groupNames(v)) == 0 {
				out.groupIDs[k] = map[string]int{}
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(u.Person)) {
		o, err := scoped(k, templates.ScopePerson)
		if err != nil {
			return nil, err
		}
		pc := u.Person[k]
		sent(k, pc.Rows)
		def, err := decodeRaw(pc.Default)
		if err != nil {
			return nil, statusErr(400, "setting %s: default: %v", k, err)
		}
		rows, err := rowsFromInput(o, pc.Rows)
		if err != nil {
			return nil, err
		}
		p, err := parsePerson(kinds, folders, o, state.PersonSetting{Default: def, Resolve: pc.Resolve, Rows: rows})
		if err != nil {
			return nil, err
		}
		out.person[k] = p
	}
	for _, k := range slices.Sorted(maps.Keys(u.Groups)) {
		o, err := scoped(k, templates.ScopeGroup)
		if err != nil {
			return nil, err
		}
		if o.Type == templates.TypeSecret {
			// Never stored in state.yaml nor served (the validator refuses
			// the template too).
			return nil, statusErr(400, "setting %s is a secret: a secret takes no group records (only an instance value, set under secrets)", k)
		}
		sent(k, u.Groups[k])
		in, err := rowsFromInput(o, u.Groups[k])
		if err != nil {
			return nil, err
		}
		rows, err := parseRows(kinds, folders, o, in)
		if err != nil {
			return nil, err
		}
		recs := make([]settings.Row, 0, len(rows))
		for _, r := range rows {
			v, _ := kinds.Parse(o, r.Value)
			recs = append(recs, settings.Row{Group: r.Group, Value: v})
		}
		if _, err := renderGroupEnv(o, recs); err != nil {
			return nil, statusErr(400, "setting %s: %v", k, err)
		}
		out.groups[k] = rows
	}
	for _, k := range slices.Sorted(maps.Keys(u.Secrets)) {
		o := optionByKey(t, k)
		if o == nil || o.Type != templates.TypeSecret {
			return nil, statusErr(400, "setting %q is not a secret option", clip(k, 64))
		}
		op, err := parseSecretChange(kinds, o, u.Secrets[k])
		if err != nil {
			return nil, err
		}
		out.secrets[k] = op
	}
	return out, nil
}

// parseSecretChange checks one secret change: exactly one of a value, a
// generate (the option must declare generate) or a clear; an empty value
// is not a clear. A value must parse as a secret and, when delivered by
// env, be one env can carry single-quoted. Errors name the option, never
// the value.
func parseSecretChange(kinds *settings.Registry, o *templates.Option, c SecretChange) (secretOp, error) {
	if o.EffectiveScope() != templates.ScopeInstance {
		return secretOp{}, statusErr(400, "setting %s: only instance secrets can be set", o.Key)
	}
	if c.Value != nil && *c.Value == "" && !c.Clear && !c.Generate {
		return secretOp{}, statusErr(400, "setting %s: an empty value doesn't clear a secret: clearing needs an explicit action (clear)", o.Key)
	}
	n := 0
	for _, b := range []bool{c.Value != nil, c.Generate, c.Clear} {
		if b {
			n++
		}
	}
	if n != 1 {
		return secretOp{}, statusErr(400, "setting %s: give exactly one of a value, generate or clear", o.Key)
	}
	switch {
	case c.Clear:
		return secretOp{clear: true}, nil
	case c.Generate:
		if o.Generate == nil {
			return secretOp{}, statusErr(400, "setting %s: the template declares no generate for this secret: enter a value", o.Key)
		}
		v, err := generateSecret(o.Generate)
		if err != nil {
			return secretOp{}, statusErr(500, "setting %s: %v", o.Key, err)
		}
		return secretOp{value: v, generated: true}, nil
	}
	v, err := parseValue(kinds, nil, o, *c.Value)
	if err != nil {
		return secretOp{}, statusErr(400, "setting %s: %s", o.Key, redactValues(err.Error(), []string{*c.Value}))
	}
	if _, err := renderOptionEnv(o, v); err != nil {
		return secretOp{}, statusErr(400, "setting %s: %s", o.Key, redactValues(err.Error(), []string{*c.Value}))
	}
	return secretOp{value: *c.Value}, nil
}

// validatePorts checks a port configuration (keys: the template's port
// keys and their <KEY>_BIND).
func validatePorts(t *templates.Template, ports map[string]string) error {
	known := map[string]bool{}
	for _, p := range t.Manifest.Ports {
		known[p.Key], known[p.Key+"_BIND"] = true, true
	}
	for _, k := range slices.Sorted(maps.Keys(ports)) {
		if !known[k] {
			return statusErr(400, "unknown port setting %q", clip(k, 64))
		}
		if templates.HasControlChars(ports[k]) {
			return statusErr(400, "port setting %s contains control characters", k)
		}
	}
	for _, p := range t.Manifest.Ports {
		if b := ports[p.Key+"_BIND"]; b != "" && net.ParseIP(b) == nil {
			return statusErr(400, "bind address for %s must be an IP address", p.Key)
		}
		v, ok := ports[p.Key]
		if !ok {
			continue
		}
		if v == "" {
			if p.Required {
				return statusErr(400, "port %s is required", p.Key)
			}
			continue
		}
		if p.Range != "" {
			if _, _, ok := parsePortRange(v); !ok {
				return statusErr(400, "port range %s must be low-high within 1-65535", p.Key)
			}
			continue
		}
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
			return statusErr(400, "port %s must be 1-65535", p.Key)
		}
	}
	return nil
}

// clip cuts s to n bytes (an echoed key in an error).
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// effectiveValue is o's value for instance t: the stored one (parsed
// again: a value a template update no longer accepts is not used —
// logged, fail closed), else the default; ok false = no value. A path's
// folder:… value is returned as stored. Caller must hold mu.
func (h *Hub) effectiveValue(t *templates.Template, o *templates.Option, s state.InstanceSettings) (any, bool) {
	if typ := s.Types[o.Key]; typ != "" && typ != o.Type {
		// Retyped by a template update: never read as the new type (the
		// prune after the sync drops it).
		return nil, false
	}
	if raw, ok := s.Values[o.Key]; ok && raw != nil {
		if str, isStr := raw.(string); isStr && o.Type == templates.TypePath && strings.HasPrefix(str, folderPrefix) {
			return str, true
		}
		v, err := h.kinds.Parse(o, raw)
		if err != nil {
			log.Printf("settings: %s: stored %s no longer fits the template (%v): not used", t.ID, o.Key, err)
			return nil, false
		}
		return v, true
	}
	if o.Default == nil {
		return nil, false
	}
	v, err := h.kinds.Parse(o, o.Default)
	if err != nil {
		return nil, false
	}
	return v, true
}

// instanceValuesLocked are t's effective instance-scope values (stored or
// default) by key. Caller must hold mu.
func (h *Hub) instanceValuesLocked(t *templates.Template, s state.InstanceSettings) map[string]settings.Value {
	out := map[string]settings.Value{}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopeInstance {
			continue
		}
		if v, ok := h.effectiveValue(t, o, s); ok {
			out[o.Key] = v
		}
	}
	return out
}

// requiresValuesLocked are the values CheckRequires sees: the effective
// instance values, plus every secret that is set as a non-empty marker
// (its value is never read). Caller must hold mu.
func (h *Hub) requiresValuesLocked(t *templates.Template, s state.InstanceSettings) map[string]settings.Value {
	out := h.instanceValuesLocked(t, s)
	for k := range s.Secrets {
		if o := optionByKey(t, k); o != nil && o.Type == templates.TypeSecret {
			out[k] = settings.SecretShown
		}
	}
	return out
}

// configCapability is what t's app can enforce in a sign-in mode (native:
// the app's own login only, where the template allows it) — as
// accessLocked computes it.
func configCapability(t *templates.Template, native bool) policy.Capability {
	auth := &t.Manifest.Auth
	method := auth.Method
	if auth.HasNativeLogin() && !(native && auth.NativeLogin.AllowWithoutGateway) {
		method = "forward-auth"
	}
	return policy.CapabilityFor(method)
}

// configCheck is configProblems plus the parsed settings (nil when they
// don't validate).
func configCheck(t *templates.Template, kinds *settings.Registry, folders FolderSource, u SettingsUpdate, native bool) (*parsedSettings, []error) {
	var out []error
	parsed, err := parseSettings(t, kinds, folders, u)
	if err != nil {
		out = append(out, err)
	}
	if u.SignIn != nil {
		nl := t.Manifest.Auth.NativeLogin
		switch {
		case !t.Manifest.Auth.HasNativeLogin():
			out = append(out, statusErr(400, "this app has no sign-in choice (its template doesn't declare auth.native_login)"))
		case *u.SignIn == SignInNative && declaresHeaders(&t.Manifest):
			// Headers need group-gate in front (spec call 13): without
			// it nothing strips a client's forged copy.
			out = append(out, statusErr(400, "the app's own login without Portcullis can't be chosen: its settings deliver headers (%s), which need Portcullis sign-in", strings.Join(headerNames(&t.Manifest), ", ")))
		case *u.SignIn == SignInNative && !nl.AllowWithoutGateway:
			out = append(out, statusErr(400, "this template doesn't allow the app's own login without Portcullis"))
		case *u.SignIn != SignInNative && *u.SignIn != SignInGateway:
			out = append(out, statusErr(400, "sign-in must be %q or %q", SignInGateway, SignInNative))
		}
	}
	if !u.Inherit && u.Policy != nil {
		if msg := configCapability(t, native).Check(*u.Policy); msg != "" {
			out = append(out, statusErr(400, "access policy: %s", msg))
		}
	}
	if _, err := validatePublic(t, u); err != nil {
		out = append(out, err)
	}
	return parsed, out
}

// configProblems lists every reason (400 StatusErrors, in a fixed order)
// why the per-instance configuration in u doesn't fit template t:
// settings (ValidateSettings, with shared folders through folders), the
// sign-in mode, the policy override against what the app enforces in its
// resulting sign-in mode (native), and the public exceptions
// (validatePublic). Shared by SaveSettings and restore, so a restored
// archive meets the same rules as a save.
func configProblems(t *templates.Template, kinds *settings.Registry, folders FolderSource, u SettingsUpdate, native bool) []error {
	_, out := configCheck(t, kinds, folders, u, native)
	return out
}

// SettingsUpdate is a settings save (PUT): the settings part plus the
// policy, public exceptions and sign-in mode.
type SettingsUpdate struct {
	// Ports: nil = unchanged; otherwise the instance's whole port
	// configuration (port keys and <KEY>_BIND; an absent key = the
	// template's default, "" = not published).
	Ports map[string]string
	// Values are instance options to change; a key not listed is
	// unchanged, JSON null = back to the default.
	Values map[string]json.RawMessage
	// ValueGroupIDs: for instance group / groups values in Values, the
	// LLDAP id the panel showed for each name (InstanceGroupIDs); a name
	// sent with an id no longer stored for it is 409, a name without one
	// is new (F3, like rows' group_id).
	ValueGroupIDs map[string]map[string]int
	// Person / Groups: per-person and per-group options (Task 8).
	Person map[string]PersonChange
	Groups map[string][]GroupValueInput
	// Secrets: secret options (Task 7).
	Secrets map[string]SecretChange

	Policy  *policy.AuthPolicy // nil = unchanged; normalised by SaveSettings
	Inherit bool               // drop the per-app policy override
	// Public exceptions (auth.public_access); nil = unchanged.
	PublicAccess        *bool     // the admin's on/off choice
	PublicAccessDefault bool      // forget the choice: template default applies
	PublicMode          *string   // "all", "listed", "" = template default
	PublicTokens        *[]string // listed shares: share URLs or bare tokens
	// SignIn: SignInGateway or SignInNative (apps with auth.native_login);
	// nil = unchanged.
	SignIn *string
}

// PersonChange is a per-person option's new configuration.
type PersonChange struct {
	Default json.RawMessage   `json:"default"`
	Resolve string            `json:"resolve,omitempty"`
	Rows    []GroupValueInput `json:"rows"`
}

// GroupValueInput is one per-group row or record as the API sends it.
//
// GroupID is the id the panel showed for a stored row (0 = a new row):
// a save whose GroupID differs from the stored row's is refused 409
// (staleRebind) — the row was purged, or its group re-created, since the
// panel was loaded.
type GroupValueInput struct {
	Group   string          `json:"group"`
	Value   json.RawMessage `json:"value"`
	GroupID int             `json:"group_id,omitempty"`
}

// SecretChange changes a secret option: a new value, a generated one, or
// cleared.
type SecretChange struct {
	Value           *string
	Generate, Clear bool
}

// SaveResult is what a settings save did: its effect (settings.Effect*),
// the changed keys, warnings and the delivery report.
type SaveResult struct {
	Effect     string          `json:"effect"`
	Changed    []string        `json:"changed"`
	Warnings   []string        `json:"warnings,omitempty"`
	Deliveries *DeliveryReport `json:"deliveries,omitempty"`
}

// Trigger is why a delivery runs (§13.8 hook triggers).
type Trigger string

// Delivery triggers.
const (
	TriggerStart      Trigger = "start"
	TriggerSave       Trigger = "settings_change"
	TriggerMembership Trigger = "membership_change"
	TriggerRetry      Trigger = "retry"
	// TriggerCredential: a person_secret credential was created,
	// regenerated, revoked or voided (contract §13.16): immediate, never
	// debounced; it ranks above a save (triggerRank).
	TriggerCredential Trigger = "credential_change"
)

// UnitResult is one delivery unit's outcome.
type UnitResult struct {
	Unit    string `json:"unit"`              // "env" | "file:<name>" | "credentials:<key>" | "hook:<name>" | "claim:<attr>" | "headers" | "reload" | "restart"
	OK      bool   `json:"ok"`                //
	Skipped string `json:"skipped,omitempty"` // Skip*: "unchanged" | "not running" | "directory unavailable" | "busy" | "superseded" | "not supported" | "previous run still running"
	// Message: what OK means ("reload signal sent, app still running").
	Message string    `json:"message,omitempty"`
	Error   string    `json:"error,omitempty"` // redacted, then clipped (2000)
	At      time.Time `json:"at"`
}

// DeliveryReport is one delivery run's outcome per unit.
type DeliveryReport struct {
	Instance string       `json:"instance"`
	Units    []UnitResult `json:"units"`
	// revokeAfter: instances whose credentials the run's secrets
	// reconcile voided (A4): applied live once the delivery lock is
	// released.
	revokeAfter []string
	// forceAgain: hooks a superseded run owes (B-I1: it wrote a file
	// with on_membership_change: hook); its re-queue forces them.
	forceAgain []string
}

// settingChange is one changed (key, scope, group) for the audit.
type settingChange struct {
	key, scope, group string
	before, after     string
	// secret: a secret's change (replaced, generated, cleared) instead
	// of before -> after.
	secret string
}

// showValue is v as the audit and the panel show it ("unset" = none).
func (h *Hub) showValue(o *templates.Option, v any, ok bool) string {
	if !ok || v == nil {
		return "unset"
	}
	if s, isStr := v.(string); isStr && strings.HasPrefix(s, folderPrefix) {
		return s
	}
	return h.kinds.Display(o, v)
}

// showPort is a port setting as the audit shows it.
func showPort(v string, ok bool) string {
	switch {
	case !ok:
		return "default"
	case v == "":
		return "off"
	}
	return v
}

// SaveSettings validates and stores an instance's settings (and
// optionally its policy, public exceptions and sign-in mode) in one
// state change, rewrites its override and .env, and hands the effect to
// the delivery engine (P5: it alone reloads or restarts): a restart (in
// the background) when a changed option applies at restart, a port or
// path changed, or the override changed (policy, public exceptions,
// sign-in); a reload for options that apply at reload. Only
// declared option keys and ports are taken. Every changed (key, scope,
// group) is audited as settings.change by actor (a refused save:
// "refused").
func (h *Hub) SaveSettings(id string, u SettingsUpdate, actor directory.Actor) (_ *SaveResult, retErr error) {
	var changes []settingChange
	var writeErr error
	defer func() {
		err := retErr
		if err == nil {
			err = writeErr
		}
		h.auditSettings(id, actor, u, changes, err)
	}()
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	h.mu.RLock()
	pendErr := h.pendingLocked(id)
	native := h.st.SignIn[id] == state.SignInNative
	// Resolved outside mu: copies (the folders' paths and definitions).
	folders := h.folderSourceLocked()
	defs := maps.Clone(h.st.Folders)
	cur := h.st.Settings[id].Clone()
	u = withPlaceholders(t, h.st.Settings[id], u)
	h.mu.RUnlock()
	if pendErr != nil {
		return nil, pendErr
	}
	if u.SignIn != nil {
		native = *u.SignIn == SignInNative
	}
	// Folder values change only through an assignment (§13.15).
	if err := folderSaveCheck(t, cur, defs, u); err != nil {
		return nil, err
	}
	parsed, problems := configCheck(t, h.kinds, folders, u, native)
	if len(problems) > 0 {
		return nil, problems[0]
	}
	if err := gidRangeSaveCheck(t, parsed); err != nil {
		return nil, err
	}
	// No hand-typed path at, above or under Docker's data root (F16).
	if err := h.dockerRootValuesRule(context.Background(), t, parsed.values); err != nil {
		return nil, err
	}
	// Rows and records are bound to the directory's group ids (and a
	// privileged option's groups checked) before mu: network calls.
	bindWarnings, err := h.bindRowsForSave(context.Background(), t, parsed)
	if err != nil {
		return nil, err
	}
	// A policy reaching LoA 3 switches AI support off first (G43,
	// contract §15.11; audited ai.disable "policy needs mTLS").
	aiWarnings := []string{}
	h.mu.RLock()
	aiOff := h.aiOffForSaveLocked(t, u)
	h.mu.RUnlock()
	if len(aiOff) > 0 {
		if err := h.switchAIOff(context.Background(), id, aiOff, actor, aiPolicyOffDetail); err != nil {
			var oe *OpError
			if !errors.As(err, &oe) {
				return nil, err
			}
			// Off in state and in the gate file; the rest is recorded.
			aiWarnings = append(aiWarnings, h.redactUnitError(id, err))
		}
		aiWarnings = append(aiWarnings, aiOffWarning(id, aiOff))
	}
	if h.testHookSave != nil {
		h.testHookSave()
	}
	sv, enabled, err := h.saveSettings(t, u, parsed)
	changes = sv.changes
	if err != nil {
		return nil, err
	}
	out := &SaveResult{Effect: sv.effect, Changed: sv.keys, Warnings: append(append(aiWarnings, bindWarnings...), h.noAccessWarnings(t, sv.keys)...)}
	if len(sv.writeErrs) > 0 {
		writeErr = errors.Join(sv.writeErrs...)
		for _, e := range sv.writeErrs {
			out.Warnings = append(out.Warnings, h.redactUnitError(id, e))
		}
	}
	if out.Changed == nil {
		out.Changed = []string{}
	}
	if !enabled {
		return out, nil
	}
	// Outside every lock (the sign-in lock is released by saveSettings):
	// the engine takes id's delivery lock and may talk to the network;
	// it writes the data files, then reloads or restarts (background).
	if len(sv.keys) > 0 || sv.effect != settings.EffectNone {
		// Never waiting for a run in progress (a hook can hold the lock
		// for its whole timeout): busy = queued, the panel polls.
		rep, err := h.deliver(context.Background(), id, TriggerSave, deliverOpts{effect: sv.effect, noWait: true})
		if err != nil {
			out.Warnings = append(out.Warnings, "delivery: "+err.Error())
		}
		out.Deliveries = rep
	}
	return out, nil
}

// saved is what saveSettings changed.
type saved struct {
	effect  string
	keys    []string
	changes []settingChange
	// writeErrs: the override or .env write failed after the commit.
	writeErrs []error
}

// saveSettings is SaveSettings' state change: under the instance's lock
// for a sign-in change, then mu.
func (h *Hub) saveSettings(t *templates.Template, u SettingsUpdate, parsed *parsedSettings) (res saved, enabled bool, retErr error) {
	id := t.ID
	res.effect = settings.EffectNone
	// A sign-in mode change holds the instance's lock (as enable, disable,
	// SetHosts and the access sync do) for the callback change and the
	// save, so their callback changes can't interleave.
	if u.SignIn != nil {
		unlock, err := h.lockApp(id)
		if err != nil {
			return res, false, err
		}
		defer unlock()
	}
	// A sign-in mode change of an enabled instance moves its extra-domain
	// sign-in callbacks (contract §5) first: a Keycloak failure changes
	// nothing; a later failure here undoes them.
	if add, remove := h.signInCallbackChange(t, u.SignIn); len(add)+len(remove) > 0 && h.idp != nil {
		if err := h.idp.UpdateForwardAuthCallbacks(context.Background(), add, remove); err != nil {
			return res, false, &StatusError{Status: 502, Err: fmt.Errorf("sign-in mode not changed (nothing was saved): Keycloak %s callbacks: %w", keycloak.ForwardAuthClient, err)}
		}
		defer func() {
			if retErr == nil {
				return
			}
			if err := h.idp.UpdateForwardAuthCallbacks(context.Background(), remove, add); err != nil {
				log.Printf("settings: %s: undoing the %s callback change failed: %v", id, keycloak.ForwardAuthClient, err)
			}
		}()
	}

	// The directory snapshot the env's group records are checked against
	// (network: before mu).
	members := h.groupSnapshot(id)
	h.mu.Lock()
	// A restore or delete may have started since SaveSettings checked,
	// or a folder assignment committed.
	if err := h.pendingLocked(id); err != nil {
		h.mu.Unlock()
		return res, false, err
	}
	// AI support switched on since SaveSettings switched it off (G43):
	// never commit a policy reaching LoA 3 with a companion on.
	if on := h.aiOffForSaveLocked(t, u); len(on) > 0 {
		h.mu.Unlock()
		return res, false, statusErr(409, "%s: AI support for %s was switched on meanwhile and the policy %s: save again", id, strings.Join(on, ", "), mtlsRefusal)
	}
	if err := folderSaveCheck(t, h.st.Settings[id], h.st.Folders, u); err != nil {
		h.mu.Unlock()
		return res, false, err
	}
	prevSignIn, hadSignIn := h.st.SignIn[id]
	prev, hadPrev := h.st.Settings[id]
	undo := func() {
		if hadSignIn {
			h.st.SignIn[id] = prevSignIn
		} else {
			delete(h.st.SignIn, id)
		}
		if hadPrev {
			h.st.Settings[id] = prev
		} else {
			delete(h.st.Settings, id)
		}
	}
	signInChanged := false
	if u.SignIn != nil {
		before := h.accessLocked(t).SignIn
		if *u.SignIn == SignInNative {
			h.st.SignIn[id] = state.SignInNative
		} else {
			delete(h.st.SignIn, id)
		}
		signInChanged = h.accessLocked(t).SignIn != before
	}
	next, effects, own, changes, err := h.nextSettingsLocked(t, prev, parsed)
	if err != nil {
		undo()
		h.mu.Unlock()
		return res, false, err
	}
	if next.IsZero() {
		delete(h.st.Settings, id)
	} else {
		h.st.Settings[id] = next
	}
	live := h.findLocked(id)
	enabled = live != nil && live.Enabled
	if enabled {
		if err := h.checkPortCollisionsLocked(t); err != nil {
			undo()
			h.mu.Unlock()
			return res, false, err
		}
	}
	// Secret values go to their store before state names them (the
	// metadata): a failed write changes nothing.
	restoreSecrets, err := h.applySecretsLocked(id, parsed.secrets)
	if err != nil {
		undo()
		h.mu.Unlock()
		return res, false, err
	}
	accBefore := h.accessAuditLocked(id)
	publicChanged, err := h.applyPublicUpdateLocked(t, u)
	if err != nil {
		restoreSecrets()
		undo()
		h.mu.Unlock()
		return res, false, err
	}
	policyChanged := false
	if u.Inherit {
		if _, had := h.st.AuthPolicies[id]; had {
			delete(h.st.AuthPolicies, id)
			policyChanged = true
		}
	} else if u.Policy != nil {
		h.st.AuthPolicies[id] = policy.Normalize(*u.Policy)
		policyChanged = true
	}
	if policyChanged {
		delete(h.st.LegacyPassword, id)
	}
	accChanges := accessChanges(accBefore, h.accessAuditLocked(id))
	if signInChanged {
		if h.accessLocked(t).SignIn == SignInNative {
			log.Printf("settings: WARNING: %s now uses the app's own login only — its routers have no Portcullis sign-in (TLS tier public@file)", id)
		} else {
			log.Printf("settings: %s: Portcullis sign-in, then the app's own login", id)
		}
	}
	h.refreshPublishedLocked()
	h.saveLocked()
	effective := h.effectivePolicyLocked(t)
	// The override reads state (policy → TLS tier): render under the lock.
	before, _ := os.ReadFile(h.overridePath(id))
	overrideErr := h.generateOverrideLocked(t, next)
	after, _ := os.ReadFile(h.overridePath(id))
	if !bytes.Equal(before, after) {
		effects = append(effects, settings.EffectRestart)
	}
	// Options with an env delivery go into the .env — every one of them,
	// empty when unset, so clearing a field actually clears it — and so
	// do the ports the app binds itself (network_mode: host, ranges).
	envErr := h.writeOptionEnvLocked(t, members)
	h.mu.Unlock()
	res.changes = changes
	for _, c := range changes {
		if !slices.Contains(res.keys, c.key) {
			res.keys = append(res.keys, c.key)
		}
	}
	// The policy and public-exception changes are audited too (G37), but
	// aren't settings keys (Changed, warnings).
	res.changes = append(res.changes, accChanges...)
	// A disabled instance restarts nothing: its effect is the changed
	// options' own (applies).
	if enabled {
		res.effect = settings.Strongest(effects...)
	} else {
		res.effect = settings.Strongest(own...)
	}
	// Committed: a failed override or .env write is a warning (audited),
	// and the delivery still runs.
	if overrideErr != nil {
		res.writeErrs = append(res.writeErrs, statusErr(500, "settings saved but override generation failed: %v", overrideErr))
	}
	if envErr != nil {
		res.writeErrs = append(res.writeErrs, statusErr(500, "settings saved but the env file write failed: %v", envErr))
	}

	if policyChanged || publicChanged || signInChanged {
		h.writePolicyLogged()
	}
	if policyChanged && h.idp != nil {
		acr := policy.ACR(effective)
		for _, c := range t.Manifest.Clients {
			if err := h.idp.UpdateClientACR(context.Background(), h.clientSpec(t, c, acr)); err != nil {
				log.Printf("auth-policy: keycloak client %s update failed: %v", c.ClientID, err)
			}
		}
	}
	return res, enabled, nil
}

// nextSettingsLocked applies parsed to cur: the new settings, the effect
// of each changed option on a running instance (a path, port or
// env-delivered option change restarts: compose reads them only at
// create), each changed option's own effect (its applies), and the
// changes for the audit. The instance options must then still satisfy
// their required and requires rules. Caller must hold mu.
func (h *Hub) nextSettingsLocked(t *templates.Template, cur state.InstanceSettings, parsed *parsedSettings) (state.InstanceSettings, []string, []string, []settingChange, error) {
	next := cur.Clone()
	var effects, own []string
	var changes []settingChange
	if parsed.ports != nil {
		next.Ports = nil
		if len(parsed.ports) > 0 {
			next.Ports = maps.Clone(parsed.ports)
		}
		keys := map[string]bool{}
		for k := range cur.Ports {
			keys[k] = true
		}
		for k := range next.Ports {
			keys[k] = true
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			a, okA := cur.Ports[k]
			b, okB := next.Ports[k]
			if a == b && okA == okB {
				continue
			}
			changes = append(changes, settingChange{key: k, scope: "port", before: showPort(a, okA), after: showPort(b, okB)})
			effects = append(effects, settings.EffectRestart)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(parsed.values)) {
		o := optionByKey(t, k)
		before, okB := h.effectiveValue(t, o, cur)
		v := parsed.values[k]
		if v == nil {
			delete(next.Values, k)
			delete(next.Types, k)
		} else {
			if next.Values == nil {
				next.Values = map[string]any{}
			}
			if next.Types == nil {
				next.Types = map[string]string{}
			}
			next.Values[k] = storedValue(v)
			next.Types[k] = o.Type
		}
		after, okA := h.effectiveValue(t, o, next)
		if okA && o.Required && settingsEmpty(after) || !okA && o.Required {
			return next, nil, nil, nil, statusErr(400, "setting %s is required", k)
		}
		if okA == okB && reflect.DeepEqual(after, before) {
			continue
		}
		changes = append(changes, settingChange{key: k, scope: templates.ScopeInstance, before: h.showValue(o, before, okB), after: h.showValue(o, after, okA)})
		e := settings.EffectOf(o.EffectiveApplies())
		own = append(own, e)
		if o.Type == templates.TypePath || len(envDeliveries(o)) > 0 {
			e = settings.EffectRestart
		}
		effects = append(effects, e)
	}
	now := time.Now().UTC()
	for _, k := range slices.Sorted(maps.Keys(parsed.secrets)) {
		o := optionByKey(t, k)
		op := parsed.secrets[k]
		_, had := cur.Secrets[k]
		detail := secretReplaced
		if op.clear {
			if !had {
				continue
			}
			if o.Required {
				return next, nil, nil, nil, statusErr(400, "setting %s is required", k)
			}
			delete(next.Secrets, k)
			detail = secretCleared
		} else {
			if next.Secrets == nil {
				next.Secrets = map[string]state.SecretMeta{}
			}
			next.Secrets[k] = state.SecretMeta{UpdatedAt: now, Generated: op.generated}
			if op.generated {
				detail = secretGenerated
			}
		}
		changes = append(changes, settingChange{key: k, scope: templates.ScopeInstance, secret: detail})
		e := settings.EffectOf(o.EffectiveApplies())
		own = append(own, e)
		if len(envDeliveries(o)) > 0 {
			e = settings.EffectRestart
		}
		effects = append(effects, e)
	}
	if len(next.Secrets) == 0 {
		next.Secrets = nil
	}
	if err := staleRebind(cur, parsed); err != nil {
		return next, nil, nil, nil, err
	}
	// Instance group values (F3): stored with the ids they were bound
	// to; a name stored against another id of that group is 409 (the
	// group was re-created since: removed and added again, never rebound
	// silently).
	for _, k := range slices.Sorted(maps.Keys(parsed.groupIDs)) {
		ids := parsed.groupIDs[k]
		for _, n := range slices.Sorted(maps.Keys(ids)) {
			if old, ok := cur.GroupIDs[k][n]; ok && old != 0 && old != ids[n] {
				return next, nil, nil, nil, statusErr(409, "setting %s: group %s was re-created since it was saved (id %d, now %d): remove it, save, then add it again", k, n, old, ids[n])
			}
			// The id the panel showed must still be the stored one: a
			// stale panel never re-binds a purged or re-created group.
			if sent, ok := parsed.sentValueIDs[k][n]; ok && (cur.GroupIDs[k][n] != sent || ids[n] != sent) {
				return next, nil, nil, nil, statusErr(409, "setting %s: group %s was re-created since it was saved (or removed from the setting): reload, then add it again", k, n)
			}
		}
		if len(ids) == 0 {
			delete(next.GroupIDs, k)
			continue
		}
		if next.GroupIDs == nil {
			next.GroupIDs = map[string]map[string]int{}
		}
		next.GroupIDs[k] = maps.Clone(ids)
	}
	if len(next.GroupIDs) == 0 {
		next.GroupIDs = nil
	}
	ge, gown, gchanges := h.groupSettingsChangesLocked(t, cur, &next, parsed)
	effects, own, changes = append(effects, ge...), append(own, gown...), append(changes, gchanges...)
	if len(parsed.values)+len(parsed.secrets) > 0 && t.Manifest.Settings != nil {
		touched := map[string]bool{}
		for k := range parsed.values {
			touched[k] = true
		}
		for k := range parsed.secrets {
			touched[k] = true
		}
		if err := settings.CheckRequiresTouched(t.Manifest.Settings, h.requiresValuesLocked(t, next), touched); err != nil {
			return next, nil, nil, nil, statusErr(400, "%v", err)
		}
	}
	if len(next.Values) == 0 {
		next.Values = nil
	}
	if len(next.Types) == 0 {
		next.Types = nil
	}
	return next, effects, own, changes, nil
}

// applySecretsLocked writes ops into instance id's secrets store and
// returns how to put the previous store back. Errors carry no value.
// Caller must hold mu (write).
func (h *Hub) applySecretsLocked(id string, ops map[string]secretOp) (func(), error) {
	if len(ops) == 0 {
		return func() {}, nil
	}
	prev, err := h.secretValues(id)
	if err != nil {
		return nil, statusErr(500, "%v", err)
	}
	next := maps.Clone(prev)
	for k, op := range ops {
		if op.clear {
			delete(next, k)
		} else {
			next[k] = op.value
		}
	}
	if err := h.writeSecrets(id, next); err != nil {
		return nil, statusErr(500, "nothing was saved: %v", err)
	}
	return func() {
		if err := h.writeSecrets(id, prev); err != nil {
			log.Printf("settings: %s: putting the previous secrets back failed: %v", id, err)
		}
	}, nil
}

// settingsEmpty reports an empty value (required options).
func settingsEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case []map[string]any:
		return len(x) == 0
	}
	return false
}

// auditSettings records a save: one settings.change per changed (key,
// scope, group) once the change is committed — also when writing the
// override or env afterwards failed, which is one more entry (target the
// instance, detail "delivery") carrying that error; a save refused or
// failed before its commit is one entry per requested key. Called with
// no lock held (auditOp takes mu).
func (h *Hub) auditSettings(id string, actor directory.Actor, u SettingsUpdate, changes []settingChange, err error) {
	if len(changes) > 0 {
		for _, c := range changes {
			d := "scope=" + c.scope
			if c.group != "" {
				d += " group=" + c.group
			}
			if c.secret != "" {
				d += ": " + c.secret
			} else {
				d += ": " + c.before + " -> " + c.after
			}
			h.auditOp(actor, "settings.change", id+"/"+c.key, d, nil)
		}
		if err != nil {
			h.auditOp(actor, "settings.change", id, "delivery", err)
		}
		return
	}
	if err != nil {
		var keys []string
		if u.Policy != nil || u.Inherit {
			keys = append(keys, "auth_policy")
		}
		if u.PublicAccess != nil || u.PublicAccessDefault {
			keys = append(keys, "public_access")
		}
		if u.PublicMode != nil {
			keys = append(keys, "public_mode")
		}
		if u.PublicTokens != nil {
			keys = append(keys, "public_tokens")
			// The refusal may quote a submitted token in any form: the
			// audit gets a fixed text, never err's.
			err = PublicTokenAuditErr(err)
		}
		for k := range u.Ports {
			keys = append(keys, k)
		}
		for k := range u.Values {
			keys = append(keys, k)
		}
		for k := range u.Person {
			keys = append(keys, k)
		}
		for k := range u.Groups {
			keys = append(keys, k)
		}
		for k := range u.Secrets {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range slices.Compact(keys) {
			h.auditOp(actor, "settings.change", id+"/"+clip(k, 64), "", err)
		}
	}
}

// accessAudit is an instance's policy and public exceptions as the audit
// shows them (G37): never a token, only how many.
type accessAudit struct {
	policy, access, mode string
	tokens               []string
}

// accessAuditLocked reads id's stored policy and public choices. Caller
// holds mu.
func (h *Hub) accessAuditLocked(id string) accessAudit {
	a := accessAudit{policy: "inherited", access: "default", mode: "default"}
	if p, ok := h.st.AuthPolicies[id]; ok {
		a.policy = showPolicy(p)
	}
	if on, ok := h.st.PublicAccess[id]; ok {
		a.access = "off"
		if on {
			a.access = "on"
		}
	}
	if m, ok := h.st.PublicMode[id]; ok && m != "" {
		a.mode = m
	}
	a.tokens = slices.Sorted(slices.Values(h.st.PublicTokens[id]))
	return a
}

// ShowPolicy is an auth policy as the audit shows it ("f1,f2 (op)").
func ShowPolicy(p policy.AuthPolicy) string { return showPolicy(p) }

func showPolicy(p policy.AuthPolicy) string {
	d := strings.Join(p.Factors, ",")
	if d == "" {
		d = "none"
	}
	if p.Op != "" {
		d += " (" + p.Op + ")"
	}
	return clip(d, 200)
}

// accessChanges: the settings.change entries (scope policy / public)
// between two accessAudits.
func accessChanges(a, b accessAudit) []settingChange {
	var out []settingChange
	if a.policy != b.policy {
		out = append(out, settingChange{key: "auth_policy", scope: "policy", before: a.policy, after: b.policy})
	}
	if a.access != b.access {
		out = append(out, settingChange{key: "public_access", scope: "public", before: a.access, after: b.access})
	}
	if a.mode != b.mode {
		out = append(out, settingChange{key: "public_mode", scope: "public", before: a.mode, after: b.mode})
	}
	if !slices.Equal(a.tokens, b.tokens) {
		after := tokenCount(len(b.tokens))
		if len(a.tokens) == len(b.tokens) {
			after += " (changed)"
		}
		out = append(out, settingChange{key: "public_tokens", scope: "public", before: tokenCount(len(a.tokens)), after: after})
	}
	return out
}

func tokenCount(n int) string {
	if n == 1 {
		return "1 token"
	}
	return fmt.Sprintf("%d tokens", n)
}

// PublicTokenAuditErr is the error the audit records for a save refused
// (or failed) while it carried public tokens: "public token refused" and
// the refusal class (its status), never err's text, which may quote a
// token in any form. The API answer keeps err (the admin sent the token).
func PublicTokenAuditErr(err error) error {
	if err == nil {
		return nil
	}
	st := errStatus(err)
	return &StatusError{Status: st, Err: fmt.Errorf("public token refused (%d)", st)}
}

// signInCallbackChange: the callback URIs a sign-in mode change of
// enabled instance t adds and removes (signInExtraHostsLocked under the
// current and the new mode; nothing for a disabled instance or no change).
func (h *Hub) signInCallbackChange(t *templates.Template, mode *string) (add, remove []string) {
	if mode == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.st.IsEnabled(t.ID) {
		return nil, nil
	}
	before := callbackURIs(h.signInExtraHostsLocked(t))
	prev, had := h.st.SignIn[t.ID]
	if *mode == SignInNative {
		h.st.SignIn[t.ID] = state.SignInNative
	} else {
		delete(h.st.SignIn, t.ID)
	}
	after := callbackURIs(h.signInExtraHostsLocked(t))
	if had {
		h.st.SignIn[t.ID] = prev
	} else {
		delete(h.st.SignIn, t.ID)
	}
	return minus(after, before), minus(before, after)
}

// DefaultPolicy returns the global default policy.
func (h *Hub) DefaultPolicy() policy.AuthPolicy {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.Default()
}

// DefaultPolicyLegacy reports whether the stored global default named the
// removed "password" factor and was normalised on load.
func (h *Hub) DefaultPolicyLegacy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.st.LegacyPassword[""]
}

// SetDefaultPolicy validates and stores a new global default and, if it
// changed, propagates it in the background. Returns whether it changed.
// The default may name any factor (each app enforces what it can of it),
// but not the removed "password" or unknown ones.
func (h *Hub) SetDefaultPolicy(p policy.AuthPolicy) (bool, error) {
	if msg := policy.CapabilityFor("forward-auth").Check(p); msg != "" {
		return false, statusErr(400, "default policy: %s", msg)
	}
	norm := policy.Normalize(p)
	h.mu.Lock()
	// Inheriting instances must have AI support off first (G43:
	// SetDefaultPolicyAs switches it off; a racing switch-on is refused).
	if on := h.defaultPolicyAIOffLocked(norm); len(on) > 0 {
		h.mu.Unlock()
		ids := slices.Sorted(maps.Keys(on))
		return false, statusErr(409, "AI support is on for %s, whose policy the new default %s: switch it off first (or save the default again)", strings.Join(ids, ", "), mtlsRefusal)
	}
	changed := !policy.Same(h.st.Default(), norm)
	h.st.SetDefault(norm)
	delete(h.st.LegacyPassword, "")
	h.saveLocked()
	h.mu.Unlock()
	if !changed {
		return false, nil
	}
	h.writePolicyLogged()
	h.goBackground(h.applyDefaultPolicy)
	return true, nil
}

// applyDefaultPolicy propagates a changed default to every enabled app that
// inherits it: regenerate overrides (TLS tier), push the Keycloak acr, and
// recreate containers whose labels changed.
func (h *Hub) applyDefaultPolicy() {
	h.defaultPolicyMu.Lock()
	defer h.defaultPolicyMu.Unlock()
	type job struct {
		t       templates.Template
		restart bool
		acr     string
	}
	var jobs []job
	h.mu.Lock()
	for _, id := range h.st.Enabled {
		if _, override := h.st.AuthPolicies[id]; override {
			continue
		}
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		before, _ := os.ReadFile(h.overridePath(id))
		if err := h.generateOverrideLocked(t, h.st.Settings[id]); err != nil {
			log.Printf("default-policy: override for %s failed: %v", id, err)
			continue
		}
		after, _ := os.ReadFile(h.overridePath(id))
		changed := !bytes.Equal(before, after)
		if changed || len(t.Manifest.Clients) > 0 {
			jobs = append(jobs, job{t: *t, restart: changed, acr: policy.ACR(h.effectivePolicyLocked(t))})
		}
	}
	h.mu.Unlock()

	for _, j := range jobs {
		if h.idp != nil {
			for _, c := range j.t.Manifest.Clients {
				if err := h.idp.UpdateClientACR(context.Background(), h.clientSpec(&j.t, c, j.acr)); err != nil {
					log.Printf("default-policy: keycloak client %s update failed: %v", c.ClientID, err)
				}
			}
		}
		if j.restart {
			h.Restart(j.t)
		}
	}
}

// ── Expert mode (compose layers: useroverride.go) ─────────

// Env returns an app's .env variables and compose service names. The
// variables of secret options are shown as [set] (write-only: set them
// under Settings).
// secretMask is the predicate Expert Env masks a variable by (and SaveEnv
// takes [set] back as unchanged by): a non-empty value of a secret
// option's env name, or of a variable the template doesn't declare
// (declaredEnvNames, Hub-set names included) holding a stored secret's
// value — a line a template update left behind (an env variable renamed,
// an option no longer secret), or an admin's copy of a secret —, every
// PORTCULLIS_AI_PROVIDER_* value and any variable holding a model
// provider secret (G30(a)).
func (h *Hub) secretMask(t *templates.Template) (func(name, value string) bool, error) {
	secrets, err := h.secretValues(t.ID)
	if err != nil {
		return nil, err
	}
	stored := map[string]bool{}
	for _, v := range secrets {
		if v != "" {
			stored[v] = true
		}
	}
	// G30(a): every provider variable (PORTCULLIS_AI_PROVIDER_*) is masked,
	// and so is any variable — declared or reserved too — holding a
	// provider secret's value (a separate set: the instance's own stored
	// values keep their narrower rule).
	provider, err := h.providerSecretValues()
	if err != nil {
		return nil, err
	}
	providerStored := map[string]bool{}
	for _, v := range provider {
		providerStored[v] = true
	}
	names := secretOptionEnvNames(t)
	declared := declaredEnvNames(t)
	return func(n, v string) bool {
		return v != "" && (names[n] || strings.HasPrefix(n, ProviderVarPrefix) || providerStored[v] ||
			stored[v] && !declared[n] && !templates.ReservedVar(n))
	}, nil
}

func (h *Hub) Env(id string) (map[string]string, []string, error) {
	t := h.Template(id)
	if t == nil {
		return nil, nil, ErrNotFound
	}
	vars := readEnvFile(h.envPath(id))
	masked, err := h.secretMask(t)
	if err != nil {
		return nil, nil, err
	}
	for n, v := range vars {
		if masked(n, v) {
			vars[n] = settings.SecretShown
		}
	}
	return vars, templates.Services(t.ReadCompose()), nil
}

// SaveEnv sets variables in an app's .env. The Expert UI posts every
// variable back: a variable an option owns (its env delivery) or the Hub
// sets (instance variables, PORTCULLIS_*) is skipped when its value is
// unchanged (a set secret's [set] counts as unchanged) and refused (400)
// when it was changed — options are set under Settings, which writes
// them.
func (h *Hub) SaveEnv(id string, vars map[string]string) error {
	_, err := h.SaveEnvChanged(id, vars)
	return err
}

// SaveEnvChanged is SaveEnv, also returning the names of the variables it
// wrote (sorted; never their values): the API's audit detail.
func (h *Hub) SaveEnvChanged(id string, vars map[string]string) ([]string, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	owners := optionEnvOwners(t)
	masked, err := h.secretMask(t)
	if err != nil {
		return nil, err
	}
	// The read-modify-write under mu, as every other .env writer's.
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.pendingLocked(id); err != nil {
		return nil, err
	}
	cur := readEnvFile(h.envPath(id))
	write := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(vars)) {
		v := vars[k]
		if !templates.EnvKeyRe.MatchString(k) || templates.HasControlChars(v) {
			return nil, statusErr(400, "invalid variable %q (keys: [A-Za-z_][A-Za-z0-9_]*, values: no newlines)", k)
		}
		if v == cur[k] || (v == settings.SecretShown && masked(k, cur[k])) {
			continue // posted back unchanged (a masked value as Env showed it)
		}
		o, owned := owners[k]
		hubSet := templates.ReservedVar(k) || k == "PORTCULLIS_DOMAIN"
		if !owned && !hubSet {
			write[k] = v
			continue
		}
		// Routing, hostnames and names come from the Hub, never the env.
		if hubSet {
			return nil, statusErr(400, "%s is set by the Hub", k)
		}
		return nil, statusErr(400, "%s belongs to the setting %s: set it under Settings", k, o)
	}
	if err := setEnvVars(h.envPath(id), write, false); err != nil {
		return nil, statusErr(500, "failed to write env: %v", err)
	}
	return slices.Sorted(maps.Keys(write)), nil
}

// seedPlaceholders are the group_values placeholders in the order their
// rows are seeded: the admin group first (under priority the more
// specific group wins), then the access group.
var seedPlaceholders = []string{templates.PlaceholderAdminGroup, templates.PlaceholderAccessGroup}

// seedSettingsLocked gives every per-person option of instance t that
// has no stored configuration its template start: the default
// (canonical) and one row per group_values placeholder, stored as the
// placeholder with no group id (unbound: it grants nothing until bound,
// Task 8). Instance options store nothing: their defaults apply
// implicitly. Run on create, on enable, after a restore and by "create
// missing groups"; never changes what is already stored. Reports
// whether it changed state. Caller must hold mu (write).
func (h *Hub) seedSettingsLocked(t *templates.Template) bool {
	s := h.st.Settings[t.ID]
	changed := false
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.EffectiveScope() != templates.ScopePerson || hubSetOption(o) {
			continue
		}
		if _, ok := s.Person[o.Key]; ok {
			continue
		}
		def, err := h.kinds.Parse(o, o.Default)
		if err != nil {
			log.Printf("settings: %s: %s: the template default doesn't parse (%v): not seeded", t.ID, o.Key, err)
			continue
		}
		p := state.PersonSetting{Default: storedValue(def)}
		for _, ph := range seedPlaceholders {
			raw, ok := o.GroupValues[ph]
			if !ok {
				continue
			}
			v, err := h.kinds.Parse(o, raw)
			if err != nil {
				log.Printf("settings: %s: %s: group_values[%s] doesn't parse (%v): not seeded", t.ID, o.Key, ph, err)
				continue
			}
			p.Rows = append(p.Rows, state.GroupValue{Group: ph, Value: storedValue(v)})
		}
		if s.Person == nil {
			s.Person = map[string]state.PersonSetting{}
		}
		if s.Types == nil {
			s.Types = map[string]string{}
		}
		s.Person[o.Key] = p
		s.Types[o.Key] = o.Type
		changed = true
	}
	if changed {
		h.st.Settings[t.ID] = s
	}
	return changed
}

// seedSettings is seedSettingsLocked for instance id (saved when it
// changed anything).
func (h *Hub) seedSettings(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t := h.findLocked(id); t != nil && h.seedSettingsLocked(t) {
		h.saveLocked()
	}
}
