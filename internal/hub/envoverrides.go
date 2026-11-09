package hub

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Env overrides (contract §11.9 "Env overrides"): the admin overrides a
// variable of an instance's .env, or adds one of their own, one at a
// time. Stored on the state entry (state.yaml env_overrides, name →
// value, never a secret) and written single-quoted into the .env after
// every template, option and Hub value — the block that starts at
// envOverrideMarker, always the file's last lines — so they win. Every
// .env writer re-checks them against the current template
// (envOverrideBlockLocked): one the rules now refuse is skipped, never
// written.

// Env row sources (EnvRow.Source).
const (
	EnvSourceTemplate = "template"
	EnvSourceHub      = "hub"
	EnvSourceOption   = "option"
	EnvSourceCustom   = "custom"
)

// envOverrideMarker starts the overrides' block of an .env: every line
// after it is an override (parseEnvRaw stops there; setEnvVars and
// rewriteEnvPrefix keep the block last).
const envOverrideMarker = "# Env overrides (Portcullis Hub, Expert): written last, they win"

// envOverrideValueMax is the longest override value (bytes).
const envOverrideValueMax = 4096

// envOverrideNameRe is an override's variable name (§11.9).
var envOverrideNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// errSecretsNotOverridden is the refusal of a secret's variable (or a
// value that is a secret's).
const errSecretsNotOverridden = "secrets aren't overridden here: use Settings"

// EnvRow is one variable of an instance's environment (GET
// /api/instances/{id}/env). Default is the value without the admin's
// override (a secret's is "[set]", "" when unset — never the value);
// Value the stored override ("" when none, and always "" on a secret
// row); HubSet: the row can't be overridden (hub, option and every
// secret); Secret: Default is masked.
type EnvRow struct {
	Name       string `json:"name"`
	Default    string `json:"default"`
	Source     string `json:"source"`
	Value      string `json:"value"`
	Overridden bool   `json:"overridden"`
	HubSet     bool   `json:"hub_set"`
	Secret     bool   `json:"secret"`
}

// EnvChange is an override's or reset's answer: the variable's row (nil
// for a removed custom variable) and the effect (EffectRestart: an
// enabled instance restarts through the delivery engine; EffectNone).
type EnvChange struct {
	Row    *EnvRow `json:"row"`
	Effect string  `json:"effect"`
}

// splitEnvOverrides splits an .env's lines into the Hub's part and the
// overrides' block (the marker line and every line after it; nil: none).
func splitEnvOverrides(lines []string) (head, block []string) {
	for i, l := range lines {
		if strings.TrimSpace(l) == envOverrideMarker {
			return lines[:i:i], lines[i:]
		}
	}
	return lines, nil
}

// envRules is what an override of template t is checked against: the
// names the Hub sets, the options' (and ports') variables, the secrets'
// names and the secret-value predicate (secretMask).
type envRules struct {
	t           *templates.Template
	owners      map[string]string // option-set variable → setting key
	secretNames map[string]bool
	masked      func(name, value string) bool
}

// envRulesFor are t's rules. It reads the instance's and the model
// providers' secrets stores (no lock needed; callers may hold mu): an
// unreadable store is an error (fail closed).
func (h *Hub) envRulesFor(t *templates.Template) (*envRules, error) {
	masked, err := h.secretMask(t)
	if err != nil {
		return nil, err
	}
	owners := optionEnvOwners(t)
	for _, p := range t.Manifest.Ports {
		owners[p.Key], owners[p.Key+"_BIND"] = p.Key, p.Key
	}
	// A folder's gid_env join sets its variable to the folder gid
	// (folderEnvIn): the option's, whether or not a folder is assigned
	// right now.
	for _, o := range mountOptions(t) {
		if o.Folder != nil && o.Folder.Join() == templates.JoinGIDEnv && o.Folder.RunsAs != nil && o.Folder.RunsAs.GIDEnv != "" {
			owners[o.Folder.RunsAs.GIDEnv] = o.Key
		}
	}
	return &envRules{t: t, owners: owners, secretNames: SecretEnvNames(t), masked: masked}, nil
}

// hubSet: the Hub sets name (every PORTCULLIS_* and COMPOSE_* variable,
// the instance variables — COMPOSE_PROFILES among them —, the AI and
// model provider variables).
func (r *envRules) hubSet(name string) bool {
	if strings.HasPrefix(name, "PORTCULLIS_") || strings.HasPrefix(name, "COMPOSE_") ||
		templates.ReservedVar(name) || HubPublicVar(name) {
		return true
	}
	_, inst := r.t.InstanceEnv[name]
	return inst
}

// secret: name always holds a secret (SecretEnvNames: a client's
// secret_env, a generated env entry, a secret option's env name) or
// looks like a secret's (SecretLookingEnvName, the redactor's rule).
func (r *envRules) secret(name string) bool {
	return r.secretNames[name] || (SecretLookingEnvName(name) && !HubPublicVar(name))
}

// nameRefusal is why name can't be overridden ("" = it can).
func (r *envRules) nameRefusal(name string) string {
	switch {
	case !envOverrideNameRe.MatchString(name):
		return fmt.Sprintf("invalid variable name %s: [A-Za-z_][A-Za-z0-9_]*, at most 128 characters", clipQuoted(name))
	case r.hubSet(name):
		return name + " is set by the Hub"
	case r.secret(name):
		return name + ": " + errSecretsNotOverridden
	}
	if key, ok := r.owners[name]; ok {
		return name + " is set by setting " + key + ": change it under Settings"
	}
	return ""
}

// valueRefusal is why value can't be name's override ("" = it can): too
// long, not single-quotable (', \, a line break or another control
// character), a mask, or a secret's value (secretMask: a stored secret
// in a variable the template doesn't declare, a model provider secret).
func (r *envRules) valueRefusal(name, value string) string {
	switch {
	case len(value) > envOverrideValueMax:
		return fmt.Sprintf("the value of %s is longer than %d bytes", name, envOverrideValueMax)
	case !utf8.ValidString(value):
		return "the value of " + name + " is not valid UTF-8"
	case strings.ContainsAny(value, `'\`) || templates.HasControlChars(value):
		return "the value of " + name + ` can't hold ', \, a line break or another control character (it is written single-quoted)`
	case isEnvMask(value):
		return "the value of " + name + " is a mask ([set], [secret]), not a value"
	case r.masked(name, value):
		return name + ": " + errSecretsNotOverridden
	}
	return ""
}

// refusal is nameRefusal, then valueRefusal.
func (r *envRules) refusal(name, value string) string {
	if why := r.nameRefusal(name); why != "" {
		return why
	}
	return r.valueRefusal(name, value)
}

// envOverrideDropText is the warning and op-record line of a stored
// override the current template refuses.
func envOverrideDropText(name, why string) string {
	return "env override " + name + " dropped: " + why
}

// envOverrideBlockLocked is the overrides' block of t's .env: the marker,
// then NAME='<value>' per stored override the rules allow, sorted (nil:
// none). A refused one is skipped, never written (fail closed), and
// recorded (setEnvOverrideDrops: logged once, the panel's env:values
// unit, the running operation's record). Caller holds mu.
func (h *Hub) envOverrideBlockLocked(t *templates.Template) ([]string, error) {
	ov := h.st.Instances[t.ID].EnvOverrides
	if len(ov) == 0 {
		h.setEnvOverrideDrops(t.ID, nil)
		return nil, nil
	}
	rules, err := h.envRulesFor(t)
	if err != nil {
		return nil, err
	}
	var lines, drops []string
	for _, n := range slices.Sorted(maps.Keys(ov)) {
		if why := rules.refusal(n, ov[n]); why != "" {
			drops = append(drops, envOverrideDropText(n, why))
			continue
		}
		lines = append(lines, envLine(n, ov[n], true))
	}
	h.setEnvOverrideDrops(t.ID, drops)
	if len(lines) == 0 {
		return nil, nil
	}
	return append([]string{envOverrideMarker}, lines...), nil
}

// writeEnvOverridesLocked writes t's overrides' block
// (envOverrideBlockLocked) as the last lines of its existing .env,
// keeping every other line; no change = no write; a missing .env =
// nothing (enable writes it whole). Caller holds mu.
func (h *Hub) writeEnvOverridesLocked(t *templates.Template) error {
	path := h.envPath(t.ID)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	block, err := h.envOverrideBlockLocked(t)
	if err != nil {
		return err
	}
	var lines []string
	if len(data) > 0 {
		lines = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	head, _ := splitEnvOverrides(lines)
	next := strings.Join(append(slices.Clone(head), block...), "\n") + "\n"
	if next == string(data) {
		return nil
	}
	return fsutil.WriteFileAtomic(path, []byte(next), 0600)
}

// setEnvOverrideDrops records instance id's skipped overrides, logging
// each new one once (the panel's env:values unit shows them; prepareUp
// adds them to the running operation's record: warnEnvOverrideDrops).
func (h *Hub) setEnvOverrideDrops(id string, drops []string) {
	sort.Strings(drops)
	h.envProblemsMu.Lock()
	defer h.envProblemsMu.Unlock()
	prev := h.envDrops[id]
	for _, d := range drops {
		if !slices.Contains(prev, d) {
			log.Printf("settings: %s: WARNING: %s (not written into the .env)", id, d)
		}
	}
	if len(drops) == 0 {
		delete(h.envDrops, id)
		return
	}
	if h.envDrops == nil {
		h.envDrops = map[string][]string{}
	}
	h.envDrops[id] = drops
}

// envOverrideDrops are instance id's skipped overrides (the last .env
// write's).
func (h *Hub) envOverrideDrops(id string) []string {
	h.envProblemsMu.Lock()
	defer h.envProblemsMu.Unlock()
	return slices.Clone(h.envDrops[id])
}

// warnEnvOverrideDrops adds instance id's skipped overrides to its
// running operation's record (an enable, start, restart or restore: the
// one that wrote the .env). Never under mu (the record's redaction reads
// state).
func (h *Hub) warnEnvOverrideDrops(id string) {
	drops := h.envOverrideDrops(id)
	if len(drops) == 0 {
		return
	}
	h.opRunsMu.Lock()
	run := h.opRuns[id]
	h.opRunsMu.Unlock()
	if run == nil {
		return
	}
	for _, d := range drops {
		run.p.Warn(d)
	}
}

// composeDefault is a ${VAR:-default} / ${VAR-default} of compose.yml:
// its text, and whether an empty value takes it too (":-").
type composeDefault struct {
	text       string
	emptyToo   bool
	hasDefault bool
}

// composeEnvDefaults are the defaults compose.yml's ${VAR:-word} and
// ${VAR-word} references give (the first reference with a default per
// variable; nested references stay literal text). $$ is an escaped $.
func composeEnvDefaults(s string) map[string]composeDefault {
	out := map[string]composeDefault{}
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if s[i+1] == '$' {
			i++
			continue
		}
		if s[i+1] != '{' {
			continue
		}
		// The matching brace (nested ${...} counted).
		depth, end := 0, -1
		for j := i + 1; j < len(s); j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = j
				break
			}
		}
		if end < 0 {
			return out
		}
		expr := s[i+2 : end]
		n := 0
		for n < len(expr) && (expr[n] == '_' || expr[n] >= 'A' && expr[n] <= 'Z' || expr[n] >= 'a' && expr[n] <= 'z' || n > 0 && expr[n] >= '0' && expr[n] <= '9') {
			n++
		}
		name, rest := expr[:n], expr[n:]
		var d composeDefault
		switch {
		case strings.HasPrefix(rest, ":-"):
			d = composeDefault{text: rest[2:], emptyToo: true, hasDefault: true}
		case strings.HasPrefix(rest, "-"):
			d = composeDefault{text: rest[1:], hasDefault: true}
		}
		if name != "" {
			if prev, seen := out[name]; !seen || !prev.hasDefault && d.hasDefault {
				out[name] = d
			}
		}
		i = end
	}
	return out
}

// EnvRows are instance id's environment rows (§11.9), sorted by name:
// one per variable of its .env (manifest env entries, generated values
// included; option env deliveries; port keys; the Hub's variables; any
// other line, shown as custom), per ${VAR:-default} / ${VAR-default}
// reference in compose.yml and per stored override. 404 unknown.
func (h *Hub) EnvRows(id string) ([]EnvRow, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	rules, err := h.envRulesFor(t)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	ov := maps.Clone(h.st.Instances[id].EnvOverrides)
	h.mu.RUnlock()
	return envRowsOf(rules, readEnvFile(h.envPath(id)), ov), nil
}

// envRowsOf are the rows of template rules.t with file (the .env's
// values without the overrides) and the stored overrides ov.
func envRowsOf(rules *envRules, file, ov map[string]string) []EnvRow {
	t := rules.t
	defaults := composeEnvDefaults(string(t.ReadCompose()))
	manifest := map[string]bool{}
	names := map[string]bool{}
	for n := range file {
		names[n] = true
	}
	for _, e := range t.Manifest.Env {
		manifest[e.Key], names[e.Key] = true, true
	}
	for n := range optionEnvOwners(t) {
		names[n] = true
	}
	for n := range t.InstanceEnv {
		names[n] = true
	}
	for n, d := range defaults {
		if d.hasDefault {
			names[n] = true
		}
	}
	for n := range ov {
		names[n] = true
	}
	refs := templates.EnvRefs(string(t.ReadCompose()))
	clients := map[string]bool{}
	for _, c := range t.Manifest.Clients {
		if c.SecretEnv != "" {
			clients[c.SecretEnv], names[c.SecretEnv] = true, true
		}
	}
	rows := make([]EnvRow, 0, len(names))
	for _, n := range slices.Sorted(maps.Keys(names)) {
		r := EnvRow{Name: n}
		fv, inFile := file[n]
		def := fv
		if d := defaults[n]; d.hasDefault && (!inFile || fv == "" && d.emptyToo) {
			def = d.text
		}
		_, owned := rules.owners[n]
		switch {
		case rules.hubSet(n) || clients[n]:
			r.Source = EnvSourceHub
		case owned:
			r.Source = EnvSourceOption
		case manifest[n] || refs[n] || defaults[n].hasDefault:
			r.Source = EnvSourceTemplate
		default:
			r.Source = EnvSourceCustom
		}
		r.Secret = rules.secret(n) || strings.HasPrefix(n, ProviderVarPrefix) || rules.masked(n, fv)
		v, stored := ov[n]
		r.Overridden = stored
		switch {
		case r.Secret:
			r.Default = ""
			if def != "" {
				r.Default = settings.SecretShown
			}
		default:
			r.Default, r.Value = def, v
		}
		r.HubSet = r.Secret || r.Source == EnvSourceHub || r.Source == EnvSourceOption
		rows = append(rows, r)
	}
	return rows
}

// envRowOf is name's row in rows (nil: none).
func envRowOf(rows []EnvRow, name string) *EnvRow {
	for i := range rows {
		if rows[i].Name == name {
			r := rows[i]
			return &r
		}
	}
	return nil
}

// SetEnvOverride stores value as instance id's override of name (PUT
// /api/instances/{id}/env/{name}, §11.9): a name without a row adds a
// custom variable. 400 refused (envRules; nothing stored), 404 unknown
// (or an implicit default instance that doesn't exist yet), 409 while
// deleting / restoring, during a shared-folder apply or busy. An
// enabled instance restarts through the delivery engine (effect
// restart, owed like a settings change); a disabled one gets the value
// at its next start. An unchanged value is effect none and not audited.
// Audited settings.env, target <id>/<name>, detail overridden or added
// (refusals refused), after mu; never the value.
func (h *Hub) SetEnvOverride(id, name, value string, actor directory.Actor) (*EnvChange, error) {
	return h.changeEnvOverride(id, name, &value, actor)
}

// ClearEnvOverride removes instance id's override of name (DELETE
// /api/instances/{id}/env/{name}): back to the default; an added
// variable is removed (row nil). No override stored: effect none, not
// audited. Audited settings.env detail reset. Refusals as
// SetEnvOverride's.
func (h *Hub) ClearEnvOverride(id, name string, actor directory.Actor) (*EnvChange, error) {
	return h.changeEnvOverride(id, name, nil, actor)
}

// changeEnvOverride is SetEnvOverride (value set) and ClearEnvOverride
// (value nil).
func (h *Hub) changeEnvOverride(id, name string, value *string, actor directory.Actor) (res *EnvChange, err error) {
	target := id + "/" + name
	if !envOverrideNameRe.MatchString(name) {
		target = id + "/(invalid name)"
	}
	detail := "refused"
	defer func() {
		// After mu (every lock below is released by now); 404 and
		// unchanged requests aren't audited.
		var se *StatusError
		if detail == "" || errors.Is(err, ErrNotFound) || errors.As(err, &se) && se.Status == 404 {
			return
		}
		h.auditOp(actor, "settings.env", target, detail, err)
	}()
	if strings.TrimSpace(actor.User) == "" {
		return nil, statusErr(400, "no signed-in user to audit the change as")
	}
	t := h.Template(id)
	if t == nil {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	// The rules read the secrets stores: before mu.
	rules, err := h.envRulesFor(t)
	if err != nil {
		return nil, statusErr(500, "reading the instance's secrets failed: %v", err)
	}
	if value != nil {
		why := rules.refusal(name, *value)
		if why == "" && rules.masked(name, readEnvFile(h.envPath(id))[name]) {
			// The variable holds a secret now (its row is masked).
			why = name + ": " + errSecretsNotOverridden
		}
		if why != "" {
			return nil, statusErr(400, "%s", why)
		}
	} else if !envOverrideNameRe.MatchString(name) {
		return nil, statusErr(400, "%s", rules.nameRefusal(name))
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return nil, h.busyErr(id, err)
	}
	defer unlock()

	h.mu.Lock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.Unlock()
		return nil, statusErr(404, "instance not found: %s", id)
	}
	if err := h.pendingLocked(id); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	e, had := h.st.Instances[id]
	if _, serr := os.Stat(h.envPath(id)); !had && !h.st.IsEnabled(id) && serr != nil {
		// An implicit default instance (never created, never started):
		// an entry would block its first create (§11.9 "First
		// instance"). One that ran before (its .env exists) takes them.
		h.mu.Unlock()
		return nil, statusErr(404, "instance %s doesn't exist yet: create the instance first", id)
	}
	if live.TemplateID != t.TemplateID || !maps.Equal(live.InstanceEnv, t.InstanceEnv) {
		h.mu.Unlock()
		return nil, statusErr(409, "instance %s changed meanwhile: retry", id)
	}
	if value != nil {
		// Checked again against the template as it is now (a source
		// sync may have run since the first check).
		lr, lerr := h.envRulesFor(live)
		if lerr != nil {
			h.mu.Unlock()
			return nil, statusErr(500, "reading the instance's secrets failed: %v", lerr)
		}
		if why := lr.refusal(name, *value); why != "" {
			h.mu.Unlock()
			return nil, statusErr(400, "%s", why)
		}
		rules = lr
	}
	cur, stored := e.EnvOverrides[name]
	switch {
	case value == nil && !stored, value != nil && stored && cur == *value:
		h.mu.Unlock()
		detail = ""
		return h.envChangeResult(id, name, settings.EffectNone)
	}
	prev := e
	if !had {
		e = state.Instance{ID: id, Template: live.TemplateID}
	}
	next := maps.Clone(e.EnvOverrides)
	if value == nil {
		delete(next, name)
		detail = "reset"
	} else {
		if next == nil {
			next = map[string]string{}
		}
		detail = "overridden"
		if !stored && !h.envNameHasRowLocked(live, rules, name) {
			detail = "added"
		}
		next[name] = *value
	}
	if len(next) == 0 {
		next = nil
	}
	e.EnvOverrides = next
	h.st.Instances[id] = e
	if serr := h.st.Save(h.statePath()); serr != nil {
		if had {
			h.st.Instances[id] = prev
		} else {
			delete(h.st.Instances, id)
		}
		h.mu.Unlock()
		return nil, statusErr(500, "saving the override failed: %v", serr)
	}
	// The .env now (a disabled instance's too); the restart's own write
	// re-checks it again.
	writeErr := h.writeEnvOverridesLocked(live)
	enabled := h.st.IsEnabled(id) && !h.instanceBusyLocked(id)
	h.mu.Unlock()
	if writeErr != nil {
		log.Printf("settings: %s: writing the env overrides failed (the next start writes them): %v", id, writeErr)
	}
	effect := settings.EffectNone
	if enabled {
		// Owed like a settings change; the engine's restart writes the
		// .env (prepareUp) before compose reads it.
		effect = settings.EffectRestart
		h.queueDelivery(id, TriggerSave, effect, 0)
	}
	return h.envChangeResult(id, name, effect)
}

// envNameHasRowLocked: name is one of t's variables without the admin's
// overrides (a row EnvRows shows with no override stored). Caller holds
// mu.
func (h *Hub) envNameHasRowLocked(t *templates.Template, rules *envRules, name string) bool {
	rows := envRowsOf(rules, readEnvFile(h.envPath(t.ID)), nil)
	return envRowOf(rows, name) != nil
}

// envChangeResult is the answer of a change of id's name with effect.
func (h *Hub) envChangeResult(id, name, effect string) (*EnvChange, error) {
	rows, err := h.EnvRows(id)
	if err != nil {
		return nil, err
	}
	return &EnvChange{Row: envRowOf(rows, name), Effect: effect}, nil
}

// pruneEnvOverridesLocked removes the stored overrides the current
// templates refuse (the prune after a source sync, §11.8: as removed
// options' values are), rewriting each instance's .env block; audited
// settings.env detail dropped (returned: after mu). Reports whether
// state changed. Caller holds mu (write).
func (h *Hub) pruneEnvOverridesLocked() (changed bool, audits []func()) {
	for _, id := range slices.Sorted(maps.Keys(h.st.Instances)) {
		e := h.st.Instances[id]
		if len(e.EnvOverrides) == 0 {
			continue
		}
		t := h.findLocked(id)
		if t == nil {
			continue // unresolved: nothing is written for it anyway
		}
		rules, err := h.envRulesFor(t)
		if err != nil {
			log.Printf("settings: %s: env overrides not checked (%v): they stay stored, and no .env write writes them until the check succeeds", id, err)
			continue
		}
		next := maps.Clone(e.EnvOverrides)
		for _, n := range slices.Sorted(maps.Keys(next)) {
			why := rules.refusal(n, next[n])
			if why == "" {
				continue
			}
			delete(next, n)
			log.Printf("settings: %s: %s", id, envOverrideDropText(n, why))
			target := id + "/" + n
			audits = append(audits, func() { h.auditOp(directory.Human(purgeActor), "settings.env", target, "dropped", nil) })
		}
		if len(next) == len(e.EnvOverrides) {
			continue
		}
		if len(next) == 0 {
			next = nil
		}
		e.EnvOverrides = next
		h.st.Instances[id] = e
		changed = true
		if err := h.writeEnvOverridesLocked(t); err != nil {
			log.Printf("settings: %s: rewriting the env overrides failed: %v", id, err)
		}
	}
	return changed, audits
}

// restoredEnvOverridesLocked checks restored instance t's stored
// overrides against its template (both restores, §11.9): a refused one
// is removed with the warning "env override <name> dropped: <reason>".
// An unreadable secrets store drops them all (fail closed). Caller holds
// mu (write); the caller saves state.
func (h *Hub) restoredEnvOverridesLocked(t *templates.Template) []string {
	e, ok := h.st.Instances[t.ID]
	if !ok || len(e.EnvOverrides) == 0 {
		return nil
	}
	var warnings []string
	next := maps.Clone(e.EnvOverrides)
	rules, err := h.envRulesFor(t)
	for _, n := range slices.Sorted(maps.Keys(next)) {
		why := ""
		if err != nil {
			why = "the instance's secrets can't be read to check it"
		} else {
			why = rules.refusal(n, next[n])
		}
		if why != "" {
			delete(next, n)
			warnings = append(warnings, envOverrideDropText(n, why))
		}
	}
	if len(next) == 0 {
		next = nil
	}
	e.EnvOverrides = next
	h.st.Instances[t.ID] = e
	return warnings
}
