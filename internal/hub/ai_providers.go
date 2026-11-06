package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Model providers (contract §15.12): the definitions live in state.yaml
// ai.providers (never a secret); their secret fields are write-only,
// stored only in <data>/ai/provider-secrets.json (0600, atomic; G71: the
// Hub's secret store for providers) as "<name>.<field>" → value, and
// shown as {set, updated_at}. Task 23 delivers them to the AI page
// instances that select a provider (PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>).

// ProviderKind is what a provider kind takes: its non-secret Fields (the
// API's names), the Required ones, its Secrets (needed to use it) and
// OptionalSecrets, and whether models.fetch is allowed.
type ProviderKind struct {
	Fields          []string
	Required        []string
	Secrets         []string
	OptionalSecrets []string
	Fetch           bool
}

// SecretFields are every secret field of the kind.
func (k ProviderKind) SecretFields() []string {
	return append(append([]string{}, k.Secrets...), k.OptionalSecrets...)
}

// Provider fields (the API's names).
const (
	pfInstance     = "instance"
	pfBaseURL      = "base_url"
	pfRegion       = "region"
	pfInstanceName = "instance_name"
	pfAPIVersion   = "api_version"
	pfDeployments  = "deployments"
)

// ProviderKinds are the kinds of §15.12 (= templates.ProviderKinds).
var ProviderKinds = map[string]ProviderKind{
	"litellm":           {Fields: []string{pfInstance}, Required: []string{pfInstance}, Secrets: []string{"key"}, Fetch: true},
	"openai_compatible": {Fields: []string{pfBaseURL}, Required: []string{pfBaseURL}, OptionalSecrets: []string{"key"}, Fetch: true},
	"anthropic":         {Fields: []string{pfBaseURL}, Secrets: []string{"key"}},
	"openai":            {Fields: []string{pfBaseURL}, Secrets: []string{"key"}, Fetch: true},
	"google":            {Fields: []string{pfBaseURL}, Secrets: []string{"key"}},
	"bedrock":           {Fields: []string{pfRegion}, Required: []string{pfRegion}, Secrets: []string{"access_key_id", "secret_access_key"}},
	// instance_name or base_url (checked in checkProviderFields).
	"azure_openai": {Fields: []string{pfInstanceName, pfBaseURL, pfAPIVersion, pfDeployments},
		Required: []string{pfAPIVersion, pfDeployments}, Secrets: []string{"key"}},
}

// LiteLLMKind is the provider kind whose instance field names an
// installed instance of the template of the same id (the kind name is the
// contract's; the Hub fills base_url from the instance's host).
const LiteLLMKind = "litellm"

// Provider credentials modes.
const (
	ProviderCredentialsAdmin     = "admin"
	ProviderCredentialsPerPerson = "per_person"
)

// ProviderVarPrefix starts every provider variable (a ReservedVar).
const ProviderVarPrefix = "PORTCULLIS_AI_PROVIDER_"

// Limits of a provider definition.
const (
	maxProviderSecretBytes = 8 << 10
	maxProviderModels      = 200
	maxProviderDeployments = 64
	maxProviderURL         = 2048
)

var (
	providerNameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	awsRegionRe      = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	azureNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	azureAPIVerRe    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$`)
	azureDeployRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	secretFieldKeyRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}\.[a-z][a-z0-9_]{0,31}$`)
)

// ProviderVar is the variable that carries provider name's secret field
// (§15.12: PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>, upper-cased, - → _).
func ProviderVar(name, field string) string {
	up := func(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "_")) }
	return ProviderVarPrefix + up(name) + "_" + up(field)
}

// ProviderUse is one AI page instance that selects a provider: its access
// group, how many people it reaches (nil: the directory is down) and
// whether a change of the provider restarts it (enabled: Settings → AI's
// save preview).
type ProviderUse struct {
	Instance string `json:"instance"`
	Group    string `json:"group"`
	People   *int   `json:"people"`
	Restarts bool   `json:"restarts"`
}

// ProviderView is a provider as the API shows it: the definition (a
// litellm provider's base_url filled from its instance), each secret
// field as {set, updated_at} and the instances selecting it.
type ProviderView struct {
	state.ModelProvider
	Secrets map[string]SecretView `json:"secrets"`
	UsedBy  []ProviderUse         `json:"used_by"`
}

// ── the secret store ───────────────────────────────────

// providerSecretsPath is <data>/ai/provider-secrets.json.
func (h *Hub) providerSecretsPath() string {
	return filepath.Join(h.cfg.DataDir, "ai", "provider-secrets.json")
}

// providerSecrets are the stored provider secret values by
// "<name>.<field>" (missing store = none; readSecretStore). Never log,
// echo or audit them; errors never quote the content.
func (h *Hub) providerSecrets() (map[string]string, error) {
	vals, err := readSecretStore(h.providerSecretsPath(), secretFieldKeyRe, "<provider>.<field>")
	var se *storeErr
	switch {
	case err == nil:
		return vals, nil
	case errors.As(err, &se) && se.stage == storeRead:
		return nil, errors.New("reading the AI provider secrets store failed")
	}
	return nil, errors.New("the AI provider secrets store: " + err.Error())
}

// providerSecretValues are the non-empty stored values (the redaction
// set, G30(c)).
func (h *Hub) providerSecretValues() ([]string, error) {
	vals, err := h.providerSecrets()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

// writeProviderSecrets replaces the store with vals (empty: the file is
// removed; writeSecretStore otherwise: atomic, 0600, buffer zeroed).
// <data>/ai is checked before every write: created 0700, set to 0700
// when group or others can reach it, else the write is refused (fail
// closed, fix round 1). Errors
// are fixed texts.
func (h *Hub) writeProviderSecrets(vals map[string]string) error {
	path := h.providerSecretsPath()
	if len(vals) > 0 {
		if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
			log.Printf("ai: the provider secrets directory: %v", err)
			return errors.New("the AI provider secrets directory is not private (0700) and can't be made so: nothing was written")
		}
	}
	err := writeSecretStore(nil, path, vals)
	var se *storeErr
	switch {
	case err == nil:
		return nil
	case errors.As(err, &se) && se.stage == storeRemove:
		return errors.New("removing the AI provider secrets store failed")
	}
	return errors.New("writing the AI provider secrets store failed")
}

// ensurePrivateDir makes dir a real directory (not a symlink) that only
// its owner can reach: created 0700 when missing, chmodded to 0700 when
// group or others have any bit; anything else is an error. (A narrower
// mode, e.g. read-only 0500, is left: the write then fails.)
func ensurePrivateDir(dir string) error {
	if err := ensureStoreDirs([]string{dir}); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
		if st, err = os.Lstat(dir); err != nil {
			return err
		}
		if st.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("%s stays %v after chmod 0700", dir, st.Mode().Perm())
		}
	}
	return nil
}

// ── views ──────────────────────────────────────────────

// ModelProviders lists the providers sorted by name. The directory is
// read once, outside mu, for the used_by population counts.
func (h *Hub) ModelProviders(ctx context.Context) []ProviderView {
	m, err := h.membership(ctx)
	if err != nil {
		m = nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]ProviderView, 0, len(h.st.AI.Providers))
	for _, p := range h.st.AI.Providers {
		out = append(out, h.providerViewLocked(p, m))
	}
	return out
}

// ModelProvider is provider name's stored definition (a copy; ok false:
// none). The Portcullis MCP's save_model_provider judges its class by it
// (Task 17b): where model traffic and secrets go.
func (h *Hub) ModelProvider(name string) (state.ModelProvider, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, p := range h.st.AI.Providers {
		if p.Name == name {
			return cloneProvider(p), true
		}
	}
	return state.ModelProvider{}, false
}

// providerViewLocked is p's view (m nil: populations unknown). Caller
// holds mu (read).
func (h *Hub) providerViewLocked(p state.ModelProvider, m *directory.Membership) ProviderView {
	v := ProviderView{ModelProvider: cloneProvider(p), Secrets: map[string]SecretView{}, UsedBy: []ProviderUse{}}
	if p.Kind == LiteLLMKind {
		v.BaseURL = h.liteLLMBaseURLLocked(p.Instance)
	}
	for _, f := range ProviderKinds[p.Kind].SecretFields() {
		sv := SecretView{}
		if meta, ok := h.st.AI.ProviderSecrets[state.ProviderSecretKey(p.Name, f)]; ok {
			at := meta.UpdatedAt
			sv = SecretView{Set: true, UpdatedAt: &at}
		}
		v.Secrets[f] = sv
	}
	for _, id := range h.selectingLocked(p.Name) {
		u := ProviderUse{Instance: id, Restarts: h.st.IsEnabled(id) && !h.instanceBusyLocked(id)}
		if t := h.findLocked(id); t != nil {
			u.Group = accessGroupOf(t)
			if m != nil {
				n := len(h.populationLocked(t, m).People)
				u.People = &n
			}
		}
		v.UsedBy = append(v.UsedBy, u)
	}
	return v
}

// selectingLocked are the instances whose AI selection names provider
// name, sorted. Caller holds mu.
func (h *Hub) selectingLocked(name string) []string {
	var out []string
	for id, a := range h.st.AIInstances {
		if slices.Contains(a.Providers, name) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// liteLLMBaseURLLocked is https://<the host of the instance's router
// litellm> ("" = no such instance or no such router: never another
// router's host). Caller holds mu.
func (h *Hub) liteLLMBaseURLLocked(id string) string {
	t := h.findLocked(id)
	if t == nil || t.Hosts[LiteLLMKind] == "" {
		return ""
	}
	return "https://" + t.Hosts[LiteLLMKind]
}

// providerIndexLocked is provider name's index in state (-1: none).
// Caller holds mu.
func (h *Hub) providerIndexLocked(name string) int {
	return slices.IndexFunc(h.st.AI.Providers, func(q state.ModelProvider) bool { return q.Name == name })
}

func cloneProvider(p state.ModelProvider) state.ModelProvider {
	c := p
	c.Deployments = maps.Clone(p.Deployments)
	c.Models.List = slices.Clone(p.Models.List)
	return c
}

// ── add / update / delete ──────────────────────────────

// AddModelProvider adds p (no secret: those are set one by one). 400 a
// bad definition or a kind no installed AI page supports, 409 a taken
// name or a provider variable another provider already has. Audited
// ai.provider.add.
func (h *Hub) AddModelProvider(p state.ModelProvider, actor directory.Actor) (ProviderView, error) {
	v, _, err := h.saveProvider("", p, actor)
	h.auditAI(actor, "ai.provider.add", p.Name, "kind="+clip(p.Kind, 64), err)
	return v, err
}

// UpdateModelProvider replaces provider name's definition (its kind
// can't change: 400; unknown 404; otherwise as AddModelProvider). Its
// secrets are kept. Audited ai.provider.update. The enabled AI pages
// whose rendering changed are re-delivered and restarted (Task 23):
// restarts lists them, sorted.
func (h *Hub) UpdateModelProvider(name string, p state.ModelProvider, actor directory.Actor) (v ProviderView, restarts []string, err error) {
	v, restarts, err = h.saveProvider(name, p, actor)
	detail := "kind=" + clip(p.Kind, 64)
	if len(restarts) > 0 {
		detail += " restarts=" + clip(strings.Join(restarts, ","), 400)
	}
	h.auditAI(actor, "ai.provider.update", name, detail, err)
	h.restartAIPages(restarts)
	return v, restarts, err
}

func (h *Hub) saveProvider(name string, p state.ModelProvider, actor directory.Actor) (v ProviderView, restarts []string, err error) {
	restarts = []string{}
	if err := checkAIActor(actor); err != nil {
		return ProviderView{}, restarts, err
	}
	update := name != ""
	if update {
		if p.Name == "" {
			p.Name = name
		}
		if p.Name != name {
			return ProviderView{}, restarts, statusErr(http.StatusBadRequest, "a provider's name can't change (%s): add a new provider", clipQuoted(p.Name))
		}
	}
	p = normalizeProvider(p)
	if err := checkProviderShape(&p); err != nil {
		return ProviderView{}, restarts, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.providerIndexLocked(p.Name)
	switch {
	case update && i < 0:
		return ProviderView{}, restarts, statusErr(http.StatusNotFound, "no model provider %s", clipQuoted(p.Name))
	case !update && i >= 0:
		return ProviderView{}, restarts, statusErr(http.StatusConflict, "a model provider named %s exists already", p.Name)
	case update && h.st.AI.Providers[i].Kind != p.Kind:
		return ProviderView{}, restarts, statusErr(http.StatusBadRequest, "a provider's kind can't change (%s → %s): add a new provider", h.st.AI.Providers[i].Kind, p.Kind)
	}
	if err := h.checkProviderLocked(&p, !update); err != nil {
		return ProviderView{}, restarts, err
	}
	before := h.aiPageDigestsLocked()
	prev := h.st.AI
	prev.ProviderSecrets = maps.Clone(prev.ProviderSecrets)
	next := slices.Clone(prev.Providers)
	if update {
		next[i] = p
	} else {
		// A store entry a crash left under this name is never inherited.
		h.st.AI.ProviderSecrets = maps.Clone(h.st.AI.ProviderSecrets)
		if err := h.dropProviderSecretsLocked(p.Name); err != nil {
			h.st.AI = prev
			return ProviderView{}, restarts, statusErr(http.StatusInternalServerError, "%v", err)
		}
		next = append(next, p)
		sort.Slice(next, func(a, b int) bool { return next[a].Name < next[b].Name })
	}
	h.st.AI.Providers = next
	if err := h.saveStateLocked(); err != nil {
		h.st.AI = prev
		return ProviderView{}, restarts, err
	}
	if r := h.aiPageChangesLocked(before); len(r) > 0 {
		restarts = r
	}
	return h.providerViewLocked(p, nil), restarts, nil
}

// dropProviderSecretsLocked removes provider name's entries from the store
// (and their metadata from memory; the caller saves state).
func (h *Hub) dropProviderSecretsLocked(name string) error {
	vals, err := h.providerSecrets()
	if err != nil {
		return err
	}
	changed := false
	for k := range vals {
		if strings.HasPrefix(k, name+".") {
			delete(vals, k)
			changed = true
		}
	}
	for k := range h.st.AI.ProviderSecrets {
		if strings.HasPrefix(k, name+".") {
			delete(h.st.AI.ProviderSecrets, k)
		}
	}
	if !changed {
		return nil
	}
	return h.writeProviderSecrets(vals)
}

// DeleteModelProvider removes provider name and its secrets: 409 naming
// the instances while any selects it, 404 unknown. Audited
// ai.provider.delete.
func (h *Hub) DeleteModelProvider(name string, actor directory.Actor) error {
	err := h.deleteProvider(name, actor)
	h.auditAI(actor, "ai.provider.delete", name, "", err)
	return err
}

func (h *Hub) deleteProvider(name string, actor directory.Actor) error {
	if err := checkAIActor(actor); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.providerIndexLocked(name)
	if i < 0 {
		return statusErr(http.StatusNotFound, "no model provider %s", clipQuoted(name))
	}
	if users := h.selectingLocked(name); len(users) > 0 {
		return statusErr(http.StatusConflict, "model provider %s is selected by %s: deselect it on their AI tab first", name, strings.Join(users, ", "))
	}
	before, err := h.providerSecrets()
	if err != nil {
		return statusErr(http.StatusInternalServerError, "%v", err)
	}
	prev := h.st.AI
	prev.ProviderSecrets = maps.Clone(prev.ProviderSecrets)
	h.st.AI.ProviderSecrets = maps.Clone(h.st.AI.ProviderSecrets)
	if err := h.dropProviderSecretsLocked(name); err != nil {
		h.st.AI = prev
		return statusErr(http.StatusInternalServerError, "%v", err)
	}
	h.st.AI.Providers = slices.Delete(slices.Clone(h.st.AI.Providers), i, i+1)
	if err := h.saveStateLocked(); err != nil {
		h.st.AI = prev
		if werr := h.writeProviderSecrets(before); werr != nil {
			log.Printf("ai: putting back the secrets of provider %s failed: %v", name, werr)
		}
		return err
	}
	return nil
}

// ── secrets ────────────────────────────────────────────

// SetProviderSecret stores value as provider name's secret field (404 an
// unknown provider, 400 a field the kind doesn't have or a value an env
// file can't carry — the error never quotes it). value is zeroed when it
// returns. Audited ai.provider.secret "<field> replaced". The enabled AI
// pages using it are re-delivered and restarted (restarts, sorted).
func (h *Hub) SetProviderSecret(name, field string, value []byte, actor directory.Actor) (SecretView, []string, error) {
	defer clear(value)
	v, _, restarts, err := h.setProviderSecret(name, field, value, false, actor)
	h.auditAI(actor, "ai.provider.secret", name, clip(field, 64)+" "+secretReplaced, err)
	h.restartAIPages(restarts)
	return v, restarts, err
}

// ClearProviderSecret removes provider name's secret field. Audited
// ai.provider.secret "<field> cleared"; a field that isn't set answers
// {set: false} with no audit and no write (ruling 10a). Restarts as
// SetProviderSecret.
func (h *Hub) ClearProviderSecret(name, field string, actor directory.Actor) (SecretView, []string, error) {
	v, changed, restarts, err := h.setProviderSecret(name, field, nil, true, actor)
	if changed || err != nil {
		h.auditAI(actor, "ai.provider.secret", name, clip(field, 64)+" "+secretCleared, err)
	}
	h.restartAIPages(restarts)
	return v, restarts, err
}

// setProviderSecret sets (or clears) the field; changed reports whether
// anything was written; restarts are the AI pages to restart.
func (h *Hub) setProviderSecret(name, field string, value []byte, clearIt bool, actor directory.Actor) (SecretView, bool, []string, error) {
	v, restarts, err := h.setProviderSecretInner(name, field, value, clearIt, actor)
	if restarts == nil {
		restarts = []string{}
	}
	if errors.Is(err, errNothingToClear) {
		return SecretView{}, false, restarts, nil
	}
	return v, err == nil, restarts, err
}

// errNothingToClear: the field to clear is not set.
var errNothingToClear = errors.New("not set")

func (h *Hub) setProviderSecretInner(name, field string, value []byte, clearIt bool, actor directory.Actor) (SecretView, []string, error) {
	if err := checkAIActor(actor); err != nil {
		return SecretView{}, nil, err
	}
	if !clearIt {
		if err := checkSecretValue(value); err != nil {
			return SecretView{}, nil, err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	i := h.providerIndexLocked(name)
	if i < 0 {
		return SecretView{}, nil, statusErr(http.StatusNotFound, "no model provider %s", clipQuoted(name))
	}
	kind := h.st.AI.Providers[i].Kind
	if !slices.Contains(ProviderKinds[kind].SecretFields(), field) {
		return SecretView{}, nil, statusErr(http.StatusBadRequest, "%s is not a secret field of kind %s (%s)", clipQuoted(field), kind,
			strings.Join(ProviderKinds[kind].SecretFields(), ", "))
	}
	vals, err := h.providerSecrets()
	if err != nil {
		return SecretView{}, nil, statusErr(http.StatusInternalServerError, "%v", err)
	}
	key := state.ProviderSecretKey(name, field)
	old, had := vals[key]
	if _, meta := h.st.AI.ProviderSecrets[key]; clearIt && !had && !meta {
		return SecretView{}, nil, errNothingToClear
	}
	// What the AI pages render now (the store as it was).
	before := h.aiPageDigestsLocked()
	if clearIt {
		delete(vals, key)
	} else {
		vals[key] = string(value)
	}
	if err := h.writeProviderSecrets(vals); err != nil {
		return SecretView{}, nil, statusErr(http.StatusInternalServerError, "%v", err)
	}
	prev := h.st.AI.ProviderSecrets
	next := maps.Clone(prev)
	if next == nil {
		next = map[string]state.SecretMeta{}
	}
	at := time.Now().UTC().Truncate(time.Second)
	if clearIt {
		delete(next, key)
	} else {
		next[key] = state.SecretMeta{UpdatedAt: at}
	}
	h.st.AI.ProviderSecrets = next
	if err := h.saveStateLocked(); err != nil {
		h.st.AI.ProviderSecrets = prev
		if had {
			vals[key] = old
		} else {
			delete(vals, key)
		}
		if werr := h.writeProviderSecrets(vals); werr != nil {
			log.Printf("ai: putting back the secret %s of provider %s failed: %v", field, name, werr)
		}
		return SecretView{}, nil, err
	}
	restarts := h.aiPageChangesLocked(before)
	if clearIt {
		return SecretView{}, restarts, nil
	}
	return SecretView{Set: true, UpdatedAt: &at}, restarts, nil
}

// checkSecretValue: 1–8 KiB of UTF-8 without control characters, single
// quotes or backslashes (the value is written single-quoted into an env
// file, envQuote). The error never quotes the value.
func checkSecretValue(v []byte) error {
	switch {
	case len(v) == 0:
		return statusErr(http.StatusBadRequest, `the value is empty: use {"clear": true} to clear it`)
	case len(v) > maxProviderSecretBytes:
		return statusErr(http.StatusBadRequest, "the value is longer than %d bytes", maxProviderSecretBytes)
	case !utf8.Valid(v):
		return statusErr(http.StatusBadRequest, "the value is not UTF-8 text")
	case bytes.ContainsAny(v, "'\\"):
		return statusErr(http.StatusBadRequest, "the value contains a single quote or a backslash, which an env value can't carry")
	case bytes.ContainsFunc(v, templates.IsControlRune):
		return statusErr(http.StatusBadRequest, "the value contains a line break or another control character")
	}
	return nil
}

// ── validation ─────────────────────────────────────────

// normalizeProvider trims the label and drops empty collections;
// credentials default to admin.
func normalizeProvider(p state.ModelProvider) state.ModelProvider {
	p = cloneProvider(p)
	p.Label = strings.TrimSpace(p.Label)
	if p.Credentials == "" {
		p.Credentials = ProviderCredentialsAdmin
	}
	if len(p.Deployments) == 0 {
		p.Deployments = nil
	}
	if len(p.Models.List) == 0 {
		p.Models.List = nil
	}
	return p
}

// providerFieldSet reports which non-secret fields p sets.
func providerFieldSet(p *state.ModelProvider) map[string]bool {
	return map[string]bool{
		pfInstance: p.Instance != "", pfBaseURL: p.BaseURL != "", pfRegion: p.Region != "",
		pfInstanceName: p.InstanceName != "", pfAPIVersion: p.APIVersion != "", pfDeployments: len(p.Deployments) > 0,
	}
}

// checkProviderShape is everything about p that needs no Hub state (400).
func checkProviderShape(p *state.ModelProvider) error {
	bad := func(format string, args ...any) error { return statusErr(http.StatusBadRequest, format, args...) }
	if !providerNameRe.MatchString(p.Name) {
		return bad("name %s: lowercase letters, digits and -, starting with a letter, at most 31 characters", clipQuoted(p.Name))
	}
	kind, ok := ProviderKinds[p.Kind]
	if !ok {
		return bad("kind %s: one of %s", clipQuoted(p.Kind), strings.Join(templates.ProviderKinds, ", "))
	}
	if p.Label == "" || utf8.RuneCountInString(p.Label) > 64 || templates.HasControlChars(p.Label) || !utf8.ValidString(p.Label) {
		return bad("label: one line of 1–64 characters")
	}
	if p.Credentials != ProviderCredentialsAdmin && p.Credentials != ProviderCredentialsPerPerson {
		return bad("credentials %s: %s or %s", clipQuoted(p.Credentials), ProviderCredentialsAdmin, ProviderCredentialsPerPerson)
	}
	set := providerFieldSet(p)
	for _, f := range slices.Sorted(maps.Keys(set)) {
		if set[f] && !slices.Contains(kind.Fields, f) {
			return bad("%s is not a field of kind %s (fields: %s)", f, p.Kind, strings.Join(kind.Fields, ", "))
		}
	}
	for _, f := range kind.Required {
		if !set[f] {
			return bad("kind %s needs %s", p.Kind, f)
		}
	}
	if p.Kind == "azure_openai" && !set[pfInstanceName] && !set[pfBaseURL] {
		return bad("kind azure_openai needs instance_name or base_url")
	}
	if p.BaseURL != "" && !validProviderURL(p.BaseURL) {
		return bad("base_url: an http or https URL without user, password, query or fragment")
	}
	if p.Region != "" && !awsRegionRe.MatchString(p.Region) {
		return bad("region %s: an AWS region such as us-east-1", clipQuoted(p.Region))
	}
	if p.InstanceName != "" && !azureNameRe.MatchString(p.InstanceName) {
		return bad("instance_name %s: an Azure resource name (letters, digits and -)", clipQuoted(p.InstanceName))
	}
	if p.APIVersion != "" && !azureAPIVerRe.MatchString(p.APIVersion) {
		return bad("api_version %s: a date such as 2024-10-21 (or 2024-10-01-preview)", clipQuoted(p.APIVersion))
	}
	if len(p.Deployments) > maxProviderDeployments {
		return bad("deployments: at most %d", maxProviderDeployments)
	}
	for _, d := range slices.Sorted(maps.Keys(p.Deployments)) {
		if !azureDeployRe.MatchString(d) {
			return bad("deployment %s: letters, digits, ., _ and -, at most 64 characters", clipQuoted(d))
		}
		if !modelName(p.Deployments[d]) {
			return bad("deployment %s: its model must be one line of 1–128 characters", d)
		}
	}
	if p.Models.Fetch && !kind.Fetch {
		return bad("models.fetch is only for litellm, openai_compatible and openai")
	}
	if len(p.Models.List) > maxProviderModels {
		return bad("models.list: at most %d", maxProviderModels)
	}
	seen := map[string]bool{}
	for _, m := range p.Models.List {
		if !modelName(m) {
			return bad("models.list: each model one line of 1–128 characters")
		}
		if seen[m] {
			return bad("models.list: %s is listed twice", clipQuoted(m))
		}
		seen[m] = true
	}
	return nil
}

func modelName(s string) bool {
	return s != "" && len(s) <= 128 && utf8.ValidString(s) && !templates.HasControlChars(s) && strings.TrimSpace(s) == s
}

// validProviderURL: http(s), a host, no user info (a key in the URL would
// be stored as a definition), query or fragment; printable ASCII.
func validProviderURL(s string) bool {
	if len(s) > maxProviderURL || templates.HasControlChars(s) || strings.ContainsAny(s, " \t'\\") {
		return false
	}
	for _, r := range s {
		if r > 0x7e {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") || u.Opaque != "" {
		return false
	}
	return true
}

// checkProviderLocked is what needs the Hub's state: a litellm
// provider's instance (400), a kind an installed AI page supports (400;
// on add only — an existing provider stays editable, ruling 10b)
// and the variable clash with other providers (409, G30(d)). Caller
// holds mu.
func (h *Hub) checkProviderLocked(p *state.ModelProvider, adding bool) error {
	if p.Kind == LiteLLMKind {
		if !h.installedInstanceLocked(p.Instance) {
			return statusErr(http.StatusBadRequest, "instance %s: no such instance", clipQuoted(p.Instance))
		}
		if h.instanceTemplateLocked(p.Instance) != LiteLLMKind {
			return statusErr(http.StatusBadRequest, "instance %s is not a LiteLLM instance", p.Instance)
		}
		if h.liteLLMBaseURLLocked(p.Instance) == "" {
			return statusErr(http.StatusBadRequest, "instance %s has no hostname to reach it by", p.Instance)
		}
	}
	if adding && !h.chatSupportsLocked(p.Kind) {
		return statusErr(http.StatusBadRequest, "no installed AI page supports kind %s", p.Kind)
	}
	mine := map[string]string{}
	for _, f := range ProviderKinds[p.Kind].SecretFields() {
		mine[ProviderVar(p.Name, f)] = f
	}
	for _, q := range h.st.AI.Providers {
		if q.Name == p.Name {
			continue
		}
		for _, g := range ProviderKinds[q.Kind].SecretFields() {
			v := ProviderVar(q.Name, g)
			if f, ok := mine[v]; ok {
				return statusErr(http.StatusConflict, "provider %s's %s would use the variable %s, which is provider %s's %s: choose another name", p.Name, f, v, q.Name, g)
			}
		}
	}
	return nil
}

// installedInstanceLocked: id is an instance in state or an enabled
// default instance, not being deleted. Caller holds mu.
func (h *Hub) installedInstanceLocked(id string) bool {
	if id == "" || h.findLocked(id) == nil {
		return false
	}
	if e, ok := h.st.Instances[id]; ok {
		return e.State != state.InstanceDeleting
	}
	return h.st.IsEnabled(id)
}

// chatSupportsLocked: a loaded template with ai.chat declares kind.
// Caller holds mu.
func (h *Hub) chatSupportsLocked(kind string) bool {
	for i := range h.templates {
		if ai := h.templates[i].Manifest.AI; ai != nil && ai.Chat != nil {
			if _, ok := ai.Chat.ProviderKinds[kind]; ok {
				return true
			}
		}
	}
	return false
}

// ── audit ──────────────────────────────────────────────

// auditAI records an AI settings / provider change (Result from err as
// the API answers it); the target is clipped to 64 bytes and the detail
// to 600 runes (callers clip what they put in it, like auditFolder). The error is redacted with every provider secret;
// a store that can't be read hides it (fail closed). Never under mu.
func (h *Hub) auditAI(actor directory.Actor, action, target, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor.User, Via: actor.Via, Client: actor.Client, Action: action, Target: clip(target, 64), Detail: actor.AuditDetail(clipRunes(detail, 600)), Result: "ok"}
	if err != nil {
		e.Result = "error"
		var se *StatusError
		var busy ErrBusy
		if (errors.As(err, &se) && se.Status < 500) || errors.As(err, &busy) {
			e.Result = "refused"
		}
		if vals, rerr := h.providerSecretValues(); rerr != nil {
			e.Error = "the message is hidden: the AI provider secrets couldn't be read to redact it"
		} else {
			e.Error = clipRunes(redactValues(err.Error(), vals), 600)
		}
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}
