package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The AI page (contract §3.2 ai.chat, §13.7, §15.12; plan 4 Task 23): an
// instance of a template with ai.chat gets
//
//   - ai-providers.json, the delivery engine's unit file:ai-providers
//     (<appfiles>/<id>/ai-providers/, 0640 in 0750, atomic), bind-mounted
//     read-only at ai.chat.file.mount in ai.chat.file.service: one entry
//     per selected provider, never a secret value (env names only);
//   - the selected providers' secrets in its .env, single-quoted
//     (PORTCULLIS_AI_PROVIDER_<NAME>_<FIELD>, only the set ones, never for
//     credentials per_person), and the override's environment: {VAR:
//     ${VAR}} on ai.chat.env.service only (G31) — every other provider
//     variable is dropped from every .env;
//   - its ai_client registered through EnsureAIClient (G10), not
//     RegisterClient: confidential with its secret_env, consent, ACR hwk,
//     basic + acr, offline_access + mcp:all, the username mapper, owner
//     the instance id; its access role and flow kept (ensureAccess). Its
//     health is merged into the AI client health map (never replaced):
//     a failed ensure — or the master switch off — keeps it out of
//     mcp-gate.json's clients.
//
// The selection (state ai_instances[id].providers) is set through PUT
// /api/instances/{id}/ai (SetAIProviders, audited ai.providers, G72); an
// instance that never chose (no ai_instances entry) gets every provider
// whose kind the template supports at create and at its first enable
// (the first by name of a "one" kind). A change of what an AI page
// renders (a selection, a provider's definition or secret, a litellm
// instance's hostname) rewrites its .env at once and owes the enabled
// ones a restart through the delivery engine (queueDelivery, effect
// restart): the engine writes file:ai-providers and restarts it; the
// answers list those instances.

// ProvidersDoc is ai-providers.json (contract §3.2).
type ProvidersDoc struct {
	Version   int             `json:"version"`
	Instance  string          `json:"instance"`
	Providers []ProviderEntry `json:"providers"`
}

// ProviderEntry is one selected provider in ai-providers.json: every
// field always present ("", {} or []).
type ProviderEntry struct {
	Name         string              `json:"name"`
	Label        string              `json:"label"`
	Kind         string              `json:"kind"`
	BaseURL      string              `json:"base_url"`
	Region       string              `json:"region"`
	InstanceName string              `json:"instance_name"`
	APIVersion   string              `json:"api_version"`
	Deployments  map[string]string   `json:"deployments"`
	Models       ProviderEntryModels `json:"models"`
	Credentials  string              `json:"credentials"`
	// Env: each secret field whose value is set → the variable holding
	// it ({} for per_person).
	Env map[string]string `json:"env"`
}

// ProviderEntryModels is an entry's models.
type ProviderEntryModels struct {
	Fetch bool     `json:"fetch"`
	List  []string `json:"list"`
}

// providersDocVersion is ai-providers.json's version.
const providersDocVersion = 1

// chatOf is t's ai.chat (nil: t is no AI page).
func chatOf(t *templates.Template) *templates.Chat {
	if t == nil || t.Manifest.AI == nil {
		return nil
	}
	return t.Manifest.AI.Chat
}

// instanceAIClient is instance view t's ai_client entry (its client id
// is the instance's; nil: none).
func instanceAIClient(t *templates.Template) *templates.KeycloakClient {
	if chatOf(t) == nil {
		return nil
	}
	for i := range t.Manifest.Clients {
		if t.Manifest.Clients[i].AIClient {
			return &t.Manifest.Clients[i]
		}
	}
	return nil
}

// instanceAIClientIDs are instance view t's ai_client ids.
func instanceAIClientIDs(t *templates.Template) map[string]bool {
	out := map[string]bool{}
	for _, c := range t.Manifest.Clients {
		if c.AIClient {
			out[c.ClientID] = true
		}
	}
	return out
}

// withoutAIClients is ids without instance view t's ai_client (a copy;
// t nil: ids as they are). The setting-claim paths use it: the ai_client
// carries no setting claims (G9/G10).
func withoutAIClients(t *templates.Template, ids []string) []string {
	if t == nil {
		return slices.Clone(ids)
	}
	ai := instanceAIClientIDs(t)
	return slices.DeleteFunc(slices.Clone(ids), func(c string) bool { return ai[c] })
}

// ── the selection ──────────────────────────────────────

// selectedProvidersLocked are the providers t's stored selection names
// that it can render now, sorted by name: existing ones of a kind the
// template declares, the first of a "one" kind (a template update may
// have narrowed it). Caller holds mu.
func (h *Hub) selectedProvidersLocked(t *templates.Template) []state.ModelProvider {
	ch := chatOf(t)
	if ch == nil {
		return nil
	}
	names := slices.Sorted(slices.Values(h.st.AIInstances[t.ID].Providers))
	var out []state.ModelProvider
	one := map[string]bool{}
	for _, n := range slices.Compact(names) {
		i := h.providerIndexLocked(n)
		if i < 0 {
			continue
		}
		p := h.st.AI.Providers[i]
		mode, ok := ch.ProviderKinds[p.Kind]
		if !ok || (mode == "one" && one[p.Kind]) {
			continue
		}
		one[p.Kind] = true
		out = append(out, p)
	}
	return out
}

// AIPageSelection is AI page id's provider selection as it renders now
// (selectedProvidersLocked: what people's data goes to), sorted; ok false
// when id is unknown or no AI page. The Portcullis MCP's set_ai_providers
// judges its class by it (fix round 1).
func (h *Hub) AIPageSelection(id string) ([]string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.findLocked(id)
	if chatOf(t) == nil {
		return nil, false
	}
	out := []string{}
	for _, p := range h.selectedProvidersLocked(t) {
		out = append(out, p.Name)
	}
	return out, true
}

// defaultSelectionLocked is §15.12's default: every provider whose kind t
// supports, the first by name of a "one" kind. Caller holds mu.
func (h *Hub) defaultSelectionLocked(t *templates.Template) []string {
	ch := chatOf(t)
	if ch == nil {
		return nil
	}
	out := []string{}
	one := map[string]bool{}
	for _, p := range h.st.AI.Providers { // sorted by name
		mode, ok := ch.ProviderKinds[p.Kind]
		if !ok || (mode == "one" && one[p.Kind]) {
			continue
		}
		one[p.Kind] = true
		out = append(out, p.Name)
	}
	return out
}

// seedAIProvidersLocked gives AI page t that never chose (no
// ai_instances entry) the default selection; reports whether it changed
// state (the caller saves). Caller holds mu (write).
func (h *Hub) seedAIProvidersLocked(t *templates.Template) bool {
	if chatOf(t) == nil {
		return false
	}
	if _, ok := h.st.AIInstances[t.ID]; ok {
		return false
	}
	if h.st.AIInstances == nil {
		h.st.AIInstances = map[string]state.AIInstance{}
	}
	h.st.AIInstances[t.ID] = state.AIInstance{Providers: h.defaultSelectionLocked(t)}
	return true
}

// checkSelectionLocked validates names as t's selection (400 each: not an
// AI page, a name twice, an unknown provider, a kind t doesn't declare,
// two of a "one" kind) and returns it sorted. Caller holds mu.
func (h *Hub) checkSelectionLocked(t *templates.Template, names []string) ([]string, error) {
	ch := chatOf(t)
	if ch == nil {
		return nil, statusErr(http.StatusBadRequest, "%s is no AI page (its template has no ai.chat): it has no model providers", t.ID)
	}
	if len(names) > aiArchiveMax {
		return nil, statusErr(http.StatusBadRequest, "at most %d model providers", aiArchiveMax)
	}
	seen := map[string]bool{}
	byKind := map[string][]string{}
	for _, n := range names {
		if !providerNameRe.MatchString(n) {
			return nil, statusErr(http.StatusBadRequest, "no model provider %s", clipQuoted(n))
		}
		if seen[n] {
			return nil, statusErr(http.StatusBadRequest, "model provider %s is listed twice", n)
		}
		seen[n] = true
		i := h.providerIndexLocked(n)
		if i < 0 {
			return nil, statusErr(http.StatusBadRequest, "no model provider %s", n)
		}
		kind := h.st.AI.Providers[i].Kind
		if _, ok := ch.ProviderKinds[kind]; !ok {
			return nil, statusErr(http.StatusBadRequest, "model provider %s is of kind %s, which %s doesn't support (it supports %s)", n, kind, t.TemplateID,
				strings.Join(slices.Sorted(maps.Keys(ch.ProviderKinds)), ", "))
		}
		byKind[kind] = append(byKind[kind], n)
	}
	for _, kind := range slices.Sorted(maps.Keys(byKind)) {
		if ch.ProviderKinds[kind] == "one" && len(byKind[kind]) > 1 {
			l := slices.Sorted(slices.Values(byKind[kind]))
			return nil, statusErr(http.StatusBadRequest, "%s takes at most one model provider of kind %s (selected: %s)", t.TemplateID, kind, strings.Join(l, ", "))
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}

// SetAIProviders sets AI page id's provider selection (PUT
// /api/instances/{id}/ai providers, G72): 404 unknown instance, 400 the
// refusals of checkSelectionLocked, 409 while it is deleted or restored,
// busy while a lifecycle operation runs. The .env follows at once; an
// enabled instance is re-delivered and restarted (background). Audited
// ai.providers "<before> -> <after>" (only a change, or a refusal).
func (h *Hub) SetAIProviders(ctx context.Context, id string, names []string, actor directory.Actor) error {
	_, err := h.setAIProviders(ctx, id, names, actor)
	return err
}

func (h *Hub) setAIProviders(_ context.Context, id string, names []string, actor directory.Actor) (restarts bool, err error) {
	detail, changed := "", false
	defer func() {
		if changed || err != nil {
			h.auditOp(actor, "ai.providers", id, detail, err)
		}
	}()
	if err := checkAIActor(actor); err != nil {
		return false, err
	}
	if h.Template(id) == nil {
		return false, ErrNotFound
	}
	restart, err := func() ([]string, error) {
		unlock, err := h.lockApp(id)
		if err != nil {
			return nil, err
		}
		defer unlock()
		defer h.aiLock(id)()
		h.mu.Lock()
		defer h.mu.Unlock()
		t := h.findLocked(id)
		if t == nil {
			return nil, ErrNotFound
		}
		next, err := h.checkSelectionLocked(t, names)
		if err != nil {
			return nil, err
		}
		if err := h.pendingLocked(id); err != nil {
			return nil, err
		}
		prev, had := h.st.AIInstances[id]
		detail = selectionText(prev.Providers) + " -> " + selectionText(next)
		if had && slices.Equal(slices.Sorted(slices.Values(prev.Providers)), next) {
			return nil, nil
		}
		before := h.aiPageDigestsLocked()
		cur := prev
		cur.Companions = maps.Clone(prev.Companions)
		cur.Providers = next
		if h.st.AIInstances == nil {
			h.st.AIInstances = map[string]state.AIInstance{}
		}
		h.st.AIInstances[id] = cur
		if err := h.saveStateLocked(); err != nil {
			if had {
				h.st.AIInstances[id] = prev
			} else {
				delete(h.st.AIInstances, id)
			}
			return nil, err
		}
		changed = true
		return h.aiPageChangesLocked(before), nil
	}()
	if err != nil {
		return false, err
	}
	h.restartAIPages(restart)
	return slices.Contains(restart, id), nil
}

// selectionText is a selection as the audit shows it ("" = none).
func selectionText(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(slices.Sorted(slices.Values(names)), ", ")
}

// providersAtInstanceLocked are the litellm providers whose instance is
// id, sorted (an instance delete is refused while any points at it).
// Caller holds mu.
func (h *Hub) providersAtInstanceLocked(id string) []string {
	var out []string
	for _, p := range h.st.AI.Providers {
		if p.Kind == LiteLLMKind && p.Instance == id {
			out = append(out, p.Name)
		}
	}
	return out
}

// ── what an AI page renders ────────────────────────────

// providersFileLocked is AI page t's ai-providers.json (nil, nil: t is no
// AI page). Never a secret value: env holds variable names, of the set
// secret fields of providers with credentials admin. Caller holds mu.
func (h *Hub) providersFileLocked(t *templates.Template) (*ProvidersDoc, error) {
	if chatOf(t) == nil {
		return nil, nil
	}
	d := &ProvidersDoc{Version: providersDocVersion, Instance: t.ID, Providers: []ProviderEntry{}}
	for _, p := range h.selectedProvidersLocked(t) {
		e := ProviderEntry{Name: p.Name, Label: p.Label, Kind: p.Kind, BaseURL: p.BaseURL, Region: p.Region, InstanceName: p.InstanceName,
			APIVersion: p.APIVersion, Deployments: maps.Clone(p.Deployments), Models: ProviderEntryModels{Fetch: p.Models.Fetch, List: slices.Clone(p.Models.List)},
			Credentials: p.Credentials, Env: map[string]string{}}
		if p.Kind == LiteLLMKind {
			e.BaseURL = h.liteLLMBaseURLLocked(p.Instance)
		}
		if e.Deployments == nil {
			e.Deployments = map[string]string{}
		}
		if e.Models.List == nil {
			e.Models.List = []string{}
		}
		if e.Credentials == "" {
			e.Credentials = ProviderCredentialsAdmin
		}
		if e.Credentials == ProviderCredentialsAdmin {
			for _, f := range ProviderKinds[p.Kind].SecretFields() {
				if _, set := h.st.AI.ProviderSecrets[state.ProviderSecretKey(p.Name, f)]; set {
					e.Env[f] = ProviderVar(p.Name, f)
				}
			}
		}
		d.Providers = append(d.Providers, e)
	}
	return d, nil
}

// providersFileBytesLocked is providersFileLocked encoded as written (nil:
// no AI page). Caller holds mu.
func (h *Hub) providersFileBytesLocked(t *templates.Template) ([]byte, error) {
	d, err := h.providersFileLocked(t)
	if d == nil || err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// providerEnvNamesLocked are the provider variables AI page t's file
// names, sorted (the override's environment). Caller holds mu.
func (h *Hub) providerEnvNamesLocked(t *templates.Template) []string {
	d, _ := h.providersFileLocked(t)
	if d == nil {
		return nil
	}
	var out []string
	for _, p := range d.Providers {
		out = append(out, slices.Collect(maps.Values(p.Env))...)
	}
	sort.Strings(out)
	return out
}

// providerEnvLocked are AI page t's provider variables with their values
// from the store (only set, non-empty ones; nil for any other template).
// The values are never logged; the error never quotes them. Caller holds
// mu.
func (h *Hub) providerEnvLocked(t *templates.Template) (map[string]string, error) {
	names := h.providerEnvNamesLocked(t)
	if len(names) == 0 {
		return nil, nil
	}
	vals, err := h.providerSecrets()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range h.selectedProvidersLocked(t) {
		for _, f := range ProviderKinds[p.Kind].SecretFields() {
			v := ProviderVar(p.Name, f)
			if x := vals[state.ProviderSecretKey(p.Name, f)]; x != "" && slices.Contains(names, v) {
				out[v] = x
			}
		}
	}
	return out, nil
}

// syncProviderEnvLocked makes the provider variables of t's existing .env
// exactly providerEnvLocked: wanted ones written single-quoted, every
// other PORTCULLIS_AI_PROVIDER_* line dropped, the rest kept as written
// (a missing .env: nothing; enable writes it whole). Caller holds mu.
func (h *Hub) syncProviderEnvLocked(t *templates.Template) error {
	want, err := h.providerEnvLocked(t)
	if err != nil {
		return err
	}
	return rewriteEnvPrefix(h.envPath(t.ID), ProviderVarPrefix, want)
}

// rewriteEnvPrefix sets the variables of envFile that start with prefix
// to exactly want (single-quoted, envLine), keeping every other line;
// no change = no write; a missing file = nothing.
func rewriteEnvPrefix(envFile, prefix string, want map[string]string) error {
	data, err := os.ReadFile(envFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var lines []string
	if len(data) > 0 {
		lines = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	out := make([]string, 0, len(lines)+len(want))
	done := map[string]bool{}
	for _, line := range lines {
		k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !strings.HasPrefix(k, prefix) {
			out = append(out, line)
			continue
		}
		if v, wanted := want[k]; wanted && !done[k] {
			out = append(out, envLine(k, v, true))
			done[k] = true
		}
	}
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if !done[k] {
			out = append(out, envLine(k, want[k], true))
		}
	}
	next := strings.Join(out, "\n") + "\n"
	if next == string(data) {
		return nil
	}
	return fsutil.WriteFileAtomic(envFile, []byte(next), 0600)
}

// providerOverrideEnvLocked is the override's environment of AI page t:
// ai.chat.env.service → "VAR: ${VAR}" lines (G31). Caller holds mu.
func (h *Hub) providerOverrideEnvLocked(t *templates.Template) map[string][]string {
	ch := chatOf(t)
	names := h.providerEnvNamesLocked(t)
	if ch == nil || len(names) == 0 {
		return nil
	}
	lines := make([]string, 0, len(names))
	for _, n := range names {
		lines = append(lines, n+": \"${"+n+"}\"")
	}
	return map[string][]string{ch.Env.Service: lines}
}

// providersFileMount is AI page t's ai-providers directory as an override
// volume entry ("" with the service: no AI page).
func (h *Hub) providersFileMount(t *templates.Template) (service, entry string) {
	ch := chatOf(t)
	if ch == nil || !templates.ValidID(t.ID) {
		return "", ""
	}
	host := path.Join(filepath.ToSlash(h.cfg.AppFilesHostDir), t.ID, templates.AIProvidersFile)
	b, _ := json.Marshal(composeLiteral(host) + ":" + composeLiteral(ch.File.Mount) + ":ro")
	return ch.File.Service, string(b)
}

// providersFileOutputLocked is the delivery engine's file:ai-providers
// output for AI page t (ok false: no AI page). Caller holds mu (read).
func (h *Hub) providersFileOutputLocked(t *templates.Template) (fileOutput, bool) {
	ch := chatOf(t)
	if ch == nil {
		return fileOutput{}, false
	}
	o := fileOutput{file: templates.DataFile{Name: templates.AIProvidersFile, Service: ch.File.Service, Mount: ch.File.Mount}, aiProviders: true}
	o.data, o.err = h.providersFileBytesLocked(t)
	if o.err == nil {
		sum := sha256.Sum256(append(append([]byte{}, o.data...), 0))
		o.hash = hex.EncodeToString(sum[:])
	}
	return o, true
}

// ── re-delivery after a provider change ───────────────

// aiPageDigestsLocked are every AI page's rendered provider state by id:
// the file's bytes and a digest of each variable's value (a replaced key
// changes the env, not the file; the digests stay in memory, compared
// and dropped). Caller holds mu.
func (h *Hub) aiPageDigestsLocked() map[string]string {
	out := map[string]string{}
	vals, verr := h.providerSecrets()
	for i := range h.instances {
		t := &h.instances[i]
		if chatOf(t) == nil {
			continue
		}
		b, err := h.providersFileBytesLocked(t)
		sum := sha256.New()
		sum.Write(b)
		if err = errors.Join(err, verr); err != nil {
			sum.Write([]byte(err.Error()))
		}
		for _, p := range h.selectedProvidersLocked(t) {
			if p.Credentials == ProviderCredentialsPerPerson {
				continue
			}
			for _, f := range ProviderKinds[p.Kind].SecretFields() {
				v := sha256.Sum256([]byte(vals[state.ProviderSecretKey(p.Name, f)]))
				fmt.Fprintf(sum, "\x00%s.%s=%x", p.Name, f, v)
			}
		}
		out[t.ID] = hex.EncodeToString(sum.Sum(nil))
	}
	return out
}

// aiPageChangesLocked compares the AI pages with before (a committed
// change): each one whose rendered state changed gets its .env provider
// variables rewritten now (enabled or not, so a cleared key leaves no
// copy behind); the enabled ones not being deleted or restored are
// returned, sorted — the caller owes them a re-delivery and restart
// (restartAIPages) once mu is released. Caller holds mu (write).
func (h *Hub) aiPageChangesLocked(before map[string]string) []string {
	var out []string
	for id, d := range h.aiPageDigestsLocked() {
		if before[id] == d {
			continue
		}
		t := h.findLocked(id)
		if t == nil {
			continue
		}
		if err := h.syncProviderEnvLocked(t); err != nil {
			// The restart's own env write retries it (fail closed: a
			// store that can't be read refuses the start).
			log.Printf("ai: %s: writing the model provider variables failed: %v", id, err)
		}
		if h.st.IsEnabled(id) && !h.instanceBusyLocked(id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// restartAIPages owes each instance a restart and queues its delivery
// (file:ai-providers, then the restart: the engine's owed machinery, so a
// Hub restart repeats it). Never under mu.
func (h *Hub) restartAIPages(ids []string) {
	for _, id := range ids {
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
}

// ── the ai_client (contract §8, G10) ───────────────────

// clientSecret is client c's secret: the instance's .env, then the core
// .env ("" = none).
func (h *Hub) clientSecret(t *templates.Template, c templates.KeycloakClient) string {
	if c.SecretEnv == "" {
		return ""
	}
	for _, p := range []string{h.envPath(t.ID), filepath.Join(h.cfg.ProjectDir, ".env")} {
		if v := readEnvFile(p)[c.SecretEnv]; v != "" {
			return v
		}
	}
	return ""
}

// instanceAIClientSpec is the EnsureAIClient spec of AI page t's ai_client
// c with Settings → AI's connection length a.
func (h *Hub) instanceAIClientSpec(t *templates.Template, c templates.KeycloakClient, a state.AISettings) keycloak.AIClientSpec {
	return keycloak.AIClientSpec{
		ClientID: c.ClientID, Name: c.Name, Public: false, Secret: h.clientSecret(t, c),
		RedirectURIs: h.redirectURIs(c), OptionalScopes: []string{aigate.ScopeAll},
		OfflineIdle: time.Duration(a.OfflineIdleDays) * 24 * time.Hour, OfflineMax: time.Duration(a.OfflineMaxDays) * 24 * time.Hour,
		Owner: t.ID,
	}
}

// ensureInstanceAIClient creates or re-asserts AI page t's ai_client
// (mcp:all ensured first, under aiKCMu) and merges its health: healthy
// only when the ensure succeeded and the master switch is on. The gate
// file is rewritten when the health changed. nil: t has no ai_client.
// Never under mu.
func (h *Hub) ensureInstanceAIClient(ctx context.Context, t *templates.Template) error {
	c := instanceAIClient(t)
	if c == nil {
		return nil
	}
	kc := h.aiKeycloak()
	h.mu.RLock()
	a := h.st.AI
	all := h.fixedScopesLocked()[aigate.ScopeAll]
	h.mu.RUnlock()
	var err error
	if kc == nil {
		err = errors.New("Keycloak: the AI client calls are not configured")
	} else {
		spec := h.instanceAIClientSpec(t, *c, a)
		h.aiKCMu.Lock()
		if err = kc.EnsureMCPScope(ctx, all); err != nil {
			err = fmt.Errorf("Keycloak: client scope %s: %w", all.Name, err)
		} else if err = kc.EnsureAIClient(ctx, spec); err != nil {
			err = fmt.Errorf("Keycloak: AI client %s: %w", c.ClientID, err)
		}
		h.logAIClientErr(c.ClientID, err)
		h.aiKCMu.Unlock()
	}
	if h.mergeAIClientHealth(map[string]bool{c.ClientID: err == nil && a.Enabled}) {
		h.writePolicyLogged()
	}
	return err
}

// instanceAIClientWant is one enabled AI page's ai_client for a pass.
type instanceAIClientWant struct {
	t templates.Template
	c templates.KeycloakClient
}

// instanceAIClientWantsLocked are the ai_clients of every enabled AI page
// not being deleted or restored. Caller holds mu (read).
func (h *Hub) instanceAIClientWantsLocked() []instanceAIClientWant {
	var out []instanceAIClientWant
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled || h.instanceBusyLocked(t.ID) {
			continue
		}
		if c := instanceAIClient(t); c != nil {
			out = append(out, instanceAIClientWant{t: *t, c: *c})
		}
	}
	return out
}

// forgetAIClientHealth drops ids from the health map (a deleted
// instance's ai_client).
func (h *Hub) forgetAIClientHealth(ids ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range ids {
		delete(h.aiHealth, id)
	}
}
