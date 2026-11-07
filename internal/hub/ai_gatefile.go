package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The gate files (contract §15.4, plan 4 Task 11): mcp-gate.json is
// rebuilt from state and one directory snapshot in every WritePolicy,
// right after the policy file; mcp-credentials.json is the aiCredStore's
// (ai_credstore.go), whose caller secrets the same pass keeps in step.
//
// Fail closed throughout: with the master switch off or no gate
// recipient the file says enabled: false; a directory that can't be read
// keeps the last file's populations, while every state change still
// reaches the gate (and the sync loop retries); every input doubt —
// an unknown LoA, a mode the companion doesn't offer, a missing host, a
// client whose Keycloak ensure failed, a username the gate wouldn't take —
// leaves the resource, the person or the client out, never in.

// errGateDirectory: populations couldn't be read (the directory is
// unavailable): the file was rebuilt from state with the last file's
// populations, and the sync loop retries.
var errGateDirectory = errors.New("mcp-gate.json: the directory is unavailable — populations kept from the last file")

// gatePeople supplies the resources' populations: from the directory
// snapshot m or, while it is unavailable (m nil), from prev — the last
// gate file's resource with the same URL (none there: the resource is
// left out, never published with a population it couldn't compute).
type gatePeople struct {
	m    *directory.Membership
	prev map[string]*aigate.Resource
	now  time.Time
}

// kept fills r from the previous file (m nil); false = leave r out. Only
// the same resource is carried over — same URL, kind, scope, instance and
// companion (a URL another instance had, e.g. after a hostname move,
// carries nothing).
func (g gatePeople) kept(r *aigate.Resource) bool {
	p := g.prev[r.URL]
	if p == nil || p.Kind != r.Kind || p.Scope != r.Scope || p.Instance != r.Instance || p.Companion != r.Companion {
		return false
	}
	r.Population = append([]string{}, p.Population...)
	r.Expiring = maps.Clone(p.Expiring)
	if r.Expiring == nil {
		r.Expiring = map[string]aigate.Time{}
	}
	r.People = nil
	if r.Identity.Mode == aigate.IdentityHeaders && p.Identity.Mode == aigate.IdentityHeaders {
		r.People = maps.Clone(p.People)
	}
	return true
}

// prevResources indexes the gate file on disk by URL (nil: none or
// unreadable — then nothing is kept).
func (h *Hub) prevResources() map[string]*aigate.Resource {
	b, err := os.ReadFile(h.gatePath())
	if err != nil {
		return nil
	}
	f, err := aigate.DecodeFile(b)
	if err != nil || !f.Enabled {
		return nil
	}
	out := make(map[string]*aigate.Resource, len(f.Resources))
	for i := range f.Resources {
		out[f.Resources[i].URL] = &f.Resources[i]
	}
	return out
}

func (h *Hub) gatePath() string  { return filepath.Join(h.cfg.DataDir, aigate.GateFileName) }
func (h *Hub) credsPath() string { return filepath.Join(h.cfg.DataDir, aigate.CredsFileName) }

// SetAIClientHealth replaces the whole AI client health map (the Hub's
// three and every ai_client: true = the last Keycloak ensure left it in
// place; only those are listed in mcp-gate.json; nil = not known yet,
// none listed). For tests only: the sync pass (ai_clients.go) and Task
// 23's ai_client registration use mergeAIClientHealth, which sets only
// the ids they own.
func (h *Hub) SetAIClientHealth(healthy map[string]bool) {
	h.mu.Lock()
	if healthy == nil {
		h.aiHealth = nil
	} else {
		h.aiHealth = maps.Clone(healthy)
	}
	h.mu.Unlock()
}

// aiClientHealth is a copy of the last SetAIClientHealth (nil = unknown).
func (h *Hub) aiClientHealth() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.aiHealth == nil {
		return nil
	}
	return maps.Clone(h.aiHealth)
}

// gateRecipient is the gate's age recipient (nil: no gate — a missing,
// unreadable or unparseable HUB_MCP_GATE_RECIPIENT_FILE — or no MCP
// listener for it to call: HUB_MCP_GATE_SECRET_FILE missing).
func (h *Hub) gateRecipient() *age.X25519Recipient {
	if h.cfg.MCPGateRecipientFile == "" || !h.cfg.MCPListener {
		return nil
	}
	r, err := aigate.ParseRecipientFile(h.cfg.MCPGateRecipientFile)
	if err != nil {
		return nil
	}
	return r
}

// gateWanted: AI support is on and a gate recipient exists, so the gate
// file needs a directory snapshot.
func (h *Hub) gateWanted() bool {
	h.mu.RLock()
	on := h.st.AI.Enabled
	h.mu.RUnlock()
	return on && h.gateRecipient() != nil
}

// gateMembership takes the directory snapshot the gate file is built
// from (network I/O: never under mu). nil, nil = not needed.
func (h *Hub) gateMembership() (*directory.Membership, error) {
	if !h.gateWanted() {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), directoryStateTimeout)
	defer cancel()
	return h.membership(ctx)
}

// callerSecretSource is where an identity_headers companion's caller
// secret is: the instance's env file and the template's variable.
type callerSecretSource struct {
	ref, envFile, key string
}

// gateFile builds mcp-gate.json from state and m (WritePolicy's one
// directory snapshot, taken before mu; G47) with the AI clients healthy
// lists (nil = none). m nil: populations come from prev (the last file's
// resources by URL; a resource missing there is left out). Takes mu
// (read) itself.
func (h *Hub) gateFile(m *directory.Membership, healthy map[string]bool, prev map[string]*aigate.Resource) (*aigate.File, []callerSecretSource, error) {
	present := h.gateRecipient() != nil
	h.mu.RLock()
	defer h.mu.RUnlock()
	domain := NormalizeHost(h.cfg.Domain)
	if !templates.ValidHostname(domain) {
		return nil, nil, fmt.Errorf("mcp-gate.json: the main domain %q is not a hostname", h.cfg.Domain)
	}
	ai := h.st.AI
	f := &aigate.File{
		Version: 1, Issuer: aigate.Issuer(domain), MainDomain: domain,
		Clients: []string{}, AllowedOrigins: []string{}, ACRLoA: aigate.ACRLoA(),
		Limits: aigate.Limits{
			ResourceRPM: ai.Limits.ResourceRPM, ResourceBurst: ai.Limits.ResourceBurst, PersonRPM: ai.Limits.PersonRPM,
			ToolCallsRPM: ai.Limits.ToolCallsRPM, ConfirmationsPerHour: ai.Limits.ConfirmationsPerHour,
			MintsPerMinute: ai.Limits.MintsPerMinute, Fanout: ai.Limits.Fanout,
			MaxRequestBytes: aigate.FixedMaxRequestBytes, MaxResultBytes: aigate.FixedMaxResultBytes,
			UpstreamTimeoutS: aigate.FixedUpstreamTimeoutS,
		},
		CoreHosts: slices.Sorted(maps.Keys(policy.CoreHosts(domain))),
		Resources: []aigate.Resource{},
	}
	f.AllowedOrigins = append(f.AllowedOrigins, ai.AllowedOrigins...)
	sort.Strings(f.AllowedOrigins)
	if !ai.Enabled || !present {
		// Every request 503 "AI support is off": nothing else published.
		return f, nil, nil
	}
	f.Enabled = true
	ok := func(id string) bool { return healthy[id] }
	// The offered AI clients (§8) and those with the admin flag.
	var offered, adminClients []string
	for _, c := range []struct {
		id string
		c  state.AIClient
	}{{keycloak.AIClientIDs.Claude, ai.Clients.Claude}, {keycloak.AIClientIDs.ClaudeCode, ai.Clients.ClaudeCode}, {keycloak.AIClientIDs.Generic, ai.Clients.Generic}} {
		if !c.c.Offered || !ok(c.id) {
			continue
		}
		offered = append(offered, c.id)
		if c.c.Admin {
			adminClients = append(adminClients, c.id)
		}
	}
	// Every ai_client of an enabled ai.chat instance (§8).
	var aiClients []string
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled || t.Manifest.AI.Chat == nil || h.instanceBusyLocked(t.ID) {
			continue
		}
		// An instance view's client ids are already the instance's.
		if c := instanceAIClient(t); c != nil && ok(c.ClientID) {
			aiClients = append(aiClients, c.ClientID)
		}
	}
	people := sortedSet(append(append([]string{}, offered...), aiClients...))
	f.Clients = people
	admin := sortedSet(adminClients)
	gp := gatePeople{m: m, prev: prev, now: time.Now().UTC()}

	var secrets []callerSecretSource
	for i := range h.instances {
		t := &h.instances[i]
		for _, r := range h.companionResourcesLocked(t, gp, f, people) {
			f.Resources = append(f.Resources, r)
			if r.Identity.Mode == aigate.IdentityHeaders {
				c := companionOf(t, r.Companion)
				secrets = append(secrets, callerSecretSource{ref: r.Identity.SecretRef, envFile: h.envPath(t.ID), key: c.Identity.CallerSecret.Env})
			}
		}
	}
	// The fixed resources: everyone (the service account is never in a
	// Membership), lldap_admin members for the admin resource.
	fixed := func(r aigate.Resource, group string) {
		if m == nil {
			if !gp.kept(&r) {
				log.Printf("mcp-gate: %s left out of mcp-gate.json: the directory is unavailable and the last file doesn't list it", r.URL)
				return
			}
		} else if group == "" {
			r.Population = validUsers(slices.Collect(maps.Keys(m.Users)))
		} else {
			r.Population = groupMembers(m, group)
			r.Expiring = pendingOf(m, group, r.Population, gp.now)
		}
		f.Resources = append(f.Resources, r)
	}
	fixed(fixedResource(aigate.KindAggregate, aigate.AggregateURL(domain), aigate.ScopeAll, aigate.LabelAggregate, "mcp."+domain, people, false), "")
	if ai.PortcullisAdmin && len(admin) > 0 {
		fixed(fixedResource(aigate.KindAdmin, aigate.AdminURL(domain), aigate.ScopeAdmin, aigate.LabelAdmin, "hub."+domain, admin, false), lldap.AdminGroup)
	}
	if ai.PortcullisPeople {
		fixed(fixedResource(aigate.KindPeople, aigate.PeopleURL(domain), aigate.ScopePeople, aigate.LabelPeople, "people."+domain, people, true), "")
	}
	sort.Slice(f.Resources, func(i, j int) bool { return f.Resources[i].URL < f.Resources[j].URL })
	return f, secrets, nil
}

// instanceBusyLocked: the instance is being deleted or restored (never
// listed, §15.4).
func (h *Hub) instanceBusyLocked(id string) bool {
	e, ok := h.st.Instances[id]
	return ok && (e.State == state.InstanceDeleting || e.State == state.InstanceRestoring)
}

func companionOf(t *templates.Template, name string) *templates.Companion {
	for i := range t.Manifest.AI.MCP {
		if t.Manifest.AI.MCP[i].Name == name {
			return &t.Manifest.AI.MCP[i]
		}
	}
	return nil
}

// companionResourcesLocked: t's switched-on companions as resources. Any
// doubt about one leaves it out (logged). Caller holds mu (read).
func (h *Hub) companionResourcesLocked(t *templates.Template, gp gatePeople, f *aigate.File, clients []string) []aigate.Resource {
	if !t.Enabled || !t.HasAIMCP() || t.Manifest.Routerless() || h.instanceBusyLocked(t.ID) {
		return nil
	}
	switches := h.st.AIInstances[t.ID].Companions
	if len(switches) == 0 {
		return nil
	}
	skip := func(c string, why string) {
		log.Printf("mcp-gate: companion %s/%s left out of mcp-gate.json: %s", t.ID, c, why)
	}
	loa := policy.LoA(h.effectivePolicyLocked(t))
	var hosts []string
	for _, hst := range t.Hosts {
		if n := NormalizeHost(hst); n != "" {
			hosts = append(hosts, n)
		}
	}
	hosts = sortedSet(hosts)
	// The settings population (§13.3, call 27), once per instance; empty
	// with a reason (sign_in native, no access group in LLDAP): nobody.
	// A reason that state alone decides (why: sign_in native, routes
	// without Portcullis identity) empties it on both paths — with the
	// directory down too: it is never carried over.
	why := h.populationWhyLocked(t)
	var population []string
	if gp.m != nil && why == "" {
		pop := h.populationLocked(t, gp.m)
		users := make([]string, 0, len(pop.People))
		for _, p := range pop.People {
			users = append(users, p.User)
		}
		population = validUsers(users)
	}
	group := accessGroupOf(t)
	var out []aigate.Resource
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		sw, on := switches[c.Name]
		if !on || !sw.Enabled || c.Identity.Mode == templates.IdentityAppOAuth {
			continue
		}
		host, unusable := companionUsable(t, c, sw, loa)
		if unusable != "" {
			skip(c.Name, unusable)
			continue
		}
		r := aigate.Resource{
			URL: aigate.CompanionURL(host, c.EffectivePublicPath()), Scope: aigate.CompanionScope(t.ID, c.Name),
			Clients: append([]string{}, clients...), Kind: aigate.KindCompanion, Instance: t.ID, Companion: c.Name,
			Label: c.Label, Host: host, Hosts: append([]string{}, hosts...), AppURL: "https://" + host, MinLoA: loa,
			Upstream: aigate.Upstream(t.ID, c.Name, c.Port, c.EffectivePath()),
			Protocol: append([]string{}, c.Protocol...), Mode: sw.Mode,
			Tools: aigate.Tools{
				Writes:  append([]string{}, c.Tools.Writes...),
				Confirm: append([]string{}, c.Tools.Confirm...),
				Never:   append([]string{}, c.Tools.Never...),
			},
			Aggregate: c.Aggregated(), Population: []string{}, Expiring: map[string]aigate.Time{},
		}
		switch c.Identity.Mode {
		case templates.IdentityAppToken:
			r.Identity = aigate.Identity{Mode: aigate.IdentityAppToken, Header: orDefault(c.Identity.Header, "Authorization"), Format: c.Identity.Format}
			if c.Identity.Basic != nil {
				r.Identity.Format, r.Identity.BasicUser = "", c.Identity.Basic.User
			}
		case templates.IdentityHeaders:
			cs := c.Identity.CallerSecret
			if cs == nil {
				skip(c.Name, "no caller secret")
				continue
			}
			r.Identity = aigate.Identity{Mode: aigate.IdentityHeaders, Header: orDefault(cs.Header, "Authorization"),
				Format: orDefault(cs.Format, "Bearer {secret}"), SecretRef: t.ID + "/" + c.Name}
		default:
			skip(c.Name, "unknown identity mode")
			continue
		}
		switch {
		case why != "":
			// Nobody: r keeps its empty population, expiring and people.
		case gp.m == nil:
			if !gp.kept(&r) {
				skip(c.Name, "the directory is unavailable and the last file doesn't list it")
				continue
			}
		default:
			r.Population = append([]string{}, population...)
			if group != "" {
				r.Expiring = pendingOf(gp.m, group, r.Population, gp.now)
			}
			if r.Identity.Mode == aigate.IdentityHeaders {
				r.People = peopleOf(gp.m, r.Population)
			}
		}
		// The gate refuses the whole file for one bad resource: check
		// this one alone first and leave it out instead.
		probe := *f
		probe.Clients = clients
		probe.Resources = []aigate.Resource{r}
		if err := probe.Validate(); err != nil {
			skip(c.Name, err.Error())
			continue
		}
		out = append(out, r)
	}
	return out
}

// companionUsable is the per-companion check of a switched-on companion
// c of t (switch sw, the instance's policy LoA loa) shared by the gate
// file and My apps (Task 21): its router's host, or why it is left out —
// a revoke_all still owed, pruned, a mode outside its modes, an LoA AI
// can't get, an alias longer than one DNS label (gate-fronted modes), no
// hostname, or an identity the gate can't apply (identity_headers
// without a caller secret, an unknown mode). app_oauth companions pass
// with their host (the gate isn't in their path; never in the file).
func companionUsable(t *templates.Template, c *templates.Companion, sw state.AICompanion, loa int) (host, why string) {
	switch {
	case sw.RevokePending:
		return "", "its app-side credentials still need a revoke_all"
	case sw.Pruned:
		return "", "switched off by a template update"
	case sw.IdentityMode != "" && sw.IdentityMode != c.Identity.Mode:
		// Switched on under another identity mode (pruneAI not yet run).
		return "", "its identity mode changed since it was switched on"
	case !slices.Contains(c.Modes, sw.Mode):
		return "", fmt.Sprintf("mode %q is not one of its modes", sw.Mode)
	case loa < 0 || loa > 2:
		return "", fmt.Sprintf("the instance's policy LoA %d can't get AI support", loa)
	}
	switch c.Identity.Mode {
	case templates.IdentityAppOAuth:
	case templates.IdentityAppToken, templates.IdentityHeaders:
		if !templates.AliasFits(t.ID, c.Name) {
			return "", "the alias is longer than one DNS label"
		}
		if c.Identity.Mode == templates.IdentityHeaders && c.Identity.CallerSecret == nil {
			return "", "no caller secret"
		}
	default:
		return "", "unknown identity mode"
	}
	host = NormalizeHost(t.Hosts[c.Router])
	if host == "" || !templates.ValidHostname(host) {
		return "", "its router has no hostname"
	}
	return host, ""
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// fixedResource is one of the three Portcullis-wide resources.
func fixedResource(kind, url, scope, label, host string, clients []string, aggregate bool) aigate.Resource {
	return aigate.Resource{
		URL: url, Scope: scope, Clients: append([]string{}, clients...), Kind: kind, Label: label, Host: host,
		Hosts: []string{}, MinLoA: 2, Protocol: []string{}, Identity: aigate.Identity{Mode: aigate.IdentityNone},
		Tools:     aigate.Tools{Writes: []string{}, Confirm: []string{}, Never: []string{}},
		Aggregate: aggregate, Population: []string{}, Expiring: map[string]aigate.Time{},
	}
}

// validUsers: sorted, deduplicated, only usernames the gate accepts
// (lldap.ValidUsername; anything else is left out and logged).
func validUsers(users []string) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if lldap.ValidUsername(u) {
			out = append(out, u)
		} else {
			log.Printf("mcp-gate: username %q left out of mcp-gate.json (not a valid username)", clip(u, 80))
		}
	}
	return sortedSet(out)
}

// groupMembers: group's members in m minus expired memberships.
func groupMembers(m *directory.Membership, group string) []string {
	var out []string
	for _, u := range m.Groups[group].Members {
		if _, isUser := m.Users[u]; isUser && !m.Expired[u][group] {
			out = append(out, u)
		}
	}
	return validUsers(out)
}

// pendingOf: the population members' pending expiry of group (§15.4
// expiring), from now on.
func pendingOf(m *directory.Membership, group string, population []string, now time.Time) map[string]aigate.Time {
	out := map[string]aigate.Time{}
	for _, u := range population {
		if at, ok := m.Pending[u][group]; ok && at.After(now) {
			out[u] = aigate.At(at)
		}
	}
	return out
}

// peopleOf: what an identity_headers companion learns of each member —
// the LLDAP email and the groups group-gate forwards (memberships past
// their expiry dropped), sorted. A member without a usable email is left
// out (no headers, never a stale or empty value).
func peopleOf(m *directory.Membership, population []string) map[string]aigate.Person {
	out := map[string]aigate.Person{}
	for _, u := range population {
		email := m.Emails[u]
		if email == "" || templates.HasControlChars(email) {
			continue
		}
		var groups []string
		for g := range personOf(m, u).Groups {
			if g != "" && !templates.HasControlChars(g) && g == strings.TrimSpace(g) {
				groups = append(groups, g)
			}
		}
		out[u] = aigate.Person{Email: email, Groups: sortedSet(groups)}
	}
	return out
}

// sortedSet: sorted, without duplicates, never nil.
func sortedSet(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return slices.Compact(out)
}

// writeGateFiles is WritePolicy's gate pass (caller holds
// policyWriteMu): mcp-gate.json from m (WritePolicy's directory
// snapshot), then the caller secrets of the companions it lists.
//
//   - m nil with mErr (the directory failed): rebuilt from state with the
//     last file's populations, marked for the sync loop's retry, and
//     errGateDirectory returned.
//   - A file the gate's rules refuse: enabled: false is written instead
//     (logged); never the old file, never a refused one.
func (h *Hub) writeGateFiles(m *directory.Membership, mErr error) error {
	var prev map[string]*aigate.Resource
	if m == nil && mErr != nil {
		prev = h.prevResources()
	}
	h.gateStale.Store(mErr != nil)
	f, secrets, err := h.gateFile(m, h.aiClientHealth(), prev)
	if err != nil {
		// Nothing valid can be built (the main domain): no gate file at
		// all is "AI support is off".
		log.Printf("mcp-gate: %v — removing %s", err, aigate.GateFileName)
		if rerr := os.Remove(h.gatePath()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		return err
	}
	if err := aigate.WriteFile(h.gatePath(), f); err != nil {
		log.Printf("mcp-gate: the gate would refuse the built file (%v) — writing enabled: false", err)
		off := *f
		off.Enabled, off.Clients, off.AllowedOrigins, off.Resources = false, []string{}, []string{}, []aigate.Resource{}
		if werr := aigate.WriteFile(h.gatePath(), &off); werr != nil {
			log.Printf("mcp-gate: writing enabled: false failed too (%v) — removing %s", werr, aigate.GateFileName)
			if rerr := os.Remove(h.gatePath()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				werr = errors.Join(werr, rerr)
			}
			return errors.Join(err, werr)
		}
		return err
	}
	if serr := h.syncCallerSecrets(f, secrets); serr != nil {
		mErr = errors.Join(mErr, serr)
		if m != nil {
			return serr
		}
	}
	if mErr != nil {
		log.Printf("mcp-gate: directory unavailable, %s rebuilt with the last populations: %v", aigate.GateFileName, mErr)
		return errGateDirectory
	}
	// app_oauth: everyone in a published population is recorded now (T27).
	h.recordOAuthHolders(m)
	return nil
}

// syncCallerSecrets keeps mcp-credentials.json's caller_secrets equal to
// the identity_headers companions f lists: each value read from the
// instance's env file as bytes and encrypted only when it, or the
// recipient, changed (a digest kept in memory, never on disk); a
// companion no longer listed loses its entry. Caller holds
// policyWriteMu.
func (h *Hub) syncCallerSecrets(f *aigate.File, sources []callerSecretSource) error {
	if !f.Enabled {
		return nil // entries of unlisted resources are ignored by the gate
	}
	recipient := h.gateRecipient()
	if recipient == nil {
		return nil // enabled implies a recipient; it vanished meanwhile
	}
	rcpt := []byte(recipient.String())
	if h.callerDigests == nil {
		h.callerDigests = map[string]string{}
	}
	want := map[string]bool{}
	var errs []error
	for _, s := range sources {
		want[s.ref] = true
		v := envValueBytes(s.envFile, s.key)
		if len(v) == 0 {
			// No secret yet: the companion refuses every caller.
			log.Printf("mcp-gate: %s has no caller secret %s yet", s.ref, s.key)
			continue
		}
		d := callerDigest(s.ref, rcpt, v)
		if h.callerDigests[s.ref] == d && h.creds().HasCallerSecret(s.ref) {
			clear(v)
			continue
		}
		if err := h.creds().PutCallerSecret(s.ref, v); err != nil { // zeroes v
			errs = append(errs, err)
			delete(h.callerDigests, s.ref)
			continue
		}
		h.callerDigests[s.ref] = d
	}
	for _, ref := range h.creds().CallerSecretRefs() {
		if !want[ref] {
			if err := h.creds().RemoveCallerSecret(ref); err != nil {
				errs = append(errs, err)
			}
			delete(h.callerDigests, ref)
		}
	}
	return errors.Join(errs...)
}

// callerDigest is sha256(ref, recipient, value): a new recipient
// re-encrypts even an unchanged value.
func callerDigest(ref string, recipient, value []byte) string {
	d := sha256.New()
	for _, b := range [][]byte{[]byte(ref), recipient, value} {
		var n [8]byte
		for i, l := 0, len(b); i < 8; i, l = i+1, l>>8 {
			n[i] = byte(l)
		}
		d.Write(n[:])
		d.Write(b)
	}
	return hex.EncodeToString(d.Sum(nil))
}

// envValueBytes is key's value in the env file as readEnvFile reads it
// (the Hub's single quotes removed), as a fresh byte slice the caller
// clears; the file buffer is cleared before returning. Missing = nil.
func envValueBytes(path, key string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	defer clear(data)
	var out []byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		k, v, ok := bytes.Cut(line, []byte("="))
		if !ok || string(k) != key {
			continue
		}
		if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' && !bytes.ContainsAny(v[1:len(v)-1], "'\\") {
			v = v[1 : len(v)-1]
		}
		clear(out)
		out = append([]byte(nil), v...) // the last line wins, as in parseEnvRaw
	}
	return out
}

// ── G74: group-readable files in the data directory ──────

// dataDirReadable are the only files in HUB_DATA_DIR another container
// may read: group-gate (world-readable, uid 10003) the first three, the
// gate (group 10001) the last three. The gate files are 0640.
var dataDirReadable = map[string]os.FileMode{
	"group-gate-policy.json":  0,
	"portal-apps.json":        0,
	policy.UserAttributesFile: 0,
	aigate.GateFileName:       aigate.FileMode,
	aigate.CredsFileName:      aigate.FileMode,
}

// checkDataDirModes (Init, G74): any other file in the data directory
// with a group or other permission bit is logged and chmodded 0600; the
// gate files are set to exactly 0640. Template checkouts (repos/) are
// left alone: apps bind-mount their files.
func (h *Hub) checkDataDirModes() {
	root := filepath.Clean(h.cfg.DataDir)
	repos := filepath.Join(root, "repos")
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("data dir check: %s: %v", p, err)
			return nil
		}
		if d.IsDir() {
			if p == repos {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		perm := info.Mode().Perm()
		want, listed := dataDirReadable[filepath.Base(p)]
		listed = listed && filepath.Dir(p) == root
		switch {
		case listed && want == 0:
			// group-gate reads these world-readable (0644): never
			// writable by anyone but the Hub.
			if perm&0o022 == 0 {
				return nil
			}
			want = perm &^ 0o022
		case listed:
			if perm == want {
				return nil
			}
		case perm&0o077 == 0:
			return nil
		default:
			want = 0o600
		}
		log.Printf("data dir check: %s had mode %04o — set to %04o (only the policy, portal, attribute and gate files may be read by other containers)", p, perm, want)
		if err := os.Chmod(p, want); err != nil {
			log.Printf("data dir check: chmod %s: %v", p, err)
		}
		return nil
	})
}
