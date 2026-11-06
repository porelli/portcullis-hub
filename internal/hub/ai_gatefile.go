package hub

import (
	"filippo.io/age"

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
// keeps the last file (and the sync loop retries); every input doubt —
// an unknown LoA, a mode the companion doesn't offer, a missing host, a
// client whose Keycloak ensure failed, a username the gate wouldn't take —
// leaves the resource, the person or the client out, never in.

// errGateDirectory: populations can't be computed (the directory is
// unavailable); the last gate file is kept.
var errGateDirectory = errors.New("mcp-gate.json: the directory is unavailable — keeping the last file")

func (h *Hub) gatePath() string  { return filepath.Join(h.cfg.DataDir, aigate.GateFileName) }
func (h *Hub) credsPath() string { return filepath.Join(h.cfg.DataDir, aigate.CredsFileName) }

// SetAIClientHealth records which AI client ids (the Hub's three and
// every ai_client) the last Keycloak ensure left in place (true) — the
// directory sync loop calls it (Task 12). Only those are listed in
// mcp-gate.json; nil (not known yet) lists none.
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
// unreadable or unparseable HUB_MCP_GATE_RECIPIENT_FILE).
func (h *Hub) gateRecipient() *age.X25519Recipient {
	if h.cfg.MCPGateRecipientFile == "" {
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

// gateFile builds mcp-gate.json from state and m (the directory snapshot
// taken before mu; G47) with the AI clients healthy lists (nil = none).
// Takes mu (read) itself. m nil with AI on: errGateDirectory.
func (h *Hub) gateFile(m *directory.Membership, healthy map[string]bool) (*aigate.File, []callerSecretSource, error) {
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
	if m == nil {
		return nil, nil, errGateDirectory
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
		for _, c := range t.Manifest.Clients {
			if id := t.InstanceClientID(c.ClientID); c.AIClient && ok(id) {
				aiClients = append(aiClients, id)
			}
		}
	}
	people := sortedSet(append(append([]string{}, offered...), aiClients...))
	f.Clients = people
	admin := sortedSet(adminClients)
	now := time.Now().UTC()

	var secrets []callerSecretSource
	for i := range h.instances {
		t := &h.instances[i]
		for _, r := range h.companionResourcesLocked(t, m, f, people, now) {
			f.Resources = append(f.Resources, r)
			if r.Identity.Mode == aigate.IdentityHeaders {
				c := companionOf(t, r.Companion)
				secrets = append(secrets, callerSecretSource{ref: r.Identity.SecretRef, envFile: h.envPath(t.ID), key: c.Identity.CallerSecret.Env})
			}
		}
	}
	everyone := validUsers(slices.Collect(maps.Keys(m.Users)))
	f.Resources = append(f.Resources, fixedResource(aigate.KindAggregate, aigate.AggregateURL(domain), aigate.ScopeAll, aigate.LabelAggregate, "mcp."+domain, people, everyone, false))
	if ai.PortcullisAdmin && len(admin) > 0 {
		adm := fixedResource(aigate.KindAdmin, aigate.AdminURL(domain), aigate.ScopeAdmin, aigate.LabelAdmin, "hub."+domain, admin, groupMembers(m, lldap.AdminGroup), false)
		adm.Expiring = pendingOf(m, lldap.AdminGroup, adm.Population, now)
		f.Resources = append(f.Resources, adm)
	}
	if ai.PortcullisPeople {
		f.Resources = append(f.Resources, fixedResource(aigate.KindPeople, aigate.PeopleURL(domain), aigate.ScopePeople, aigate.LabelPeople, "people."+domain, people, everyone, true))
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
func (h *Hub) companionResourcesLocked(t *templates.Template, m *directory.Membership, f *aigate.File, clients []string, now time.Time) []aigate.Resource {
	if !t.Enabled || t.Manifest.AI.Unsupported != "" || len(t.Manifest.AI.MCP) == 0 || t.Manifest.Routerless() || h.instanceBusyLocked(t.ID) {
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
	var out []aigate.Resource
	for i := range t.Manifest.AI.MCP {
		c := &t.Manifest.AI.MCP[i]
		sw, on := switches[c.Name]
		if !on || !sw.Enabled || c.Identity.Mode == templates.IdentityAppOAuth {
			continue
		}
		switch {
		case !slices.Contains(c.Modes, sw.Mode):
			skip(c.Name, fmt.Sprintf("mode %q is not one of its modes", sw.Mode))
			continue
		case loa < 0 || loa > 2:
			skip(c.Name, fmt.Sprintf("the instance's policy LoA %d can't get AI support", loa))
			continue
		case !templates.AliasFits(t.ID, c.Name):
			skip(c.Name, "the alias is longer than one DNS label")
			continue
		}
		host := NormalizeHost(t.Hosts[c.Router])
		if host == "" || !templates.ValidHostname(host) {
			skip(c.Name, "its router has no hostname")
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
		// The settings population (§13.3, call 27); empty with a reason
		// (sign_in native, no access group in LLDAP): nobody gets in.
		pop := h.populationLocked(t, m)
		users := make([]string, 0, len(pop.People))
		for _, p := range pop.People {
			users = append(users, p.User)
		}
		r.Population = validUsers(users)
		if g := accessGroupOf(t); g != "" {
			r.Expiring = pendingOf(m, g, r.Population, now)
		}
		if r.Identity.Mode == aigate.IdentityHeaders {
			r.People = peopleOf(m, r.Population)
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

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// fixedResource is one of the three Portcullis-wide resources.
func fixedResource(kind, url, scope, label, host string, clients, population []string, aggregate bool) aigate.Resource {
	return aigate.Resource{
		URL: url, Scope: scope, Clients: append([]string{}, clients...), Kind: kind, Label: label, Host: host,
		Hosts: []string{}, MinLoA: 2, Protocol: []string{}, Identity: aigate.Identity{Mode: aigate.IdentityNone},
		Tools:     aigate.Tools{Writes: []string{}, Confirm: []string{}, Never: []string{}},
		Aggregate: aggregate, Population: population, Expiring: map[string]aigate.Time{},
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
// policyWriteMu): mcp-gate.json from m (taken before mu), then the
// caller secrets of the companions it lists. A directory failure keeps
// the last gate file and marks it for the sync loop's retry.
func (h *Hub) writeGateFiles(m *directory.Membership, mErr error) error {
	f, secrets, err := h.gateFile(m, h.aiClientHealth())
	if err != nil {
		h.gateStale.Store(true)
		if mErr != nil {
			log.Printf("mcp-gate: directory unavailable, keeping the last %s: %v", aigate.GateFileName, mErr)
		}
		return err
	}
	if err := aigate.WriteFile(h.gatePath(), f); err != nil {
		h.gateStale.Store(true)
		return err
	}
	h.gateStale.Store(false)
	return h.syncCallerSecrets(f, secrets)
}

// syncCallerSecrets keeps mcp-credentials.json's caller_secrets equal to
// the identity_headers companions f lists: each value read from the
// instance's env file and encrypted only when it changed (a digest kept
// in memory, never on disk); a companion no longer listed loses its
// entry. Caller holds policyWriteMu.
func (h *Hub) syncCallerSecrets(f *aigate.File, sources []callerSecretSource) error {
	if !f.Enabled {
		return nil // entries of unlisted resources are ignored by the gate
	}
	if h.callerDigests == nil {
		h.callerDigests = map[string]string{}
	}
	want := map[string]bool{}
	var errs []error
	for _, s := range sources {
		want[s.ref] = true
		v := readEnvFile(s.envFile)[s.key]
		if v == "" {
			// No secret yet: the companion refuses every caller.
			log.Printf("mcp-gate: %s has no caller secret %s yet", s.ref, s.key)
			continue
		}
		sum := sha256.Sum256([]byte(s.ref + "\x00" + v))
		d := hex.EncodeToString(sum[:])
		if h.callerDigests[s.ref] == d && h.creds().HasCallerSecret(s.ref) {
			continue
		}
		if err := h.creds().PutCallerSecret(s.ref, []byte(v)); err != nil {
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
			return nil
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
