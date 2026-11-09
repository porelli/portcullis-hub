package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Instance hostnames (contract §11.3): defaults, validation against the
// main domain and the enrolled domains, collisions, and the live change
// (SetHosts).

// Domain is a domain instances may get hostnames on: the main domain or an
// enrolled one (contract §12). State DomainReady = assignable (§12.3).
type Domain struct {
	Name  string
	State string
}

// DomainReady is the state of an assignable domain (records OK, valid
// certificate, §12.3).
const DomainReady = "ready"

// DomainSource lists the known domains. Every entry other than the main
// domain is an enrolled domain: a host at or under one is an extra-domain
// host (§5). Domains is called under the Hub's lock: it must return a
// cached list (no network calls): in production knownDomains, the last
// known list of the domains service in state.yaml (domains.go).
type DomainSource interface {
	Domains() []Domain
}

// SetDomainSource replaces the domain list (tests; production uses the
// known list in state.yaml, domains.go). nil = the known list.
func (h *Hub) SetDomainSource(ds DomainSource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ds == nil {
		ds = knownDomains{h}
	}
	h.domains = ds
	h.rebuildLocked()
}

// Auditor appends audit entries (the Hub's audit.jsonl, contract §9.5).
type Auditor interface {
	Append(e directory.AuditEntry) error
}

// SetAudit sets where instance operations are audited (§11.7).
func (h *Hub) SetAudit(a Auditor) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.audit = a
}

// auditOp records an instance operation; Result from err as the API does
// (a 4xx StatusError or ErrBusy is "refused").
func (h *Hub) auditOp(actor directory.Actor, action, target, detail string, err error) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	e := directory.AuditEntry{Actor: actor.User, Via: actor.Via, Client: actor.Client, Action: action, Target: target, Detail: actor.AuditDetail(detail), Result: "ok"}
	if err != nil {
		inst, _, _ := strings.Cut(target, "/")
		// Redact, then clip (600 runes, as the routes' audits do).
		e.Result, e.Error = "error", clipRunes(h.RedactErr(inst, err), 600)
		var se *StatusError
		var busy ErrBusy
		if (errors.As(err, &se) && se.Status < 500) || errors.As(err, &busy) {
			e.Result = "refused"
		}
	}
	if aerr := a.Append(e); aerr != nil {
		log.Printf("audit: %v", aerr)
	}
}

// RedactErr is err's text as an audit entry may hold it: for an instance
// id, redacted like its op records (stored secret settings,
// secret-looking env values, credential hashes); else unchanged.
func (h *Hub) RedactErr(instance string, err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if templates.ValidID(instance) {
		msg = h.secretRedactor(instance, secretsOf(err))(msg)
	}
	return msg
}

// NormalizeHost lowercases a hostname and drops surrounding space and one
// trailing dot. Anything else (a port, a scheme) stays and fails
// validation.
func NormalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// enrolledLocked returns the enrolled domains (every known domain except
// the main one), normalised. Caller must hold mu.
func (h *Hub) enrolledLocked() []Domain {
	main := strings.ToLower(h.cfg.Domain)
	var out []Domain
	if h.domains == nil {
		return nil
	}
	for _, d := range h.domains.Domains() {
		n := NormalizeHost(d.Name)
		if n == main {
			continue
		}
		if domainNameProblem(n, main) != "" {
			continue // validKnown logged it when the list arrived
		}
		out = append(out, Domain{Name: n, State: d.State})
	}
	return out
}

// extraDomainOf returns the enrolled domain host is at or under.
func extraDomainOf(host string, enrolled []Domain) (Domain, bool) {
	for _, d := range enrolled {
		if host == d.Name || strings.HasSuffix(host, "."+d.Name) {
			return d, true
		}
	}
	return Domain{}, false
}

// extraFunc reports the extra-domain hosts (at or under any enrolled
// domain, assignable or not).
func extraFunc(enrolled []Domain) func(string) bool {
	if len(enrolled) == 0 {
		return nil
	}
	return func(host string) bool {
		_, ok := extraDomainOf(host, enrolled)
		return ok
	}
}

// placeHost checks host (normalised) against §11.3 "Valid hostnames": a
// valid hostname that is an assignable enrolled domain <d> or <label>.<d>,
// or, at or under no enrolled domain, <label>.<main domain>. keep: the
// instance already has this host (a domain that stopped being assignable
// keeps its hostnames, §12.3).
func placeHost(router, host, main string, enrolled []Domain, keep bool) error {
	if host == main {
		return statusErr(409, "hostname %s is a core hostname (the portal)", host)
	}
	if !templates.ValidHostname(host) {
		return statusErr(400, "hostname %q (host router %s) is not a valid hostname (lowercase labels, no scheme, port or wildcard, at most 253 characters)", host, router)
	}
	if d, ok := extraDomainOf(host, enrolled); ok {
		if rest := strings.TrimSuffix(strings.TrimSuffix(host, d.Name), "."); rest != "" && !templates.ValidLabel(rest) {
			return statusErr(400, "hostname %s (host router %s): only %s or <label>.%s — the domain's certificate covers one label", host, router, d.Name, d.Name)
		}
		if d.State == DomainUnreachable && !keep {
			return errDomainsUnreachable(host, router, d.Name)
		}
		if d.State == DomainMissing && !keep {
			return statusErr(409, "hostname %s (host router %s): domain %s is no longer listed by the domains service (state %q): re-enroll it before giving it new hostnames", host, router, d.Name, d.State)
		}
		if d.State != DomainReady && !keep {
			return statusErr(409, "hostname %s (host router %s): domain %s is not assignable yet (state %q: its records or certificate are not ready)", host, router, d.Name, d.State)
		}
		return nil
	}
	label, ok := strings.CutSuffix(host, "."+main)
	if !ok {
		return statusErr(400, "hostname %s (host router %s) is neither <label>.%s nor on an enrolled domain", host, router, main)
	}
	if !templates.ValidLabel(label) {
		return statusErr(400, "hostname %s (host router %s): only <label>.%s — deeper names need an enrolled domain", host, router, main)
	}
	return nil
}

// instanceSuffix is the id without a leading "<template>-" (§11.3).
func instanceSuffix(templateID, id string) string {
	if s, ok := strings.CutPrefix(id, templateID+"-"); ok && s != "" {
		return s
	}
	return id
}

// defaultHost is the pre-filled hostname <sub>-<suffix>.<domain> (§11.3),
// the suffix truncated so the label fits 63 characters (a trailing "-"
// dropped); false if there's no room or the result isn't a valid hostname.
func defaultHost(sub, suffix, domain string) (string, bool) {
	if max := 63 - len(sub) - 1; len(suffix) > max {
		if max < 1 {
			return "", false
		}
		suffix = strings.TrimRight(suffix[:max], "-")
		if suffix == "" {
			return "", false
		}
	}
	h := sub + "-" + suffix + "." + strings.ToLower(domain)
	return h, templates.ValidHostname(h)
}

// defaultHostsFor are a new instance's pre-filled hostnames on domain
// (§11.3). A host router without a valid default is an error naming it.
func defaultHostsFor(t *templates.Template, id, domain string) (map[string]string, error) {
	suffix := instanceSuffix(t.TemplateID, id)
	out := map[string]string{}
	for r, sub := range t.HostRouters {
		h, ok := defaultHost(sub, suffix, domain)
		if !ok {
			return nil, statusErr(400, "host router %s: no valid default hostname for %s-%s.%s — give an explicit hostname", r, sub, suffix, domain)
		}
		out[r] = h
	}
	return out, nil
}

// DefaultHosts are instance instanceID's pre-filled hostnames on domain
// ("" = the main domain): each host router's default subdomain plus
// "-<suffix>" (§11.3), or the default subdomains themselves for the
// default instance. Host routers with no valid default are left out (the
// admin must give one); nil for an unknown template.
func (h *Hub) DefaultHosts(templateID, instanceID, domain string) map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	t := h.catalogLocked(templateID)
	if t == nil {
		return nil
	}
	if domain == "" {
		domain = h.cfg.Domain
	}
	domain = NormalizeHost(domain)
	if instanceID == templateID {
		return t.DefaultHosts(domain)
	}
	suffix := instanceSuffix(t.TemplateID, instanceID)
	out := map[string]string{}
	for r, sub := range t.HostRouters {
		if host, ok := defaultHost(sub, suffix, domain); ok {
			out[r] = host
		}
	}
	return out
}

// resolveHostsLocked normalises hosts, checks each against the domain
// rules (placeHost; current: the instance's hosts now) and returns the
// instance view of t for id with them. Caller must hold mu.
func (h *Hub) resolveHostsLocked(t *templates.Template, id string, hosts, current map[string]string) (templates.Template, error) {
	enrolled := h.enrolledLocked()
	main := strings.ToLower(h.cfg.Domain)
	norm := make(map[string]string, len(hosts))
	routers := make([]string, 0, len(hosts))
	for r := range hosts {
		routers = append(routers, r)
	}
	sort.Strings(routers)
	for _, r := range routers {
		if _, ok := t.HostRouters[r]; !ok {
			return templates.Template{}, statusErr(400, "%s is not a host router of template %s", r, t.TemplateID)
		}
		host := NormalizeHost(hosts[r])
		keep := false
		for _, c := range current {
			keep = keep || c == host
		}
		if err := placeHost(r, host, main, enrolled, keep); err != nil {
			return templates.Template{}, err
		}
		norm[r] = host
	}
	view, err := h.newViewLocked(t, id, norm, extraFunc(enrolled))
	if err != nil {
		return templates.Template{}, statusErr(400, "%v", err)
	}
	// Hostnames the routing can't serve (a router mixing main- and
	// extra-domain hosts, a chain reaching portcullis-auth on an extra
	// domain) are refused now, not at the next enable.
	if len(view.ExtraHosts) > 0 {
		if _, err := h.routeLabelsLocked(&view); err != nil {
			return templates.Template{}, statusErr(400, "these hostnames can't be routed: %v", err)
		}
	}
	return view, nil
}

// checkInstanceHostsLocked refuses (409) hostnames used twice by the
// instance, a core host, or a hostname held by any other instance (enabled
// or not, its template resolvable or not), by the published snapshot of a
// default instance whose template is missing, or that is the default
// hostname of any other template of any source, or that a running app
// project other than the instance's own still routes (runtime: Reconcile's
// last view, runtimeCopy — taken before mu). Caller must hold mu.
func (h *Hub) checkInstanceHostsLocked(v *templates.Template, runtime map[string][]string) error {
	main := strings.ToLower(h.cfg.Domain)
	seen := map[string]string{}
	routers := make([]string, 0, len(v.Hosts))
	for r := range v.Hosts {
		routers = append(routers, r)
	}
	sort.Strings(routers)
	for _, r := range routers {
		host := v.Hosts[r]
		if o, ok := seen[host]; ok {
			return statusErr(409, "hostname %s is used by host routers %s and %s", host, o, r)
		}
		seen[host] = r
		if host == main {
			return statusErr(409, "hostname %s is a core hostname (the portal)", host)
		}
	}
	// Every host, main or extra-domain, whatever its classification: never
	// the main apex (above), never at or under a core host; the templates'
	// reserved default hostnames are checked last (full hosts).
	coreSubs := policy.CoreSubdomains()
	for _, r := range routers {
		host := v.Hosts[r]
		for sub := range coreSubs {
			if c := sub + "." + main; host == c || strings.HasSuffix(host, "."+c) {
				return statusErr(409, "hostname %s (host router %s) is at or under the core hostname %s", host, r, c)
			}
		}
	}
	mine := map[string]bool{}
	for _, sub := range v.Subdomains {
		if coreSubs[sub] {
			return statusErr(409, "hostname %s.%s is a core hostname", sub, h.cfg.Domain)
		}
		mine[sub] = true
	}
	subClash := func(subs []string) string {
		for _, s := range subs {
			if mine[s] {
				return s
			}
		}
		return ""
	}
	for i := range h.instances {
		o := &h.instances[i]
		if o.ID == v.ID {
			continue
		}
		for _, oh := range o.Hosts {
			if r, ok := seen[oh]; ok {
				return statusErr(409, "hostname %s (host router %s) is already used by instance %s", oh, r, o.ID)
			}
		}
		if s := subClash(o.Subdomains); s != "" {
			return statusErr(409, "hostname %s.%s is already routed by instance %s", s, h.cfg.Domain, o.ID)
		}
	}
	// Instances without a view (template missing, hosts no longer fit)
	// keep their hostnames: their containers may still route them.
	for id, e := range h.st.Instances {
		if id == v.ID || h.findLocked(id) != nil {
			continue
		}
		for _, oh := range e.Hosts {
			if r, ok := seen[NormalizeHost(oh)]; ok {
				return statusErr(409, "hostname %s (host router %s) is held by instance %s (its template is missing or broken)", oh, r, id)
			}
		}
	}
	for id, snap := range h.st.Published {
		if id == v.ID || h.findLocked(id) != nil {
			continue
		}
		// Snapshots store full hosts (v5), main-domain and extra-domain.
		for _, host := range append(append([]string{}, snap.Hosts...), snap.PublicHosts...) {
			label, onMain := strings.CutSuffix(host, "."+main)
			if _, ok := seen[host]; ok || (onMain && mine[label]) {
				return statusErr(409, "hostname %s is still published for instance %s (its template is missing)", host, id)
			}
		}
	}
	// Projects still running with a hostname (a disabled or deleted
	// instance whose containers survived, an old hostname after a failed
	// restart): two routers for one host.
	rids := make([]string, 0, len(runtime))
	for id := range runtime {
		rids = append(rids, id)
	}
	sort.Strings(rids)
	for _, id := range rids {
		if id == v.ID {
			continue
		}
		for _, oh := range runtime[id] {
			if r, ok := seen[NormalizeHost(oh)]; ok {
				return statusErr(409, "hostname %s (host router %s) is still routed by the running project of %s — restart or stop it first", oh, r, id)
			}
		}
	}
	// Templates from other sources and skipped duplicates route their
	// default hostnames too, should they ever be enabled.
	for _, tt := range h.allTemplates {
		if tt.ID == v.ID {
			continue
		}
		// Compared as full hosts, so an extra-domain host such as an
		// enrolled team-a.<main> can't take a template's team-a.<main>.
		for _, s := range tt.Subdomains {
			if r, ok := seen[s+"."+main]; ok {
				return statusErr(409, "hostname %s.%s (host router %s) is the default hostname of template %s (source %s)", s, h.cfg.Domain, r, tt.ID, tt.Source)
			}
		}
	}
	return nil
}

// signInExtraHostsLocked are t's extra-domain hosts that get a sign-in
// router (§5): those a router uses portcullis-auth on, as rendered (the
// native_login prepend included). Caller must hold mu.
func (h *Hub) signInExtraHostsLocked(t *templates.Template) []string {
	if len(t.ExtraHosts) == 0 {
		return nil
	}
	rl, err := h.routeLabelsLocked(t)
	if err != nil {
		// Unknown routing: keep every extra host's callback (an unused
		// callback URI opens nothing).
		return append([]string(nil), t.ExtraHosts...)
	}
	set := map[string]bool{}
	for _, hosts := range rl.signIn {
		for _, host := range hosts {
			set[host] = true
		}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func callbackURIs(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, keycloak.CallbackURI(host))
	}
	return out
}

// minus returns the entries of a not in b.
func minus(a, b []string) []string {
	drop := map[string]bool{}
	for _, x := range b {
		drop[x] = true
	}
	var out []string
	for _, x := range a {
		if !drop[x] {
			out = append(out, x)
		}
	}
	return out
}

// hostsChange is a validated hostname change, computed under mu and
// applied without it.
type hostsChange struct {
	id       string
	old, new templates.Template
	enabled  bool
	// clients: per manifest client, the redirect URIs before and after.
	clients            []clientHosts
	toNew, toOld       map[string]string // host → host, per host router
	cbAdd, cbRemove    []string          // portcullis-forward-auth callback URIs
	allowed            []string          // old ∪ new hosts (untagged-client adoption)
	oldHosts, newHosts map[string]string
	// reapply: same hostnames, re-applied after a failed change.
	reapply bool
	// members: the directory snapshot the env's group records are
	// checked against (fetched before mu; nil = none delivered).
	members *directory.Membership
	// scopesOld / scopesNew: the mcp:* scopes of the instance's
	// switched-on companions for the old and the new hostnames (§8
	// "Follows the resource": moved in the Keycloak step, undone with
	// the redirect URIs).
	scopesOld, scopesNew map[string]keycloak.MCPScope
}

type clientHosts struct {
	clientID         string
	oldURIs, newURIs []string
}

// hostsDetail renders a change for the audit log: "r: old -> new, ...".
func hostsDetail(old, new map[string]string) string {
	keys := map[string]bool{}
	for r := range old {
		keys[r] = true
	}
	for r := range new {
		keys[r] = true
	}
	rs := make([]string, 0, len(keys))
	for r := range keys {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s: %s -> %s", r, old[r], new[r]))
	}
	return "hosts " + strings.Join(parts, ", ")
}

// SetHosts changes an instance's hostnames (contract §11.3; host router →
// hostname, every host router named). actor is the signed-in admin; the
// change is audited as instance.update with the old and new hostnames.
//
// Order, with one commit point (state saved):
//  1. Validate everything — hostnames, domains, collisions — and refuse
//     (400/409) before anything changes.
//  2. Keycloak: the instance's clients' redirect URIs and web origins,
//     then the portcullis-forward-auth callbacks of its extra-domain
//     hosts. A failure undoes the Keycloak steps already done: the old
//     hostnames stay fully in force.
//  3. Under mu: re-check collisions (a lost race undoes step 2 and is a
//     409), render env and override (a failure restores both files and
//     undoes step 2), then record the new hostnames in state — the commit
//     point.
//  4. After the commit nothing is undone: the policy file and
//     portal-apps.json are written (the old hostnames vanish at once) and
//     an enabled instance is restarted. Any failure (state save, policy,
//     restart) is reported as an OpError with the new hostnames in force.
//
// Steps 2–4 record their outcome as op "hosts". While that record is a
// failure, SetHosts with the instance's current hostnames re-applies steps
// 2–4 (Keycloak, files, policy, restart) instead of being a no-op, so
// retrying the same change reconciles.
func (h *Hub) SetHosts(instanceID string, hosts map[string]string, actor directory.Actor) (err error) {
	detail := ""
	defer func() {
		var busy ErrBusy
		if !errors.As(err, &busy) {
			h.auditOp(actor, "instance.update", instanceID, detail, err)
		}
	}()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(400, "no signed-in user to audit the change as")
	}
	unlock, err := h.lockApp(instanceID)
	if err != nil {
		return err
	}
	defer unlock()
	// lockApp → aiLock (G35): no mint runs against the companion URLs
	// while they move.
	defer h.lifecycleAILock(instanceID)()

	runtime := h.runtimeCopy() // driftMu before mu
	h.mu.Lock()
	ch, err := h.planHostsLocked(instanceID, hosts, runtime)
	h.mu.Unlock()
	if ch != nil {
		detail = hostsDetail(ch.oldHosts, ch.newHosts)
		if ch.reapply {
			detail += " (re-applied after a failed change)"
		}
	}
	if err != nil || ch == nil {
		if err == nil {
			detail = "hosts unchanged"
		}
		return err
	}

	// The scope passes (aiKCMu) wait until the new hostnames are
	// committed or the move is undone: a pass in between would put the
	// state's old audience back. Released before the restart (its start
	// syncs scopes).
	// The directory snapshot first: never a directory call under aiKCMu.
	ch.members = h.groupSnapshot(instanceID)
	scopeUnlock := func() {}
	if len(ch.scopesNew)+len(ch.scopesOld) > 0 {
		h.aiKCMu.Lock()
		scopeUnlock = sync.OnceFunc(h.aiKCMu.Unlock)
		defer scopeUnlock()
	}
	if err := h.applyKeycloakHosts(ch); err != nil {
		return h.finishOp(instanceID, OpHosts, err, false)
	}

	runtime = h.runtimeCopy()
	h.mu.Lock()
	// AI pages whose litellm provider points at this instance render its
	// new host (Task 23): re-delivered and restarted after the commit.
	pagesBefore := h.aiPageDigestsLocked()
	view, keep, saveErr, err := h.commitHostsLocked(ch, runtime)
	var aiPages []string
	if err == nil {
		aiPages = slices.DeleteFunc(h.aiPageChangesLocked(pagesBefore), func(p string) bool { return p == instanceID })
	}
	h.mu.Unlock()
	defer h.restartAIPages(aiPages)
	if err != nil {
		var se *StatusError
		lostRace := errors.As(err, &se) && se.Status < 500
		if lostRace {
			log.Printf("instance %s: %v — undoing its Keycloak changes", instanceID, err)
		}
		h.revertKeycloakHosts(ch, len(ch.clients), true, keep)
		if lostRace {
			return err // a refusal, nothing changed
		}
		return h.finishOp(instanceID, OpHosts, err, false)
	}

	scopeUnlock()
	// An AI page's ai_client: UpdateClientHosts moved its redirect URIs;
	// EnsureAIClient re-asserts them exactly (T10 carry), in the
	// background (it takes aiKCMu; the pass retries a failure).
	if ch.enabled && instanceAIClient(&view) != nil {
		v := view
		h.goBackground(func() {
			if _, err := h.ensureInstanceAIClient(context.Background(), &v); err != nil {
				log.Printf("instance %s: re-asserting its AI client after the hostname change: %v", instanceID, err)
			}
		})
	}
	// Committed: from here on, report, never undo.
	var errs []error
	if saveErr != nil {
		errs = append(errs, fmt.Errorf("saving state.yaml failed (the new hostnames are in force until the Hub restarts; retry the change): %w", saveErr))
	}
	if perr := h.WritePolicy(); perr != nil {
		errs = append(errs, fmt.Errorf("policy file write failed (retry the change): %w", perr))
	}
	log.Printf("instance %s: %s", instanceID, detail)
	if ch.enabled && (headersNeedPeople(&view) || h.headerRecorded(instanceID)) {
		// The header deliveries are keyed by host: a delivery moves them
		// to the new hostnames whatever the restart does (queued: it runs
		// once this operation releases the instance).
		h.TriggerDelivery(instanceID, TriggerMembership, true)
	}
	if ch.enabled {
		defer h.TriggerReconcile()
		if rerr := h.restartLocked(context.Background(), &view); rerr != nil {
			errs = append(errs, rerr)
		}
	}
	return h.finishOp(instanceID, OpHosts, errors.Join(errs...), false)
}

// planHostsLocked validates a hostname change; nil, nil = no change.
// Caller must hold mu.
func (h *Hub) planHostsLocked(id string, hosts map[string]string, runtime map[string][]string) (*hostsChange, error) {
	cur := h.findLocked(id)
	if cur == nil {
		if _, broken := h.brokenInstances[id]; broken {
			return nil, statusErr(409, "instance %s can't be resolved (%s): fix its template first", id, h.brokenInstances[id])
		}
		return nil, statusErr(404, "instance not found: %s", id)
	}
	if err := h.pendingLocked(id); err != nil {
		return nil, err
	}
	if cur.HostForm == templates.FormLegacy {
		return nil, statusErr(409, "template %s still uses ${PORTCULLIS_DOMAIN} rules: its hostnames are fixed", cur.TemplateID)
	}
	t := h.catalogLocked(cur.TemplateID)
	if t == nil {
		return nil, statusErr(409, "template %s is missing", cur.TemplateID)
	}
	if len(hosts) == 0 {
		return nil, statusErr(400, "no hostnames given")
	}
	view, err := h.resolveHostsLocked(t, id, hosts, cur.Hosts)
	if err != nil {
		return nil, err
	}
	view.Enabled = cur.Enabled
	reapply := false
	if reflect.DeepEqual(view.Hosts, cur.Hosts) {
		// Nothing to change, unless the last change failed part-way:
		// then re-apply it (Keycloak, files, policy, restart).
		if lo := h.lastHostsOp(id); lo == nil || lo.OK {
			return nil, nil
		}
		reapply = true
	}
	for r, o := range cur.Hosts {
		if view.Hosts[r] != o && t.Manifest.ImmutableHost(r) {
			return nil, statusErr(409, "the hostname of %s (%s) can't change: template %s fixes it once the instance exists (create a new instance for another hostname)", r, o, cur.TemplateID)
		}
	}
	if err := h.checkInstanceHostsLocked(&view, runtime); err != nil {
		return nil, err
	}
	ch := &hostsChange{id: id, old: *cur, new: view, enabled: h.st.IsEnabled(id), reapply: reapply,
		toNew: map[string]string{}, toOld: map[string]string{},
		oldHosts: copyMap(cur.Hosts), newHosts: copyMap(view.Hosts)}
	allowed := map[string]bool{}
	for r, o := range cur.Hosts {
		n := view.Hosts[r]
		if o != n {
			ch.toNew[o], ch.toOld[n] = n, o
		}
		allowed[o], allowed[n] = true, true
	}
	for x := range allowed {
		ch.allowed = append(ch.allowed, x)
	}
	sort.Strings(ch.allowed)
	for i, c := range view.Manifest.Clients {
		ch.clients = append(ch.clients, clientHosts{clientID: c.ClientID,
			oldURIs: h.redirectURIs(cur.Manifest.Clients[i]), newURIs: h.redirectURIs(c)})
	}
	ch.scopesOld, ch.scopesNew = map[string]keycloak.MCPScope{}, map[string]keycloak.MCPScope{}
	h.instanceScopesLocked(cur, ch.scopesOld)
	h.instanceScopesLocked(&view, ch.scopesNew)
	oldCB, newCB := callbackURIs(h.signInExtraHostsLocked(cur)), callbackURIs(h.signInExtraHostsLocked(&view))
	ch.cbRemove = minus(oldCB, newCB)
	if ch.enabled {
		// Callbacks exist while the instance runs (added on enable); a
		// re-apply makes sure every current one is there.
		ch.cbAdd = minus(newCB, oldCB)
		if reapply {
			ch.cbAdd = newCB
		}
	}
	return ch, nil
}

func (ch *hostsChange) spec(i int, back bool) (keycloak.ClientSpec, []string, map[string]string) {
	c := ch.clients[i]
	s := keycloak.ClientSpec{ClientID: c.clientID, TemplateID: ch.id, AllowedHosts: ch.allowed, RedirectURIs: c.newURIs}
	if back {
		s.RedirectURIs = c.oldURIs
		return s, c.newURIs, ch.toOld
	}
	return s, c.oldURIs, ch.toNew
}

// applyKeycloakHosts moves the instance's clients and the forward-auth
// callbacks to the new hostnames; on failure it undoes what it did. A
// client that doesn't exist yet (never enabled) is skipped: enable
// registers it with the new hostnames.
func (h *Hub) applyKeycloakHosts(ch *hostsChange) error {
	ctx := context.Background()
	if err := h.applyKeycloakClientHosts(ctx, ch); err != nil {
		return err
	}
	return h.moveAIScopes(ctx, ch)
}

// moveAIScopes rewrites the audience and consent text of the instance's
// companion scopes for the new hostnames (12a's ensureAIScopes; §8
// "Follows the resource"). A failure undoes every Keycloak step of the
// change (the scopes back to the old hostnames included). Caller holds
// aiKCMu.
func (h *Hub) moveAIScopes(ctx context.Context, ch *hostsChange) error {
	if len(ch.scopesNew) == 0 {
		return nil
	}
	kc := h.aiKeycloak()
	var errs []error
	if kc == nil {
		errs = []error{errors.New("Keycloak: the AI scope calls are not configured")}
	} else {
		errs = ensureAIScopes(ctx, kc, ch.scopesNew)
	}
	if len(errs) == 0 {
		return nil
	}
	h.revertKeycloakHosts(ch, len(ch.clients), true, nil)
	return &StatusError{Status: 502, Err: fmt.Errorf("%w — nothing changed, the old hostnames stay in force", errors.Join(errs...))}
}

// applyKeycloakClientHosts is the clients' and callbacks' part.
func (h *Hub) applyKeycloakClientHosts(ctx context.Context, ch *hostsChange) error {
	if h.idp == nil {
		return nil
	}
	for i := range ch.clients {
		s, oldURIs, m := ch.spec(i, false)
		err := h.idp.UpdateClientHosts(ctx, s, oldURIs, m)
		if errors.Is(err, keycloak.ErrClientNotFound) {
			continue
		}
		if err != nil {
			h.revertKeycloakHosts(ch, i, false, nil)
			status := 502
			var conflict *keycloak.ConflictError
			if errors.As(err, &conflict) {
				status = 409
			}
			return &StatusError{Status: status, Err: fmt.Errorf("Keycloak client %s: %w — nothing changed, the old hostnames stay in force", s.ClientID, err)}
		}
	}
	if err := h.idp.UpdateForwardAuthCallbacks(ctx, ch.cbAdd, ch.cbRemove); err != nil {
		h.revertKeycloakHosts(ch, len(ch.clients), false, nil)
		return &StatusError{Status: 502, Err: fmt.Errorf("Keycloak client %s callbacks: %w — nothing changed, the old hostnames stay in force", keycloak.ForwardAuthClient, err)}
	}
	return nil
}

// revertKeycloakHosts moves the first n clients (and, if callbacks, the
// forward-auth callbacks) back to the old hostnames, best effort. keep
// holds callback URIs not to remove (their host now belongs to another
// instance).
func (h *Hub) revertKeycloakHosts(ch *hostsChange, n int, callbacks bool, keep map[string]bool) {
	ctx := context.Background()
	if callbacks && len(ch.scopesOld) > 0 {
		// The whole Keycloak step ran (or its scope part failed): the
		// companion scopes go back to the old hostnames too.
		if kc := h.aiKeycloak(); kc != nil {
			for _, err := range ensureAIScopes(ctx, kc, ch.scopesOld) {
				log.Printf("instance %s: undoing the hostname change on an AI scope failed (retry the hostname change): %v", ch.id, err)
			}
		}
	}
	if h.idp == nil {
		return
	}
	if callbacks {
		var drop []string
		for _, u := range ch.cbAdd {
			if !keep[u] {
				drop = append(drop, u)
			}
		}
		if err := h.idp.UpdateForwardAuthCallbacks(ctx, ch.cbRemove, drop); err != nil {
			log.Printf("instance %s: undoing the %s callback change failed (retry the hostname change): %v", ch.id, keycloak.ForwardAuthClient, err)
		}
	}
	for i := 0; i < n; i++ {
		s, uris, m := ch.spec(i, true)
		if err := h.idp.UpdateClientHosts(ctx, s, uris, m); err != nil && !errors.Is(err, keycloak.ErrClientNotFound) {
			log.Printf("instance %s: undoing the hostname change on Keycloak client %s failed (retry the hostname change): %v", ch.id, s.ClientID, err)
		}
	}
}

// commitHostsLocked re-checks the change (another instance may have taken
// a host since planning), renders the instance's env and override for the
// new hostnames (a failure restores both files) and then records the new
// hostnames in state — the commit point. It returns the new view; keep
// (on a lost race) holds the callback URIs whose host another instance
// now holds; saveErr is a failed state.yaml write after the commit; err
// means nothing was committed. Caller must hold mu (write).
func (h *Hub) commitHostsLocked(ch *hostsChange, runtime map[string][]string) (view templates.Template, keep map[string]bool, saveErr, err error) {
	cur := h.findLocked(ch.id)
	t := (*templates.Template)(nil)
	if cur != nil {
		t = h.catalogLocked(cur.TemplateID)
	}
	if t == nil {
		return view, nil, nil, statusErr(409, "instance %s changed meanwhile: retry", ch.id)
	}
	if view, err = h.resolveHostsLocked(t, ch.id, ch.newHosts, ch.oldHosts); err == nil {
		err = h.checkInstanceHostsLocked(&view, runtime)
	}
	if err != nil {
		keep = map[string]bool{}
		for _, host := range ch.new.ExtraHosts {
			if h.hostHeldByOtherLocked(host, ch.id) {
				keep[keycloak.CallbackURI(host)] = true
			}
		}
		return view, keep, nil, err
	}
	view.Enabled = cur.Enabled

	// Files first, restorable: nothing is committed if they fail.
	envPath, ovPath := h.envPath(ch.id), h.overridePath(ch.id)
	restore := backupFiles(envPath, ovPath)
	ferr := h.refreshInstanceEnvLocked(&view, ch.members)
	if ferr == nil && fileExists(ovPath) {
		ferr = h.generateOverrideLocked(&view, h.st.Settings[ch.id])
	}
	if ferr != nil {
		if rerr := restore(); rerr != nil {
			log.Printf("instance %s: restoring env/override after a failed rewrite: %v", ch.id, rerr)
		}
		return view, nil, nil, statusErr500Wrap("env/override rewrite failed — nothing changed, the old hostnames stay in force", ferr)
	}

	// Commit.
	e, ok := h.st.Instances[ch.id]
	if !ok {
		e = state.Instance{ID: ch.id, Template: t.ID}
	}
	e.Hosts = copyMap(view.Hosts)
	if ch.id == t.ID && e.State == "" && !e.HoldsIdentity() && !hasImmutableHosts(t) && reflect.DeepEqual(e.Hosts, t.DefaultHosts(h.cfg.Domain)) {
		delete(h.st.Instances, ch.id) // the default instance needs no entry
	} else {
		h.st.Instances[ch.id] = e
	}
	h.rebuildLocked()
	h.refreshPublishedLocked()
	saveErr = h.st.Save(h.statePath())
	if saveErr != nil {
		log.Printf("ERROR: save state: %v", saveErr)
	}
	if nv := h.findLocked(ch.id); nv != nil {
		view = *nv
	}
	return view, nil, saveErr, nil
}

// hostHeldByOtherLocked reports whether an instance other than id has
// host. Caller must hold mu.
func (h *Hub) hostHeldByOtherLocked(host, id string) bool {
	for i := range h.instances {
		if h.instances[i].ID == id {
			continue
		}
		for _, oh := range h.instances[i].Hosts {
			if oh == host {
				return true
			}
		}
	}
	for oid, e := range h.st.Instances {
		if oid == id {
			continue
		}
		for _, oh := range e.Hosts {
			if NormalizeHost(oh) == host {
				return true
			}
		}
	}
	return false
}

// backupFiles snapshots paths; the returned func puts them back (a file
// that didn't exist is removed).
func backupFiles(paths ...string) func() error {
	type saved struct {
		data []byte
		ok   bool
	}
	old := make([]saved, len(paths))
	for i, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			old[i] = saved{b, true}
		}
	}
	return func() error {
		var errs []error
		for i, p := range paths {
			if old[i].ok {
				if cur, err := os.ReadFile(p); err == nil && string(cur) == string(old[i].data) {
					continue
				}
				errs = append(errs, fsutil.WriteFileAtomic(p, old[i].data, 0600))
			} else if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
