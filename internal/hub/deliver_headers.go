package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Header deliveries (contract §4.1 v2 hosts, §13.6, spec calls 13, 26).
// group-gate returns X-Forwarded-Attr-<suffix> on allow, per host, from
// the hosts section of user-attributes.json: host → header suffix (the
// part after X-Forwarded-Attr-, which group-gate prefixes again) → user
// → value. Every host of every router of the instance whose rendered
// chain has portcullis-groups@docker (extra-domain hosts included) gets
// the same headers.
//
// One unit "headers" per instance, after the claims: the population's
// rendered values (RenderDelivery: one line, ≤ 1024 B; UNRESOLVED / nil /
// unrenderable values left out, never a default) go into h.hostHeaders
// under mu (generation re-checked), then a policy write publishes them
// (applies next_request: no reload, no restart). delivered.json keeps
// only the unit's hash (P13); the record itself is the hosts section of
// user-attributes.json, which Init reads back (seedHostHeaders). Without
// a directory snapshot the unit is skipped and the last published hosts
// are kept. WritePolicy publishes only enabled instances with a template
// view, only on hosts their routers currently gate (fail closed).

const unitHeaders = "headers"

// headerOptions are t's person and person-entered options with header
// deliveries (a person-entered header carries each person's own value).
func headerOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		if sc := opts[i].EffectiveScope(); (sc == templates.ScopePerson || sc == templates.ScopePersonEntered) && len(headerDeliveries(&opts[i])) > 0 {
			out = append(out, &opts[i])
		}
	}
	return out
}

// headerDeliveries are o's header deliveries.
func headerDeliveries(o *templates.Option) []templates.Delivery {
	var out []templates.Delivery
	for _, d := range o.Delivery {
		if d.Header != nil {
			out = append(out, d)
		}
	}
	return out
}

// declaresHeaders: some option of m (any scope) delivers a header.
func declaresHeaders(m *templates.Manifest) bool {
	return len(headerNames(m)) > 0
}

// headerNames are every header-delivery name m declares (any scope).
func headerNames(m *templates.Manifest) []string {
	var out []string
	for _, o := range m.Options() {
		for _, d := range o.Delivery {
			if d.Header != nil {
				out = append(out, d.Header.Name)
			}
		}
	}
	return out
}

// headersNeedPeople: t delivers headers (they need the directory).
func headersNeedPeople(t *templates.Template) bool { return len(headerOptions(t)) > 0 }

// headerSuffix is a header delivery name's hosts key.
func headerSuffix(name string) string {
	if len(name) > len(policy.HeaderPrefix) && strings.EqualFold(name[:len(policy.HeaderPrefix)], policy.HeaderPrefix) {
		return name[len(policy.HeaderPrefix):]
	}
	return name
}

// groupsHostsLocked is every host (normalised, valid, sorted) of every
// router of t whose rendered chain (routeLabelsLocked: the native_login
// prepend and the extra-domain swap included) has
// portcullis-groups@docker. Caller holds mu.
func (h *Hub) groupsHostsLocked(t *templates.Template) ([]string, error) {
	rl, err := h.routeLabelsLocked(t)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for name, ri := range rl.routes.Info {
		mws := ri.Middlewares
		if m, ok := rl.middlewares[name]; ok {
			mws = strings.Split(m, ",")
		}
		gated := false
		for _, m := range mws {
			if strings.TrimSpace(m) == "portcullis-groups@docker" {
				gated = true
			}
		}
		if !gated {
			continue
		}
		for _, host := range routerHosts(t, ri, h.cfg.Domain) {
			if n := NormalizeHost(host); templates.ValidHostname(n) {
				set[n] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

// routerHosts are the instance hostnames router ri's Host() arguments
// name: its hostname variables' values (contract v2), or in the legacy
// form the host of the host router of each subdomain.
func routerHosts(t *templates.Template, ri *templates.RouterInfo, domain string) []string {
	var out []string
	for i, sub := range ri.Subdomains {
		hv := ""
		if i < len(ri.HostVars) {
			hv = ri.HostVars[i]
		}
		if hv != "" {
			if host := t.InstanceEnv[hv]; host != "" {
				out = append(out, host)
			}
			continue
		}
		host := sub + "." + domain
		for r, s := range t.HostRouters {
			if s == sub && t.Hosts[r] != "" {
				host = t.Hosts[r]
				break
			}
		}
		out = append(out, host)
	}
	return out
}

// headerPlan is the header unit's desired state for one run.
type headerPlan struct {
	active bool                                    // the unit runs
	hosts  map[string]map[string]map[string]string // host → suffix → user → value (nil: none)
	hash   string
	// unrenderable: values no delivery could take (left out).
	unrenderable int
	skip         string // SkipDirectory: no snapshot
	err          error
}

// buildHeadersLocked is t's header plan with snapshot m (nil: the
// directory unavailable — skipped, nothing changed). The unit also runs
// with no header option while something is still published, to clear
// it. Caller holds mu (read).
func (h *Hub) buildHeadersLocked(t *templates.Template, m *directory.Membership, recorded bool) headerPlan {
	opts := headerOptions(t)
	plan := headerPlan{active: len(opts) > 0 || recorded || len(h.hostHeaders[t.ID]) > 0}
	if !plan.active {
		return plan
	}
	if len(opts) > 0 && m == nil {
		plan.skip = SkipDirectory
		return plan
	}
	bySuffix := map[string]map[string]string{}
	if len(opts) > 0 {
		people := h.peopleWithEntriesLocked(t, m)
		users := sortedUsers(people)
		for _, o := range opts {
			for _, d := range headerDeliveries(o) {
				vals := map[string]string{}
				for _, user := range users {
					res, ok := people[user][o.Key]
					if !ok || res.Value == nil {
						continue // no value, or UNRESOLVED (fail closed)
					}
					r, err := settings.RenderDelivery(o, res.Value, &d)
					if err != nil {
						log.Printf("settings: %s: %s: the value of %s can't be delivered as a header (%v): left out", t.ID, o.Key, user, err)
						plan.unrenderable++
						continue
					}
					vals[strings.ToLower(user)] = r.Text
				}
				bySuffix[headerSuffix(d.Header.Name)] = vals
			}
		}
		hosts, err := h.groupsHostsLocked(t)
		if err != nil {
			plan.err = fmt.Errorf("the routers' hosts: %w", err)
			return plan
		}
		if len(hosts) > 0 {
			plan.hosts = make(map[string]map[string]map[string]string, len(hosts))
			for _, host := range hosts {
				hh := make(map[string]map[string]string, len(bySuffix))
				for s, v := range bySuffix {
					hh[s] = maps.Clone(v)
				}
				plan.hosts[host] = hh
			}
		}
	}
	b, _ := json.Marshal(plan.hosts)
	sum := sha256.Sum256(b)
	plan.hash = hex.EncodeToString(sum[:])
	return plan
}

// runHeaders applies the header plan: h.hostHeaders[id] under mu (the
// generation re-checked: stop = superseded), then a policy write.
func (h *Hub) runHeaders(id string, p headerPlan, current func() bool, delivered *deliveredDoc, now time.Time) (u UnitResult, stop bool) {
	u = UnitResult{Unit: unitHeaders, At: now}
	switch {
	case p.skip != "":
		u.Skipped = p.skip
		return u, false
	case p.err != nil:
		u.Error = h.redactUnitError(id, p.err)
		return u, false
	}
	h.mu.Lock()
	if !current() {
		h.mu.Unlock()
		return u, true
	}
	same := reflect.DeepEqual(h.hostHeaders[id], p.hosts)
	if !same {
		if h.hostHeaders == nil {
			h.hostHeaders = map[string]map[string]map[string]map[string]string{}
		}
		if p.hosts == nil {
			delete(h.hostHeaders, id)
		} else {
			h.hostHeaders[id] = p.hosts
		}
	}
	h.mu.Unlock()
	// Unchanged: the record equals the plan and the plan's hash is
	// recorded — only after a successful write (nil plans included): a
	// failed write leaves no hash, so the next run rewrites the file.
	if same && delivered.Hashes[unitHeaders] == p.hash {
		u.OK, u.Skipped = true, SkipUnchanged
		return u, false
	}
	written, err := h.writePolicy()
	switch {
	case err != nil:
		u.Error = h.redactUnitError(id, err)
		delete(delivered.Hashes, unitHeaders)
	case !written:
		// The directory failed for the policy write: the attributes file
		// (the last published hosts) is kept; the next write publishes.
		u.Error = "user-attributes.json kept as it was (directory unavailable): the headers follow with the next policy write"
		delete(delivered.Hashes, unitHeaders)
	default:
		u.OK = true
		delivered.Hashes[unitHeaders] = p.hash
		if p.unrenderable > 0 {
			u.Message = fmt.Sprintf("%d value(s) could not be rendered as a header: left out", p.unrenderable)
		}
	}
	return u, false
}

// publishedHostHeadersLocked merges the header records of the enabled
// instances with a template view onto the hosts their routers gate now
// (WritePolicy). Every header suffix an enabled instance declares is
// declared on each host it gates, with no values while there is no
// record yet (enabled again, the first delivery pending or skipped, a
// failed seed, a host SetHosts just added): group-gate then drops the
// same-named shared-field header there. suppress: the folded suffixes
// of instances whose gated hosts are unknown — the caller drops the
// colliding shared-field headers everywhere (fail closed). Caller holds
// mu (read).
func (h *Hub) publishedHostHeadersLocked() (out map[string]map[string]map[string]string, suppress map[string]bool) {
	out = map[string]map[string]map[string]string{}
	for i := range h.instances {
		t := &h.instances[i]
		if !h.st.IsEnabled(t.ID) {
			continue
		}
		rec := h.hostHeaders[t.ID]
		suffixes := map[string]bool{}
		for _, name := range headerNames(&t.Manifest) {
			suffixes[headerSuffix(name)] = true
		}
		if len(suffixes) == 0 && len(rec) == 0 {
			continue
		}
		hosts, err := h.groupsHostsLocked(t)
		if err != nil {
			log.Printf("auth-policy: %s: its routers' hosts are unknown (%v): no setting headers published, same-named shared-field headers withheld", t.ID, err)
			if suppress == nil {
				suppress = map[string]bool{}
			}
			for s := range suffixes {
				suppress[strings.ToLower(s)] = true
			}
			for _, byS := range rec {
				for s := range byS {
					suppress[strings.ToLower(s)] = true
				}
			}
			continue
		}
		for _, host := range hosts {
			if out[host] == nil {
				out[host] = map[string]map[string]string{}
			}
			for s := range suffixes {
				if out[host][s] == nil {
					out[host][s] = map[string]string{}
				}
			}
			for s, v := range rec[host] {
				out[host][s] = v
			}
		}
	}
	// Enabled instances without a view (the template missing) are
	// enforced from their published snapshot: their header suffixes
	// stay declared, with no values, on its hosts.
	core := policy.CoreHosts(h.cfg.Domain)
	for _, id := range h.st.Enabled {
		snap, ok := h.st.Published[id]
		if h.findLocked(id) != nil || !ok || len(snap.HeaderSuffixes) == 0 {
			continue
		}
		for host := range hostSet(snap.Hosts, core) {
			if out[host] == nil {
				out[host] = map[string]map[string]string{}
			}
			for _, s := range snap.HeaderSuffixes {
				if out[host][s] == nil {
					out[host][s] = map[string]string{}
				}
			}
		}
	}
	return out, suppress
}

// dropHostHeadersLocked forgets the header records of instances that
// are not enabled or have no view (rebuildLocked): re-enabled, an
// instance publishes nothing until its next delivery. Caller holds mu.
func (h *Hub) dropHostHeadersLocked() {
	for id := range h.hostHeaders {
		if !h.st.IsEnabled(id) || h.findLocked(id) == nil {
			delete(h.hostHeaders, id)
		}
	}
}

// seedHostHeaders reads the header records back from the hosts section
// of user-attributes.json (Init, before the first policy write): each
// enabled instance's gated hosts, its declared header suffixes.
func (h *Hub) seedHostHeaders() {
	b, err := os.ReadFile(h.attributesPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("settings: user-attributes.json unreadable (%v): setting headers are published again by the next deliveries", err)
		}
		return
	}
	var doc policy.UserAttributesDocument
	if err := json.Unmarshal(b, &doc); err != nil || doc.Version != policy.UserAttributesVersion {
		log.Printf("settings: user-attributes.json is not a version %d document (%v): setting headers are published again by the next deliveries", policy.UserAttributesVersion, err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.instances {
		t := &h.instances[i]
		opts := headerOptions(t)
		if !h.st.IsEnabled(t.ID) || len(opts) == 0 {
			continue
		}
		suffixes := map[string]bool{}
		for _, o := range opts {
			for _, d := range headerDeliveries(o) {
				suffixes[headerSuffix(d.Header.Name)] = true
			}
		}
		hosts, err := h.groupsHostsLocked(t)
		if err != nil {
			continue
		}
		rec := map[string]map[string]map[string]string{}
		for _, host := range hosts {
			for s, v := range doc.Hosts[host] {
				if !suffixes[s] {
					continue
				}
				if rec[host] == nil {
					rec[host] = map[string]map[string]string{}
				}
				rec[host][s] = v
			}
		}
		if len(rec) > 0 {
			if h.hostHeaders == nil {
				h.hostHeaders = map[string]map[string]map[string]map[string]string{}
			}
			h.hostHeaders[t.ID] = rec
		}
	}
}

// replaceAttrHosts rewrites only the hosts section of the existing
// user-attributes.json (WritePolicy while the directory state fails).
// written: the file has these hosts now; false when there is no
// readable version 2 file (it is left as it is). suppress: the shared
// fields whose header collides with an instance's unknown hosts are
// dropped from the kept fields and users (publishedHostHeadersLocked).
func (h *Hub) replaceAttrHosts(hosts map[string]map[string]map[string]string, suppress map[string]bool) (written bool, err error) {
	b, rerr := os.ReadFile(h.attributesPath())
	if rerr != nil {
		return false, nil
	}
	var doc policy.UserAttributesDocument
	if json.Unmarshal(b, &doc) != nil || doc.Version != policy.UserAttributesVersion || doc.Fields == nil || doc.Users == nil {
		return false, nil
	}
	next := policy.BuildHosts(hosts)
	fields := len(doc.Fields)
	policy.SuppressFieldHeaders(&doc, suppress)
	if reflect.DeepEqual(policy.BuildHosts(doc.Hosts), next) && doc.Hosts != nil && len(doc.Fields) == fields {
		return true, nil
	}
	doc.Hosts = next
	if err := policy.WriteUserAttributes(h.attributesPath(), doc); err != nil {
		return false, err
	}
	return true, nil
}

// headerRecorded: instance id has a header record (in memory or a unit
// hash in delivered.json).
func (h *Hub) headerRecorded(id string) bool {
	h.mu.RLock()
	n := len(h.hostHeaders[id])
	h.mu.RUnlock()
	_, ok := h.loadDelivered(id).Hashes[unitHeaders]
	return n > 0 || ok
}
