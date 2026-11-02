package hub

import (
	"context"
	"log"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// App instances (contract §11). Every template in the catalog has a
// default instance whose id is the template id, with today's names and
// hostnames; it needs no state entry. Other instances live in state.yaml
// `instances`. Everything per app — enable state, settings, policies,
// public access, sign-in mode, published snapshot, ops record, env and
// override files, compose project — is keyed by instance id. In the Hub,
// an instance is a templates.Template view (Template.Instance) whose ID is
// the instance id.

// Instance states (contract §11.2).
const (
	StateCreated  = "created"
	StateEnabled  = "enabled"
	StateDisabled = "disabled"
	StateDeleting = "deleting"
	StateError    = "error"
)

// InstanceView is one instance as GET /api/instances shows it (§11.7).
type InstanceView struct {
	ID              string            `json:"id"`
	Template        string            `json:"template"`
	Default         bool              `json:"default"`
	State           string            `json:"state"`
	Hosts           map[string]string `json:"hosts"`
	AccessGroup     string            `json:"access_group"`
	AdminGroup      string            `json:"admin_group"`
	KeycloakClients []string          `json:"keycloak_clients"`
	Project         string            `json:"project"`
	// Error says why an instance can't be resolved (state "error"): its
	// template is missing or no longer fits its hostnames.
	Error string `json:"error,omitempty"`
}

// rebuildLocked recomputes the instance views from the catalog and state
// and the catalog's enabled flags and instance lists. Caller must hold mu
// (write).
func (h *Hub) rebuildLocked() {
	var out []templates.Template
	byTemplate := map[string][]string{}
	broken := map[string]string{}
	for i := range h.templates {
		t := &h.templates[i]
		var hosts map[string]string
		if e, ok := h.st.Instances[t.ID]; ok && e.Template == t.ID && len(e.Hosts) > 0 {
			hosts = e.Hosts
		}
		v, err := t.Instance(t.ID, hosts, h.cfg.Domain)
		if err != nil {
			log.Printf("instance %s: %v", t.ID, err)
			broken[t.ID] = err.Error()
			continue
		}
		v.Enabled = h.st.IsEnabled(t.ID)
		out = append(out, v)
	}
	ids := make([]string, 0, len(h.st.Instances))
	for id := range h.st.Instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := h.st.Instances[id]
		if id == e.Template {
			continue // the default instance with stored hosts: above
		}
		t := h.catalogLocked(e.Template)
		if t == nil {
			// Fail-closed via the published snapshot; listed as error.
			broken[id] = "template " + e.Template + " is missing"
			continue
		}
		v, err := t.Instance(id, e.Hosts, h.cfg.Domain)
		if err != nil {
			// Kept (listed as error, enforced from its published snapshot)
			// rather than dropped: its containers may still run.
			log.Printf("instance %s: %v", id, err)
			broken[id] = err.Error()
			continue
		}
		v.Enabled = h.st.IsEnabled(id)
		out = append(out, v)
	}
	for i := range h.templates {
		t := &h.templates[i]
		t.Enabled = h.st.IsEnabled(t.ID)
	}
	for _, v := range out {
		byTemplate[v.TemplateID] = append(byTemplate[v.TemplateID], v.ID)
	}
	for i := range h.templates {
		h.templates[i].Instances = byTemplate[h.templates[i].ID]
	}
	h.instances = out
	h.brokenInstances = broken
}

// catalogLocked returns the catalog entry of a template id. Caller must
// hold mu.
func (h *Hub) catalogLocked(templateID string) *templates.Template {
	for i := range h.templates {
		if h.templates[i].ID == templateID {
			return &h.templates[i]
		}
	}
	return nil
}

// instanceTemplateLocked returns the template id of instance id ("" if
// unknown). Caller must hold mu.
func (h *Hub) instanceTemplateLocked(id string) string {
	if e, ok := h.st.Instances[id]; ok {
		return e.Template
	}
	if h.catalogLocked(id) != nil {
		return id
	}
	return ""
}

// Instances lists every instance, sorted by id: the default instance of
// each template that is enabled or has a lifecycle record, and every
// instance in state.
func (h *Hub) Instances() []InstanceView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	h.opsMu.Lock()
	ops := make(map[string]OpRecord, len(h.ops))
	for k, v := range h.ops {
		ops[k] = v
	}
	h.opsMu.Unlock()
	out := []InstanceView{}
	for i := range h.instances {
		t := &h.instances[i]
		e, inState := h.st.Instances[t.ID]
		_, hasOp := ops[t.ID]
		if t.IsDefault() && !t.Enabled && !hasOp && !inState {
			continue
		}
		n := t.NamesFor(t.ID)
		v := InstanceView{ID: t.ID, Template: t.TemplateID, Default: t.IsDefault(), Hosts: copyMap(t.Hosts),
			AccessGroup: n.AccessGroup, AdminGroup: n.AdminGroup, KeycloakClients: append([]string{}, n.Clients...), Project: n.Project}
		op, hasOp := ops[t.ID]
		switch {
		case e.State == state.InstanceDeleting:
			v.State = StateDeleting
		case hasOp && !op.OK:
			v.State = StateError
		case t.Enabled:
			v.State = StateEnabled
		case e.State == state.InstanceCreated:
			v.State = StateCreated
		default:
			v.State = StateDisabled
		}
		out = append(out, v)
	}
	for id, reason := range h.brokenInstances {
		e, inState := h.st.Instances[id]
		tid := e.Template
		if !inState {
			tid = id
		}
		out = append(out, InstanceView{ID: id, Template: tid, Default: id == tid, State: StateError, Error: reason,
			Hosts: copyMap(e.Hosts), KeycloakClients: []string{}, Project: projectName(id)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// instanceSuffix is the id without a leading "<template>-" (§11.3).
func instanceSuffix(templateID, id string) string {
	if s, ok := strings.CutPrefix(id, templateID+"-"); ok && s != "" {
		return s
	}
	return id
}

// defaultHostsFor are a new instance's pre-filled hostnames on the main
// domain (§11.3): each host router's default subdomain plus
// "-<suffix>", the suffix truncated so the label fits 63 characters.
func defaultHostsFor(t *templates.Template, id, domain string) (map[string]string, error) {
	suffix := instanceSuffix(t.TemplateID, id)
	out := map[string]string{}
	for r, sub := range t.HostRouters {
		s := suffix
		if max := 63 - len(sub) - 1; len(s) > max {
			if max < 1 {
				return nil, statusErr(400, "host router %s: no room for an instance suffix on %s — give an explicit hostname", r, sub)
			}
			s = strings.TrimRight(s[:max], "-")
		}
		out[r] = sub + "-" + s + "." + domain
	}
	return out, nil
}

// CreateInstance creates instance id of a template without enabling it
// (state "created", contract §11.1–11.3). hosts (host router → full
// hostname) nil means the defaults on the main domain. Refused before
// anything is created: a bad id (400), a single template (409), and any
// derived-name or hostname collision (409).
func (h *Hub) CreateInstance(templateID, id string, hosts map[string]string) error {
	if !templates.InstanceIDRe.MatchString(id) {
		return statusErr(400, "instance id %q must match %s", id, templates.InstanceIDRe)
	}
	if strings.HasPrefix(id, templates.ReservedInstancePrefix) {
		return statusErr(400, "instance id %q: ids starting with %q are reserved", id, templates.ReservedInstancePrefix)
	}
	// A leftover project of that name (e.g. a deleted instance whose
	// containers survived) is someone else's: refuse. Docker first, never
	// under mu.
	if h.engine != nil {
		cs, err := h.engine.ListContainers(context.Background(), docker.ProjectFilter(projectName(id)))
		if err != nil {
			return statusErr(503, "cannot check for an existing compose project %s: %v", projectName(id), err)
		}
		for _, c := range cs {
			if c.Project() == projectName(id) {
				return statusErr(409, "compose project %s already exists (stop and remove it first)", projectName(id))
			}
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.catalogLocked(templateID)
	if t == nil {
		return statusErr(404, "template not found: %s", templateID)
	}
	if !t.Manifest.Multi() {
		return statusErr(409, "template %s is instances: single — it runs only as its default instance%s", templateID, singleReason(t))
	}
	if err := h.checkInstanceNamesLocked(t, id); err != nil {
		return err
	}
	if hosts == nil {
		var err error
		if hosts, err = defaultHostsFor(t, id, h.cfg.Domain); err != nil {
			return err
		}
	}
	norm := map[string]string{}
	for r, host := range hosts {
		norm[r] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	}
	view, err := t.Instance(id, norm, h.cfg.Domain)
	if err != nil {
		return statusErr(400, "%v", err)
	}
	if err := h.checkInstanceHostsLocked(&view); err != nil {
		return err
	}
	h.st.Instances[id] = state.Instance{ID: id, Template: templateID, Hosts: view.Hosts, State: state.InstanceCreated}
	h.rebuildLocked()
	h.saveLocked()
	log.Printf("instance %s of %s created (hosts %v)", id, templateID, view.Hosts)
	return nil
}

// singleReason points at the template's notes for why it is single.
func singleReason(t *templates.Template) string {
	if strings.TrimSpace(t.Manifest.Auth.Notes) != "" {
		return " (see the template's auth notes for why)"
	}
	return ""
}

// checkInstanceNamesLocked refuses an id whose derived names (§11.2)
// collide with any template's default instance (enabled or not), with any
// template id, or with another instance (§11.1). Caller must hold mu.
func (h *Hub) checkInstanceNamesLocked(t *templates.Template, id string) error {
	if _, ok := h.st.Instances[id]; ok {
		return statusErr(409, "instance %s already exists", id)
	}
	if h.templateIDs[id] || h.catalogLocked(id) != nil {
		return statusErr(409, "instance id %s is a template id (the default instance of that template)", id)
	}
	taken := map[string]string{} // claim → owner
	for _, tt := range h.allTemplates {
		for _, c := range nameClaims(tt.NamesFor(tt.ID)) {
			taken[c] = "the default instance of " + tt.ID
		}
	}
	for oid, e := range h.st.Instances {
		if ot := h.catalogLocked(e.Template); ot != nil {
			for _, c := range nameClaims(ot.NamesFor(oid)) {
				taken[c] = "instance " + oid
			}
		}
	}
	for _, c := range nameClaims(t.NamesFor(id)) {
		if who, ok := taken[c]; ok {
			kind, name, _ := strings.Cut(c, "\x00")
			return statusErr(409, "instance id %s: its %s %s is already used by %s", id, kind, name, who)
		}
	}
	return nil
}

// nameClaims are an instance's derived names as comparable claims
// ("<kind>\x00<lower-cased name>", §11.1: case-insensitive), in a fixed
// order: project, groups, volumes (by key), Keycloak clients.
func nameClaims(n templates.InstanceNames) []string {
	var out []string
	add := func(kind, name string) {
		if name != "" {
			out = append(out, kind+"\x00"+strings.ToLower(name))
		}
	}
	add("project", n.Project)
	add("group", n.AccessGroup)
	add("group", n.AdminGroup)
	keys := make([]string, 0, len(n.Volumes))
	for k := range n.Volumes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add("volume", n.Volumes[k])
	}
	for _, c := range n.Clients {
		add("Keycloak client", c)
	}
	return out
}

// claimCollision reports (as "<kind> <name> of instance <id>")
// whether template t's default instance would use a name an existing
// instance of another template already derives. Caller must hold mu.
func (h *Hub) claimCollision(t *templates.Template, byID map[string]*templates.Template) string {
	mine := map[string]bool{}
	for _, c := range nameClaims(t.NamesFor(t.ID)) {
		mine[c] = true
	}
	ids := make([]string, 0, len(h.st.Instances))
	for id := range h.st.Instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := h.st.Instances[id]
		ot := byID[e.Template]
		if ot == nil || e.Template == t.ID || id == e.Template {
			continue
		}
		for _, c := range nameClaims(ot.NamesFor(id)) {
			if mine[c] {
				kind, name, _ := strings.Cut(c, "\x00")
				return kind + " " + name + " of instance " + id
			}
		}
	}
	return ""
}

// checkInstanceHostsLocked refuses hostnames used twice by the instance,
// by any other instance (enabled or not) or by core. Caller must hold mu.
func (h *Hub) checkInstanceHostsLocked(v *templates.Template) error {
	seen := map[string]string{}
	for r, host := range v.Hosts {
		if o, ok := seen[host]; ok {
			return statusErr(409, "hostname %s is used by host routers %s and %s", host, o, r)
		}
		seen[host] = r
	}
	for _, sub := range v.Subdomains {
		if policy.CoreSubdomains[sub] {
			return statusErr(409, "hostname %s.%s is a core hostname", sub, h.cfg.Domain)
		}
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
		for _, s := range o.Subdomains {
			for _, mine := range v.Subdomains {
				if s == mine {
					return statusErr(409, "hostname %s.%s is already routed by instance %s", s, h.cfg.Domain, o.ID)
				}
			}
		}
	}
	// Templates from other sources and skipped duplicates route their
	// default hostnames too, should they ever be enabled.
	for _, tt := range h.allTemplates {
		for _, s := range tt.Subdomains {
			for _, mine := range v.Subdomains {
				if s == mine {
					return statusErr(409, "hostname %s.%s is the default hostname of template %s (source %s)", s, h.cfg.Domain, tt.ID, tt.Source)
				}
			}
		}
	}
	return nil
}

// templateDir is the directory name of t's support files under
// <core>/templates (shared by all its instances).
func templateDir(t *templates.Template) string {
	if t.TemplateID != "" {
		return t.TemplateID
	}
	return t.ID
}
