package hub

import (
	"context"
	"log"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/docker"
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
	// StateRestoring: a same-instance restore started and hasn't finished
	// (an interrupted one is rolled back on the next restore or start).
	StateRestoring = "restoring"
	StateError     = "error"
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
	extra := extraFunc(h.enrolledLocked())
	var out []templates.Template
	byTemplate := map[string][]string{}
	broken := map[string]string{}
	for i := range h.templates {
		t := &h.templates[i]
		var hosts map[string]string
		if e, ok := h.st.Instances[t.ID]; ok && e.Template == t.ID && len(e.Hosts) > 0 {
			hosts = e.Hosts
		}
		v, err := t.InstanceOn(t.ID, hosts, h.cfg.Domain, extra)
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
		v, err := t.InstanceOn(id, e.Hosts, h.cfg.Domain, extra)
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
	h.dropHostHeadersLocked()
}

// pendingLocked refuses (409) changes to an instance a guarded delete or
// a restore hasn't finished ("deleting" / "restoring"). Caller must hold
// mu.
func (h *Hub) pendingLocked(id string) error {
	if fid, ok := h.folderApplying[id]; ok {
		name := fid
		if f, ok := h.st.Folders[fid]; ok {
			name = f.Name
		}
		return statusErr(409, "shared folder %s is being applied to %s: try again when it has finished", name, id)
	}
	switch e := h.st.Instances[id]; e.State {
	case state.InstanceDeleting:
		return statusErr(409, "instance %s is being deleted: delete it again to finish", id)
	case state.InstanceRestoring:
		if e.RestoreAs != "" {
			return statusErr(409, "instance %s is being restored from %s (a restore into a new id): wait for it — an interrupted one is removed at the next Hub start, or delete it", id, e.RestoreAs)
		}
		return statusErr(409, "instance %s has an unfinished restore: restore it again (its pre-restore backup %s is put back first)", id, e.Backup)
	}
	return nil
}

// pending is pendingLocked taking mu.
func (h *Hub) pending(id string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pendingLocked(id)
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
		case e.State == state.InstanceRestoring:
			v.State = StateRestoring
		case hasOp && !op.OK && !op.Running:
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
		st := StateError
		switch e.State {
		case state.InstanceDeleting:
			st = StateDeleting
		case state.InstanceRestoring:
			st = StateRestoring
		}
		out = append(out, InstanceView{ID: id, Template: tid, Default: id == tid, State: st, Error: reason,
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
	if err := templates.CheckIDShape(id); err != nil {
		return statusErr(400, "instance %v", err)
	}
	h.mu.RLock()
	_, exists := h.st.Instances[id]
	h.mu.RUnlock()
	if exists {
		return statusErr(409, "instance %s already exists", id)
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
		// Nor may it adopt an existing volume: a deleted instance's
		// leftover, or anything else's (§11.1).
		h.mu.RLock()
		var want map[string]string
		if t := h.catalogLocked(templateID); t != nil {
			want = t.NamesFor(id).Volumes
		}
		h.mu.RUnlock()
		vs, err := h.engine.ListVolumes(context.Background(), nil)
		if err != nil {
			return statusErr(503, "cannot check for existing volumes: %v", err)
		}
		mine := map[string]bool{}
		for _, n := range want {
			mine[strings.ToLower(n)] = true
		}
		for _, v := range vs {
			if mine[strings.ToLower(v.Name)] || v.Labels[docker.LabelProject] == projectName(id) {
				return statusErr(409, "volume %s already exists (a leftover of a deleted instance or someone else's): remove it, or choose another instance id", v.Name)
			}
		}
	}

	runtime := h.runtimeCopy() // driftMu before mu
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
	if c := templates.CoreContainerClash(id, t.Services); c != "" {
		return statusErr(409, "instance id %s: its container %s would be a core service's container name", id, c)
	}
	if err := aliasesFitInstance(t, id); err != nil {
		return err
	}
	if hosts == nil {
		var err error
		if hosts, err = defaultHostsFor(t, id, h.cfg.Domain); err != nil {
			return err
		}
	}
	view, err := h.resolveHostsLocked(t, id, hosts, nil)
	if err != nil {
		return err
	}
	if err := h.checkInstanceHostsLocked(&view, runtime); err != nil {
		return err
	}
	h.st.Instances[id] = state.Instance{ID: id, Template: templateID, Hosts: view.Hosts, State: state.InstanceCreated}
	h.rebuildLocked()
	if v := h.findLocked(id); v != nil {
		h.seedSettingsLocked(v)
		h.seedAIProvidersLocked(v)
	}
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
	r := h.reservationsLocked(func(tid string) *templates.Template { return h.catalogLocked(tid) }, "")
	for _, tt := range h.allTemplates {
		for _, c := range nameClaims(tt.NamesFor(tt.ID)) {
			r.exact[c] = "the default instance of " + tt.ID
		}
	}
	if c, who := r.match(nameClaims(t.NamesFor(id))); who != "" {
		kind, name, _ := strings.Cut(c, "\x00")
		return statusErr(409, "instance id %s: its %s %s is already used by %s", id, kind, name, who)
	}
	return nil
}

// reservations are names existing instances hold: exact claims
// (nameClaims form) and, for instances whose template can't be resolved,
// prefixes of the names they may derive.
type reservations struct {
	exact    map[string]string // claim → owner
	prefixes []struct{ prefix, who string }
}

// match returns the first claim (and its owner) that is reserved.
func (r *reservations) match(claims []string) (string, string) {
	for _, c := range claims {
		if who, ok := r.exact[c]; ok {
			return c, who
		}
		for _, p := range r.prefixes {
			if strings.HasPrefix(c, p.prefix) {
				return c, p.who
			}
		}
	}
	return "", ""
}

// reservationsLocked collects the names every instance in state holds,
// whether or not its template resolves (a missing template must not free
// its instances' names, §11.1): for each non-default instance id, its
// project, users_<id>, admin_<id> and client <id> always; its exact
// derived names when lookup finds its template, else the patterns
// portcullis_<id>-* (volumes), <id>-* (further clients) and <id>_*
// (Traefik names). Default
// instances whose template is missing keep their project and the groups
// of their published snapshot. Instances of skipTemplate (and its default
// instance) are left out. Caller must hold mu.
func (h *Hub) reservationsLocked(lookup func(templateID string) *templates.Template, skipTemplate string) *reservations {
	r := &reservations{exact: map[string]string{}}
	claim := func(kind, name, who string) {
		r.exact[kind+"\x00"+strings.ToLower(name)] = who
	}
	ids := make([]string, 0, len(h.st.Instances))
	for id := range h.st.Instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := h.st.Instances[id]
		if id == e.Template || (skipTemplate != "" && e.Template == skipTemplate) {
			continue
		}
		who := "instance " + id
		claim("project", projectName(id), who)
		claim("group", "users_"+id, who)
		claim("group", "admin_"+id, who)
		claim("Keycloak client", id, who)
		if ot := lookup(e.Template); ot != nil {
			for _, c := range nameClaims(ot.NamesFor(id)) {
				r.exact[c] = who
			}
			continue
		}
		who += " (template " + e.Template + " missing)"
		snapshotClaims(r, h.st.Published[id], who)
		r.prefixes = append(r.prefixes,
			struct{ prefix, who string }{"volume\x00portcullis_" + id + "-", who},
			struct{ prefix, who string }{"Keycloak client\x00" + id + "-", who},
			struct{ prefix, who string }{traefikClaim + "\x00" + templates.InstanceName(id, ""), who})
	}
	// Default instances whose template is gone: last known names.
	for id, snap := range h.st.Published {
		if id == skipTemplate || lookup(id) != nil {
			continue
		}
		if e, ok := h.st.Instances[id]; ok && e.Template != id {
			continue // a non-default instance: above
		}
		who := "the default instance of " + id + " (template missing)"
		claim("project", projectName(id), who)
		if snap.AccessGroup != "" {
			claim("group", snap.AccessGroup, who)
		}
		if snap.AdminGroup != "" {
			claim("group", snap.AdminGroup, who)
		}
		snapshotClaims(r, snap, who)
	}
	return r
}

// snapshotClaims adds the volume, Keycloak client and Traefik names a
// published snapshot records (an enabled instance whose template is
// missing keeps them, §11.1).
func snapshotClaims(r *reservations, snap state.PublishedApp, who string) {
	for _, v := range snap.Volumes {
		r.exact["volume\x00"+strings.ToLower(v)] = who
	}
	for _, c := range snap.Clients {
		r.exact["Keycloak client\x00"+strings.ToLower(c)] = who
	}
	for _, n := range snap.Traefik {
		r.exact[traefikClaim+"\x00"+strings.ToLower(n)] = who
	}
}

// nameClaims are an instance's derived names as comparable claims
// ("<kind>\x00<lower-cased name>", §11.1: case-insensitive), in a fixed
// order: project, groups, volumes (by key), Keycloak clients, Traefik
// names.
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
	for _, c := range n.Traefik {
		add(traefikClaim, c)
	}
	return out
}

// traefikClaim is the claim kind of a Traefik router / service /
// middleware name (Traefik merges same-name objects across containers: a
// template defining another app's service name would receive its traffic,
// forward-auth identity headers included).
const traefikClaim = "Traefik name"

// defaultClaimKinds: the claims two templates' default instances may not
// share (Discover; the first template — enabled ones first — keeps them).
// Groups are left out: templates may share an access group on purpose.
var defaultClaimKinds = map[string]bool{"volume": true, traefikClaim: true}

// defaultClaims are t's default-instance claims of defaultClaimKinds.
func defaultClaims(t *templates.Template) []string {
	var out []string
	for _, c := range nameClaims(t.NamesFor(t.ID)) {
		if kind, _, _ := strings.Cut(c, "\x00"); defaultClaimKinds[kind] {
			out = append(out, c)
		}
	}
	return out
}

// claimCollision reports (as "<kind> <name> of <owner>") whether template
// t's default instance would use a name an existing instance of another
// template holds (reservationsLocked; byID resolves templates discovered
// now). Caller must hold mu.
func (h *Hub) claimCollision(t *templates.Template, byID map[string]*templates.Template) string {
	r := h.reservationsLocked(func(tid string) *templates.Template { return byID[tid] }, t.ID)
	if c, who := r.match(nameClaims(t.NamesFor(t.ID))); who != "" {
		kind, name, _ := strings.Cut(c, "\x00")
		return kind + " " + name + " of " + who
	}
	return ""
}

// templateDir is the directory name of t's support files under
// <core>/templates (shared by all its instances).
func templateDir(t *templates.Template) string {
	if t.TemplateID != "" {
		return t.TemplateID
	}
	return t.ID
}

// firstClaimed returns the first of claims already in claimed, and its
// owner.
func firstClaimed(claims []string, claimed map[string]string) (string, string) {
	for _, c := range claims {
		if who, ok := claimed[c]; ok {
			return c, who
		}
	}
	return "", ""
}
