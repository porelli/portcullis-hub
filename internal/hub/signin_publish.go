package hub

// Publishing the sign-in settings (contract §4 v6, §8.1, plan D9, D10,
// D18, D20): the compiled templates for the policy file and for
// signin-keycloak.json (the Keycloak extension's file: the native-OIDC
// clients' templates), and the TLS tier changes a sign-in change restarts.

import (
	"encoding/json"
	"log"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/fidomds"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/publish"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// SignInKeycloakFile is the Keycloak extension's file in the Hub's data
// directory (core mounts it as /hub-data/signin-keycloak.json).
const SignInKeycloakFile = "signin-keycloak.json"

// KeycloakSignInVersion is signin-keycloak.json's version.
const KeycloakSignInVersion = 1

// KeycloakSignIn is signin-keycloak.json (D20): the switched-on methods,
// the add-stronger switch, every enabled template's compiled rule, the
// native-OIDC clients' templates, the passkey trust list and the FIDO
// list it came from (writePolicy fills Authenticators and MDS from
// signInTrust, signin_mds.go).
type KeycloakSignIn struct {
	Version        int                                   `json:"version"`
	Methods        []string                              `json:"methods"`
	AddStronger    bool                                  `json:"add_stronger"`
	Templates      map[string]signin.Node                `json:"templates"`
	Clients        map[string]KeycloakClientTemplate     `json:"clients"`
	Authenticators map[string]fidomds.AuthenticatorTrust `json:"authenticators"`
	MDS            KeycloakMDS                           `json:"mds"`
	// AppHosts (contract §8.1 "Let through", sign-in gate): the hostnames
	// the policy file of the same pass publishes (appHosts), the only app
	// hosts the extension's "Let through" page names. A display list: it
	// never admits anyone. Never null.
	AppHosts []string `json:"app_hosts"`
}

// MaxAppHosts is the most app_hosts the extension accepts (contract §8.1):
// more and it refuses the whole file, so the Hub publishes at most this many.
const MaxAppHosts = 4096

// appHostRE is a published app host as the extension accepts it: a
// lowercase DNS name (labels [a-z0-9]([a-z0-9-]*[a-z0-9])?), at most 253
// characters. A host that isn't one is left out (never the whole file).
var appHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// appHosts is signin-keycloak.json app_hosts: the gated core pages' hosts
// (the policy file's core) and every host of an enabled app the policy file
// doesn't deny (never a drift deny entry, never a public-only host),
// lowercase, valid, sorted, each once, at most MaxAppHosts (the first ones
// in order; the rest are logged and left out: the page then says "your
// app" for them).
func appHosts(apps []policy.App, core map[string]string) []string {
	set := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(h)
		if len(h) > 253 || !appHostRE.MatchString(h) {
			log.Printf("signin: %q isn't a plain lowercase hostname — not in signin-keycloak.json app_hosts", h)
			return
		}
		set[h] = true
	}
	for h := range core {
		add(h)
	}
	for _, a := range apps {
		if !a.Enabled || a.Deny {
			continue
		}
		for h := range a.Hosts {
			add(h)
		}
	}
	out := slices.Sorted(maps.Keys(set))
	if len(out) > MaxAppHosts {
		log.Printf("signin: %d app hosts, signin-keycloak.json lists the first %d (the Let through page says \"your app\" for the rest)", len(out), MaxAppHosts)
		out = out[:MaxAppHosts]
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// KeycloakMDS is the FIDO metadata BLOB the authenticators come from: its
// serial ("no") and next update; zero before the first good BLOB.
type KeycloakMDS struct {
	Serial     int       `json:"serial"`
	NextUpdate time.Time `json:"next_update"`
}

// KeycloakClientTemplate is a native-OIDC client's template id and the
// instance name the needs-stronger page shows.
type KeycloakClientTemplate struct {
	Template string `json:"template"`
	Name     string `json:"name"`
}

func (h *Hub) signInKeycloakPath() string { return filepath.Join(h.cfg.DataDir, SignInKeycloakFile) }

// methodsOnLocked are the switched-on methods in canonical order
// (MethodsOn). Caller holds mu.
func (h *Hub) methodsOnLocked() []signin.Method {
	on := h.st.SignIn.MethodsOn()
	var out []signin.Method
	for _, m := range signin.Methods {
		if on[m] {
			out = append(out, m)
		}
	}
	return out
}

// publishedTemplatesLocked is every enabled template that compiles, by
// id, compiled (compiledLocked: the only rules any reader gets). Caller
// holds mu.
func (h *Hub) publishedTemplatesLocked() map[string]signin.Node {
	out := map[string]signin.Node{}
	for id := range h.st.SignIn.Templates {
		if c, ok := h.compiledLocked(id); ok {
			out[id] = c
		}
	}
	return out
}

// signInClientIDs are t's Keycloak client ids signin-keycloak.json lists
// (every keycloak_clients entry but ai_client: mcp-gate checks those,
// §15.2).
func signInClientIDs(t *templates.Template) []string {
	var out []string
	for _, c := range t.Manifest.Clients {
		if !c.AIClient {
			out = append(out, c.ClientID)
		}
	}
	return out
}

// unpublishedTemplate is the template id a client gets when two
// instances declare it with templates neither of which implies the other:
// it is never a template, so the Keycloak extension refuses the whole file
// (fail closed: neither instance's template is let go weaker).
const unpublishedTemplate = "__unpublished__"

// keycloakSignInLocked builds signin-keycloak.json from state: clients
// maps the client id of every Keycloak client (not ai_client) of every
// enabled native-OIDC instance to the instance's template — a template
// that can't be published is still named (the extension then refuses the
// whole file and nobody signs in: fail closed, never an unlisted client
// let through). An enabled instance whose template is missing keeps its
// published snapshot's clients (SignInClients) with its pick or the
// default, named by its id. Caller holds mu.
func (h *Hub) keycloakSignInLocked() KeycloakSignIn {
	doc := KeycloakSignIn{
		Version:        KeycloakSignInVersion,
		Methods:        []string{},
		AddStronger:    h.st.SignIn.AddStronger,
		Templates:      h.publishedTemplatesLocked(),
		Clients:        map[string]KeycloakClientTemplate{},
		Authenticators: map[string]fidomds.AuthenticatorTrust{},
		AppHosts:       []string{},
	}
	for _, m := range h.methodsOnLocked() {
		doc.Methods = append(doc.Methods, string(m))
	}
	slices.Sort(doc.Methods)
	ids := map[string]bool{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		ids[t.ID] = true
		acc := h.accessLocked(t)
		if acc.Capability.Enforcement != policy.EnforceAtLogin {
			continue
		}
		for _, c := range signInClientIDs(t) {
			doc.addClient(t.ID, c, acc.Template, instanceName(t))
		}
	}
	// Enabled instances without a view (template missing): the snapshot.
	for _, id := range h.st.Enabled {
		snap, ok := h.st.Published[id]
		if ids[id] || !ok {
			continue
		}
		tmpl := snap.SignInTemplate
		if tmpl == "" {
			tmpl = h.st.SignIn.Default
		}
		for _, c := range snap.SignInClients {
			doc.addClient(id, c, tmpl, id)
		}
	}
	return doc
}

// addClient lists client of instance id with template tmpl; a client
// listed already keeps the template that implies the other — or none
// (unpublishedTemplate: the extension refuses the file) when neither
// does; an unpublishable template is kept (it fails closed).
func (doc *KeycloakSignIn) addClient(id, client, tmpl, name string) {
	if _, ok := doc.Templates[tmpl]; !ok {
		log.Printf("signin: %s: template %q can't be published — signin-keycloak.json names it anyway, so the Keycloak extension refuses every sign-in until it is fixed", id, tmpl)
	}
	prev, dup := doc.Clients[client]
	if !dup || prev.Template == tmpl {
		if !dup {
			doc.Clients[client] = KeycloakClientTemplate{Template: tmpl, Name: name}
		}
		return
	}
	// Declared twice (state edited by hand): never weaker.
	a, aok := doc.Templates[prev.Template]
	b, bok := doc.Templates[tmpl]
	switch {
	case !aok:
		// prev already fails closed.
	case !bok:
		doc.Clients[client] = KeycloakClientTemplate{Template: tmpl, Name: prev.Name}
	case signin.Implies(a, b):
	case signin.Implies(b, a):
		doc.Clients[client] = KeycloakClientTemplate{Template: tmpl, Name: prev.Name}
	default:
		log.Printf("signin: Keycloak client %s is declared by several instances with templates %q and %q, neither stricter — signin-keycloak.json names no template for it, so the Keycloak extension refuses every sign-in until it is fixed", client, prev.Template, tmpl)
		doc.Clients[client] = KeycloakClientTemplate{Template: unpublishedTemplate, Name: prev.Name}
	}
}

// publishKeycloakSignIn publishes doc (contract §8.1; on Docker the file
// atomically, 0644: Keycloak reads it from a read-only mount as another
// user).
func (h *Hub) publishKeycloakSignIn(doc KeycloakSignIn) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return h.publish(publish.SignInKeycloak, append(b, '\n'))
}

// tierChangesLocked lists, sorted, the enabled instances whose routers'
// TLS option differs between sign-in sections before and after (D18: a
// certificate method switched, a template's rule or the default changed):
// their overrides are rendered again and they restart. Caller holds mu.
func (h *Hub) tierChangesLocked(before, after state.SignIn) []string {
	out := []string{}
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled || t.Manifest.Routerless() {
			continue
		}
		pub := h.publicLocked(t, t.Public).Active()
		pick, mode := h.st.Instances[t.ID].SignInTemplate, h.st.SignInMode[t.ID]
		a := h.accessWith(t, before, pick, mode).tier(before.MethodsOn(), pub)
		b := h.accessWith(t, after, pick, mode).tier(after.MethodsOn(), pub)
		if a != b {
			out = append(out, t.ID)
		}
	}
	slices.Sort(out)
	return out
}
