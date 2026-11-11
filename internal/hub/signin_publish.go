package hub

// Publishing the sign-in settings (contract §4 v6, §8.1, plan D9, D10,
// D18, D20): the compiled templates for the policy file and for
// signin-keycloak.json (the Keycloak extension's file: the native-OIDC
// clients' templates), and the TLS tier changes a sign-in change restarts.

import (
	"encoding/json"
	"log"
	"path/filepath"
	"slices"
	"time"

	"github.com/portcullis/hub/internal/fidomds"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/policy"
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

// writeKeycloakSignIn writes doc atomically, 0644 (Keycloak reads it from
// a read-only mount as another user).
func writeKeycloakSignIn(path string, doc KeycloakSignIn) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(b, '\n'), 0644)
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
