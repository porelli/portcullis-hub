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
)

// SignInKeycloakFile is the Keycloak extension's file in the Hub's data
// directory (core mounts it as /hub-data/signin-keycloak.json).
const SignInKeycloakFile = "signin-keycloak.json"

// KeycloakSignInVersion is signin-keycloak.json's version.
const KeycloakSignInVersion = 1

// KeycloakSignIn is signin-keycloak.json (D20): the switched-on methods,
// the add-stronger switch, every enabled template's compiled rule, the
// native-OIDC clients' templates, the passkey trust list and the FIDO
// list it came from (Task 8 fills Authenticators and MDS).
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

// methodsOnLocked are the switched-on methods in canonical order (never
// browser_cert in part 1: MethodsOn). Caller holds mu.
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

// peopleMethodsLocked is each person's set-up methods (the policy file's
// people, page text only). Task 5 fills it from the inventory; nil = not
// known, nobody listed. Caller holds mu.
func (h *Hub) peopleMethodsLocked() map[string][]signin.Method {
	return nil
}

// keycloakSignInLocked builds signin-keycloak.json from state: clients
// maps the client id of every Keycloak client (not ai_client) of every
// enabled native-OIDC instance to the instance's template — a template
// that can't be published is still named (the extension then refuses the
// whole file and nobody signs in: fail closed, never an unlisted client
// let through). Caller holds mu.
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
	for i := range h.instances {
		t := &h.instances[i]
		if !t.Enabled {
			continue
		}
		acc := h.accessLocked(t)
		if acc.Capability.Enforcement != policy.EnforceAtLogin {
			continue
		}
		if _, ok := doc.Templates[acc.Template]; !ok {
			log.Printf("signin: %s: template %q can't be published — signin-keycloak.json names it anyway, so the Keycloak extension refuses every sign-in until it is fixed", t.ID, acc.Template)
		}
		for _, c := range t.Manifest.Clients {
			if c.AIClient {
				continue // mcp-gate checks it (§15.2)
			}
			if prev, dup := doc.Clients[c.ClientID]; dup && prev.Template != acc.Template {
				log.Printf("signin: Keycloak client %s is declared by several instances — keeping %s's template", c.ClientID, prev.Name)
				continue
			}
			doc.Clients[c.ClientID] = KeycloakClientTemplate{Template: acc.Template, Name: instanceName(t)}
		}
	}
	return doc
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
