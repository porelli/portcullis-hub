package hub

import (
	"fmt"
	"strings"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Sign-in modes of apps with their own login (auth.native_login).
const (
	// SignInGateway: Portcullis sign-in (forward-auth + group-gate, added
	// by the Hub's override), then the app's own login. The default.
	SignInGateway = "gateway"
	// SignInNative: the app's own login only — no Portcullis in front.
	// Only if the template sets native_login.allow_without_gateway.
	SignInNative = "native"
)

// Gateway middlewares the override puts first on every router of an app
// signed in through Portcullis before its own login.
var gatewayMiddlewares = []string{"portcullis-auth@docker", "portcullis-groups@docker"}

// access is how an app is signed in and what Portcullis enforces for it.
type access struct {
	// SignIn is "" for apps without auth.native_login (the method
	// decides), else SignInGateway or SignInNative.
	SignIn string
	// Blocked explains a stored choice the template no longer allows.
	Blocked string
	// Method is the auth method as deployed: a custom app behind
	// Portcullis sign-in is forward-auth.
	Method     string
	Capability policy.Capability
	// Template is the instance's sign-in template (its own pick, else the
	// default; "" for an app that takes none); Inherits: from the default.
	Template string
	Inherits bool
	// Rule is Template's compiled rule; nil for an app that takes none,
	// or when Template can't be published (Unusable: disabled, gone or
	// unmeetable — fail closed: the strictest tier, certificate-only for
	// AI support).
	Rule     *signin.Node
	Unusable bool
}

// GroupAccess reports whether group-gate restricts the app to its access
// group: never for an app whose routers have no Portcullis sign-in.
func (a access) groupAccess(t *templates.Template) bool {
	return t.Manifest.Auth.GroupAccess && a.SignIn != SignInNative
}

// accessLocked computes an app's access. Caller must hold mu (read).
func (h *Hub) accessLocked(t *templates.Template) access {
	return h.accessWith(t, h.st.SignIn, h.st.Instances[t.ID].SignInTemplate, h.st.SignInMode[t.ID])
}

// accessWith is t's access under sign-in section si, with the instance's
// template pick ("" = the default) and sign-in mode (state.SignInNative or
// ""): what a save or a sign-in change would make it. Caller holds mu.
func (h *Hub) accessWith(t *templates.Template, si state.SignIn, pick, mode string) access {
	auth := &t.Manifest.Auth
	a := access{Method: auth.Method}
	if auth.HasNativeLogin() {
		a.SignIn, a.Method = SignInGateway, "forward-auth"
		if mode == state.SignInNative {
			if auth.NativeLogin.AllowWithoutGateway {
				a.SignIn, a.Method = SignInNative, auth.Method
			} else {
				a.Blocked = "the template no longer allows the app's own login without Portcullis: Portcullis sign-in applies"
			}
		}
	}
	a.Capability = policy.CapabilityFor(a.Method)
	if !a.Capability.Templates {
		return a
	}
	a.Template, a.Inherits = pick, pick == ""
	if pick == "" {
		a.Template = si.Default
	}
	if c, ok := compiledIn(si, a.Template); ok {
		a.Rule = &c
	} else {
		a.Unusable = true
	}
	return a
}

// tierLocked is the TLS option of every router of t (contract §5 "TLS
// tier per host", D18): an mtls app protected@file (the certificate is
// its authentication); an app without Portcullis sign-in public@file; a
// template that can't be published protected@file (fail closed); else
// policy.Tier of its compiled rule, with publicActive's downgrade. Caller
// holds mu.
func (h *Hub) tierLocked(t *templates.Template, publicActive bool) string {
	return h.accessLocked(t).tier(h.st.SignIn.MethodsOn(), publicActive)
}

func (a access) tier(on map[signin.Method]bool, publicActive bool) string {
	switch {
	case a.Capability.Enforcement == policy.EnforceTLS:
		return policy.TierProtected
	case !a.Capability.Templates:
		return policy.TierPublic
	case a.Unusable:
		return policy.TierProtected
	}
	return policy.Tier(a.Rule, on, publicActive)
}

// certOnlyLocked: every way into t needs a client certificate
// (signin.NeedsCertificate of its compiled rule; an mtls app; a template
// that can't be published counts too, fail closed). AI clients present
// none, so AI support is refused (D19). Caller holds mu.
func (h *Hub) certOnlyLocked(t *templates.Template) bool {
	return h.accessLocked(t).certOnly()
}

func (a access) certOnly() bool {
	switch {
	case a.Capability.Enforcement == policy.EnforceTLS:
		return true
	case !a.Capability.Templates:
		return false
	case a.Unusable:
		return true
	}
	return signin.NeedsCertificate(*a.Rule)
}

// gatewayRouterMiddlewares is a router's middleware chain behind
// Portcullis sign-in: the gateway pair first, then the template's own.
func gatewayRouterMiddlewares(own []string) string {
	out := append([]string(nil), gatewayMiddlewares...)
	for _, m := range own {
		if m != gatewayMiddlewares[0] && m != gatewayMiddlewares[1] {
			out = append(out, m)
		}
	}
	return strings.Join(out, ",")
}

// nativeRouterMiddlewares is a router's middleware chain with the app's
// own login only: the template's, without any Portcullis sign-in.
func nativeRouterMiddlewares(own []string) string {
	var out []string
	for _, m := range own {
		if m != gatewayMiddlewares[0] && m != gatewayMiddlewares[1] {
			out = append(out, m)
		}
	}
	return strings.Join(out, ",")
}

// signInNotes explains an app's sign-in for the settings view: its
// template (sentence and score, signin.Sentence / ScoreOf) and where
// Portcullis enforces it. Caller holds mu.
func (h *Hub) signInNotes(a access) []string {
	switch a.Capability.Enforcement {
	case policy.EnforceNone:
		return []string{"This app handles its own sign-in: Portcullis doesn't sign users in for it, so no sign-in template applies."}
	case policy.EnforceTLS:
		return []string{"YubiKey-certificate app: a YubiKey certificate is required at the TLS handshake (protected@file, which accepts YubiKey certificates only); it takes no sign-in template."}
	}
	var notes []string
	src := "this app's own pick"
	if a.Inherits {
		src = "the default"
	}
	tmpl, ok := h.st.SignIn.Templates[a.Template]
	name := a.Template
	if ok {
		name = tmpl.Name
	}
	if a.Unusable || !ok {
		notes = append(notes, fmt.Sprintf("Sign-in template %q (%s) is disabled, missing or can't be met with the sign-in methods that are switched on: nobody is let in until it is fixed.", name, src))
	} else {
		sentence, score, _ := describeRule(tmpl.Rule, h.st.SignIn.MethodsOn())
		notes = append(notes, fmt.Sprintf("Sign-in template %q (%s): %s", name, src, sentence),
			fmt.Sprintf("Score %s: %s.", score, score.Reason))
	}
	switch a.Capability.Enforcement {
	case policy.EnforceAtLogin:
		notes = append(notes, "Native OIDC: Keycloak checks the template when someone signs in to the app, not on every request.")
	case policy.EnforcePerRequest:
		notes = append(notes, "group-gate checks the template on every request; a YubiKey or browser certificate counts only when the request presents it.")
	}
	switch policy.Tier(a.Rule, h.st.SignIn.MethodsOn(), false) {
	case policy.TierProtected:
		notes = append(notes, "Every way in needs a YubiKey certificate: it is asked for at the TLS handshake (protected@file, YubiKey certificates only).")
	case policy.TierProtectedAny:
		notes = append(notes, "Every way in needs a certificate: a YubiKey or browser certificate is asked for at the TLS handshake (protected-any@file).")
	}
	return notes
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
