package hub

import (
	"strings"

	"github.com/portcullis/hub/internal/policy"
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
	// Configured is the override or the global default; Inherits says
	// which. Resolved is what applies (Configured ∩ Capability).
	Configured policy.AuthPolicy
	Inherits   bool
	Resolved   policy.Resolution
}

// GroupAccess reports whether group-gate restricts the app to its access
// group: never for an app whose routers have no Portcullis sign-in.
func (a access) groupAccess(t *templates.Template) bool {
	return t.Manifest.Auth.GroupAccess && a.SignIn != SignInNative
}

// accessLocked computes an app's access. Caller must hold mu (read).
func (h *Hub) accessLocked(t *templates.Template) access {
	auth := &t.Manifest.Auth
	a := access{Method: auth.Method}
	if auth.HasNativeLogin() {
		a.SignIn, a.Method = SignInGateway, "forward-auth"
		if h.st.SignIn[t.ID] == state.SignInNative {
			if auth.NativeLogin.AllowWithoutGateway {
				a.SignIn, a.Method = SignInNative, auth.Method
			} else {
				a.Blocked = "the template no longer allows the app's own login without Portcullis: Portcullis sign-in applies"
			}
		}
	}
	a.Capability = policy.CapabilityFor(a.Method)
	p, override := h.st.AuthPolicies[t.ID]
	if !override {
		p = h.st.Default()
	}
	a.Configured, a.Inherits = p, !override
	a.Resolved = policy.Resolve(p, a.Capability)
	return a
}

// effectivePolicyLocked is the policy that applies to an app (TLS tier,
// Keycloak acr). Caller must hold mu (read).
func (h *Hub) effectivePolicyLocked(t *templates.Template) policy.AuthPolicy {
	return h.accessLocked(t).Resolved.Policy
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

var factorLabel = map[string]string{"mtls": "mTLS (client certificate)", "webauthn": "WebAuthn (passkey)"}

// describePolicy renders a policy for notes: "mTLS or WebAuthn".
func describePolicy(p policy.AuthPolicy) string {
	if len(p.Factors) == 0 {
		return "no sign-in factor (public)"
	}
	names := make([]string, len(p.Factors))
	for i, f := range p.Factors {
		names[i] = strings.SplitN(factorLabel[f], " ", 2)[0]
		if names[i] == "" {
			names[i] = f
		}
	}
	sep := " or "
	if p.Op == "all" {
		sep = " and "
	}
	return strings.Join(names, sep)
}

// policyNotes explains how the configured policy maps onto what the app
// can enforce, for the settings view.
func policyNotes(a access, legacyPassword bool) []string {
	var notes []string
	src := "this app's override"
	if a.Inherits {
		src = "the global default"
	}
	r := a.Resolved
	if a.Capability.Enforcement == policy.EnforceNone {
		return append(notes, "This app handles its own sign-in: Portcullis doesn't sign users in for it, so no access policy applies.")
	}
	if legacyPassword {
		save := "Saving this app's policy stores it."
		if a.Inherits {
			save = "Saving the default (Settings tab) stores it."
		}
		notes = append(notes, capFirst(src)+" named \"password\", which is no longer a sign-in method; it was normalised to "+describePolicy(a.Configured)+". "+save)
	}
	switch a.Capability.Enforcement {
	case policy.EnforceTLS:
		notes = append(notes, "mTLS-only app: the client certificate is required at the TLS handshake (protected TLS tier).")
	case policy.EnforceAtLogin:
		notes = append(notes, "Native OIDC: Keycloak enforces the policy when the user signs in to the app (acr "+policy.ACR(r.Policy)+"), not on every request.")
		if policy.Tier(r.Policy) == "protected@file" {
			notes = append(notes, "mTLS is also checked on every connection (protected TLS tier).")
		} else if a.Capability.Supports("mtls") {
			notes = append(notes, "mTLS is checked at login only; per-connection mTLS needs an mTLS-only (or mTLS and WebAuthn) policy, which selects the protected TLS tier.")
		}
	case policy.EnforcePerRequest:
		notes = append(notes, "group-gate enforces the policy on every request; a client certificate is bound to the signed-in user.")
	}
	switch {
	case r.Fallback && len(a.Configured.Factors) == 0:
		notes = append(notes, capFirst(src)+" is public, which this app can't be: "+describePolicy(r.Policy)+" applies.")
	case r.Fallback:
		notes = append(notes, capFirst(src)+" requires "+describePolicy(a.Configured)+", which this app can't enforce: "+describePolicy(r.Policy)+" applies instead.")
	case len(r.Unsupported) > 0:
		notes = append(notes, capFirst(src)+" allows "+describePolicy(a.Configured)+"; this app can't enforce "+describePolicy(policy.AuthPolicy{Factors: r.Unsupported, Op: "any"})+", so it enforces "+describePolicy(r.Policy)+".")
	}
	return notes
}

func capFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
