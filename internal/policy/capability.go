package policy

import "strings"

// Where Portcullis enforces an app's policy, by auth method.
const (
	// EnforcePerRequest: group-gate checks every request (forward-auth,
	// header-auth, Portcullis sign-in in front of an app's own login);
	// mTLS is bound to the session's certificate on each request.
	EnforcePerRequest = "request"
	// EnforceAtLogin: Keycloak's acr at the app's own OIDC login
	// (native-oidc). mTLS is checked per connection only with the
	// protected TLS tier.
	EnforceAtLogin = "login"
	// EnforceTLS: the client certificate at the TLS handshake (mtls).
	EnforceTLS = "tls"
	// EnforceNone: the gateway doesn't sign users in (custom, public).
	EnforceNone = "none"
)

// Capability is what Portcullis can enforce for an app.
type Capability struct {
	// Factors are the factors a policy for the app may name (sorted).
	Factors     []string `json:"factors"`
	Enforcement string   `json:"enforcement"`
}

// CapabilityFor maps an auth method (as deployed: a custom app behind
// Portcullis sign-in counts as forward-auth) to what it can enforce.
// Unknown methods enforce nothing.
func CapabilityFor(method string) Capability {
	switch method {
	case "forward-auth", "header-auth":
		return Capability{Factors: []string{"mtls", "webauthn"}, Enforcement: EnforcePerRequest}
	case "native-oidc":
		return Capability{Factors: []string{"mtls", "webauthn"}, Enforcement: EnforceAtLogin}
	case "mtls":
		return Capability{Factors: []string{"mtls"}, Enforcement: EnforceTLS}
	}
	return Capability{Factors: []string{}, Enforcement: EnforceNone}
}

// Supports reports whether the app can enforce factor f.
func (c Capability) Supports(f string) bool {
	for _, s := range c.Factors {
		if s == f {
			return true
		}
	}
	return false
}

// Resolution is the policy that applies to an app, given the policy it is
// configured with (its override or the global default).
type Resolution struct {
	Policy AuthPolicy `json:"policy"`
	// Unsupported are factors of the configured policy the app can't
	// enforce; they were left out of Policy.
	Unsupported []string `json:"unsupported,omitempty"`
	// Fallback: none of the configured factors is enforceable, so Policy
	// is what the app enforces by itself (mtls apps: the certificate).
	Fallback bool `json:"fallback,omitempty"`
}

// Resolve intersects a normalised policy with what the app can enforce:
//   - apps that handle their own sign-in get the empty policy (the gateway
//     enforces nothing; TLS tier public@file);
//   - otherwise unsupported factors are left out ("any": one alternative
//     fewer; "all": one requirement the app can't check);
//   - if nothing is left, the app's own floor applies: every supported
//     factor ("any"). For an mtls app that is the certificate, which its
//     TLS tier always requires, even under a public policy.
func Resolve(p AuthPolicy, c Capability) Resolution {
	if c.Enforcement == EnforceNone {
		return Resolution{Policy: AuthPolicy{Factors: []string{}}}
	}
	var r Resolution
	kept := []string{}
	for _, f := range p.Factors {
		if c.Supports(f) {
			kept = append(kept, f)
		} else {
			r.Unsupported = append(r.Unsupported, f)
		}
	}
	switch {
	case len(kept) > 0:
		r.Policy = Normalize(AuthPolicy{Factors: kept, Op: p.Op})
	case len(p.Factors) == 0 && c.Enforcement != EnforceTLS:
		r.Policy = AuthPolicy{Factors: []string{}} // public
	default:
		r.Fallback = true
		r.Policy = Normalize(AuthPolicy{Factors: c.Factors, Op: "any"})
	}
	return r
}

// Check reports the first problem with p (as submitted, before Normalize)
// as a policy for an app with capability c; "" means acceptable.
func (c Capability) Check(p AuthPolicy) string {
	if c.Enforcement == EnforceNone {
		return "this app handles its own sign-in: Portcullis doesn't sign users in for it, so it has no access policy"
	}
	for _, f := range p.Factors {
		f = normFactor(f)
		switch {
		case f == LegacyFactorPassword:
			return `"password" is not a sign-in method any more (passkey or client certificate only)`
		case !KnownFactor(f):
			return "unknown factor " + quote(f) + " (known: " + strings.Join(Factors, ", ") + ")"
		case !c.Supports(f):
			return "this app can't enforce " + quote(f) + "; supported: " + strings.Join(c.Factors, ", ")
		}
	}
	if len(p.Factors) == 0 && c.Enforcement == EnforceTLS {
		return "an mTLS-only app always requires the client certificate at the TLS handshake; it can't be public"
	}
	return ""
}

func quote(s string) string { return `"` + s + `"` }
