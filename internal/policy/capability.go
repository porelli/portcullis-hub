package policy

// Where Portcullis enforces an app's sign-in template, by auth method.
const (
	// EnforcePerRequest: group-gate checks every request (forward-auth,
	// header-auth, Portcullis sign-in in front of an app's own login); a
	// YubiKey certificate counts only when the request presents it.
	EnforcePerRequest = "request"
	// EnforceAtLogin: the Keycloak extension's portcullis-template at the
	// app's own OIDC login (native-oidc, signin-keycloak.json clients).
	EnforceAtLogin = "login"
	// EnforceTLS: the client certificate at the TLS handshake (mtls); the
	// app takes no template.
	EnforceTLS = "tls"
	// EnforceNone: the gateway doesn't sign users in (custom, public).
	EnforceNone = "none"
)

// Capability is what Portcullis can enforce for an app: whether it takes a
// sign-in template, and where it is enforced.
type Capability struct {
	Templates   bool   `json:"templates"`
	Enforcement string `json:"enforcement"`
}

// CapabilityFor maps an auth method (as deployed: a custom app behind
// Portcullis sign-in counts as forward-auth) to what it can enforce.
// Unknown methods enforce nothing and take no template.
func CapabilityFor(method string) Capability {
	switch method {
	case "forward-auth", "header-auth":
		return Capability{Templates: true, Enforcement: EnforcePerRequest}
	case "native-oidc":
		return Capability{Templates: true, Enforcement: EnforceAtLogin}
	case "mtls":
		return Capability{Enforcement: EnforceTLS}
	}
	return Capability{Enforcement: EnforceNone}
}
