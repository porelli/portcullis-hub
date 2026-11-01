// Package templates discovers and validates app templates
// (<source>/<app-id>/manifest.yaml + compose.yml) and parses the bits of
// compose files the Hub needs (services, routed subdomains, router names).
package templates

// Auth describes how an app handles authentication.
type Auth struct {
	Method      string      `yaml:"method" json:"method"`
	SSO         interface{} `yaml:"sso" json:"sso"` // true, false, or "partial"
	GroupAccess bool        `yaml:"group_access" json:"group_access"`
	GroupAdmin  bool        `yaml:"group_admin" json:"group_admin"`
	AccessGroup string      `yaml:"access_group" json:"access_group"`
	AdminGroup  string      `yaml:"admin_group" json:"admin_group"`
	// AdminPaths are URL path prefixes that additionally require AdminGroup
	// (published to group-gate as path_groups).
	AdminPaths []string `yaml:"admin_paths" json:"admin_paths,omitempty"`
	// PublicAccess declares path prefixes the app serves to anonymous
	// visitors (share links). Off unless enabled (template default, then the
	// admin's choice in the Hub).
	PublicAccess *PublicAccess `yaml:"public_access" json:"public_access,omitempty"`
	// IdentityHeaders are the request headers a header-auth app reads the
	// user from (e.g. X-Forwarded-User). Required for header-auth apps with
	// public_access: the public router has no forward-auth, so the Hub
	// strips them (and the core identity headers) itself.
	IdentityHeaders []string `yaml:"identity_headers" json:"identity_headers,omitempty"`
	// NativeLogin declares that a custom app (no SSO) has its own login.
	// The Hub then offers "Portcullis sign-in, then the app's own login"
	// (default: its override adds forward-auth + group-gate) and, if
	// AllowWithoutGateway, "the app's own login only" (no Portcullis).
	NativeLogin *NativeLogin `yaml:"native_login" json:"native_login,omitempty"`
	Notes       string       `yaml:"notes" json:"notes"`
}

// NativeLogin is auth.native_login (method custom only).
type NativeLogin struct {
	Supported bool `yaml:"supported" json:"supported"`
	// AllowWithoutGateway lets an admin remove Portcullis from in front of
	// the app (its routers then have no forward-auth, TLS tier public).
	AllowWithoutGateway bool   `yaml:"allow_without_gateway" json:"allow_without_gateway"`
	Note                string `yaml:"note" json:"note,omitempty"`
}

// HasNativeLogin reports whether the app has its own login the Hub can
// put Portcullis sign-in in front of.
func (a *Auth) HasNativeLogin() bool { return a.NativeLogin != nil && a.NativeLogin.Supported }

// Methods are the accepted auth.method values.
var Methods = map[string]bool{"native-oidc": true, "forward-auth": true, "header-auth": true, "mtls": true, "custom": true, "public": true}

// PublicAccess is auth.public_access: when enabled, the Hub adds a Traefik
// router for Paths that bypasses forward-auth and group-gate (see
// PlanPublic).
type PublicAccess struct {
	// EnabledByDefault is the setting until an admin chooses in the Hub.
	EnabledByDefault bool   `yaml:"enabled_by_default" json:"enabled_by_default"`
	Description      string `yaml:"description" json:"description"`
	// DefaultMode is "listed" (only shares whose tokens an admin lists in
	// the Hub) or "all" (every share). Unset: "listed" if any path has a
	// {token} placeholder, else "all".
	DefaultMode string `yaml:"default_mode" json:"default_mode,omitempty"`
	// TokenPattern is an anchored regular expression every listed share
	// token must match. Required iff a path contains {token}.
	TokenPattern string `yaml:"token_pattern" json:"token_pattern,omitempty"`
	// CredentialHeaders are request headers the app logs a user in with
	// besides Authorization / Proxy-Authorization (e.g. Immich x-api-key):
	// stripped on the public router like those two.
	CredentialHeaders []string `yaml:"credential_headers" json:"credential_headers,omitempty"`
	// CredentialCookies / CredentialQuery are cookies and query parameters
	// the app logs a user in with (session, remember-me, API key). Core's
	// public guard refuses requests carrying one (names normalised like
	// PHP), with CredentialHeaders, Authorization and Proxy-Authorization.
	CredentialCookies []string `yaml:"credential_cookies" json:"credential_cookies,omitempty"`
	CredentialQuery   []string `yaml:"credential_query" json:"credential_query,omitempty"`
	// StaticExtensions adds file extensions to the ones supporting paths
	// may serve (StaticExtensions in public.go).
	StaticExtensions []string `yaml:"static_extensions" json:"static_extensions,omitempty"`
	// Service is the compose service the public router targets; default:
	// the only service with HTTP routers.
	Service string       `yaml:"service" json:"service,omitempty"`
	Paths   []PublicPath `yaml:"paths" json:"paths"`
}

// PublicPath is one anonymous-access path prefix (segment-boundary match).
// A prefix may contain one {token} segment (a share's token): in "listed"
// mode it is opened once per listed token, in "all" mode up to the segment
// before {token}. Supporting paths (static assets, l10n, ...) carry no token
// and are open in both modes; other token-free paths only in "all" mode.
type PublicPath struct {
	Prefix      string `yaml:"prefix" json:"prefix"`
	Description string `yaml:"description" json:"description"`
	// Supporting: token-free, opened in both modes, and only for static
	// files (StaticExtensions) unless Exact.
	Supporting bool `yaml:"supporting" json:"supporting,omitempty"`
	// Exact opens only the path itself (Path, no subpaths); for single app
	// routes a share page needs. Requires a justification.
	Exact bool `yaml:"exact" json:"exact,omitempty"`
	// Broad must be set (with a Justification) for prefixes on the
	// broad-prefix list, e.g. /api or /index.php. Justification is also
	// required for Exact.
	Broad         bool   `yaml:"broad" json:"broad,omitempty"`
	Justification string `yaml:"justification" json:"justification,omitempty"`
}

// SettingTarget maps a setting to a compose service volume mount.
type SettingTarget struct {
	Service string `yaml:"service" json:"service"`
	Mount   string `yaml:"mount" json:"mount"`
}

// Setting is a user-configurable option defined in a manifest.
type Setting struct {
	Key         string         `yaml:"key" json:"key"`
	Label       string         `yaml:"label" json:"label"`
	Description string         `yaml:"description" json:"description"`
	Type        string         `yaml:"type" json:"type"` // text, path, paths, boolean, select
	Required    bool           `yaml:"required" json:"required"`
	Default     string         `yaml:"default" json:"default"`
	Options     []string       `yaml:"options" json:"options"`
	Target      *SettingTarget `yaml:"target" json:"target"`
}

// Port is a host port binding declared by a manifest. The Hub checks these
// for collisions at enable-time and emits the effective bindings into the
// per-app compose override so users can rebind or disable them from the UI.
type Port struct {
	Key             string `yaml:"key" json:"key"`
	Label           string `yaml:"label" json:"label"`
	Description     string `yaml:"description" json:"description"`
	Container       int    `yaml:"container" json:"container"`
	Protocol        string `yaml:"protocol" json:"protocol"` // tcp, udp
	Default         int    `yaml:"default" json:"default"`
	Bind            string `yaml:"bind" json:"bind"` // default "0.0.0.0"
	Required        bool   `yaml:"required" json:"required"`
	Service         string `yaml:"service" json:"service"`
	NetworkModeHost bool   `yaml:"network_mode_host" json:"network_mode_host"`
	Range           string `yaml:"range" json:"range"` // e.g. "49152-65535" (coturn media relays)
}

// EnvVar is a per-app variable the Hub writes into the app's .env.
type EnvVar struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	Generate    string `yaml:"generate" json:"generate"` // "random", "none", ""
	Required    *bool  `yaml:"required" json:"required"`
}

// KeycloakClient is an OIDC client the Hub registers for the app.
type KeycloakClient struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	SecretEnv    string   `yaml:"secret_env" json:"secret_env"`
	RedirectURI  string   `yaml:"redirect_uri" json:"redirect_uri"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
	Name         string   `yaml:"name" json:"name"`
	// EmailVerifiedClaim false swaps the realm's "email" client scope for
	// "email-unverified" (email claim, no email_verified), for apps that
	// refuse email_verified=false but accept the claim being absent.
	// Unset means true.
	EmailVerifiedClaim *bool `yaml:"email_verified_claim" json:"email_verified_claim,omitempty"`
}

// SendsEmailVerified reports whether the client gets the email_verified
// claim (the default).
func (c KeycloakClient) SendsEmailVerified() bool {
	return c.EmailVerifiedClaim == nil || *c.EmailVerifiedClaim
}

// ConfigFile is copied from the template into the core checkout on enable.
type ConfigFile struct {
	Src  string `yaml:"src" json:"src"`
	Dest string `yaml:"dest" json:"dest"`
}

// AppURL is a link shown on the app card.
type AppURL struct {
	Label string `yaml:"label" json:"label"`
	URL   string `yaml:"url" json:"url"`
}

// Manifest describes an app template.
type Manifest struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Icon        string           `yaml:"icon" json:"icon"`
	Category    string           `yaml:"category" json:"category"`
	Tags        []string         `yaml:"tags" json:"tags"`
	Auth        Auth             `yaml:"auth" json:"auth"`
	Settings    []Setting        `yaml:"settings" json:"settings"`
	Ports       []Port           `yaml:"ports" json:"ports"`
	Env         []EnvVar         `yaml:"env" json:"env"`
	Clients     []KeycloakClient `yaml:"keycloak_clients" json:"keycloak_clients"`
	ConfigFiles []ConfigFile     `yaml:"config_files" json:"config_files"`
	URLs        []AppURL         `yaml:"urls" json:"urls"`
}

// Template is a discovered template with its source info.
type Template struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"` // name of the source (template repo) this came from
	Manifest Manifest `json:"manifest"`
	Path     string   `json:"-"` // filesystem path
	Enabled  bool     `json:"enabled"`
	// Subdomains routed by the template's Traefik rules (see ParseRoutes).
	Subdomains []string `json:"subdomains"`
	// Public is the routing plan for auth.public_access (nil if none).
	Public *PublicPlan `json:"-"`
}
