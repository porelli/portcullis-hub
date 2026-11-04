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
	// KeycloakAccessRole (native-oidc with access_group only) makes the Hub
	// enforce the access group in Keycloak (contract §8 "Access role"):
	// each client of the instance gets the client role "access", the
	// instance's access group gets it, and the client's browser flow denies
	// sign-in without it. For apps that can't restrict sign-in to a group
	// themselves (or let outsiders create accounts without rights). The Hub
	// does the same for every native-oidc template with group_access: false
	// (see Template.AccessRoleEnforced; such a template must declare an
	// access_group). Every client of an enforced app has direct access
	// grants, implicit flow, service accounts, device/CIBA grants and
	// standard token exchange switched off: only the browser flow signs in.
	KeycloakAccessRole bool   `yaml:"keycloak_access_role" json:"keycloak_access_role,omitempty"`
	Notes              string `yaml:"notes" json:"notes"`
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
	// LanOnly: the port should be reachable only from the local networks
	// (§13.15). It changes nothing in the binding; the doctor judges it.
	LanOnly bool `yaml:"lan_only" json:"lan_only"`
}

// EnvVar is a per-app variable the Hub writes into the app's .env.
type EnvVar struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	Generate    string `yaml:"generate" json:"generate"` // "random" or ""
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
	// BackchannelLogoutURL is the app's OIDC back-channel logout endpoint
	// (https://{{HOST_<ROUTER>}}/<path>): Keycloak POSTs a logout token
	// there when a session ends, so the app ends its own session too
	// (e.g. Nextcloud user_oidc, Synapse).
	BackchannelLogoutURL string `yaml:"backchannel_logout_url" json:"backchannel_logout_url,omitempty"`
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
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	// Instances is "multi" (any number of instances) or "single" (only the
	// default instance; the default when unset). Contract §3.1.
	Instances   string           `yaml:"instances" json:"instances"`
	Icon        string           `yaml:"icon" json:"icon"`
	Category    string           `yaml:"category" json:"category"`
	Tags        []string         `yaml:"tags" json:"tags"`
	Auth        Auth             `yaml:"auth" json:"auth"`
	Settings    *SettingsSpec    `yaml:"settings" json:"settings,omitempty"`
	Ports       []Port           `yaml:"ports" json:"ports"`
	Env         []EnvVar         `yaml:"env" json:"env"`
	Clients     []KeycloakClient `yaml:"keycloak_clients" json:"keycloak_clients"`
	ConfigFiles []ConfigFile     `yaml:"config_files" json:"config_files"`
	URLs        []AppURL         `yaml:"urls" json:"urls"`
	// Hosts are per-host-router properties (contract §3.1).
	Hosts *HostsSpec `yaml:"hosts" json:"hosts,omitempty"`
	// Files, Hooks and Reload are what settings deliveries name (§13.7, §13.8).
	Files  []DataFile `yaml:"files" json:"files,omitempty"`
	Hooks  []Hook     `yaml:"hooks" json:"hooks,omitempty"`
	Reload *Reload    `yaml:"reload" json:"reload,omitempty"`
}

// HostsSpec is the manifest's hosts block.
type HostsSpec struct {
	// Immutable host routers keep the hostname the instance was created
	// with (e.g. Synapse's server_name, part of every user and room id):
	// SetHosts refuses to change it.
	Immutable []string `yaml:"immutable" json:"immutable,omitempty"`
}

// ImmutableHost reports whether host router r's hostname may never change.
func (m *Manifest) ImmutableHost(r string) bool {
	if m.Hosts == nil {
		return false
	}
	for _, x := range m.Hosts.Immutable {
		if x == r {
			return true
		}
	}
	return false
}

// AccessRoleEnforced reports whether the Hub enforces the access group in
// Keycloak for the app's clients (contract §8 "Access role"): native-oidc
// apps with an access group that either can't restrict sign-in to it
// (group_access: false) or ask for it (auth.keycloak_access_role).
func (m *Manifest) AccessRoleEnforced() bool {
	a := &m.Auth
	return a.Method == "native-oidc" && a.AccessGroup != "" && (!a.GroupAccess || a.KeycloakAccessRole)
}

// Instance modes (Manifest.Instances).
const (
	InstancesMulti  = "multi"
	InstancesSingle = "single"
)

// Multi reports whether the template may run as several instances.
func (m *Manifest) Multi() bool { return m.Instances == InstancesMulti }

// Template is a discovered template with its source info. The Hub also
// uses it for an instance (contract §11): a copy whose ID is the instance
// id, with the instance's hosts and derived names resolved (Instance).
type Template struct {
	// ID is the template id in the catalog, the instance id in an
	// instance view (the default instance's id is the template id).
	ID string `json:"id"`
	// TemplateID is the template's id (= ID in the catalog).
	TemplateID string   `json:"template"`
	Source     string   `json:"source"` // name of the source (template repo) this came from
	Manifest   Manifest `json:"manifest"`
	Path       string   `json:"-"` // filesystem path
	Enabled    bool     `json:"enabled"`
	// Subdomains routed by the template's Traefik rules (see ParseRoutes);
	// in an instance view, the instance's (main-domain labels).
	Subdomains []string `json:"subdomains"`
	// Public is the routing plan for auth.public_access (nil if none).
	Public *PublicPlan `json:"-"`
	// HostRouters maps each host router to its default subdomain
	// (contract §3.1); HostVars to its hostname variable.
	HostRouters map[string]string `json:"host_routers"`
	HostVars    map[string]string `json:"-"`
	// HostForm is the rule form (FormV2 or FormLegacy).
	HostForm string `json:"host_form"`
	// Hosts maps each host router to the instance's full hostname (the
	// default instance's in the catalog).
	Hosts map[string]string `json:"hosts"`
	// ExtraHosts are the hosts of Hosts on an enrolled domain (extra-domain
	// hosts, contract §5), sorted; they have no entry in Subdomains.
	ExtraHosts []string `json:"extra_hosts,omitempty"`
	// Volumes are the compose file's top-level volume keys that aren't
	// external (the Hub names them per instance, §11.2).
	Volumes []string `json:"-"`
	// NamedVolumes are the names the compose file gives its volumes
	// (key → name; single templates only: portcullis_<template-id>[-_…]).
	NamedVolumes map[string]string `json:"-"`
	// Services are the compose file's service names, sorted.
	Services []string `json:"-"`
	// Names are the Traefik names the template defines (Routes.Names).
	Names map[string]bool `json:"-"`
	// InstanceEnv are the instance variables (§3.1) of an instance view.
	InstanceEnv map[string]string `json:"-"`
	// Instances lists the template's instance ids (catalog only).
	Instances []string `json:"instances"`
	// GIDRefs (GIDRefs) and GIDEnvLeaks (GIDEnvLeaks), computed once at
	// discovery from the manifest and compose.yml (shared, read-only, by
	// every view of the template).
	GIDRefs     map[string]string `json:"-"`
	GIDEnvLeaks map[string]string `json:"-"`
	// raw is the manifest as written ({{HOST_*}} unexpanded); nil = Manifest.
	raw *Manifest
}

// IsDefault reports whether t is (the catalog entry or) the default
// instance of its template.
func (t *Template) IsDefault() bool { return t.TemplateID == "" || t.ID == t.TemplateID }
