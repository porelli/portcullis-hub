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
	Notes      string   `yaml:"notes" json:"notes"`
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
}
