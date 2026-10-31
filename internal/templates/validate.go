package templates

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	// IDRe constrains template / source identifiers: they end up in file
	// paths, compose project names, URLs and HTML attributes.
	IDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	// EnvKeyRe constrains setting / port / env keys (they become .env keys).
	EnvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	// groupRe constrains LLDAP group names published to group-gate.
	groupRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// ValidID reports whether s is an acceptable template / source identifier.
func ValidID(s string) bool { return IDRe.MatchString(s) }

// HasControlChars reports whether s contains newlines or other control
// characters — such values would inject extra lines into .env / YAML files.
func HasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ValidateManifest rejects manifests whose keys/values would be unsafe to
// splice into .env files, compose overrides, the group-gate policy file or
// the UI's HTML.
func ValidateManifest(m *Manifest) error {
	for _, st := range m.Settings {
		if !EnvKeyRe.MatchString(st.Key) {
			return fmt.Errorf("invalid setting key %q", st.Key)
		}
		if HasControlChars(st.Default) {
			return fmt.Errorf("setting %s: default contains control characters", st.Key)
		}
	}
	for _, p := range m.Ports {
		if !EnvKeyRe.MatchString(p.Key) {
			return fmt.Errorf("invalid port key %q", p.Key)
		}
		if p.Bind != "" && net.ParseIP(p.Bind) == nil {
			return fmt.Errorf("port %s: bind %q is not an IP address", p.Key, p.Bind)
		}
	}
	for _, v := range m.Env {
		if !EnvKeyRe.MatchString(v.Key) {
			return fmt.Errorf("invalid env key %q", v.Key)
		}
	}
	for _, c := range m.Clients {
		if c.SecretEnv != "" && !EnvKeyRe.MatchString(c.SecretEnv) {
			return fmt.Errorf("client %s: invalid secret_env %q", c.ClientID, c.SecretEnv)
		}
	}
	a := &m.Auth
	if a.AccessGroup != "" && !groupRe.MatchString(a.AccessGroup) {
		return fmt.Errorf("invalid auth.access_group %q", a.AccessGroup)
	}
	if a.AdminGroup != "" && !groupRe.MatchString(a.AdminGroup) {
		return fmt.Errorf("invalid auth.admin_group %q", a.AdminGroup)
	}
	if len(a.AdminPaths) > 0 && a.AdminGroup == "" {
		return fmt.Errorf("auth.admin_paths requires auth.admin_group")
	}
	for i, p := range a.AdminPaths {
		norm, err := ValidateAdminPath(p)
		if err != nil {
			return fmt.Errorf("auth.admin_paths[%d]: %w", i, err)
		}
		a.AdminPaths[i] = norm
	}
	return ValidatePublicAccess(a)
}

// ValidateAdminPath checks a path prefix from auth.admin_paths and returns it
// normalised (trailing "/" removed, except for "/" itself).
//
// group-gate matches prefixes against a normalised request path (decoded
// once, "//" collapsed, dot-segments resolved), so a prefix that is not
// itself in that normal form could never match — and silently leaving an
// admin area unprotected is exactly what this guards against.
func ValidateAdminPath(p string) (string, error) {
	if p == "" || p[0] != '/' {
		return "", fmt.Errorf("path %q must start with /", p)
	}
	if len(p) > 256 {
		return "", fmt.Errorf("path %q is too long", p)
	}
	if HasControlChars(p) || strings.ContainsAny(p, " \t?#%\\") {
		return "", fmt.Errorf("path %q may not contain whitespace, control characters, ?, #, %% or \\", p)
	}
	if strings.Contains(p, "//") {
		return "", fmt.Errorf("path %q may not contain //", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("path %q may not contain . or .. segments", p)
		}
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path %q may not contain ..", p)
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p, nil
}

// ValidatePathSetting checks a host path destined for a "<host>:<container>"
// volume entry in the override YAML.
func ValidatePathSetting(v string) error {
	// ":" would be parsed by compose as host:container[:mode].
	if HasControlChars(v) || strings.Contains(v, ":") {
		return fmt.Errorf("path %q may not contain ':' or control characters", v)
	}
	return nil
}
