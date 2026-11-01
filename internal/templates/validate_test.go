package templates

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidID(t *testing.T) {
	good := []string{"a", "grafana", "actual-budget", "vault_ui", "0x", strings.Repeat("a", 64)}
	bad := []string{"", "-a", "_a", "A", "Grafana", "a b", "a/b", "../x", "a.b", strings.Repeat("a", 65), "a\n", "ä"}
	for _, s := range good {
		if !ValidID(s) {
			t.Errorf("ValidID(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidID(s) {
			t.Errorf("ValidID(%q) = true, want false", s)
		}
	}
}

func TestHasControlChars(t *testing.T) {
	for s, want := range map[string]bool{"": false, "abc def": false, "a\nb": true, "a\rb": true, "\x00": true, "\x7f": true, "tab\t": true, "ünï": false} {
		if got := HasControlChars(s); got != want {
			t.Errorf("HasControlChars(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestValidateAdminPath(t *testing.T) {
	ok := map[string]string{
		"/":             "/",
		"/admin":        "/admin",
		"/admin/":       "/admin",
		"/api/v1/admin": "/api/v1/admin",
		"/a-b_c.d~e":    "/a-b_c.d~e",
	}
	for in, want := range ok {
		got, err := ValidateAdminPath(in)
		if err != nil || got != want {
			t.Errorf("ValidateAdminPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "admin", " /admin", "/admin/../x", "/..", "/./admin", "/admin/.", "//admin", "/a//b",
		"/admin?x=1", "/admin#x", "/%2e%2e", "/a b", "/a\nb", "/a\\b", "/a..b", "/" + strings.Repeat("a", 300)}
	for _, in := range bad {
		if _, err := ValidateAdminPath(in); err == nil {
			t.Errorf("ValidateAdminPath(%q) accepted", in)
		}
	}
}

func TestValidatePathSetting(t *testing.T) {
	if err := ValidatePathSetting("/mnt/media/My Movies #1"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	for _, v := range []string{"/a:/b", "/a\n- /etc:/x", "C:\\x"} {
		if ValidatePathSetting(v) == nil {
			t.Errorf("ValidatePathSetting(%q) accepted", v)
		}
	}
}

func TestValidateManifest(t *testing.T) {
	base := func() Manifest {
		return Manifest{
			Name:     "App",
			Settings: []Setting{{Key: "MEDIA", Default: "/mnt"}},
			Ports:    []Port{{Key: "HTTP_PORT", Bind: "127.0.0.1"}},
			Env:      []EnvVar{{Key: "SECRET", Generate: "random"}},
			Clients:  []KeycloakClient{{ClientID: "app", SecretEnv: "APP_SECRET"}},
			Auth:     Auth{Method: "forward-auth", AccessGroup: "users_app", AdminGroup: "admin_app", AdminPaths: []string{"/admin/", "/settings"}},
		}
	}
	m := base()
	if err := ValidateManifest(&m); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if got := m.Auth.AdminPaths; got[0] != "/admin" || got[1] != "/settings" {
		t.Errorf("admin paths not normalised: %v", got)
	}
	m = base()
	m.Auth.Method, m.Auth.SSO = "custom", false
	m.Auth.NativeLogin = &NativeLogin{Supported: true, AllowWithoutGateway: true, Note: "Plex accounts"}
	if err := ValidateManifest(&m); err != nil || !m.Auth.HasNativeLogin() {
		t.Errorf("custom app with native_login rejected: %v", err)
	}

	cases := map[string]func(*Manifest){
		"setting key":          func(m *Manifest) { m.Settings[0].Key = "BAD-KEY" },
		"setting key newline":  func(m *Manifest) { m.Settings[0].Key = "A\nB" },
		"setting default ctl":  func(m *Manifest) { m.Settings[0].Default = "x\nEVIL=1" },
		"port key":             func(m *Manifest) { m.Ports[0].Key = "1PORT" },
		"port bind":            func(m *Manifest) { m.Ports[0].Bind = "localhost" },
		"env key":              func(m *Manifest) { m.Env[0].Key = "A=B" },
		"secret env":           func(m *Manifest) { m.Clients[0].SecretEnv = "X Y" },
		"access group":         func(m *Manifest) { m.Auth.AccessGroup = "users app" },
		"admin group":          func(m *Manifest) { m.Auth.AdminGroup = "admin\"x" },
		"admin path no slash":  func(m *Manifest) { m.Auth.AdminPaths = []string{"admin"} },
		"admin path dotdot":    func(m *Manifest) { m.Auth.AdminPaths = []string{"/x/../admin"} },
		"admin paths no group": func(m *Manifest) { m.Auth.AdminGroup = "" },
		"no method":            func(m *Manifest) { m.Auth.Method = "" },
		"unknown method":       func(m *Manifest) { m.Auth.Method = "saml" },
		"native login on sso method": func(m *Manifest) {
			m.Auth.SSO = false
			m.Auth.NativeLogin = &NativeLogin{Supported: true}
		},
		"native login with sso": func(m *Manifest) {
			m.Auth.Method, m.Auth.SSO = "custom", "partial"
			m.Auth.NativeLogin = &NativeLogin{Supported: true}
		},
		"native login sso unset": func(m *Manifest) {
			m.Auth.Method = "custom"
			m.Auth.NativeLogin = &NativeLogin{Supported: true}
		},
		"without gateway, not supported": func(m *Manifest) {
			m.Auth.Method, m.Auth.SSO = "custom", false
			m.Auth.NativeLogin = &NativeLogin{AllowWithoutGateway: true}
		},
		"native login note ctl": func(m *Manifest) {
			m.Auth.Method, m.Auth.SSO = "custom", false
			m.Auth.NativeLogin = &NativeLogin{Supported: true, Note: "a\nb"}
		},
	}
	for name, mut := range cases {
		m := base()
		mut(&m)
		if err := ValidateManifest(&m); err == nil {
			t.Errorf("%s: invalid manifest accepted", name)
		}
	}
}

func TestKeycloakClientEmailVerifiedClaim(t *testing.T) {
	cases := map[string]bool{
		"":                            true,
		"email_verified_claim: true":  true,
		"email_verified_claim: false": false,
		"email_verified_claim: null":  true,
		"email_verified_claim: ~":     true,
	}
	for line, want := range cases {
		var m Manifest
		doc := "keycloak_clients:\n  - client_id: app\n    " + line + "\n"
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got := m.Clients[0].SendsEmailVerified(); got != want {
			t.Errorf("%q: SendsEmailVerified = %v, want %v", line, got, want)
		}
	}
	// Not a boolean: the manifest fails to load (Discover skips it).
	for _, line := range []string{`email_verified_claim: "false"`, "email_verified_claim: [false]", "email_verified_claim: 0"} {
		var m Manifest
		if err := yaml.Unmarshal([]byte("keycloak_clients:\n  - client_id: app\n    "+line+"\n"), &m); err == nil {
			t.Errorf("%q accepted", line)
		}
	}
}
