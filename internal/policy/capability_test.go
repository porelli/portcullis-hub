package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestCapabilityMatrix(t *testing.T) {
	cases := map[string]struct {
		factors     []string
		enforcement string
	}{
		"forward-auth": {[]string{"mtls", "webauthn"}, EnforcePerRequest},
		"header-auth":  {[]string{"mtls", "webauthn"}, EnforcePerRequest},
		"native-oidc":  {[]string{"mtls", "webauthn"}, EnforceAtLogin},
		"mtls":         {[]string{"mtls"}, EnforceTLS},
		"custom":       {[]string{}, EnforceNone},
		"public":       {[]string{}, EnforceNone},
		"":             {[]string{}, EnforceNone},
		"saml":         {[]string{}, EnforceNone},
	}
	for method, want := range cases {
		c := CapabilityFor(method)
		if !reflect.DeepEqual(c.Factors, want.factors) || c.Enforcement != want.enforcement {
			t.Errorf("CapabilityFor(%q) = %+v, want %v %s", method, c, want.factors, want.enforcement)
		}
		if c.Supports(LegacyFactorPassword) {
			t.Errorf("%q supports password", method)
		}
	}
}

func TestResolve(t *testing.T) {
	gw, oidc, cert, own := CapabilityFor("forward-auth"), CapabilityFor("native-oidc"), CapabilityFor("mtls"), CapabilityFor("custom")
	anyBoth := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}
	allBoth := AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}
	hwk := AuthPolicy{Factors: []string{"webauthn"}}
	pub := AuthPolicy{}
	cases := []struct {
		name        string
		p           AuthPolicy
		c           Capability
		want        []string
		op          string
		unsupported []string
		fallback    bool
	}{
		{"gateway keeps any", anyBoth, gw, []string{"mtls", "webauthn"}, "any", nil, false},
		{"gateway keeps all", allBoth, gw, []string{"mtls", "webauthn"}, "all", nil, false},
		{"oidc keeps any", anyBoth, oidc, []string{"mtls", "webauthn"}, "any", nil, false},
		{"gateway public", pub, gw, []string{}, "", nil, false},
		{"mtls: any narrows to the cert", anyBoth, cert, []string{"mtls"}, "", []string{"webauthn"}, false},
		{"mtls: all loses webauthn", allBoth, cert, []string{"mtls"}, "", []string{"webauthn"}, false},
		{"mtls: webauthn-only can't apply", hwk, cert, []string{"mtls"}, "", []string{"webauthn"}, true},
		{"mtls: public default keeps the cert", pub, cert, []string{"mtls"}, "", nil, true},
		{"own sign-in: nothing", anyBoth, own, []string{}, "", nil, false},
	}
	for _, c := range cases {
		r := Resolve(c.p, c.c)
		if !reflect.DeepEqual(append([]string{}, r.Policy.Factors...), c.want) || r.Policy.Op != c.op ||
			!reflect.DeepEqual(r.Unsupported, c.unsupported) || r.Fallback != c.fallback {
			t.Errorf("%s: Resolve = %+v", c.name, r)
		}
	}
	// The TLS tier follows the resolved policy: mtls apps keep protected,
	// apps with their own sign-in get public.
	if Tier(Resolve(InitialDefault(), cert).Policy) != "protected@file" || Tier(Resolve(InitialDefault(), own).Policy) != "public@file" ||
		Tier(Resolve(InitialDefault(), gw).Policy) != "authaware@file" {
		t.Error("tier of resolved policies is wrong")
	}
}

func TestCapabilityCheck(t *testing.T) {
	gw, cert, own := CapabilityFor("header-auth"), CapabilityFor("mtls"), CapabilityFor("public")
	ok := []struct {
		c Capability
		p AuthPolicy
	}{
		{gw, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}},
		{gw, AuthPolicy{Factors: []string{" WebAuthn "}}},
		{gw, AuthPolicy{}},
		{cert, AuthPolicy{Factors: []string{"mtls"}}},
	}
	for _, c := range ok {
		if msg := c.c.Check(c.p); msg != "" {
			t.Errorf("Check(%+v) on %s = %q", c.p, c.c.Enforcement, msg)
		}
	}
	bad := []struct {
		c    Capability
		p    AuthPolicy
		want string
	}{
		{gw, AuthPolicy{Factors: []string{"password"}}, "not a sign-in method"},
		{gw, AuthPolicy{Factors: []string{"sms"}}, "unknown factor"},
		{cert, AuthPolicy{Factors: []string{"mtls", "webauthn"}}, `can't enforce "webauthn"`},
		{cert, AuthPolicy{}, "can't be public"},
		{own, AuthPolicy{Factors: []string{"mtls"}}, "handles its own sign-in"},
		{own, AuthPolicy{}, "handles its own sign-in"},
	}
	for _, c := range bad {
		if msg := c.c.Check(c.p); !strings.Contains(msg, c.want) {
			t.Errorf("Check(%+v) on %s = %q, want %q", c.p, c.c.Enforcement, msg, c.want)
		}
	}
}
