package policy

import (
	"reflect"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want AuthPolicy
	}{
		{AuthPolicy{}, AuthPolicy{}},
		{AuthPolicy{Factors: []string{" WebAuthn ", "bogus", "webauthn"}, Op: "all"}, AuthPolicy{Factors: []string{"webauthn"}, Op: ""}},
		{AuthPolicy{Factors: []string{"webauthn", "mtls"}}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}},
		{AuthPolicy{Factors: []string{"MTLS", "webauthn"}, Op: " ALL "}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}},
		{AuthPolicy{Factors: []string{"webauthn", "mtls"}, Op: "xor"}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}},
		// Legacy "password": every hwk/mtls session satisfies it (group-gate),
		// so it is redundant in "all" and an open alternative otherwise —
		// never rewritten into something weaker (public).
		{AuthPolicy{Factors: []string{"password", "mtls"}, Op: " ALL "}, AuthPolicy{Factors: []string{"mtls"}, Op: ""}},
		{AuthPolicy{Factors: []string{"password", "mtls", "webauthn"}, Op: "all"}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}},
		{AuthPolicy{Factors: []string{"password", "mtls"}, Op: "any"}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}},
		{AuthPolicy{Factors: []string{"Password"}}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}},
		{AuthPolicy{Factors: []string{"password"}, Op: "all"}, AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}},
	}
	for _, c := range cases {
		if got := Normalize(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalize(%+v) = %+v, want %+v", c.in, got, c.want)
		}
	}
	if !LegacyPassword(AuthPolicy{Factors: []string{" PASSWORD "}}) || LegacyPassword(InitialDefault()) {
		t.Error("LegacyPassword is wrong")
	}
}

func TestLoAACRTier(t *testing.T) {
	cases := []struct {
		p     AuthPolicy
		loa   int
		acr   string
		tier  string
		score float64
	}{
		{AuthPolicy{}, 0, "public", "public@file", 0},
		{AuthPolicy{Factors: []string{"webauthn"}}, 2, "hwk", "authaware@file", 2},
		{AuthPolicy{Factors: []string{"mtls"}}, 3, "mtls", "protected@file", 3},
		{AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}, 2, "hwk", "authaware@file", 2},
		{AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}, 3, "mtls", "protected@file", 3.5},
	}
	for _, c := range cases {
		if got := LoA(c.p); got != c.loa {
			t.Errorf("LoA(%+v) = %d, want %d", c.p, got, c.loa)
		}
		if got := ACR(c.p); got != c.acr {
			t.Errorf("ACR(%+v) = %s, want %s", c.p, got, c.acr)
		}
		if got := Tier(c.p); got != c.tier {
			t.Errorf("Tier(%+v) = %s, want %s", c.p, got, c.tier)
		}
		if got := SafetyScore(c.p); got != c.score {
			t.Errorf("SafetyScore(%+v) = %v, want %v", c.p, got, c.score)
		}
	}
	if !Same(AuthPolicy{Factors: []string{"a"}}, AuthPolicy{Factors: []string{"a"}}) || Same(AuthPolicy{Op: "any"}, AuthPolicy{}) {
		t.Error("Same is wrong")
	}
}

func TestHostTier(t *testing.T) {
	cases := []struct {
		p            AuthPolicy
		public, want string
	}{
		{AuthPolicy{Factors: []string{"mtls"}}, "authaware@file", "protected@file"},
		{AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "all"}, "authaware@file", "protected@file"},
		{AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}, "authaware@file", "authaware@file"},
		{AuthPolicy{Factors: []string{"webauthn"}}, "authaware@file", "authaware@file"},
		{AuthPolicy{}, "public@file", "public@file"},
	}
	for _, c := range cases {
		if got := HostTier(c.p, false); got != c.want {
			t.Errorf("HostTier(%v, false) = %s, want %s", c.p, got, c.want)
		}
		if got := HostTier(c.p, true); got != c.public {
			t.Errorf("HostTier(%v, true) = %s, want %s", c.p, got, c.public)
		}
	}
}

// The unset default accepts either YubiKey method and must keep deriving
// the values core relies on.
func TestInitialDefault(t *testing.T) {
	d := InitialDefault()
	if !Same(Normalize(d), d) {
		t.Errorf("InitialDefault not normalised: %+v vs %+v", d, Normalize(d))
	}
	if ACR(d) != "hwk" || LoA(d) != 2 || Tier(d) != "authaware@file" || HostTier(d, true) != "authaware@file" || SafetyScore(d) != 2 {
		t.Errorf("acr=%s loa=%d tier=%s score=%v", ACR(d), LoA(d), Tier(d), SafetyScore(d))
	}
}
