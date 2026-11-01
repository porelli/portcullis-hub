// Package policy holds the auth-policy model (factors + AND/OR), what each
// auth method can enforce of it, and builds the group-gate policy file
// (contract §4, version 3).
package policy

import (
	"sort"
	"strings"
)

// AuthPolicy is a per-app (or global default) authentication requirement.
// Factors is a subset of {"mtls","webauthn"}. Op is "any" or "all"
// (ignored when len(Factors) <= 1). An empty Factors list means public.
//
// "password" is no factor any more: the realm's browser flow has no
// password (its LoA 1 is a client cert or a passkey), and group-gate counts
// every hwk/mtls session as having it. Stored policies naming it are
// rewritten by Normalize (see LegacyPassword); the API refuses it.
type AuthPolicy struct {
	Factors []string `json:"factors" yaml:"factors"`
	Op      string   `json:"op" yaml:"op"`
}

// InitialDefault is the global default until an admin sets one: this is a
// hardware-key gateway, so fresh installs require a YubiKey — either
// method: a client certificate (mtls, LoA 3) or a passkey (webauthn,
// LoA 2). group-gate matches factors via amr, so a webauthn-only default
// would turn away users who signed in with their certificate. "any" makes
// Keycloak step up to the lower LoA (hwk), and with a non-mtls alternative
// the routers get authaware@file (cert optional at the handshake).
// Normalised (sorted factors, op "any") as the Hub writes it.
func InitialDefault() AuthPolicy {
	return AuthPolicy{Factors: []string{"mtls", "webauthn"}, Op: "any"}
}

var factorLoA = map[string]int{"webauthn": 2, "mtls": 3}

// Factors are the factors a policy may name, sorted.
var Factors = []string{"mtls", "webauthn"}

// LegacyFactorPassword is the factor older policies used for a password
// sign-in, which no longer exists.
const LegacyFactorPassword = "password"

// KnownFactor reports whether f (normalised) is a factor.
func KnownFactor(f string) bool {
	_, ok := factorLoA[f]
	return ok
}

func normFactor(f string) string { return strings.ToLower(strings.TrimSpace(f)) }

// LegacyPassword reports whether p names the removed "password" factor.
func LegacyPassword(p AuthPolicy) bool {
	for _, f := range p.Factors {
		if normFactor(f) == LegacyFactorPassword {
			return true
		}
	}
	return false
}

// Normalize trims and lower-cases factor names, drops unknown/duplicate
// values, sorts them, and normalises op ("" for ≤1 factor, else "any" unless
// "all").
//
// The legacy "password" factor is rewritten to what group-gate makes of it
// (every hwk/mtls session counts as having it), never dropped into a weaker
// policy: in "all" it is redundant and removed; as an alternative ("any",
// or alone) it lets every session through, i.e. any of mtls, webauthn.
func Normalize(p AuthPolicy) AuthPolicy {
	out := AuthPolicy{}
	seen := map[string]bool{}
	password := false
	for _, f := range p.Factors {
		f = normFactor(f)
		if f == LegacyFactorPassword {
			password = true
			continue
		}
		if _, ok := factorLoA[f]; !ok || seen[f] {
			continue
		}
		seen[f] = true
		out.Factors = append(out.Factors, f)
	}
	op := strings.ToLower(strings.TrimSpace(p.Op))
	if password && (op != "all" || len(out.Factors) == 0) {
		return AuthPolicy{Factors: append([]string(nil), Factors...), Op: "any"}
	}
	sort.Strings(out.Factors)
	if len(out.Factors) <= 1 {
		out.Op = ""
	} else {
		if op != "all" {
			op = "any"
		}
		out.Op = op
	}
	return out
}

// Same reports whether two (normalised) policies are equal.
func Same(a, b AuthPolicy) bool {
	return a.Op == b.Op && strings.Join(a.Factors, ",") == strings.Join(b.Factors, ",")
}

// LoA returns the Level of Authentication a client should request to satisfy
// the policy: 0 for public; min factor LoA for "any"; max for "all".
func LoA(p AuthPolicy) int {
	if len(p.Factors) == 0 {
		return 0
	}
	if p.Op == "all" {
		max := 0
		for _, f := range p.Factors {
			if l, ok := factorLoA[f]; ok && l > max {
				max = l
			}
		}
		return max
	}
	min := 0
	for _, f := range p.Factors {
		if l, ok := factorLoA[f]; ok && (min == 0 || l < min) {
			min = l
		}
	}
	return min
}

// ACR returns the acr value an OIDC client should request via
// default.acr.values to prompt Keycloak for the right LoA step-up.
func ACR(p AuthPolicy) string {
	switch LoA(p) {
	case 2:
		return "hwk"
	case 3:
		return "mtls"
	}
	return "public"
}

// Tier returns the Traefik TLS options for an app. "protected@file" requires
// a cert at the TLS handshake and is used when every allowed login path goes
// through mTLS; "authaware@file" accepts connections with or without a cert.
func Tier(p AuthPolicy) string {
	if len(p.Factors) == 0 {
		return "public@file"
	}
	hasMTLS := false
	for _, f := range p.Factors {
		if f == "mtls" {
			hasMTLS = true
		}
	}
	if !hasMTLS {
		return "authaware@file"
	}
	if p.Op == "all" || len(p.Factors) == 1 {
		return "protected@file"
	}
	return "authaware@file"
}

// HostTier is the TLS options for every router of an app. Traefik selects
// TLS options per SNI host, so all routers of a host must share one tier
// (on a mismatch Traefik falls back to its default options and answers 421
// Misdirected Request). With public exceptions on, anonymous visitors must
// complete the handshake without a client cert, so a policy that would
// require one at the handshake ("protected@file") gets "authaware@file"
// for ALL of the app's routers. mTLS then stays enforced per request by
// group-gate's mTLS binding on gated routers; native-OIDC routers (no
// group-gate) only enforce it at login, through the Keycloak acr.
func HostTier(p AuthPolicy, publicExceptions bool) string {
	t := Tier(p)
	if publicExceptions && t == "protected@file" {
		return "authaware@file"
	}
	return t
}

// SafetyScore is a cosmetic number surfaced in the UI.
func SafetyScore(p AuthPolicy) float64 {
	loa := float64(LoA(p))
	if len(p.Factors) <= 1 || p.Op != "all" {
		return loa
	}
	return loa + 0.5*float64(len(p.Factors)-1)
}
