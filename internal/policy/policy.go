// Package policy holds the auth-policy model (factors + AND/OR) and builds
// the group-gate policy file (contract §4, version 2).
package policy

import (
	"sort"
	"strings"
)

// AuthPolicy is a per-app (or global default) authentication requirement.
// Factors is a subset of {"mtls","webauthn","password"}. Op is "any" or "all"
// (ignored when len(Factors) <= 1). An empty Factors list means public.
type AuthPolicy struct {
	Factors []string `json:"factors" yaml:"factors"`
	Op      string   `json:"op" yaml:"op"`
}

// InitialDefault is the global default until an admin sets one: this is a
// hardware-key gateway, so fresh installs require WebAuthn (routers get
// authaware@file and step up to LoA 2).
func InitialDefault() AuthPolicy { return AuthPolicy{Factors: []string{"webauthn"}} }

var factorLoA = map[string]int{"password": 1, "webauthn": 2, "mtls": 3}

// Normalize trims and lower-cases factor names, drops unknown/duplicate
// values, sorts them, and normalises op ("" for ≤1 factor, else "any" unless
// "all").
func Normalize(p AuthPolicy) AuthPolicy {
	out := AuthPolicy{}
	seen := map[string]bool{}
	for _, f := range p.Factors {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := factorLoA[f]; !ok || seen[f] {
			continue
		}
		seen[f] = true
		out.Factors = append(out.Factors, f)
	}
	sort.Strings(out.Factors)
	if len(out.Factors) <= 1 {
		out.Op = ""
	} else {
		op := strings.ToLower(strings.TrimSpace(p.Op))
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
	case 1:
		return "pwd"
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
