// Package policy builds the group-gate policy file (contract §4, version 6)
// from the sign-in templates (§8.1), and says what each auth method can
// enforce of a template and which TLS option an app's routers get.
package policy

import "github.com/portcullis/hub/internal/signin"

// TLS options (core's static traefik/dynamic/tls.yml, contract §5 "TLS
// tier per host").
const (
	// TierProtected: RequireAndVerifyClientCert against the YubiKey CA
	// only (ca-chain-yubikey.crt): a browser certificate never passes.
	TierProtected = "protected@file"
	// TierProtectedAny: RequireAndVerifyClientCert against both CAs
	// (ca-chain.crt).
	TierProtectedAny = "protected-any@file"
	// TierDefault: VerifyClientCertIfGiven, both CAs. It is Traefik's
	// default TLS options (bare "default", never "default@file"): a
	// name without a router of its own gets them too, so a browser
	// reusing one HTTP/2 connection across names never gets 421
	// Misdirected Request between such a name, the core pages and these
	// apps (Traefik compares the options' names, contract §5).
	TierDefault = "default"
	TierPublic  = "public@file" // no client certificate requested
)

// certMethod reports whether m is a certificate method (contract §5).
func certMethod(m signin.Method) bool {
	return m == signin.YubiKeyCert || m == signin.BrowserCert
}

// Tier is the TLS option of an app's routers from its compiled rule
// (contract §5 "TLS tier per host"), where a certificate is a
// switched-on certificate method: every alternative holds yubikey_cert →
// protected@file; every alternative holds a certificate (so at least one
// accepts only a browser certificate there) → protected-any@file; some
// alternative does → default; none does, or rule is nil (the app
// has no Portcullis sign-in) → public@file. A rule that isn't compiled,
// or has no alternative at all, gets the strictest answer,
// protected@file. An auth.method: mtls app is protected@file before any
// rule (the Hub's access.tier). Then HostTier(t, publicExceptions).
//
// Traefik selects TLS options per SNI host, so every router of one host
// carries the same option (a mismatch answers 421 Misdirected Request).
func Tier(rule *signin.Node, on map[signin.Method]bool, publicExceptions bool) string {
	if rule == nil {
		return TierPublic
	}
	t := TierProtected
	// A rule that isn't compiled, or one with no way in, stays protected.
	if alts, err := signin.Alternatives(*rule); err == nil && len(alts) > 0 {
		allYubiKey, allCert, someCert := true, true, false
		for _, alt := range alts {
			cert, yubikey := false, false
			for _, m := range alt {
				if certMethod(m) && on[m] {
					cert = true
					yubikey = yubikey || m == signin.YubiKeyCert
				}
			}
			allYubiKey = allYubiKey && yubikey
			allCert = allCert && cert
			someCert = someCert || cert
		}
		switch {
		case allYubiKey:
			t = TierProtected
		case allCert:
			t = TierProtectedAny
		case someCert:
			t = TierDefault
		default:
			t = TierPublic
		}
	}
	return HostTier(t, publicExceptions)
}

// HostTier is the option every router of an app's host gets: while its
// public router exists (publicExceptions) protected@file and
// protected-any@file become default (anonymous visitors complete
// the handshake without a certificate; group-gate's certificate binding
// still applies per request on gated routers). Other options are kept.
func HostTier(tier string, publicExceptions bool) string {
	if publicExceptions && (tier == TierProtected || tier == TierProtectedAny) {
		return TierDefault
	}
	return tier
}
