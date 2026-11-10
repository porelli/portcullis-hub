// Package policy builds the group-gate policy file (contract §4, version 6)
// from the sign-in templates (§8.1), and says what each auth method can
// enforce of a template and which TLS option an app's routers get.
package policy

import "github.com/portcullis/hub/internal/signin"

// TLS options (core's static traefik/dynamic/tls.yml, contract §5 "TLS
// tier per host").
const (
	TierProtected = "protected@file" // RequireAndVerifyClientCert
	TierAuthAware = "authaware@file" // VerifyClientCertIfGiven
	TierPublic    = "public@file"    // no client certificate requested
)

// certMethod reports whether m is a certificate method (contract §5).
func certMethod(m signin.Method) bool {
	return m == signin.YubiKeyCert || m == signin.BrowserCert
}

// Tier is the TLS option of an app's routers from its compiled rule (D18):
// every alternative holds a switched-on certificate method →
// protected@file; some alternative does → authaware@file; none does, or
// rule is nil (the app has no Portcullis sign-in) → public@file. A rule
// that isn't compiled gets the strictest answer, protected@file. With
// public exceptions protected@file becomes authaware@file (anonymous
// visitors complete the handshake without a certificate; group-gate's
// mTLS binding still applies per request on gated routers).
//
// Traefik selects TLS options per SNI host, so every router of one host
// carries the same option (a mismatch answers 421 Misdirected Request).
func Tier(rule *signin.Node, on map[signin.Method]bool, publicExceptions bool) string {
	if rule == nil {
		return TierPublic
	}
	t := TierProtected
	if alts, err := signin.Alternatives(*rule); err == nil {
		all, some := true, false
		for _, alt := range alts {
			has := false
			for _, m := range alt {
				if certMethod(m) && on[m] {
					has = true
				}
			}
			all = all && has
			some = some || has
		}
		switch {
		case len(alts) > 0 && all:
			t = TierProtected
		case some:
			t = TierAuthAware
		default:
			t = TierPublic
		}
	}
	if publicExceptions && t == TierProtected {
		return TierAuthAware
	}
	return t
}
