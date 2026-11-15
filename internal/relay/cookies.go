// Package relay is portcullis-relay (contract §5, §17.2): the primary-side
// stand-in for a service placed on a worker. It carries the Hub's rendered
// Traefik labels unchanged, so every request reaches it through Traefik's
// forward-auth, group-gate and TLS tier, and forwards it over link's data
// CONNECT to the worker's agent. It strips the Portcullis cookies from
// requests and makes every Set-Cookie host-only.
package relay

import (
	"net/http"
	"strings"
)

// reservedPrefixes are the contract's Portcullis cookie names (§5): each
// one exactly, or followed by "_" or "-" and anything (the split-cookie
// forms _oauth2_proxy_0, __Host-portcullis_ext_1, …).
var reservedPrefixes = []string{"_oauth2_proxy", "__host-portcullis_ext"}

// Reserved reports whether a cookie name is a Portcullis cookie (contract
// §5), without case: a reserved name (reservedPrefixes) exactly or with
// "_"/"-" and a suffix, or any name containing "_csrf" (the CSRF
// cookies).
func Reserved(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range reservedPrefixes {
		if n == p || strings.HasPrefix(n, p+"_") || strings.HasPrefix(n, p+"-") {
			return true
		}
	}
	return strings.Contains(n, "_csrf")
}

// FilterRequestCookies removes every Portcullis cookie from the request's
// Cookie headers (and any malformed pair), keeping the app's own in one
// header; no cookie left: no header.
func FilterRequestCookies(h http.Header) {
	var keep []string
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, ok := strings.Cut(part, "=")
			if !ok || strings.TrimSpace(name) == "" || Reserved(name) {
				continue
			}
			keep = append(keep, part)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// FilterResponseCookies makes the response's cookies host-only: each
// Set-Cookie is parsed alone; a reserved name or an unparsable one is
// dropped, every other loses its Domain attribute (so a worker app can
// never set a cookie on the parent or a sibling host) and is re-encoded.
func FilterResponseCookies(h http.Header, host string) {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var keep []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name == "" || Reserved(c.Name) {
			continue
		}
		c.Domain = ""
		if s := c.String(); s != "" {
			keep = append(keep, s)
		}
	}
	h.Del("Set-Cookie")
	for _, s := range keep {
		h.Add("Set-Cookie", s)
	}
}
