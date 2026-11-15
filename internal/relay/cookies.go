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

// Reserved reports whether a cookie name is a Portcullis cookie (contract
// §5): _oauth2_proxy and _oauth2_proxy_*, __Host-portcullis_ext and
// __Host-portcullis_ext-*, and the CSRF cookies (*_csrf*). Matched without
// case, so a spelling variant never slips through.
func Reserved(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasPrefix(n, "_oauth2_proxy"):
		return true
	case n == "__host-portcullis_ext" || strings.HasPrefix(n, "__host-portcullis_ext-"):
		return true
	case strings.Contains(n, "_csrf"):
		return true
	}
	return false
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
