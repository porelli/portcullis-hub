// Package httpapi serves the Hub's UI and JSON API, guarded by the Traefik
// proxy secret (contract §5) and a CSRF check.
package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// ProxySecretHeader is set by Traefik on every request routed to the Hub.
const ProxySecretHeader = "X-Portcullis-Proxy-Secret"

// MinSecretLen is the minimum accepted HUB_PROXY_SECRET length.
const MinSecretLen = 32

// CheckSecret validates a configured proxy secret.
func CheckSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("HUB_PROXY_SECRET is not set (generate one with `portcullis init`)")
	}
	if len(secret) < MinSecretLen {
		return fmt.Errorf("HUB_PROXY_SECRET is too short (%d chars, need at least %d)", len(secret), MinSecretLen)
	}
	return nil
}

// isHealthz is the only route reachable without the proxy secret.
func isHealthz(r *http.Request) bool {
	return r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead)
}

// ProxySecret rejects every request whose X-Portcullis-Proxy-Secret header
// does not match secret, except GET/HEAD /healthz. Only Traefik knows the
// secret, so this stops anything else on the Docker networks from talking
// to the Hub directly and spoofing X-Forwarded-User. Both sides are hashed
// before the constant-time compare so the secret's length doesn't leak.
func ProxySecret(secret string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealthz(r) {
			next.ServeHTTP(w, r)
			return
		}
		vals := r.Header.Values(ProxySecretHeader)
		if len(vals) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := sha256.Sum256([]byte(vals[0]))
		if len(vals) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Don't let the secret travel any further (logs, upstream handlers).
		r.Header.Del(ProxySecretHeader)
		next.ServeHTTP(w, r)
	})
}

// CSRF rejects cross-origin state-changing requests. The Hub sits behind
// forward-auth with a SameSite=Lax cookie scoped to the parent domain, so
// any sibling app subdomain counts as same-site — cookies alone don't stop a
// malicious page on another app from POSTing here. CrossOriginProtection
// uses Sec-Fetch-Site / Origin; additionally a JSON body is required so
// plain HTML forms (which can't send application/json) are refused — except
// the read-only CSV upload of the import review (multipart).
func CSRF(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			// The CSV upload of the import review is multipart; the review
			// changes nothing (apply is JSON) and the cross-origin check
			// above still applies.
			upload := mt == "multipart/form-data" && r.Method == http.MethodPost && r.URL.Path == "/api/directory/import/review"
			if mt != "application/json" && !upload {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	return cop.Handler(inner)
}

// ImpersonationHeader is group-gate's impersonation id header (contract
// §5): set only on a request it allows for a live impersonation, from
// the validated file record; Traefik deletes client copies (every
// forward-auth middleware's authResponseHeaders, every public router's
// strip list).
const ImpersonationHeader = "X-Forwarded-Impersonation"

// stopOwnImpersonationPath is the one change an impersonated browser may
// make: Stop (contract §5.1).
const stopOwnImpersonationPath = "/api/me/impersonation/stop"

// errWhileImpersonated is the read-only rule's answer (D42).
const errWhileImpersonated = "not while you are signed in as someone else: Stop first"

// RefuseWhileImpersonated makes both listeners read-only while an
// administrator is signed in as someone else (D42, contract §5.1):
// while X-Forwarded-Impersonation is present (any value, empty
// included: fail closed), or the X-Forwarded-Access-Token's payload has
// an act or a pc_imp claim (any value: defence in depth should the
// header ever go missing, Task 6 review M2), every request that isn't
// GET or HEAD is 403,
// except POST /api/me/impersonation/stop (exactly that path: the mux
// never sees an uncleaned form of it). My apps values, credentials, AI
// connections, passwords, certificates, confirmations and every
// directory action are refused; reads work.
func RefuseWhileImpersonated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values(ImpersonationHeader)) > 0 || impersonatedToken(r) {
			switch {
			case r.Method == http.MethodGet || r.Method == http.MethodHead:
			case r.Method == http.MethodPost && r.URL.Path == stopOwnImpersonationPath && r.URL.RawPath == "":
			default:
				http.Error(w, errWhileImpersonated, http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// impersonatedToken reports whether any X-Forwarded-Access-Token's
// payload (base64url, padded or not, then JSON, as callerSID decodes it)
// has an act or a pc_imp key. A token that can't be decoded isn't one
// (the routes' own sign-in checks refuse it).
func impersonatedToken(r *http.Request) bool {
	for _, v := range r.Header.Values("X-Forwarded-Access-Token") {
		parts := strings.Split(strings.TrimSpace(v), ".")
		if len(parts) != 3 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
		if err != nil {
			continue
		}
		var claims map[string]json.RawMessage
		if json.Unmarshal(raw, &claims) != nil {
			continue
		}
		_, act := claims["act"]
		_, imp := claims["pc_imp"]
		if act || imp {
			return true
		}
	}
	return false
}
