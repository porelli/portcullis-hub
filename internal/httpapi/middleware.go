// Package httpapi serves the Hub's UI and JSON API, guarded by the Traefik
// proxy secret (contract §5) and a CSRF check.
package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"mime"
	"net/http"
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
