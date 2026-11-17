package relay

import (
	"html"
	"net/http"
	"strings"
)

// OfflinePage is the static 503 a relay answers when the worker can't be
// reached (contract §5): "<app> runs on <server>, which is offline". The
// labels are display text, HTML-escaped; no cookie, never cached.
func OfflinePage(app, server string) http.HandlerFunc {
	msg := html.EscapeString(app) + " runs on " + html.EscapeString(server) + ", which is offline"
	body := "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + msg + "</title></head>" +
		"<body><h1>" + msg + "</h1><p>Try again once the server is back.</p></body></html>\n"
	return func(w http.ResponseWriter, _ *http.Request) {
		hd := w.Header()
		for k := range hd {
			delete(hd, k)
		}
		hd.Set("Content-Type", "text/html; charset=utf-8")
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(body))
	}
}

// cleanLabel keeps a display label printable and short.
func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}
