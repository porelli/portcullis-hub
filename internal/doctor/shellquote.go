package doctor

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ShellQuote is s as one POSIX shell word for a step an operator pastes
// into a root shell: single-quoted, each embedded single quote closed,
// escaped and reopened (the four characters quote-backslash-quote-quote). ok is
// false — no step may be built from s — when s is empty, isn't valid
// UTF-8 or holds a control character (a newline or carriage return would
// end the command line; the others hide what is pasted) or a format
// character (bidi overrides, zero-width: the shown step would differ
// from the pasted one).
func ShellQuote(s string) (quoted string, ok bool) {
	if s == "" || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return "", false
		}
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'", true
}
