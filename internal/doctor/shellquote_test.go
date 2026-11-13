package doctor

import "testing"

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/a":     "'/srv/a'",
		"/srv/a b":   "'/srv/a b'",
		"/srv/it's":  `'/srv/it'\''s'`,
		"/srv/$(id)": "'/srv/$(id)'",
		"/srv/x;y":   "'/srv/x;y'",
		"/srv/'":     `'/srv/'\'''`,
		"/srv/naïve": "'/srv/naïve'",
	} {
		if got, ok := ShellQuote(in); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "/srv/a\nb", "/srv/a\rb", "/srv/\x00", "/srv/\x7f", "/srv/ ", "/srv/\xff", "/srv/\u0085"} {
		if got, ok := ShellQuote(bad); ok || got != "" {
			t.Errorf("%q accepted: %q", bad, got)
		}
	}
}
