package keycloak

import (
	"strings"
	"testing"
)

// TestFreshAuthVPNRedirect (V8, contract §8): the fresh-auth client's
// model is per host — people.<d> may carry /signin and /vpn/, any other
// host only / — with one web origin per host.
func TestFreshAuthVPNRedirect(t *testing.T) {
	ok := []string{"https://people.example.org/signin", "https://people.example.org/vpn/", "https://hub.example.org/"}
	origins := []string{"https://people.example.org", "https://hub.example.org"}
	if err := checkFreshAuthURIs(ok, origins); err != nil {
		t.Fatal(err)
	}
	if err := checkFreshAuthURIs(ok[:1], origins[:1]); err != nil {
		t.Fatalf("one URI: %v", err)
	}
	for _, c := range []struct {
		uris, origins []string
		want          string
	}{
		{[]string{"https://people.example.org/signin", "https://people.example.org/signin"}, origins[:1], "listed twice"},
		{[]string{"https://people.example.org/vpn"}, origins[:1], "isn't allowed"},
		{[]string{"https://people.example.org/"}, origins[:1], "isn't allowed"},
		{[]string{"https://hub.example.org/vpn/"}, []string{"https://hub.example.org"}, "isn't allowed"},
		{[]string{"http://people.example.org/vpn/"}, origins[:1], "must be"},
		{[]string{"https://people.example.org/vpn/?x=1"}, origins[:1], "must be"},
		{ok, []string{"https://people.example.org", "https://people.example.org"}, "listed twice"},
		{ok, []string{"https://people.example.org"}, "one web origin per host"},
		{ok, []string{"https://people.example.org", "https://evil.example.org"}, "must be https://<a redirect URI's host>"},
		{nil, nil, "no redirect URI"},
	} {
		if err := checkFreshAuthURIs(c.uris, c.origins); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v %v: %v, want %q", c.uris, c.origins, err, c.want)
		}
	}
}
