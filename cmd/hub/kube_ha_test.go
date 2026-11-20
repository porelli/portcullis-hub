package main

import (
	"strings"
	"testing"
)

// TestHAAndTraefikPeerFromEnv: HUB_HA is on only for exactly "on";
// HUB_TRAEFIK_PEER (the params' traefik value) wins, else the mode's
// default; a malformed peer refuses the start.
func TestHAAndTraefikPeerFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for v, want := range map[string]bool{"on": true, "": false, "On": false, "true": false, "1": false} {
		if got := haFromEnv(env(map[string]string{"HUB_HA": v})); got != want {
			t.Errorf("HUB_HA=%q: %v", v, got)
		}
	}
	for _, c := range []struct {
		val  string
		ha   bool
		want string
	}{
		{"", false, "pc:portcullis.io/component=traefik"},
		{"", true, "portcullis-ingress:app.kubernetes.io/name=traefik"},
		{"portcullis-ingress:app.kubernetes.io/name=traefik", true, "portcullis-ingress:app.kubernetes.io/name=traefik"},
		{"pc:portcullis.io/component=traefik", false, "pc:portcullis.io/component=traefik"},
	} {
		p, err := traefikPeerFromEnv(env(map[string]string{"HUB_TRAEFIK_PEER": c.val}), c.ha, "pc")
		if err != nil || p.String() != c.want {
			t.Errorf("%q ha %v: %s %v, want %s", c.val, c.ha, p, err, c.want)
		}
	}
	// Exactly the two values core writes; the HA one in either mode (the
	// chart sets both together with HUB_HA).
	if p, err := traefikPeerFromEnv(env(map[string]string{"HUB_TRAEFIK_PEER": "portcullis-ingress:app.kubernetes.io/name=traefik"}), false, "pc"); err != nil || p.Namespace != "portcullis-ingress" {
		t.Errorf("the HA value: %s %v", p, err)
	}
	for _, bad := range []string{
		"portcullis-ingress",
		"ingress2:app.kubernetes.io/name=traefik",            // another namespace
		"portcullis:portcullis.io/component=traefik",         // not the Hub's own core namespace (pc)
		"portcullis-apps:portcullis.io/instance=evil",        // an app's pods
		"kube-system:k8s-app=kube-dns",                       // another system pod
		"portcullis-edge:app.kubernetes.io/name=traefik",     // the edge namespace
		"pc:portcullis.io/component=mcp-gate",                // another core component
		"pc:app.kubernetes.io/name=traefik",                  // the HA selector in the core namespace
		"portcullis-ingress:portcullis.io/component=traefik", // the core selector in the ingress namespace
		" portcullis-ingress:app.kubernetes.io/name=traefik", // not exact
	} {
		if p, err := traefikPeerFromEnv(env(map[string]string{"HUB_TRAEFIK_PEER": bad}), true, "pc"); err == nil {
			t.Errorf("%q taken as %s", bad, p)
		}
	}
}

// TestDNSProviderFromEnv (HA review S1): HUB_DNS_PROVIDER is a provider
// id or nothing (then core.env's, else unknown); never anything else.
func TestDNSProviderFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for v, want := range map[string]string{"": "", "porkbun": "porkbun", " hetzner-cloud ": "hetzner-cloud", "Porkbun": "", "a b": "", "<b>": "",
		strings.Repeat("a", 33): ""} {
		if got := dnsProviderFromEnv(env(map[string]string{"HUB_DNS_PROVIDER": v})); got != want {
			t.Errorf("%q: %q, want %q", v, got, want)
		}
	}
}
