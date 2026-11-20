package main

import "testing"

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
		{"ingress2:app.kubernetes.io/name=traefik", true, "ingress2:app.kubernetes.io/name=traefik"},
	} {
		p, err := traefikPeerFromEnv(env(map[string]string{"HUB_TRAEFIK_PEER": c.val}), c.ha, "pc")
		if err != nil || p.String() != c.want {
			t.Errorf("%q ha %v: %s %v, want %s", c.val, c.ha, p, err, c.want)
		}
	}
	if _, err := traefikPeerFromEnv(env(map[string]string{"HUB_TRAEFIK_PEER": "portcullis-ingress"}), true, "pc"); err == nil {
		t.Error("a malformed peer was taken")
	}
}
