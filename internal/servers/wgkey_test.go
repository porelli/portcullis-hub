package servers

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestNewWGKeyPair(t *testing.T) {
	priv, pub, err := NewWGKeyPair()
	if err != nil || ValidWGKey(priv) != nil || ValidWGKey(pub) != nil {
		t.Fatalf("%v", err)
	}
	k, _ := base64.StdEncoding.DecodeString(priv)
	p, _ := curve25519.X25519(k, curve25519.Basepoint)
	if base64.StdEncoding.EncodeToString(p) != pub {
		t.Error("pub isn't priv's")
	}
	for _, bad := range []string{"", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "abc", pub + "="} {
		if ValidWGKey(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
