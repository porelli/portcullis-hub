package servers

import (
	"strings"
	"testing"
)

func TestValidIDReservesPrimary(t *testing.T) {
	for _, ok := range []string{"a", "nas", "worker-2", "w" + strings.Repeat("x", 30), "a-b"} {
		if err := ValidID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if err := ValidID("primary"); err == nil || err.Error() != "primary is the local server's name" {
		t.Errorf("primary: %v", err)
	}
	for _, bad := range []string{"", "1a", "-a", "A", "a_b", "a.b", "w" + strings.Repeat("x", 31), "a-", "é", "a b", "nas\n"} {
		if err := ValidID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
