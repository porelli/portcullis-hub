package idmap

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseShapes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         string
		err        bool
		identity   bool
		consistent bool
	}{
		{name: "identity", in: "         0          0 4294967295\n", identity: true},
		{name: "consistent", in: "0 1001 1\n1 100000 65536", consistent: true},
		{name: "consistent larger range", in: "0 1001 1\n1 100000 200000\n", consistent: true},
		{name: "single remap", in: "0 100000 65536"},
		{name: "range too small", in: "0 1001 1\n1 100000 65535"},
		{name: "operator is root", in: "0 0 1\n1 100000 65536"},
		{name: "three ranges", in: "0 1001 1\n1 100000 65536\n65537 300000 10"},
		{name: "second range not at 1", in: "0 1001 1\n2 100000 65536"},
		{name: "first size not 1", in: "0 1001 2\n2 100000 65536"},
		{name: "empty", in: "", err: true},
		{name: "blank lines only", in: "\n\n", err: true},
		{name: "garbage", in: "hello world", err: true},
		{name: "two fields", in: "0 0", err: true},
		{name: "four fields", in: "0 0 1 1", err: true},
		{name: "negative", in: "0 -1 1", err: true},
		{name: "overflow", in: "0 0 4294967296", err: true},
		{name: "zero size", in: "0 0 0", err: true},
		{name: "sign", in: "+0 0 1", err: true},
		{name: "too many lines", in: strings.Repeat("0 0 1\n", 341), err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, want an error", tc.in, m)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got := m.Identity(); got != tc.identity {
				t.Errorf("Identity = %v, want %v", got, tc.identity)
			}
			if got := m.Consistent(); got != tc.consistent {
				t.Errorf("Consistent = %v, want %v", got, tc.consistent)
			}
		})
	}
}

func TestToHost(t *testing.T) {
	m, err := Parse("0 1001 1\n1 100000 65536")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    uint32
		h    uint32
		okay bool
	}{{0, 1001, true}, {1, 100000, true}, {10001, 110000, true}, {65536, 165535, true}, {65537, 0, false}} {
		h, ok := m.ToHost(tc.c)
		if ok != tc.okay || (ok && h != tc.h) {
			t.Errorf("ToHost(%d) = %d, %v; want %d, %v", tc.c, h, ok, tc.h, tc.okay)
		}
	}
	id, _ := Parse("0 0 4294967295")
	if h, ok := id.ToHost(4294967294); !ok || h != 4294967294 {
		t.Errorf("identity ToHost = %d, %v", h, ok)
	}
}

func TestJSON(t *testing.T) {
	m, _ := Parse("0 1001 1\n1 100000 65536")
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"container":0,"host":1001,"size":1},{"container":1,"host":100000,"size":65536}]`; string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}
