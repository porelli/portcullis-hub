package linkdoc

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// linkVector is one entry of testdata/link_json_vectors.json, shared
// byte for byte with core's wg reader (tests/link_json_vectors.json): a
// document (a JSON string is the file's raw text: duplicate keys,
// malformed JSON), whether it is valid, and a substring of this reader's
// error (other readers treat any invalid document as "no peers").
type linkVector struct {
	Name  string          `json:"name"`
	Doc   json.RawMessage `json:"doc"`
	Valid bool            `json:"valid"`
	Error string          `json:"error"`
}

func vectorBytes(v linkVector) []byte {
	var s string
	if json.Unmarshal(v.Doc, &s) == nil {
		return []byte(s)
	}
	return v.Doc
}

func TestLinkDocVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/link_json_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []linkVector
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 30 {
		t.Fatalf("%d vectors, want ≥ 30", len(vs))
	}
	names := map[string]bool{}
	valid := 0
	for _, v := range vs {
		if names[v.Name] {
			t.Errorf("duplicate vector name %q", v.Name)
		}
		names[v.Name] = true
		d, err := Parse(vectorBytes(v))
		if v.Valid {
			valid++
			if err != nil || d == nil {
				t.Errorf("%s: %v", v.Name, err)
			}
			if v.Error != "" {
				t.Errorf("%s: a valid vector names an error", v.Name)
			}
			continue
		}
		if v.Error == "" {
			t.Errorf("%s: an invalid vector without an error substring", v.Name)
		}
		if err == nil || !strings.Contains(err.Error(), v.Error) {
			t.Errorf("%s: err %v, want %q", v.Name, err, v.Error)
		}
		if d != nil {
			t.Errorf("%s: a refused document returned peers", v.Name)
		}
	}
	if valid < 3 {
		t.Errorf("%d valid vectors", valid)
	}
}

func sample() *Doc {
	return &Doc{Version: 1, WrittenAt: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), Subnet: Subnet,
		Peers:  []Peer{{ID: "nas", PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", IP: netip.MustParseAddr("10.214.0.10"), State: StateReady}},
		Relays: []Relay{{TokenSHA256: strings.Repeat("ab", 32), Instance: "immich", Server: "nas"}}}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	gid := os.Getgid()
	d := sample()
	if err := Write(dir, gid, d); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, FileName)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 || int(fi.Sys().(*syscall.Stat_t).Gid) != gid {
		t.Errorf("mode %v gid %d", fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid)
	}
	b, _ := os.ReadFile(p)
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Peers[0] != d.Peers[0] || got.Relays[0] != d.Relays[0] || !got.WrittenAt.Equal(d.WrittenAt) {
		t.Errorf("round trip %+v", got)
	}
	// No peers and no relays are written as [] (null is refused).
	if err := Write(dir, gid, &Doc{Version: 1, WrittenAt: d.WrittenAt, Subnet: Subnet}); err != nil {
		t.Fatalf("empty: %v", err)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), `"peers": []`) || !strings.Contains(string(b), `"relays": []`) {
		t.Errorf("empty lists: %s", b)
	}
	// An invalid document is never written; the last good one stays.
	bad := sample()
	bad.Relays[0].Server = "other"
	if err := Write(dir, gid, bad); err == nil {
		t.Error("invalid document written")
	}
	if b2, _ := os.ReadFile(p); string(b2) != string(b) {
		t.Error("the file changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp files left: %d entries", len(entries))
	}
}

// TestRelayCap: 4096 relays are read, 4097 refused before any entry is
// checked (kept out of the shared vectors for size: core's reader tests
// the same two counts).
func TestRelayCap(t *testing.T) {
	d := sample()
	d.Relays = nil
	for i := 0; i < MaxRelays; i++ {
		d.Relays = append(d.Relays, Relay{TokenSHA256: strings.Repeat("0", 56) + fmt.Sprintf("%08x", i), Instance: fmt.Sprintf("i%d", i), Server: "nas"})
	}
	b, _ := json.Marshal(d)
	if _, err := Parse(b); err != nil {
		t.Fatalf("4096 relays: %v", err)
	}
	d.Relays = append(d.Relays, d.Relays[0])
	b, _ = json.Marshal(d)
	if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), "more than 4096 relays") {
		t.Errorf("4097 relays: %v", err)
	}
}
