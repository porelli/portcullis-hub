package vpn

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// docVector is one entry of testdata/vpn_json_vectors.json, shared with
// core's two readers (wg and group-gate): a document (a JSON string is
// the file's raw text), the reader's clock, "ok" or a substring of the
// Go reader's error (other readers treat any non-"ok" as "must refuse
// the whole file"), and addresses that must be denied.
type docVector struct {
	Name string          `json:"name"`
	Doc  json.RawMessage `json:"doc"`
	Now  time.Time       `json:"now"`
	Want string          `json:"want"`
	Deny []struct {
		IP       string `json:"ip"`
		Provider string `json:"provider"`
	} `json:"deny"`
}

func loadDocVectors(t *testing.T) []docVector {
	t.Helper()
	b, err := os.ReadFile("testdata/vpn_json_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []docVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func vectorBytes(v docVector) []byte {
	var s string
	if json.Unmarshal(v.Doc, &s) == nil {
		return []byte(s)
	}
	return v.Doc
}

func TestParseVectors(t *testing.T) {
	vs := loadDocVectors(t)
	need := map[string]bool{"valid two providers": true, "unknown top-level key": true, "version 1": true, "overlapping provider ranges": true,
		"duplicate device ip": true, "provider past stale_after denies its own": true, "peer past expires dropped": true, "missing builtin with a builtin provider": true}
	for _, v := range vs {
		delete(need, v.Name)
		d, err := Parse(vectorBytes(v))
		if v.Want == "ok" {
			if err != nil {
				t.Errorf("%s: %v", v.Name, err)
				continue
			}
		} else {
			if err == nil || !strings.Contains(err.Error(), v.Want) {
				t.Errorf("%s: err %v, want %q", v.Name, err, v.Want)
			}
			continue // a refused file denies everything
		}
		for _, dn := range v.Deny {
			if dv, ok := d.Lookup(netip.MustParseAddr(dn.IP), v.Now); ok {
				t.Errorf("%s: %s allowed (%+v)", v.Name, dn.IP, dv)
			}
		}
	}
	for n := range need {
		t.Errorf("vector %q missing", n)
	}
}

func TestLookupAllows(t *testing.T) {
	v := loadDocVectors(t)[0]
	d, err := Parse(vectorBytes(v))
	if err != nil {
		t.Fatal(err)
	}
	for ip, user := range map[string]string{"10.213.0.2": "alice", "100.64.0.7": "alice"} {
		dv, ok := d.Lookup(netip.MustParseAddr(ip), v.Now)
		if !ok || dv.User != user {
			t.Errorf("%s: %+v %v", ip, dv, ok)
		}
	}
	// A builtin device whose peer is gone is denied.
	d.Builtin.Peers = d.Builtin.Peers[1:]
	if _, ok := d.Lookup(netip.MustParseAddr("10.213.0.2"), v.Now); ok {
		t.Error("device without its peer allowed")
	}
}

func TestWriteRoundTrip(t *testing.T) {
	old := FileGID
	FileGID = os.Getgid()
	defer func() { FileGID = old }()
	v := loadDocVectors(t)[0]
	d, err := Parse(vectorBytes(v))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), FileName)
	if err := Write(p, *d); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	// Write refuses an invalid document.
	d.Version = 1
	if err := Write(p, *d); err == nil {
		t.Error("invalid doc written")
	}
	// An empty doc writes [] lists.
	if err := Write(p, Doc{Version: DocVersion}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), `"providers": []`) || strings.Contains(string(b), "builtin") {
		t.Errorf("%s", b)
	}
}

func TestWriteMode0640Group(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown to group 10001")
	}
	p := filepath.Join(t.TempDir(), FileName)
	if err := Write(p, Doc{Version: DocVersion}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 || st.Sys().(*syscall.Stat_t).Gid != 10001 {
		t.Fatalf("mode %v gid %d", st.Mode(), st.Sys().(*syscall.Stat_t).Gid)
	}
}

func TestValidPublicKey(t *testing.T) {
	for k, ok := range map[string]bool{
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=": true,
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==": false,
		"not base64": false, "": false,
	} {
		if ValidPublicKey(k) != ok {
			t.Errorf("%q", k)
		}
	}
}
