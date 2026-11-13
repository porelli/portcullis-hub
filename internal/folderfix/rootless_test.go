package folderfix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/portcullis/hub/internal/idmap"
)

func mustMap(t *testing.T, s string) idmap.Map {
	t.Helper()
	m, err := idmap.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

const (
	identityMapText = "0 0 4294967295"
	podmanUIDMap    = "0 1001 1\n1 100000 65536"
	podmanGIDMap    = "0 1001 1\n1 200000 65536"
)

// withIDMaps makes the fixer read uid / gid as its maps for the test.
func withIDMaps(t *testing.T, uid, gid string) {
	t.Helper()
	u, g := mustMap(t, uid), mustMap(t, gid)
	old := readIDMaps
	readIDMaps = func() (idmap.Map, idmap.Map, error) { return u, g, nil }
	t.Cleanup(func() { readIDMaps = old })
}

// withOwner makes the walk read rel as owned by uid:gid.
func withOwner(t *testing.T, owners map[string][2]uint32) {
	t.Helper()
	testHookOwnerOf = func(rel string, uid, gid uint32) (uint32, uint32) {
		if o, ok := owners[rel]; ok {
			return o[0], o[1]
		}
		return uid, gid
	}
	t.Cleanup(func() { testHookOwnerOf = nil })
}

func TestIDMapsAllowed(t *testing.T) {
	id := mustMap(t, identityMapText)
	pu, pg := mustMap(t, podmanUIDMap), mustMap(t, podmanGIDMap)
	remap := mustMap(t, "0 100000 65536")
	for _, c := range []struct {
		name     string
		uid, gid idmap.Map
		ok       bool
	}{
		{"identity", id, id, true},
		{"consistent uid+gid", pu, pg, true},
		{"consistent uid, userns-remap gid", pu, remap, false},
		{"single remap", remap, remap, false},
		{"identity uid, consistent gid", id, pg, false},
	} {
		err := idMapsAllowed(c.uid, c.gid)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && (!IsRefused(err) || err.Error() != "the fixer runs in a user namespace with translated ids (userns-remap or rootless Docker): owners and ACLs would be wrong") {
			t.Errorf("%s: message %q", c.name, err)
		}
	}
}

// An unreadable map refuses (fail closed).
func TestUnreadableIDMapsRefuse(t *testing.T) {
	old := readIDMaps
	readIDMaps = func() (idmap.Map, idmap.Map, error) { return nil, nil, fmt.Errorf("no /proc") }
	t.Cleanup(func() { readIDMaps = old })
	if _, err := Scan(Options{Root: simpleTree(t)}); !IsRefused(err) {
		t.Fatalf("scan with unreadable maps: %v", err)
	}
}

func TestScanCountsUnmapped(t *testing.T) {
	withIDMaps(t, podmanUIDMap, podmanGIDMap)
	root := simpleTree(t)
	withOwner(t, map[string][2]uint32{"d/f": {idmap.Overflow, 10001}})
	r, err := Scan(Options{Root: root, Children: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Unmapped.N != 1 || len(r.Unmapped.Sample) != 1 || r.Unmapped.Sample[0] != "d/f" {
		t.Errorf("unmapped = %+v", r.Unmapped)
	}
	if r.IDMap == nil || !reflect.DeepEqual(r.IDMap.UID, mustMap(t, podmanUIDMap)) || !reflect.DeepEqual(r.IDMap.GID, mustMap(t, podmanGIDMap)) {
		t.Errorf("id_map = %+v", r.IDMap)
	}
	if len(r.Owners) == 0 {
		t.Fatal("no owners")
	}
	for _, o := range r.Owners {
		wu, uok := mustMap(t, podmanUIDMap).ToHost(uint32(o.UID))
		wg, gok := mustMap(t, podmanGIDMap).ToHost(uint32(o.GID))
		if uok != (o.HostUID != nil) || (uok && *o.HostUID != wu) || gok != (o.HostGID != nil) || (gok && *o.HostGID != wg) {
			t.Errorf("owner %+v: host ids %v %v, want %d %d", o, o.HostUID, o.HostGID, wu, wg)
		}
	}
	for _, c := range r.Children {
		if c.HostUID == nil && c.UID <= 65536 {
			t.Errorf("child %+v without host uid", c)
		}
	}
	b, _ := json.Marshal(r)
	for _, k := range []string{`"id_map":{"uid":[{"container":0,"host":1001,"size":1}`, `"unmapped":{"n":1`, `"host_uid":`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("report has no %s: %s", k, b)
		}
	}
}

func TestScanIdentityNoUnmapped(t *testing.T) {
	withIDMaps(t, identityMapText, identityMapText)
	root := simpleTree(t)
	withOwner(t, map[string][2]uint32{"d/f": {idmap.Overflow, idmap.Overflow}})
	r, err := Scan(Options{Root: root, Children: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Unmapped.N != 0 || r.IDMap != nil {
		t.Errorf("identity: unmapped %+v id_map %+v", r.Unmapped, r.IDMap)
	}
	b, _ := json.Marshal(r)
	for _, k := range []string{`"id_map"`, `"host_uid"`, `"host_gid"`, `"selinux_label"`} {
		if bytes.Contains(b, []byte(k)) {
			t.Errorf("identity report has %s: %s", k, b)
		}
	}
}

func TestApplyRefusesUnmapped(t *testing.T) {
	needWritableFS(t)
	withIDMaps(t, podmanUIDMap, podmanGIDMap)
	root := simpleTree(t)
	withOwner(t, map[string][2]uint32{"d/f": {0, idmap.Overflow}})
	dev, ino := rootIDs(t, root)
	ms, _ := readMountinfo()
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, ExpectMountRoot: effectiveMountRoot(ms, root), Target: Target{GID: 60001, Files: "rw"}}
	r, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	before := treeState(t, root)
	_, err = Apply(o, r.Plan.Changes)
	if !IsRefused(err) || err.Error() != fmt.Sprintf(UnmappedMsg, "d/f") {
		t.Fatalf("apply = %v, want %q", err, fmt.Sprintf(UnmappedMsg, "d/f"))
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Error("a refused apply changed something")
	}
}

func TestChildfixRefusesUnmapped(t *testing.T) {
	withIDMaps(t, podmanUIDMap, podmanGIDMap)
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "tm"), 0o755)
	alice := filepath.Join(root, "tm", "alice")
	mkdir(t, alice, 0o755)
	dev, ino := rootIDs(t, alice)
	ms, _ := readMountinfo()
	mr := effectiveMountRoot(ms, alice)
	if mr == "" {
		t.Skip("no mountinfo here: childfix stops at the mount root check")
	}
	withOwner(t, map[string][2]uint32{"tm/alice": {idmap.Overflow, idmap.Overflow}})
	before := treeState(t, root)
	me := os.Getuid()
	if me == 0 {
		me = 4242
	}
	r, err := FixChild(Options{Root: root, ExpectDev: dev, ExpectIno: ino, ExpectMountRoot: mr}, "tm", ChildFix{Name: "alice", UID: me, Owner: me})
	if !IsRefused(err) || err.Error() != fmt.Sprintf(UnmappedMsg, "tm/alice") {
		t.Fatalf("childfix = %v", err)
	}
	if r.Unmapped.N != 1 || r.IDMap == nil {
		t.Errorf("report %+v", r)
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Error("a refused childfix changed something")
	}
}

func TestScanSELinuxLabel(t *testing.T) {
	old := readSELinux
	readSELinux = func(int) string { return "system_u:object_r:container_file_t:s0" }
	t.Cleanup(func() { readSELinux = old })
	r, err := Scan(Options{Root: simpleTree(t)})
	if err != nil {
		t.Fatal(err)
	}
	if r.SELinux != "system_u:object_r:container_file_t:s0" {
		t.Errorf("selinux_label = %q", r.SELinux)
	}
	b, _ := json.Marshal(r)
	if !bytes.Contains(b, []byte(`"selinux_label":"system_u:object_r:container_file_t:s0"`)) {
		t.Errorf("JSON: %s", b)
	}
}

// A restore under the consistent map refuses an entry that reads unmapped,
// before anything changes (the seekable snapshot is checked first; the
// entries were never applied, so nothing else would refuse first).
func TestRestoreRefusesUnmapped(t *testing.T) {
	needWritableFS(t)
	withIDMaps(t, podmanUIDMap, podmanGIDMap)
	root := simpleTree(t)
	dev, ino := rootIDs(t, root)
	ms, _ := readMountinfo()
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, ExpectMountRoot: effectiveMountRoot(ms, root), Target: Target{GID: 60001, Files: "rw"}}
	var snap bytes.Buffer
	if _, err := WriteSnapshot(o, &snap); err != nil {
		t.Fatal(err)
	}
	withOwner(t, map[string][2]uint32{"g": {idmap.Overflow, 60001}})
	before := treeState(t, root)
	_, err := Restore(o, bytes.NewReader(snap.Bytes()))
	if !IsRefused(err) || err.Error() != fmt.Sprintf(UnmappedMsg, "g") {
		t.Fatalf("restore = %v", err)
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Error("a refused restore changed something")
	}
}
