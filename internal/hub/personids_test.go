package hub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

const smbID = "smbfixture"

// smbFixture loads testdata/settings/smbfixture (a router-less template
// with a person_id option uid, pool posix_uid) as the default instance
// and creates a second instance smbfixture-b.
func smbFixture(t *testing.T) *fixture {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", smbID, "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", smbID, "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{smbID: {string(m), string(c)}})
	if f.h.Template(smbID) == nil {
		t.Fatalf("smbfixture not loaded (see the log)")
	}
	if err := f.h.CreateInstance(smbID, smbID+"-b", nil); err != nil {
		t.Fatal(err)
	}
	return f
}

func persons(users ...string) []settings.Person {
	out := make([]settings.Person, 0, len(users))
	for _, u := range users {
		out = append(out, settings.Person{User: u})
	}
	return out
}

func mustPersonID(t *testing.T, h *Hub, user string) int {
	t.Helper()
	id, ok := h.PersonID(templates.PoolPOSIXUID, user)
	if !ok {
		t.Fatalf("no %s id for %s", templates.PoolPOSIXUID, user)
	}
	return id
}

func loadState(t *testing.T, f *fixture) *state.AppState {
	t.Helper()
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPersonIDStableAcrossInstances(t *testing.T) {
	f := smbFixture(t)
	uuids := map[string]string{"alice": "uuid-a", "bob": "uuid-b", "carol": "uuid-c"}
	if err := f.h.ensurePersonIDs(smbID, persons("alice", "bob"), uuids); err != nil {
		t.Fatal(err)
	}
	alice, bob := mustPersonID(t, f.h, "alice"), mustPersonID(t, f.h, "bob")
	if alice != 20000 || bob != 20001 {
		t.Errorf("alice %d bob %d, want 20000 20001", alice, bob)
	}
	// The second instance: alice keeps hers, carol is next.
	if err := f.h.ensurePersonIDs(smbID+"-b", persons("carol", "alice"), uuids); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != alice {
		t.Errorf("alice in the second instance = %d, want %d", got, alice)
	}
	if got := mustPersonID(t, f.h, "carol"); got != 20002 {
		t.Errorf("carol = %d, want 20002", got)
	}
	// allocPersonIDs answers the same ids.
	ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("alice", "bob", "carol"), uuids)
	if err != nil {
		t.Fatal(err)
	}
	if ids["alice"] != 20000 || ids["bob"] != 20001 || ids["carol"] != 20002 {
		t.Errorf("ids = %v", ids)
	}
	// Saved in state.yaml.
	p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]
	if p.Next != 20003 || len(p.Entries) != 3 {
		t.Errorf("saved pool = %+v", p)
	}
	// A template without person_id options allocates nothing.
	if err := f.h.ensurePersonIDs("grafana", persons("dave"), map[string]string{"dave": "uuid-d"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.h.PersonID(templates.PoolPOSIXUID, "dave"); ok {
		t.Error("dave got an id from an instance without person_id options")
	}
}

func TestPersonIDWithoutUUIDLeftOut(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("alice", "bob"), map[string]string{"bob": "uuid-b"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.h.PersonID(templates.PoolPOSIXUID, "alice"); ok {
		t.Error("alice has no uuid but got an id")
	}
	if got := mustPersonID(t, f.h, "bob"); got != 20000 {
		t.Errorf("bob = %d, want 20000", got)
	}
}

func TestRecreatedAccountNewUID(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "uuid-A"}); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20000 {
		t.Fatalf("alice = %d", got)
	}
	// alice was deleted and created again: another uuid.
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "uuid-B"}); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20001 {
		t.Errorf("re-created alice = %d, want 20001", got)
	}
	p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]
	var retired, active int
	for _, e := range p.Entries {
		switch {
		case e.UUID == "uuid-A" && e.ID == 20000 && e.RetiredAt != nil:
			retired++
		case e.UUID == "uuid-B" && e.ID == 20001 && e.RetiredAt == nil:
			active++
		}
	}
	if retired != 1 || active != 1 || len(p.Entries) != 2 {
		t.Errorf("entries = %+v", p.Entries)
	}
	// 20000 is never handed out again.
	if err := f.h.ensurePersonIDs(smbID, persons("bob", "carol"), map[string]string{"bob": "b", "carol": "c"}); err != nil {
		t.Fatal(err)
	}
	if b, c := mustPersonID(t, f.h, "bob"), mustPersonID(t, f.h, "carol"); b != 20002 || c != 20003 {
		t.Errorf("bob %d carol %d, want 20002 20003", b, c)
	}
}

func TestPoolExhausted(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "uuid-A"}); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	p := f.h.st.PersonIDs[templates.PoolPOSIXUID]
	p.Next = 60000
	f.h.st.PersonIDs[templates.PoolPOSIXUID] = p
	if err := f.h.saveStateLocked(); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Unlock()
	before, _ := os.ReadFile(filepath.Join(f.data, "state.yaml"))
	// alice re-created (her entry would be retired) and bob new: neither
	// fits, nothing changes.
	err := f.h.ensurePersonIDs(smbID, persons("alice", "bob"), map[string]string{"alice": "uuid-B", "bob": "uuid-b"})
	if err == nil || !strings.Contains(err.Error(), "uid pool posix_uid is exhausted") {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.data, "state.yaml"))
	if string(before) != string(after) {
		t.Error("state.yaml changed on an exhausted pool")
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20000 {
		t.Errorf("alice = %d after the refusal (her entry was retired in memory?)", got)
	}
	f.h.mu.RLock()
	p = f.h.st.PersonIDs[templates.PoolPOSIXUID]
	f.h.mu.RUnlock()
	if p.Next != 60000 || len(p.Entries) != 1 || p.Entries[0].RetiredAt != nil {
		t.Errorf("pool in memory = %+v", p)
	}
	if _, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("bob"), map[string]string{"bob": "uuid-b"}); err == nil {
		t.Error("allocPersonIDs on an exhausted pool succeeded")
	}
}

func TestPoolSkipsCoreUIDs(t *testing.T) {
	for _, id := range []int{0, 999, 1000, 10000, 10001, 10002, 10099, 65534, 60000, 60999} {
		if !state.ReservedPersonID(id) {
			t.Errorf("%d is not reserved", id)
		}
	}
	for _, id := range []int{1001, 9999, 10100, 20000, 59999, 61000, 65533} {
		if state.ReservedPersonID(id) {
			t.Errorf("%d is reserved", id)
		}
	}
	// The real pool starts clear of every core uid.
	f := smbFixture(t)
	if r := templates.PersonIDPools[templates.PoolPOSIXUID]; r[0] != 20000 || r[1] != 59999 {
		t.Errorf("posix_uid = %v", r)
	}
	// A range overlapping the reserved set skips it.
	f.h.idRanges = map[string][2]int{templates.PoolPOSIXUID: {998, 10101}}
	users := []string{"u1", "u2", "u3", "u4"}
	uuids := map[string]string{}
	for _, u := range users {
		uuids[u] = "uuid-" + u
	}
	ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons(users...), uuids)
	if err != nil {
		t.Fatal(err)
	}
	// 998–1000 are reserved: 1001, 1002, …
	if ids["u1"] != 1001 || ids["u2"] != 1002 || ids["u3"] != 1003 || ids["u4"] != 1004 {
		t.Errorf("ids = %v", ids)
	}
	f.h.mu.Lock()
	p := f.h.st.PersonIDs[templates.PoolPOSIXUID]
	p.Next = 9999
	f.h.st.PersonIDs[templates.PoolPOSIXUID] = p
	f.h.mu.Unlock()
	ids, err = f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("u5", "u6"), map[string]string{"u5": "5", "u6": "6"})
	if err != nil {
		t.Fatal(err)
	}
	if ids["u5"] != 9999 || ids["u6"] != 10100 {
		t.Errorf("ids = %v, want 9999 then 10100 (10000-10099 skipped)", ids)
	}
	// 10101 is the last free id; after it, exhausted.
	if ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("u7"), map[string]string{"u7": "7"}); err != nil || ids["u7"] != 10101 {
		t.Fatalf("u7 = %v, %v", ids, err)
	}
	if _, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("u8"), map[string]string{"u8": "8"}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("u8 = %v, want exhausted", err)
	}
}

func TestPoolSkipsSeenOwners(t *testing.T) {
	f := smbFixture(t)
	f.h.NoteSeenOwners(templates.PoolPOSIXUID, []int{20000, 20002})
	ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("alice", "bob"), map[string]string{"alice": "a", "bob": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if ids["alice"] != 20001 || ids["bob"] != 20003 {
		t.Errorf("ids = %v, want 20001 20003 (20000 and 20002 own files)", ids)
	}
}

func TestPoolAdvancesAfterCoreRestore(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "a"}); err != nil {
		t.Fatal(err)
	}
	// The secrets-epoch check (Task 6) found a core restore.
	if err := f.h.AdvancePools(1000); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20000 {
		t.Errorf("alice = %d: an existing id never moves", got)
	}
	ids, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("bob"), map[string]string{"bob": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if ids["bob"] != 21001 {
		t.Errorf("bob = %d, want 21001 (next 20001 + 1000)", ids["bob"])
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 21002 {
		t.Errorf("saved next = %d", p.Next)
	}
}

func TestPoolAdvancesWithoutState(t *testing.T) {
	// A restored state.yaml without any pool still skips the ids files may
	// already be owned by.
	f := smbFixture(t)
	if err := f.h.AdvancePools(1000); err != nil {
		t.Fatal(err)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 21000 {
		t.Errorf("saved next = %d, want 21000", p.Next)
	}
}

func TestPersonIDsSurviveRestore(t *testing.T) {
	f, _, _ := grafanaB(t)
	if _, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("alice", "bob"), map[string]string{"alice": "a", "bob": "b"}); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("grafana-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, "root"); err != nil {
		t.Fatal(err)
	}
	if a, b := mustPersonID(t, f.h, "alice"), mustPersonID(t, f.h, "bob"); a != 20000 || b != 20001 {
		t.Errorf("after restores alice %d bob %d", a, b)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 20002 || len(p.Entries) != 2 {
		t.Errorf("state.yaml pool = %+v", p)
	}
	// The pools are never in an instance archive.
	data, err := os.ReadFile(archivePath(f, entry.Archive))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "person_ids") {
		t.Error("the instance archive carries person_ids")
	}
}
