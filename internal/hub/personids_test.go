package hub

import (
	"github.com/portcullis/hub/internal/directory"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// PersonID is user's current id in pool whatever its uuid (tests only:
// production code reads ids through personIDForLocked, B-M5).
func (h *Hub) PersonID(pool, user string) (int, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, e := range h.st.PersonIDs[pool].Entries {
		if e.User == user && e.RetiredAt == nil {
			return e.ID, true
		}
	}
	return 0, false
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
	if err := f.h.NoteSeenOwners(templates.PoolPOSIXUID, []int{20000, 20002}); err != nil {
		t.Fatal(err)
	}
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
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); err != nil {
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

// Fix round 1 #1: the same uuid is the same LLDAP account: it gets its
// own entry and id back, never a second entry.
func TestRestoredUUIDReactivates(t *testing.T) {
	f := smbFixture(t)
	for _, u := range []string{"uuid-A", "uuid-B"} {
		if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": u}); err != nil {
			t.Fatal(err)
		}
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20001 {
		t.Fatalf("alice/B = %d", got)
	}
	// LLDAP says alice = A again (e.g. an LLDAP restore).
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "uuid-A"}); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20000 {
		t.Errorf("alice/A again = %d, want her own 20000", got)
	}
	st := loadState(t, f) // Save → Load round trip: nothing Load refuses
	p := st.PersonIDs[templates.PoolPOSIXUID]
	if len(p.Entries) != 2 || p.Next != 20002 {
		t.Fatalf("pool = %+v", p)
	}
	for _, e := range p.Entries {
		if (e.UUID == "uuid-A") != (e.RetiredAt == nil) {
			t.Errorf("entry %+v: A active, B retired expected", e)
		}
	}
	// A uuid already held under another name gets nothing.
	if err := f.h.ensurePersonIDs(smbID, persons("bob"), map[string]string{"bob": "uuid-A"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.h.PersonID(templates.PoolPOSIXUID, "bob"); ok {
		t.Error("bob got an id with alice's uuid")
	}
	loadState(t, f)
}

// The allocator never writes what Load refuses: names are lowercased and
// a uuid with control characters gets no id.
func TestPersonIDInputsNormalised(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("Alice", "bob", ""), map[string]string{"Alice": "a", "bob": "b\n", "": "x"}); err != nil {
		t.Fatal(err)
	}
	if got := mustPersonID(t, f.h, "alice"); got != 20000 {
		t.Errorf("alice = %d", got)
	}
	if _, ok := f.h.PersonID(templates.PoolPOSIXUID, "bob"); ok {
		t.Error("bob's uuid has a newline but he got an id")
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; len(p.Entries) != 1 || p.Entries[0].User != "alice" {
		t.Errorf("entries = %+v", p.Entries)
	}
}

// Fix round 1 #2: one advance per process.
func TestAdvancePoolsOnce(t *testing.T) {
	f := smbFixture(t)
	for range 2 {
		if err := f.h.AdvancePools(PoolRewindStep); err != nil {
			t.Fatal(err)
		}
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 21000 {
		t.Errorf("next = %d after two calls, want 21000 (one advance)", p.Next)
	}
}

// Fix round 1 #4: by is bounded and next stops at range end + 1.
func TestAdvancePoolsBounded(t *testing.T) {
	f := smbFixture(t)
	for _, by := range []int{0, -1, maxPoolAdvance + 1} {
		if err := f.h.AdvancePools(by); err == nil {
			t.Errorf("AdvancePools(%d) accepted", by)
		}
	}
	f.h.mu.Lock()
	f.h.st.PersonIDs[templates.PoolPOSIXUID] = state.PersonIDPool{Next: 59500}
	f.h.mu.Unlock()
	if err := f.h.AdvancePools(PoolRewindStep); err != nil {
		t.Fatal(err)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 60000 {
		t.Errorf("next = %d, want 60000 (range end + 1)", p.Next)
	}
	if _, err := f.h.allocPersonIDs(templates.PoolPOSIXUID, persons("x"), map[string]string{"x": "x"}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("alloc after cap = %v", err)
	}
}

// Fix round 1 #3: a failed save changes nothing in memory.
func TestPersonIDFailedSave(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.ensurePersonIDs(smbID, persons("alice"), map[string]string{"alice": "uuid-A"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.data, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.data, 0755) })
	err := f.h.ensurePersonIDs(smbID, persons("alice", "bob"), map[string]string{"alice": "uuid-B", "bob": "b"})
	os.Chmod(f.data, 0755)
	if err == nil {
		t.Fatal("ensurePersonIDs with a failing save succeeded")
	}
	f.h.mu.RLock()
	p := f.h.st.PersonIDs[templates.PoolPOSIXUID]
	f.h.mu.RUnlock()
	if p.Next != 20001 || len(p.Entries) != 1 || p.Entries[0].RetiredAt != nil || p.Entries[0].UUID != "uuid-A" {
		t.Errorf("pool in memory after a failed save = %+v", p)
	}
	if err := f.h.NoteSeenOwners(templates.PoolPOSIXUID, []int{20005}); err != nil {
		t.Fatal(err)
	}
	os.Chmod(f.data, 0500)
	if err := f.h.AdvancePools(PoolRewindStep); err == nil {
		t.Error("AdvancePools with a failing save succeeded")
	}
	os.Chmod(f.data, 0755)
	f.h.mu.RLock()
	p = f.h.st.PersonIDs[templates.PoolPOSIXUID]
	f.h.mu.RUnlock()
	if p.Next != 20001 || len(p.Seen) != 1 {
		t.Errorf("pool after a failed advance = %+v", p)
	}
	// The failed advance didn't count: it may run again.
	if err := f.h.AdvancePools(PoolRewindStep); err != nil {
		t.Fatal(err)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next != 21001 {
		t.Errorf("next = %d", p.Next)
	}
}

// Fix round 1 #5: concurrent allocations hand out distinct ids.
func TestEnsurePersonIDsConcurrent(t *testing.T) {
	f := smbFixture(t)
	uuids := map[string]string{}
	var a, b []string
	for i := range 40 {
		u := fmt.Sprintf("u%02d", i)
		uuids[u] = "uuid-" + u
		if i < 30 {
			a = append(a, u)
		}
		if i >= 10 {
			b = append(b, u)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for id, users := range map[string][]string{smbID: a, smbID + "-b": b} {
		wg.Go(func() { errs <- f.h.ensurePersonIDs(id, persons(users...), uuids) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int]string{}
	for u := range uuids {
		id := mustPersonID(t, f.h, u)
		if other, dup := seen[id]; dup {
			t.Errorf("%s and %s share %d", u, other, id)
		}
		seen[id] = u
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; len(p.Entries) != 40 || p.Next != 20040 {
		t.Errorf("pool = next %d, %d entries", p.Next, len(p.Entries))
	}
}

// Fix round 1 #6: seen owners are persisted, bounded and skipped after a
// restart.
func TestSeenOwnersPersist(t *testing.T) {
	f := smbFixture(t)
	if err := f.h.NoteSeenOwners(templates.PoolPOSIXUID, []int{20002, 20000, 20002, 5, 10001, 70000}); err != nil {
		t.Fatal(err)
	}
	p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]
	if len(p.Seen) != 2 || p.Seen[0].ID != 20000 || p.Seen[1].ID != 20002 {
		t.Fatalf("seen = %+v (sorted, deduplicated, only in range)", p.Seen)
	}
	if err := f.h.NoteSeenOwners("nope", []int{20000}); err == nil {
		t.Error("an unknown pool accepted")
	}
	h := reopen(t, f)
	ids, err := h.allocPersonIDs(templates.PoolPOSIXUID, persons("alice", "bob"), map[string]string{"alice": "a", "bob": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if ids["alice"] != 20001 || ids["bob"] != 20003 {
		t.Errorf("after a restart ids = %v, want 20001 20003", ids)
	}
	// At most maxSeenOwners: the oldest go.
	var many []int
	for i := range state.MaxSeenOwners {
		many = append(many, 30000+i)
	}
	if err := h.NoteSeenOwners(templates.PoolPOSIXUID, many); err != nil {
		t.Fatal(err)
	}
	p = loadState(t, f).PersonIDs[templates.PoolPOSIXUID]
	if len(p.Seen) != state.MaxSeenOwners {
		t.Fatalf("%d seen owners kept", len(p.Seen))
	}
	if p.Seen[0].ID == 20000 || p.Seen[0].ID == 20002 {
		t.Errorf("the oldest seen owners were kept: first %+v", p.Seen[0])
	}
}
