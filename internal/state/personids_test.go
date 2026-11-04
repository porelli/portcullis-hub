package state

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func goodPool() PersonIDPool {
	at := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	return PersonIDPool{Next: 20003, Entries: []PersonIDEntry{
		{User: "alice", UUID: "uuid-a", ID: 20000, RetiredAt: &at},
		{User: "alice", UUID: "uuid-a2", ID: 20001},
		{User: "bob", UUID: "uuid-b", ID: 20002},
	}}
}

// A corrupt person_ids pool stops the Hub at start, like folders.
func TestLoadRefusesCorruptPersonIDs(t *testing.T) {
	for name, mut := range map[string]func(p *PersonIDPool) string{
		"unknown pool":     func(p *PersonIDPool) string { return "gid_pool" },
		"next below range": func(p *PersonIDPool) string { p.Next = 100; p.Entries = nil; return "" },
		"id out of range":  func(p *PersonIDPool) string { p.Entries[2].ID = 60000; p.Next = 60001; return "" },
		"id reserved":      func(p *PersonIDPool) string { p.Entries[2].ID = 10001; return "" },
		"id not below next": func(p *PersonIDPool) string {
			p.Next = 20002
			return ""
		},
		"duplicate id":    func(p *PersonIDPool) string { p.Entries[2].ID = 20001; return "" },
		"two active":      func(p *PersonIDPool) string { p.Entries[0].RetiredAt = nil; return "" },
		"no uuid":         func(p *PersonIDPool) string { p.Entries[2].UUID = ""; return "" },
		"upper-case user": func(p *PersonIDPool) string { p.Entries[2].User = "Bob"; return "" },
		"empty user":      func(p *PersonIDPool) string { p.Entries[2].User = ""; return "" },
		"uuid reused":     func(p *PersonIDPool) string { p.Entries[2].UUID = "uuid-a2"; return "" },
	} {
		p := goodPool()
		pool := mut(&p)
		if pool == "" {
			pool = "posix_uid"
		}
		s := New()
		s.PersonIDs = map[string]PersonIDPool{pool: p}
		path := filepath.Join(t.TempDir(), "state.yaml")
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "corrupt") || !strings.Contains(err.Error(), "person_ids") {
			t.Errorf("%s: Load = %v, want a refusal", name, err)
		}
	}
	// The good one loads and round-trips.
	s := New()
	s.PersonIDs = map[string]PersonIDPool{"posix_uid": goodPool()}
	path := filepath.Join(t.TempDir(), "state.yaml")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("good pool: %v", err)
	}
	if p := got.PersonIDs["posix_uid"]; p.Next != 20003 || len(p.Entries) != 3 || p.Entries[0].RetiredAt == nil {
		t.Errorf("round trip = %+v", p)
	}
	// An advanced next beyond the range is an exhausted pool, not corrupt.
	s.PersonIDs = map[string]PersonIDPool{"posix_uid": {Next: 61000}}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("advanced next: %v", err)
	}
}

func TestReservedPersonID(t *testing.T) {
	for _, id := range []int{0, 999, 1000, 10000, 10099, 65534, 60000, 60999} {
		if !ReservedPersonID(id) {
			t.Errorf("%d not reserved", id)
		}
	}
	for _, id := range []int{1001, 10100, 20000, 59999, 61000} {
		if ReservedPersonID(id) {
			t.Errorf("%d reserved", id)
		}
	}
}
