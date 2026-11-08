package hub

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUserSweepRetryInterval(t *testing.T) {
	// The retry interval is accessible for the scheduler.
	if SweepRetryInterval() != time.Minute {
		t.Errorf("retry interval = %v, want 1 minute", SweepRetryInterval())
	}
}

func TestUserSweepSkipSetsSkippedSince(t *testing.T) {
	f, ll, kc := newSweep(t)
	ll.err = errors.New("connection refused")

	// First skip: SkippedSince is set.
	before := time.Now().UTC()
	if f.h.RunUserSweep(context.Background()) {
		t.Fatal("swept with LLDAP down")
	}
	st := f.h.UserSweep()
	if st.Skipped == "" || st.SkippedSince.IsZero() {
		t.Fatalf("first skip: status = %+v", st)
	}
	if st.SkippedSince.Before(before) || st.SkippedSince.After(time.Now().UTC().Add(time.Second)) {
		t.Errorf("SkippedSince out of range: %v", st.SkippedSince)
	}
	firstSkip := st.SkippedSince

	// Subsequent skips: SkippedSince unchanged.
	time.Sleep(10 * time.Millisecond)
	if f.h.RunUserSweep(context.Background()) {
		t.Fatal("swept with LLDAP still down")
	}
	st = f.h.UserSweep()
	if st.SkippedSince != firstSkip {
		t.Errorf("SkippedSince changed: %v -> %v", firstSkip, st.SkippedSince)
	}

	// Success clears SkippedSince.
	ll.err = nil
	if !f.h.RunUserSweep(context.Background()) || kc.count() != 1 {
		t.Fatal("not swept after LLDAP came back")
	}
	st = f.h.UserSweep()
	if st.Skipped != "" || !st.SkippedSince.IsZero() {
		t.Errorf("skip not cleared: %+v", st)
	}
}

func TestUserSweepPauseClearsSkipped(t *testing.T) {
	f, ll, _ := newSweep(t)
	// Start with a skip.
	ll.err = errors.New("connection refused")
	f.h.RunUserSweep(context.Background())
	st := f.h.UserSweep()
	if st.Skipped == "" || st.SkippedSince.IsZero() {
		t.Fatalf("skip not set: %+v", st)
	}

	// A pause (missing account) clears the skip.
	ll.err = nil
	ll.set(people(18)[1:]...) // no admin
	f.h.RunUserSweep(context.Background())
	st = f.h.UserSweep()
	if !st.Paused || st.Skipped != "" || !st.SkippedSince.IsZero() {
		t.Errorf("pause didn't clear skip: %+v", st)
	}
}

func TestUserSweepSkipNeverSetsPaused(t *testing.T) {
	f, ll, _ := newSweep(t)
	ll.err = errors.New("connection refused")
	for i := 0; i < 5; i++ {
		if f.h.RunUserSweep(context.Background()) {
			t.Fatal("swept with LLDAP down")
		}
		st := f.h.UserSweep()
		if st.Paused {
			t.Errorf("skip set Paused: %+v", st)
		}
	}
}

func TestUserSweepStatusJSON(t *testing.T) {
	f, ll, _ := newSweep(t)
	ll.err = errors.New("connection refused")
	f.h.RunUserSweep(context.Background())
	st := f.h.UserSweep()

	// The status has all the fields.
	if st.Skipped == "" {
		t.Error("Skipped not set")
	}
	if st.SkippedSince.IsZero() {
		t.Error("SkippedSince not set")
	}
	if st.Paused {
		t.Error("Paused incorrectly set")
	}
	if !st.Configured {
		t.Error("Configured not set")
	}
}
