package hub

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
)

// fakeFreshAuth answers every proof with err (nil: alice, now).
type fakeFreshAuth struct {
	err   error
	calls atomic.Int32
}

func (f *fakeFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &freshauth.Result{User: user, AuthTime: time.Now(), AMR: []string{"hwk"}}, nil
}

func (f *fakeFreshAuth) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{AuthorizeURL: "https://auth.example.org/a", ClientID: freshauth.ClientID, RedirectURI: "https://people.example.org/"}
}

var testProof = freshauth.Proof{Code: "the-code", CodeVerifier: "the-verifier", Nonce: "the-nonce"}

// Every fresh-auth failure is a 403 with the generic text; the reason is
// returned for the audit only and never carries the proof.
func TestCheckFreshAuth(t *testing.T) {
	f := newFixture(t)
	// Not configured: refused (fail closed), never a pass.
	if _, reason, err := f.h.checkFreshAuth(context.Background(), testProof, "alice"); statusOf(err) != 403 || err.Error() != freshauth.Message || reason == "" {
		t.Errorf("unconfigured: %v (%q)", err, reason)
	}
	if f.h.FreshAuthInfo() != nil {
		t.Error("Info without a verifier")
	}
	fa := &fakeFreshAuth{}
	f.h.SetFreshAuth(fa)
	f.h.freshAuthReady.Store(true) // the client is in place
	if info := f.h.FreshAuthInfo(); info == nil || info.ClientID != freshauth.ClientID {
		t.Errorf("FreshAuthInfo = %+v", info)
	}
	res, _, err := f.h.checkFreshAuth(context.Background(), testProof, "Alice")
	if err != nil || res.User != "alice" {
		t.Fatalf("accepted proof: %+v, %v", res, err)
	}
	for _, e := range []error{&freshauth.Error{Reason: "nonce mismatch"}, errors.New("unexpected: the-code the-verifier the-nonce")} {
		fa.err = e
		_, reason, err := f.h.checkFreshAuth(context.Background(), testProof, "alice")
		if statusOf(err) != 403 || err.Error() != freshauth.Message {
			t.Errorf("%v: answered %d %q", e, statusOf(err), err)
		}
		for _, s := range []string{testProof.Code, testProof.CodeVerifier, testProof.Nonce} {
			if strings.Contains(reason, s) {
				t.Errorf("reason %q carries the proof", reason)
			}
		}
		if reason == "" {
			t.Error("no reason")
		}
	}
}

// F45: a refused proof is a 4xx, so it counts toward the people
// listener's per-caller refusal limit (shared with value saves): ten in a
// minute and the caller's next save is a 429.
func TestFreshAuthRefusalsCountTowardLimit(t *testing.T) {
	f, _, _, _ := entryFixture(t)
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	f.h.entryNow = func() time.Time { return now }
	f.h.SetFreshAuth(&fakeFreshAuth{err: &freshauth.Error{Reason: "stale"}})
	f.h.freshAuthReady.Store(true)
	for i := range entryRefusalLimit {
		if !f.h.entryLimit.reserve("alice", f.h.entryClock()) {
			t.Fatalf("limited after %d refusals", i)
		}
		_, _, err := f.h.checkFreshAuth(context.Background(), testProof, "alice")
		f.h.entryLimit.release("alice", f.h.entryClock(), isRefusal(err))
	}
	if _, err := setEntry(f, entryID, "ext_id", "alice", aliceExt, "alice"); statusOf(err) != 429 {
		t.Errorf("after ten refused proofs = %v, want 429", err)
	}
}

// The directory sync loop ensures the fresh-auth client at start and on
// every sync, next to the attribute mappers; its failure blocks nothing.
func TestRunDirectorySyncEnsuresFreshAuthClient(t *testing.T) {
	f := newFixture(t)
	var syncs, ensures atomic.Int32
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, nil
	}, func(context.Context) error { syncs.Add(1); return nil })
	f.h.SetFreshAuthClient(func(context.Context) error { ensures.Add(1); return errors.New("keycloak down") })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunDirectorySync(ctx); close(done) }()
	waitFor := func(n int32) {
		t.Helper()
		for i := 0; i < 500 && (ensures.Load() < n || syncs.Load() < n); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if ensures.Load() < n || syncs.Load() < n {
			t.Fatalf("ensures %d syncs %d, want %d", ensures.Load(), syncs.Load(), n)
		}
	}
	waitFor(1)
	f.h.TriggerDirectorySync()
	waitFor(2)
	cancel()
	<-done
}

// Review fix 1: until the fresh-auth client is in place (the last ensure
// succeeded), every proof is refused, even one a verifier would accept: a
// conflicting (untagged or foreign) client must fail closed.
func TestFreshAuthRefusedUntilClientInPlace(t *testing.T) {
	f := newFixture(t)
	f.h.SetFreshAuth(&fakeFreshAuth{}) // accepts everything
	var ensureErr atomic.Value
	ensureErr.Store(errBox{&keycloak.ConflictError{ClientID: freshauth.ClientID}})
	var ensures atomic.Int32
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, nil
	}, nil)
	f.h.SetFreshAuthClient(func(context.Context) error { ensures.Add(1); return ensureErr.Load().(errBox).err })
	check := func(label string, wantOK bool) {
		t.Helper()
		_, reason, err := f.h.checkFreshAuth(context.Background(), testProof, "alice")
		// The flag is stored right after the ensure returns: wait for it.
		for i := 0; i < 500 && (err == nil) != wantOK; i++ {
			time.Sleep(10 * time.Millisecond)
			_, reason, err = f.h.checkFreshAuth(context.Background(), testProof, "alice")
		}
		if wantOK && err != nil {
			t.Errorf("%s: refused: %v (%s)", label, err, reason)
		}
		if !wantOK && (statusOf(err) != 403 || err.Error() != freshauth.Message || reason != "fresh-auth client not in place" || !isRefusal(err)) {
			t.Errorf("%s: %v (%q), want the 403 with reason \"fresh-auth client not in place\"", label, err, reason)
		}
	}
	check("before any ensure", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunDirectorySync(ctx); close(done) }()
	waitEnsures := func(n int32) {
		t.Helper()
		for i := 0; i < 500 && ensures.Load() < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if ensures.Load() < n {
			t.Fatalf("ensures %d, want %d", ensures.Load(), n)
		}
	}
	waitEnsures(1)
	check("ensure answered *ConflictError", false)
	ensureErr.Store(errBox{nil})
	f.h.TriggerDirectorySync()
	waitEnsures(2)
	check("after a nil ensure", true)
	ensureErr.Store(errBox{errors.New("keycloak down")})
	f.h.TriggerDirectorySync()
	waitEnsures(3)
	check("after a later failed ensure", false)
	cancel()
	<-done
}

type errBox struct{ err error }
