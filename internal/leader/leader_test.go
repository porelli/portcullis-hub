package leader

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/portcullis/hub/internal/fsutil"
)

const testNS = "portcullis"

// rig is a fake cluster holding the chart's Lease (no spec, contract
// §20.5) whose updates can be cut, and a fence on it with a fake clock.
type rig struct {
	cs    *fake.Clientset
	clock *clocktesting.FakeClock
	f     *Fence
	cut   atomic.Bool
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		cs:    fake.NewSimpleClientset(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "portcullis-hub", Namespace: testNS}}),
		clock: clocktesting.NewFakeClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)),
	}
	r.cs.PrependReactor("*", "leases", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		if r.cut.Load() {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})
	r.f = New(Config{Client: r.cs, Namespace: testNS, Name: "portcullis-hub", Identity: "portcullis-hub-0",
		LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second, Clock: r.clock})
	return r
}

// lead runs the fence until it leads (the fake clock stands still: the
// renewal recorded is at the clock's t0).
func (r *rig) lead(t *testing.T) time.Time {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.f.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := r.f.WaitLeading(wctx); err != nil {
		t.Fatalf("WaitLeading = %v", err)
	}
	// Cut every later renewal: the last successful one is at t0.
	r.cut.Store(true)
	return r.clock.Now()
}

func TestCheckStandsByAfterRenewDeadline(t *testing.T) {
	r := newRig(t)
	if err := r.f.Check(); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("Check before leading = %v, want ErrStandingBy", err)
	}
	t0 := r.lead(t)
	if err := r.f.Check(); err != nil {
		t.Fatalf("Check at t0 = %v", err)
	}
	r.clock.SetTime(t0.Add(9900 * time.Millisecond))
	if err := r.f.Check(); err != nil {
		t.Fatalf("Check at t0+9.9s = %v", err)
	}
	r.clock.SetTime(t0.Add(10 * time.Second))
	if err := r.f.Check(); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("Check at t0+10s = %v, want ErrStandingBy", err)
	}
	if r.f.Leading() {
		t.Error("Leading at t0+10s")
	}
	if ErrStandingBy.Error() != "this Hub is standing by: another Hub is the active writer" {
		t.Errorf("ErrStandingBy = %q", ErrStandingBy)
	}
}

func TestAlwaysLeads(t *testing.T) {
	f := Always()
	if err := f.Check(); err != nil {
		t.Fatalf("Always().Check() = %v", err)
	}
	if err := f.WaitLeading(context.Background()); err != nil {
		t.Fatalf("WaitLeading = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	select {
	case <-done:
		t.Fatal("Always().Run returned before its context ended")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	<-done
	if err := f.Check(); err != nil || !f.Leading() {
		t.Errorf("after Run: Check = %v", err)
	}
}

// TestNoLeaseNoWrite (fail closed): a fence that never got its Lease
// refuses every write through the gate; with no fence at all (Docker,
// Podman: no gate set) writes go on as before.
func TestNoLeaseNoWrite(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("*", "leases", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	f := New(Config{Client: cs, Namespace: testNS, Name: "portcullis-hub", Identity: "portcullis-hub-0"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go f.Run(ctx)
	if err := f.WaitLeading(ctx); err == nil {
		t.Fatal("led without a Lease")
	}
	p := filepath.Join(t.TempDir(), "state.yaml")
	fsutil.SetWriteGate(f.Check)
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	if err := fsutil.WriteFileAtomic(p, []byte("x"), 0o600); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("write without the Lease = %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("a file was written: %v", err)
	}
	fsutil.SetWriteGate(nil)
	if err := fsutil.WriteFileAtomic(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("write with no gate (Docker) = %v", err)
	}
}

func TestDefaultTimings(t *testing.T) {
	f := New(Config{Client: fake.NewSimpleClientset(), Namespace: testNS, Name: "portcullis-hub", Identity: "p"})
	if f.cfg.LeaseDuration != 15*time.Second || f.cfg.RenewDeadline != 10*time.Second || f.cfg.RetryPeriod != 2*time.Second {
		t.Errorf("timings %v %v %v", f.cfg.LeaseDuration, f.cfg.RenewDeadline, f.cfg.RetryPeriod)
	}
}

// TestLeaseLostStopsInflightWrites: an op writes every 100 ms (of the
// fence's clock); renewals stop at t0; no write lands from t0+10 s on,
// and the op ends with ErrStandingBy, recorded in memory only.
func TestLeaseLostStopsInflightWrites(t *testing.T) {
	r := newRig(t)
	t0 := r.lead(t)
	fsutil.SetWriteGate(r.f.Check)
	t.Cleanup(func() { fsutil.SetWriteGate(nil) })
	p := filepath.Join(t.TempDir(), "op.json")

	type opRecord struct {
		writes int
		err    error
	}
	tick := make(chan int)
	done := make(chan opRecord)
	go func() { // the background op
		var rec opRecord
		for i := range tick {
			if err := fsutil.WriteFileAtomic(p, fmt.Appendf(nil, "write %d", i), 0o600); err != nil {
				rec.err = err // in memory: the op can't write its own record
				done <- rec
				return
			}
			rec.writes++
			done <- rec
		}
	}()
	var last opRecord
	for i := 1; i <= 150; i++ {
		r.clock.SetTime(t0.Add(time.Duration(i) * 100 * time.Millisecond))
		tick <- i
		last = <-done
		if last.err != nil {
			break
		}
	}
	close(tick)
	if !errors.Is(last.err, ErrStandingBy) {
		t.Fatalf("op error = %v, want ErrStandingBy", last.err)
	}
	// Writes at t0+0.1s … t0+9.9s landed (99), the one at t0+10s didn't.
	if last.writes != 99 {
		t.Errorf("writes = %d, want 99", last.writes)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(b) != sha256.Sum256([]byte("write 99")) {
		t.Errorf("file = %q, want the t0+9.9s write", b)
	}
	// Later, nothing lands either.
	r.clock.SetTime(t0.Add(time.Minute))
	if err := fsutil.WriteFileAtomic(p, []byte("late"), 0o600); !errors.Is(err, ErrStandingBy) {
		t.Errorf("late write = %v", err)
	}
	if b2, _ := os.ReadFile(p); string(b2) != string(b) {
		t.Errorf("file changed to %q", b2)
	}
}
