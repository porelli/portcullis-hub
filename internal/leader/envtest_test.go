//go:build envtest

package leader

// Envtest (KUBEBUILDER_ASSETS from `setup-envtest use 1.33.x`): two
// fences on one real Lease, the contract's timings, real clocks.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// cuttable is a transport that fails every request once cut (the
// leader's node losing the API server).
type cuttable struct {
	next http.RoundTripper
	cut  *atomic.Bool
}

func (c cuttable) RoundTrip(r *http.Request) (*http.Response, error) {
	if c.cut.Load() {
		return nil, errors.New("network unreachable")
	}
	return c.next.RoundTrip(r)
}

// TestSecondHubNeverWrites: two Hubs on the Lease `portcullis-hub` (as
// the chart creates it: no spec); the first leads, its connection is cut
// at 20 s. Sampled over 60 s, never both may write; the second leads only
// LeaseDuration after the first's last renewal, and only after the first
// stood by.
func TestSecondHubNeverWrites(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer te.Stop()
	admin, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := admin.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "portcullis"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.CoordinationV1().Leases("portcullis").Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: "portcullis-hub"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	fence := func(identity string, cut *atomic.Bool) *Fence {
		c := rest.CopyConfig(cfg)
		c.Wrap(func(rt http.RoundTripper) http.RoundTripper { return cuttable{next: rt, cut: cut} })
		cs, err := kubernetes.NewForConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		return New(Config{Client: cs, Namespace: "portcullis", Name: "portcullis-hub", Identity: identity})
	}
	var cutA, cutB atomic.Bool
	a, b := fence("portcullis-hub-a", &cutA), fence("portcullis-hub-b", &cutB)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Run(ctx) }()
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := a.WaitLeading(wctx); err != nil {
		t.Fatalf("a never led: %v", err)
	}
	wg.Add(1)
	go func() { defer wg.Done(); b.Run(ctx) }()

	start := time.Now()
	var cutAt, aLastRenew, aStoodBy, bLed time.Time
	for time.Since(start) < 60*time.Second {
		if cutAt.IsZero() && time.Since(start) >= 20*time.Second {
			cutA.Store(true)
			cutAt = time.Now()
		}
		aOK, bOK := a.Check() == nil, b.Check() == nil
		now := time.Now()
		if aOK && bOK {
			t.Fatalf("both Hubs may write at %s", now.Sub(start))
		}
		if !cutAt.IsZero() && !aOK && aStoodBy.IsZero() {
			aStoodBy = now
		}
		if bOK && bLed.IsZero() {
			bLed = now
		}
		if cutAt.IsZero() && bOK {
			t.Fatalf("b led at %s while a still renewed", now.Sub(start))
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	// a's last successful renewal (one in flight at the cut may still
	// have landed after it).
	a.mu.Lock()
	aLastRenew = a.renewed
	a.mu.Unlock()
	if aStoodBy.IsZero() || bLed.IsZero() {
		t.Fatalf("a stood by at %v, b led at %v", aStoodBy, bLed)
	}
	if d := aStoodBy.Sub(aLastRenew); d > DefaultRenewDeadline+time.Second { // the sampling's lag
		t.Errorf("a stood by %s after its last renewal, want ≤ %s", d, DefaultRenewDeadline)
	}
	if d := bLed.Sub(aLastRenew); d < DefaultLeaseDuration {
		t.Errorf("b led %s after a's last renewal, want ≥ %s", d, DefaultLeaseDuration)
	}
	if !bLed.After(aStoodBy) {
		t.Error("b led before a stood by")
	}
	t.Logf("cut at %s; a stood by %s after its last renewal; b led %s after it",
		cutAt.Sub(start), aStoodBy.Sub(aLastRenew), bLed.Sub(aLastRenew))
}
