// Package leader is the Hub's write fence (contract §20.5): on
// Kubernetes the Hub writes only while it holds the Lease
// `portcullis-hub`, taken and renewed with client-go's leaderelection.
// The fence answers "standing by" once its last successful renewal is
// older than the RenewDeadline, measured locally on a monotonic clock,
// before client-go's own callback fires. On Docker and Podman the Hub
// always leads (Always).
package leader

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/clock"
)

// ErrStandingBy is the fence's answer while another Hub may be writing.
var ErrStandingBy = errors.New("this Hub is standing by: another Hub is the active writer")

// The contract's timings (§20.5).
const (
	DefaultLeaseDuration = 15 * time.Second
	DefaultRenewDeadline = 10 * time.Second
	DefaultRetryPeriod   = 2 * time.Second
)

// Config is a fence on one Lease. Zero timings are the contract's; a nil
// Clock is the real (monotonic) clock.
type Config struct {
	Client                                    kubernetes.Interface
	Namespace, Name, Identity                 string
	LeaseDuration, RenewDeadline, RetryPeriod time.Duration
	// Clock measures the renewals' age and ticks the watchdog (tests: a
	// fake clock).
	Clock clock.WithTicker
}

// Fence tells whether this process may write now.
type Fence struct {
	cfg    Config
	always bool

	mu      sync.Mutex
	renewed time.Time          // when the last successful renewal was sent (zero: never)
	lost    bool               // stood by after leading, or the elector ended: never leads again
	cancel  context.CancelFunc // the elector's context (nil before Run)
	leading chan struct{}      // closed at the first renewal
	once    sync.Once
	lostCh  chan struct{} // closed when lost is set
	lostOne sync.Once
}

// New is a fence on cfg's Lease; it leads only once Run took the Lease.
func New(cfg Config) *Fence {
	if cfg.LeaseDuration == 0 {
		cfg.LeaseDuration = DefaultLeaseDuration
	}
	if cfg.RenewDeadline == 0 {
		cfg.RenewDeadline = DefaultRenewDeadline
	}
	if cfg.RetryPeriod == 0 {
		cfg.RetryPeriod = DefaultRetryPeriod
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.RealClock{}
	}
	return &Fence{cfg: cfg, leading: make(chan struct{}), lostCh: make(chan struct{})}
}

// Always is the fence of a Hub with no Lease (Docker, Podman): it always
// leads.
func Always() *Fence {
	f := &Fence{always: true, leading: make(chan struct{}), lostCh: make(chan struct{})}
	close(f.leading)
	return f
}

// Check is nil while this Hub may write, else ErrStandingBy: before the
// Lease was taken, and for good from the moment the last successful
// renewal is RenewDeadline old or the elector ended. Stand-by is final:
// a renewal that still succeeds later never reopens the fence (the
// Hub's memory may already disagree with its disk: only a restart leads
// again), and the elector is cancelled so Run returns.
func (f *Fence) Check() error {
	if f.always {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost || f.renewed.IsZero() {
		return ErrStandingBy
	}
	if f.cfg.Clock.Since(f.renewed) >= f.cfg.RenewDeadline {
		f.loseLocked()
		return ErrStandingBy
	}
	return nil
}

// Lost is closed the moment the fence stands by after leading (or its
// elector ended): the Hub cancels its background work and every long
// writer on it. Never closed for Always.
func (f *Fence) Lost() <-chan struct{} { return f.lostCh }

// loseLocked makes stand-by final (f.mu held).
func (f *Fence) loseLocked() {
	f.lost = true
	if f.cancel != nil {
		f.cancel()
	}
	f.lostOne.Do(func() { close(f.lostCh) })
}

// Leading reports Check() == nil.
func (f *Fence) Leading() bool { return f.Check() == nil }

// WaitLeading blocks until the fence first leads (nil) or ctx ends (its
// error).
func (f *Fence) WaitLeading(ctx context.Context) error {
	select {
	case <-f.leading:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LeaseDuration is how long another Hub waits after the last renewal it
// saw before it takes the Lease.
func (f *Fence) LeaseDuration() time.Duration { return f.cfg.LeaseDuration }

// Run takes the Lease and renews it until ctx ends or the fence stands
// by (a renewal RenewDeadline old: the elector is cancelled at once, the
// Lease left to expire); the fence then stands by for good. Always's Run
// waits for ctx.
func (f *Fence) Run(ctx context.Context) {
	if f.always {
		<-ctx.Done()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()
	defer f.stop()
	// The watchdog: the deadline is enforced even when nothing asks
	// Check (Lost closes, the elector is cancelled, at renewal + 10 s).
	// One ticker, made before the elector can lead: it is never between
	// two timers when the clock moves on (a fresh After per tick missed
	// a fake clock's step taken in that gap).
	tick := f.cfg.Clock.NewTicker(watchEvery)
	go func() {
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C():
				f.Check()
			}
		}
	}()
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          f.newLock(),
		LeaseDuration: f.cfg.LeaseDuration,
		RenewDeadline: f.cfg.RenewDeadline,
		RetryPeriod:   f.cfg.RetryPeriod,
		// Never released: a Hub that stops leaves the Lease to expire, so
		// a successor waits a full LeaseDuration after the last write.
		ReleaseOnCancel: false,
		Name:            f.cfg.Name,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(context.Context) {
				log.Printf("leader: holding the Lease %s/%s as %s", f.cfg.Namespace, f.cfg.Name, f.cfg.Identity)
			},
			OnStoppedLeading: func() {},
		},
	})
	if err != nil {
		log.Printf("leader: %v: standing by", err)
		return
	}
	le.Run(ctx)
}

// watchEvery is how often the watchdog asks Check.
const watchEvery = 100 * time.Millisecond

// newLock is the Lease lock timing this fence's renewals.
func (f *Fence) newLock() *fenceLock {
	return &fenceLock{
		LeaseLock: &resourcelock.LeaseLock{
			LeaseMeta:  metav1.ObjectMeta{Namespace: f.cfg.Namespace, Name: f.cfg.Name},
			Client:     f.cfg.Client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{Identity: f.cfg.Identity},
		},
		f: f,
	}
}

// stop: the elector ended; never lead again in this process.
func (f *Fence) stop() {
	f.mu.Lock()
	f.loseLocked()
	f.mu.Unlock()
}

// renewedAt records a successful acquire or renewal sent at start.
func (f *Fence) renewedAt(start time.Time) {
	f.mu.Lock()
	if !f.lost {
		f.renewed = start
	}
	f.mu.Unlock()
	f.once.Do(func() { close(f.leading) })
}

// fenceLock is the LeaseLock, timing each successful write of a record
// naming this Hub: the time is taken before the request is sent, so the
// fence's deadline never runs later than any other Hub's view of it.
type fenceLock struct {
	*resourcelock.LeaseLock
	f *Fence
}

func (l *fenceLock) Create(ctx context.Context, r resourcelock.LeaderElectionRecord) error {
	start := l.f.cfg.Clock.Now()
	if err := l.LeaseLock.Create(ctx, r); err != nil {
		return err
	}
	l.record(r, start)
	return nil
}

func (l *fenceLock) Update(ctx context.Context, r resourcelock.LeaderElectionRecord) error {
	start := l.f.cfg.Clock.Now()
	if err := l.LeaseLock.Update(ctx, r); err != nil {
		return err
	}
	l.record(r, start)
	return nil
}

func (l *fenceLock) record(r resourcelock.LeaderElectionRecord, start time.Time) {
	if r.HolderIdentity == l.f.cfg.Identity {
		l.f.renewedAt(start)
	}
}
