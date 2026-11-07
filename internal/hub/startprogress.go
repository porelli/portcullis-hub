package hub

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// The steps startUp reports into its operation's progress (contract
// §11.7 "Steps per operation"): the images downloaded before compose
// create, the create, the start (compose up) and the wait until the
// services are healthy. Only with a reporter in the context
// (progressFrom): without one startUp pulls nothing itself and waits for
// nothing, exactly as before.
const (
	StepImages  = "images"
	StepCreate  = "create"
	StepStart   = "start"
	StepHealthy = "healthy"
)

// pullRefs are the images compose would pull for t's project, as the
// Hub renders it (loadRendered: the template, the Hub's override, the
// custom override and the instance's .env — never `docker compose
// config`), sorted, once each. Left out — compose's create pulls them as
// before — is anything not known statically: a service with a profile
// (whether compose activates it depends on its env), one that builds,
// one with pull_policy never / build, a platform, or a reference still
// holding a "$". A project that doesn't load gives none.
func (h *Hub) pullRefs(ctx context.Context, t *templates.Template) []string {
	proj, err := loadRendered(ctx, h.project(t), h.cfg.ProjectDir)
	if err != nil {
		return nil
	}
	var refs []string
	for _, s := range proj.Services {
		if !pullable(s) || slices.Contains(refs, s.Image) {
			continue
		}
		refs = append(refs, s.Image)
	}
	slices.Sort(refs)
	return refs
}

func pullable(s types.ServiceConfig) bool {
	switch {
	case s.Image == "", s.Build != nil, len(s.Profiles) > 0, s.Platform != "", strings.Contains(s.Image, "$"):
		return false
	case s.PullPolicy == types.PullPolicyNever, s.PullPolicy == types.PullPolicyBuild:
		return false
	}
	return true
}

// imagePull is one image of the images step.
type imagePull struct {
	ref, label  string
	done, total int64
	state       string // "" waiting, pulling, done, left (to compose)
}

func (ip *imagePull) line() string {
	switch ip.state {
	case "done":
		return ip.label + " — done"
	case "left":
		return ip.label + " — left to compose"
	case "pulling":
		if ip.total > 0 {
			return ip.label + " — " + megabytes(ip.done, ip.total)
		}
		return ip.label + " — starting"
	}
	return ip.label + " — waiting"
}

// megabytes is "312 of 690 MB" (one decimal under 10 MB).
func megabytes(done, total int64) string {
	if total < 10_000_000 {
		return fmt.Sprintf("%.1f of %.1f MB", float64(done)/1e6, float64(total)/1e6)
	}
	return fmt.Sprintf("%d of %d MB", (done+500_000)/1_000_000, (total+500_000)/1_000_000)
}

// imageLabel is ref without its digest (the detail stays readable).
func imageLabel(ref string) string {
	name, _, _ := strings.Cut(ref, "@")
	return name
}

// pullImages is the images step: every pullRefs image pulled in
// parallel through the Engine API (PullWithProgress; an image already
// present is done at once), the step's percent the bytes done of the
// bytes known summed over every image's layers (never going back), its
// detail one entry per image. A pull that fails is left to compose's
// create, which pulls it as before (logged): never an error. Cancelling
// ctx (a Stop) stops the pulls — downloaded layers are kept — and
// returns ctx's error (isStopErr); the step is then the Stop's (stopped).
func (h *Hub) pullImages(ctx context.Context, p *Progress, t *templates.Template) error {
	p.Start(StepImages)
	var refs []string
	if h.engine != nil {
		refs = h.pullRefs(ctx, t)
	}
	imgs := make([]*imagePull, len(refs))
	for i, r := range refs {
		imgs[i] = &imagePull{ref: r, label: imageLabel(r)}
	}
	var mu sync.Mutex
	last := 0
	// report: under mu, so the writes keep their order.
	report := func() {
		var done, total int64
		lines := make([]string, len(imgs))
		for i, ip := range imgs {
			done, total = done+ip.done, total+ip.total
			lines[i] = ip.line()
		}
		pct := 0
		if total > 0 {
			pct = int(done * 100 / total)
		}
		last = max(last, pct)
		p.Percent(StepImages, last, strings.Join(lines, "; "))
	}
	mu.Lock()
	report()
	mu.Unlock()
	redact := h.secretRedactor(t.ID)
	var wg sync.WaitGroup
	for _, ip := range imgs {
		wg.Go(func() {
			err := h.engine.PullWithProgress(ctx, ip.ref, func(done, total int64) {
				mu.Lock()
				defer mu.Unlock()
				ip.state, ip.done, ip.total = "pulling", done, total
				report()
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ip.state, ip.done = "done", ip.total
			case ctx.Err() != nil:
				return
			default:
				ip.state = "left"
				log.Printf("instance %s: downloading %s failed, compose will pull it: %s", t.ID, ip.ref, clip(redact(err.Error()), 600))
			}
			report()
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("downloading images: %w", err)
	}
	mu.Lock()
	last = 100
	report()
	mu.Unlock()
	p.Done(StepImages)
	return nil
}

// containerStarted: compose started it (it runs, or it ran and ended).
func containerStarted(st docker.State) bool {
	return st.Running || (st.Status != "" && st.Status != "created")
}

// containerReady: it runs and its healthcheck (if any) says healthy, or
// it is a one-shot that finished (exited 0).
func containerReady(st docker.State) bool {
	if st.Running {
		return st.Status != "restarting" && (st.Health == "" || st.Health == "healthy")
	}
	return st.Status == "exited" && st.ExitCode == 0
}

// countContainers is, over t's project containers (appContainers), how
// many ok says yes to, of how many, and the names of the others with
// their state ("web starting").
func (h *Hub) countContainers(ctx context.Context, t *templates.Template, ok func(docker.State) bool) (n, m int, others []string, err error) {
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return 0, 0, nil, err
	}
	for _, c := range cs {
		st, err := h.engine.ContainerState(ctx, c.ID)
		if err != nil {
			return 0, 0, nil, err
		}
		m++
		if ok(st) {
			n++
			continue
		}
		what := st.Health
		if what == "" || !st.Running {
			what = st.Status
		}
		if what == "" {
			what = "not running"
		}
		others = append(others, c.Service()+" "+what)
	}
	return n, m, others, nil
}

func percentOf(n, m int) int {
	if m == 0 {
		return 100
	}
	return n * 100 / m
}

// watchStart reports the start step while compose up runs: "Starting
// services (n of m)" every aiReadyPoll until stop is closed.
func (h *Hub) watchStart(ctx context.Context, p *Progress, t *templates.Template, stop <-chan struct{}) {
	for {
		if n, m, _, err := h.countContainers(ctx, t, containerStarted); err == nil {
			p.Percent(StepStart, percentOf(n, m), fmt.Sprintf("Starting services (%d of %d)", n, m))
		}
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-time.After(aiReadyPoll):
		}
	}
}

// startStepDone ends the start step once compose up returned.
func (h *Hub) startStepDone(ctx context.Context, p *Progress, t *templates.Template) {
	if n, m, _, err := h.countContainers(ctx, t, containerStarted); err == nil {
		p.Percent(StepStart, percentOf(n, m), fmt.Sprintf("Starting services (%d of %d)", n, m))
	}
	p.Done(StepStart)
}

// waitHealthy is the healthy step: "Waiting until healthy (n of m)",
// polled with ContainerState every aiReadyPoll for at most aiReadyWait —
// the readiness bounds the AI hooks after an up use (ai_ready.go). Every
// container ready (containerReady) = done; the wait spent = the step
// failed naming the services still not ready, and the start goes on (a
// start never failed on health before). Cancelling ctx returns its error.
func (h *Hub) waitHealthy(ctx context.Context, p *Progress, t *templates.Template) error {
	p.Start(StepHealthy)
	var slept time.Duration
	begin := time.Now()
	for {
		n, m, others, err := h.countContainers(ctx, t, containerReady)
		if err == nil {
			p.Percent(StepHealthy, percentOf(n, m), fmt.Sprintf("Waiting until healthy (%d of %d)", n, m))
			if n == m {
				p.Done(StepHealthy)
				return nil
			}
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("waiting until healthy: %w", cerr)
		}
		if slept >= aiReadyWait || time.Since(begin) >= aiReadyWait {
			var why error
			switch {
			case err != nil:
				why = fmt.Errorf("the services' health can't be read: %w", err)
			default:
				why = fmt.Errorf("%d of %d services healthy after %s (%s); the app goes on starting", n, m, aiReadyWait, strings.Join(others, ", "))
			}
			log.Printf("instance %s: %v", t.ID, why)
			p.Fail(StepHealthy, why)
			return nil
		}
		if err := h.sleep(ctx, aiReadyPoll); err != nil {
			return fmt.Errorf("waiting until healthy: %w", err)
		}
		slept += aiReadyPoll
	}
}
