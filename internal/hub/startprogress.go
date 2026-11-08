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
// nothing, exactly as before. Only the steps the operation planned are
// reported (startSteps): a key it didn't list is left out, never appended.
// An unplanned step hides only reporting: the pre-pull, the start watcher
// and the healthy wait exist only to report and are skipped with their
// step, while every wait that ran before (the AI hooks' post-up
// readiness wait, runAIHookAfterUp) runs whatever the plan.
const (
	StepImages  = "images"
	StepCreate  = "create"
	StepStart   = "start"
	StepHealthy = "healthy"
	// StepSettings: the start hooks (and the owed AI hooks) after the up;
	// the data files are written before the create (prepareUp).
	StepSettings = "settings"
	// StepGroups / StepKeycloak: an enable's derived groups and sign-in
	// clients (stop.go, lifecycle.go).
	StepGroups   = "groups"
	StepKeycloak = "keycloak"
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

// startSteps reports startUp's steps into p, only those p lists (Has, at
// the start: a step added later — an undo step — is never one of these).
type startSteps struct {
	p    *Progress
	keys map[string]bool
}

func newStartSteps(p *Progress) *startSteps {
	s := &startSteps{p: p, keys: map[string]bool{}}
	for _, k := range []string{StepImages, StepCreate, StepStart, StepHealthy, StepSettings} {
		s.keys[k] = p.Has(k)
	}
	return s
}

func (s *startSteps) Start(key string) {
	if s.keys[key] {
		s.p.Start(key)
	}
}

func (s *startSteps) Percent(key string, pct int, detail string) {
	if s.keys[key] {
		s.p.Percent(key, pct, detail)
	}
}

func (s *startSteps) Warn(text string) { s.p.Warn(text) }

func (s *startSteps) Done(key string) {
	if s.keys[key] {
		s.p.Done(key)
	}
}

// percentCap: the images step's percent while some layer's size isn't
// known yet (the total can still grow).
const percentCap = 95

// imagePull is one image of the images step.
type imagePull struct {
	ref, label  string
	done, total int64
	sized       bool
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
// bytes known summed over every image's layers (never going back; at
// most percentCap while a layer seen has no size yet, below 100 until
// every image is through), its detail one entry per image. A pull that
// fails — or whose stream ends unfinished — is left to compose's create,
// which pulls it as before (logged): never an error. Cancelling ctx (a
// Stop) stops the pulls — downloaded layers are kept — and returns ctx's
// error (isStopErr); the step is then the Stop's (stopped).
func (h *Hub) pullImages(ctx context.Context, p *startSteps, t *templates.Template) error {
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
		limit := 100
		for i, ip := range imgs {
			done, total = done+ip.done, total+ip.total
			lines[i] = ip.line()
			switch {
			case ip.state == "pulling" && !ip.sized:
				limit = min(limit, percentCap)
			case ip.state == "" || ip.state == "pulling":
				limit = min(limit, 99)
			}
		}
		pct := 0
		if total > 0 {
			pct = int(done * 100 / total)
		}
		last = max(last, min(pct, limit))
		p.Percent(StepImages, last, strings.Join(lines, "; "))
	}
	mu.Lock()
	report()
	mu.Unlock()
	redact := h.secretRedactor(t.ID)
	var wg sync.WaitGroup
	for _, ip := range imgs {
		wg.Go(func() {
			err := h.engine.PullWithProgress(ctx, ip.ref, func(done, total int64, sized bool) {
				mu.Lock()
				defer mu.Unlock()
				ip.state, ip.done, ip.total, ip.sized = "pulling", done, total, sized
				report()
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ip.state, ip.done, ip.sized = "done", ip.total, true
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
func containerStarted(st docker.State, isJob bool) bool {
	// Jobs and non-jobs both: started means not "created".
	return st.Running || (st.Status != "" && st.Status != "created")
}

// containerReady: a non-job is ready when running and healthy (or no
// healthcheck); a job is ready only when exited 0 (I2).
func containerReady(st docker.State, isJob bool) bool {
	if isJob {
		// Job ready only when exited 0.
		return st.Status == "exited" && st.ExitCode == 0
	}
	// Non-job: must be running and healthy (exited-0 non-job is not ready).
	if st.Running {
		return st.Status != "restarting" && (st.Health == "" || st.Health == "healthy")
	}
	return false
}

// renderedServices are the services of t's project as the Hub renders it
// (loadRendered, every profile); nil when it doesn't load.
func (h *Hub) renderedServices(ctx context.Context, t *templates.Template) map[string]bool {
	proj, err := loadRendered(ctx, h.project(t), h.cfg.ProjectDir)
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(proj.Services))
	for name := range proj.Services {
		out[name] = true
	}
	return out
}

// countContainers is, over t's project containers (appContainers) whose
// compose service is one of services (the rendered project's,
// renderedServices: an orphan of a service the project no longer has is
// never counted; nil = every one appContainers lists), how many are ready,
// of how many, the services of the others, and failed job services.
func (h *Hub) countContainers(ctx context.Context, t *templates.Template, services map[string]bool) (n, m int, others, failedJobs []string, err error) {
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	for _, c := range cs {
		if services != nil && !services[c.Service()] {
			continue
		}
		st, err := h.engine.ContainerState(ctx, c.ID)
		if err != nil {
			return 0, 0, nil, nil, err
		}
		m++
		isJob := t.Jobs[c.Service()]
		if containerReady(st, isJob) {
			n++
			continue
		}
		// Check for failed job (exited non-zero).
		if isJob && st.Status == "exited" && st.ExitCode != 0 {
			if !slices.Contains(failedJobs, c.Service()) {
				failedJobs = append(failedJobs, c.Service())
			}
		}
		if !slices.Contains(others, c.Service()) {
			others = append(others, c.Service())
		}
	}
	return n, m, others, failedJobs, nil
}

// countStarted counts how many containers are started (not created).
func (h *Hub) countStarted(ctx context.Context, t *templates.Template, services map[string]bool) (n, m int, others []string, err error) {
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return 0, 0, nil, err
	}
	for _, c := range cs {
		if services != nil && !services[c.Service()] {
			continue
		}
		st, err := h.engine.ContainerState(ctx, c.ID)
		if err != nil {
			return 0, 0, nil, err
		}
		m++
		isJob := t.Jobs[c.Service()]
		if containerStarted(st, isJob) {
			n++
			continue
		}
		if !slices.Contains(others, c.Service()) {
			others = append(others, c.Service())
		}
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
// services (n of m)" every aiReadyPoll (h.sleep) until ctx ends (the
// caller cancels it once compose up returned).
func (h *Hub) watchStart(ctx context.Context, p *startSteps, t *templates.Template) {
	services := h.renderedServices(ctx, t)
	for {
		if n, m, _, err := h.countStarted(ctx, t, services); err == nil && ctx.Err() == nil {
			p.Percent(StepStart, percentOf(n, m), fmt.Sprintf("Starting services (%d of %d)", n, m))
		}
		// ctx checked too: a sleep that returns at once (a test clock)
		// must not keep the watcher spinning after compose up returned.
		if h.sleep(ctx, aiReadyPoll) != nil || ctx.Err() != nil {
			return
		}
	}
}

// startStepDone ends the start step once compose up returned.
func (h *Hub) startStepDone(ctx context.Context, p *startSteps, t *templates.Template) {
	if n, m, _, err := h.countStarted(ctx, t, h.renderedServices(ctx, t)); err == nil {
		p.Percent(StepStart, percentOf(n, m), fmt.Sprintf("Starting services (%d of %d)", n, m))
	}
	p.Done(StepStart)
}

// waitHealthy is the healthy step: "Waiting until healthy (n of m)",
// polled with ContainerState every aiReadyPoll for at most aiReadyWait —
// the readiness bounds the AI hooks after an up use (ai_ready.go). Every
// container ready (containerReady) = done; a failed job ends the wait early
// with warning (I2); the wait spent = done too, its detail "not ready after
// <wait>: web starting, …" and the same text an operation warning (Progress.Warn),
// and the start goes on (a start never failed on health). Cancelling ctx returns
// its error.
func (h *Hub) waitHealthy(ctx context.Context, p *startSteps, t *templates.Template) error {
	p.Start(StepHealthy)
	var slept time.Duration
	begin := time.Now()
	services := h.renderedServices(ctx, t)
	for {
		n, m, others, failedJobs, err := h.countContainers(ctx, t, services)
		if err == nil {
			p.Percent(StepHealthy, percentOf(n, m), fmt.Sprintf("Waiting until healthy (%d of %d)", n, m))
			// I2: A failed job ends the wait early with warning.
			if len(failedJobs) > 0 {
				var why string
				if len(failedJobs) == 1 {
					why = fmt.Sprintf("job %s failed", failedJobs[0])
				} else {
					why = fmt.Sprintf("jobs failed: %s", strings.Join(failedJobs, ", "))
				}
				log.Printf("instance %s: %s", t.ID, why)
				p.Percent(StepHealthy, percentOf(n, m), why)
				p.Done(StepHealthy)
				p.p.Warn(why)
				return nil
			}
			if n == m {
				p.Done(StepHealthy)
				return nil
			}
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("waiting until healthy: %w", cerr)
		}
		if slept >= aiReadyWait || time.Since(begin) >= aiReadyWait {
			var why string
			switch {
			case err != nil:
				why = fmt.Sprintf("health not read after %g s: %v", aiReadyWait.Seconds(), err)
			default:
				why = fmt.Sprintf("not ready after %g s: %s", aiReadyWait.Seconds(), strings.Join(others, ", "))
			}
			log.Printf("instance %s: %s", t.ID, why)
			p.Percent(StepHealthy, percentOf(n, m), why)
			p.Done(StepHealthy)
			p.p.Warn(why)
			return nil
		}
		if err := h.sleep(ctx, aiReadyPoll); err != nil {
			return fmt.Errorf("waiting until healthy: %w", err)
		}
		slept += aiReadyPoll
	}
}
