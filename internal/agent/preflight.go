package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/fsutil"
)

// Preflight pulls (contract §17.4): the Hub's placement pre-pull, before
// any bundle of the instance exists. Only a ref pinned by digest; at most
// PreflightConcurrency at once and PreflightPerMinute a minute (429
// beyond); the ref alone is logged. An image the pull brought in (absent
// before) is recorded in <data>/preflight.json and removed by the sweep
// once PreflightKeep passed and no bundle names it.
var (
	PreflightConcurrency = 8
	PreflightPerMinute   = 30
	PreflightKeep        = 24 * time.Hour
)

// Images is the engine's image side the preflight records need
// (internal/docker). nil: preflight pulls are recorded nowhere and never
// swept (tests).
type Images interface {
	ImagePresent(ctx context.Context, ref string) (bool, error)
	RemoveImage(ctx context.Context, ref string) error
}

type preflightState struct {
	mu      sync.Mutex
	slots   chan struct{}
	limiter *rate.Limiter
}

func newPreflightState() *preflightState {
	return &preflightState{
		slots:   make(chan struct{}, PreflightConcurrency),
		limiter: rate.NewLimiter(rate.Every(time.Minute/time.Duration(PreflightPerMinute)), PreflightConcurrency),
	}
}

type preflightFile struct {
	Version int                  `json:"version"`
	Images  map[string]time.Time `json:"images"`
}

func (a *API) preflightPath() string { return filepath.Join(a.cfg.DataDir, "preflight.json") }

func (a *API) loadPreflight() (preflightFile, error) {
	f := preflightFile{Version: 1, Images: map[string]time.Time{}}
	b, err := os.ReadFile(a.preflightPath())
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		return preflightFile{Version: 1, Images: map[string]time.Time{}}, errors.New("preflight.json is unreadable")
	}
	if f.Images == nil {
		f.Images = map[string]time.Time{}
	}
	return f, nil
}

func (a *API) savePreflight(f preflightFile) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.preflightPath(), b, 0o600)
}

// preflightPull serves POST /v1/images/pull with "preflight": true.
func (a *API) preflightPull(w http.ResponseWriter, r *http.Request, ref string) {
	if !docker.DigestRef(ref) {
		writeError(w, http.StatusBadRequest, "a preflight pull needs a reference pinned by digest (name@sha256:…)")
		return
	}
	pf := a.preflight
	if !pf.limiter.Allow() {
		writeError(w, http.StatusTooManyRequests, "too many preflight pulls: try again in a minute")
		return
	}
	select {
	case pf.slots <- struct{}{}:
		defer func() { <-pf.slots }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many preflight pulls at once")
		return
	}
	log.Printf("preflight pull %s", ref)
	present := true
	if a.cfg.Images != nil {
		p, err := a.cfg.Images.ImagePresent(r.Context(), ref)
		if err != nil {
			engineError(w, err)
			return
		}
		present = p
	}
	ctx, done := a.opContext(r)
	defer done()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flush(w)
	out := &ndjson{w: w}
	err := a.cfg.Runtime.Pull(ctx, ref, func(d, t int64, sized bool) {
		out.line(agentapi.ProgressLine{Done: d, Total: t, Sized: sized})
	})
	end := agentapi.ProgressLine{End: true}
	if err != nil {
		end.Error, end.Status = clipMsg(err.Error()), statusOfErr(err)
	} else if !present {
		a.recordPreflight(ref)
	}
	out.line(end)
}

func (a *API) recordPreflight(ref string) {
	a.preflight.mu.Lock()
	defer a.preflight.mu.Unlock()
	f, err := a.loadPreflight()
	if err != nil {
		log.Printf("preflight pull %s: %v (starting a new record)", ref, err)
	}
	if _, ok := f.Images[ref]; !ok {
		f.Images[ref] = time.Now().UTC()
	}
	if err := a.savePreflight(f); err != nil {
		log.Printf("preflight pull %s: recording it: %v", ref, err)
	}
}

// bundleImage: ref is named by a bundle's model.
func (a *API) bundleImage(ref string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.projects {
		if p.images[ref] {
			return true
		}
	}
	return false
}

// SweepPreflight removes the images preflight pulls brought in that no
// bundle names once PreflightKeep passed (never forced: one a container
// uses stays and is tried again); a ref a bundle names is dropped from
// the record and kept.
func (a *API) SweepPreflight(ctx context.Context, now time.Time) {
	if a.cfg.Images == nil {
		return
	}
	a.preflight.mu.Lock()
	defer a.preflight.mu.Unlock()
	f, err := a.loadPreflight()
	if err != nil {
		log.Printf("preflight sweep: %v", err)
		return
	}
	refs := make([]string, 0, len(f.Images))
	for ref := range f.Images {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	changed := false
	for _, ref := range refs {
		switch {
		case a.bundleImage(ref) || ref == a.cfg.HelperImage:
			delete(f.Images, ref)
			changed = true
		case now.Sub(f.Images[ref]) < PreflightKeep:
		default:
			err := a.cfg.Images.RemoveImage(ctx, ref)
			if err == nil || docker.IsNotFound(err) {
				log.Printf("preflight sweep: removed %s (no bundle named it)", ref)
				delete(f.Images, ref)
				changed = true
			} else {
				log.Printf("preflight sweep: %s stays: %s", ref, clipMsg(err.Error()))
			}
		}
	}
	if changed {
		if err := a.savePreflight(f); err != nil {
			log.Printf("preflight sweep: %v", err)
		}
	}
}

// RunPreflightSweep sweeps at start and every `every`.
func (a *API) RunPreflightSweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.SweepPreflight(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
