package hub

import (
	"context"
	"time"

	"github.com/portcullis/hub/internal/templates"
)

// AI hooks that run right after a compose up (contract §15.5): the up has
// just recreated or started the hook's service, which may not answer yet.
// In task 32's live check the app wasn't listening 1 s after its container
// started, so a revoke_all run then failed to connect. Such a hook waits
// for its service first (runAIHookAfterUp). A hook that can run before
// the up, while the app still runs as it was, runs there instead (a
// switch-off's revoke_all, UpdateInstanceAI).

// aiReadyWait bounds how long an AI hook run right after a compose up
// waits for its service (and is retried while the service isn't known to
// be ready); aiReadyPoll is the polling interval.
var (
	aiReadyWait = 60 * time.Second
	aiReadyPoll = time.Second
)

// aiHookService is the service ai hook name of t runs in ("" = no such ai
// hook).
func aiHookService(t *templates.Template, name string) string {
	for i := range t.Manifest.Hooks {
		if hk := &t.Manifest.Hooks[i]; hk.Name == name && hk.IsAI() {
			return hk.Service
		}
	}
	return ""
}

// aiServiceState: whether service of t has a running container, and that
// container's healthcheck status ("" = it has none; starting, healthy or
// unhealthy). An error: not known.
func (h *Hub) aiServiceState(ctx context.Context, t *templates.Template, service string) (running bool, health string, err error) {
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return false, "", err
	}
	c := runningContainer(cs, service)
	if c == nil {
		return false, "", nil
	}
	st, err := h.engine.ContainerState(ctx, c.ID)
	if err != nil {
		return false, "", err
	}
	return st.Running, st.Health, nil
}

// runAIHookAfterUp is runAIHook for a hook that runs right after a compose
// up recreated or started its service. It first waits (polling
// aiReadyPoll, at most aiReadyWait in all) until the service has a running
// container whose healthcheck no longer says starting. Then it runs the
// hook; while a run fails and the service isn't known to be ready — no
// running container, its health still starting, or no healthcheck to tell
// — it runs it again after aiReadyPoll until aiReadyWait is spent. The
// failure of a service that is healthy (or unhealthy) is final, and a run
// that timed out is never repeated (it may still run). The last result is
// returned: a hook still failing fails as before (fail closed: the
// caller's owed flags stay).
func (h *Hub) runAIHookAfterUp(ctx context.Context, t *templates.Template, name string, stdin []byte) (stdout []byte, res UnitResult) {
	service := ""
	if h.engine != nil {
		service = aiHookService(t, name)
	}
	start := time.Now()
	var slept time.Duration
	pause := func() bool {
		if slept >= aiReadyWait || time.Since(start) >= aiReadyWait {
			return false
		}
		if err := h.sleep(ctx, aiReadyPoll); err != nil {
			return false
		}
		slept += aiReadyPoll
		return true
	}
	for service != "" {
		running, health, err := h.aiServiceState(ctx, t, service)
		if err == nil && running && health != "starting" {
			break
		}
		if !pause() {
			break
		}
	}
	for {
		out, _, res, timedOut := h.execAIHook(ctx, t, name, stdin)
		if res.OK || timedOut || service == "" {
			return out, res
		}
		running, health, err := h.aiServiceState(ctx, t, service)
		if (err == nil && running && health != "" && health != "starting") || !pause() {
			return out, res
		}
	}
}

// SetAIReadyWaitForTest sets aiReadyWait for another package's tests (a
// test that fails a hook wants the failure at once). Call it before any
// Hub runs a hook (an init).
func SetAIReadyWaitForTest(d time.Duration) { aiReadyWait = d }
