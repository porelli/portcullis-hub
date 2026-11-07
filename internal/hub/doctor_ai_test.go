package hub

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 20: the Hub's inputs of the AI checks (doctorInputs →
// aiDoctorInputs) as the doctor reports them.

const tokPin = "sha256:" + "c0ffee0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func TestDoctorAIInputs(t *testing.T) {
	a := newInstAIFixture(t, func(st *state.AppState) {
		st.AIInstances = map[string]state.AIInstance{"aiapp": {Companions: map[string]state.AICompanion{"tok": {Enabled: true, Mode: "read_write"}}}}
	}, func(extra map[string][2]string) {
		f := extra["aiapp"]
		f[1] = strings.Replace(f[1], "image: tok-mcp", "image: example.org/tok-mcp:1.2@"+tokPin, 1)
		extra["aiapp"] = f
	})
	a.enable(t, "aiapp")
	ctx := context.Background()
	setTok := func(state, status, image string) {
		a.engine.mu.Lock()
		defer a.engine.mu.Unlock()
		var keep []docker.Container
		for _, c := range a.engine.containers {
			if c.Service() != "tok-mcp" {
				keep = append(keep, c)
			}
		}
		if state != "" {
			c := container("portcullis-aiapp-tok", "portcullis-aiapp", "tok-mcp", state)
			c.Status, c.Image = status, image
			keep = append(keep, c)
		}
		a.engine.containers = keep
	}
	kinds := func() map[string]doctor.Finding {
		t.Helper()
		r, err := a.h.Doctor(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]doctor.Finding{}
		for _, f := range r.Findings {
			if strings.HasPrefix(f.Kind, "ai_") {
				out[f.Kind] = f
			}
		}
		return out
	}

	// Running the pinned image: nothing.
	setTok("running", "Up 3 minutes (healthy)", "example.org/tok-mcp:1.2@"+tokPin)
	if got := kinds(); len(got) != 0 {
		t.Fatalf("healthy = %+v", got)
	}
	// Not running: a Problem linking to the AI tab.
	setTok("", "", "")
	f, ok := kinds()[doctor.KindAICompanionUnhealthy]
	if !ok || f.Severity != doctor.Problem || f.Link == nil || f.Link.Tab != "ai" || f.Link.Instance != "aiapp" || !strings.Contains(f.Title, "Tokens") {
		t.Fatalf("missing container = %+v", f)
	}
	// Unhealthy, on another digest: both.
	setTok("running", "Up 1 minute (unhealthy)", "example.org/tok-mcp:1.1@sha256:"+strings.Repeat("d", 64))
	got := kinds()
	if _, ok := got[doctor.KindAICompanionUnhealthy]; !ok {
		t.Errorf("unhealthy not reported: %+v", got)
	}
	if f, ok := got[doctor.KindAICompanionImageOld]; !ok || f.Severity != doctor.Warning || !strings.Contains(f.Why, "sha256:dddddddddddd") {
		t.Errorf("image old = %+v", got)
	}
	setTok("running", "Up", "example.org/tok-mcp:1.2@"+tokPin)
	// A revoking entry: a Warning naming the instance.
	if err := a.h.creds().Put(aigate.Credential{Instance: "aiapp", Companion: "tok", User: "alice", ID: "7", MintedAt: aigate.At(time.Now())}, []byte("x-credential")); err != nil {
		t.Fatal(err)
	}
	if err := a.h.creds().MarkRevoking("aiapp", "tok", "alice"); err != nil {
		t.Fatal(err)
	}
	f, ok = kinds()[doctor.KindAICredentialsRevoking]
	if !ok || f.Severity != doctor.Warning || !strings.Contains(f.Title, "AI App") || len(f.Instances) != 1 || f.Instances[0] != "aiapp" {
		t.Fatalf("revoking = %+v", f)
	}
	// Master switch off: health, policy and image aren't judged; the owed
	// revocation still is.
	a.h.mu.Lock()
	a.h.st.AI.Enabled = false
	a.h.mu.Unlock()
	setTok("exited", "Exited (1)", "")
	got = kinds()
	if _, ok := got[doctor.KindAICompanionUnhealthy]; ok {
		t.Errorf("master off: unhealthy reported %+v", got)
	}
	if _, ok := got[doctor.KindAICredentialsRevoking]; !ok {
		t.Errorf("master off: the owed revocation is gone: %+v", got)
	}
}
