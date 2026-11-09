package hub

import (
	"context"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
)

// Job manifests and compose files for testing.
const jobAppManifest = `name: Job App
auth:
  method: forward-auth
  group_access: true
access_group: users_jobapp
ai:
  unsupported: true
urls:
  - url: https://jobapp.{{DOMAIN}}
    group: users_jobapp
`

const jobAppCompose = `services:
  web:
    image: example.org/web:1.0
    labels:
      traefik.http.routers.jobapp.rule: Host(` + "`jobapp.${PORTCULLIS_DOMAIN:-portcullis.local}`" + `)
      traefik.http.routers.jobapp.entrypoints: websecure
    depends_on:
      setup:
        condition: service_completed_successfully
  setup:
    image: example.org/setup:1.0
`

func jobFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	// Add a template with a job (setup depends on by web with
	// service_completed_successfully).
	writeFile(t, f.src+"/jobapp/manifest.yaml", jobAppManifest)
	writeFile(t, f.src+"/jobapp/compose.yml", jobAppCompose)
	f.h.Discover()
	return f
}

func jobappLabels(t *testing.T, f *fixture, service string) map[string]string {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	want, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("jobapp"))
	if err != nil {
		t.Fatal(err)
	}
	return want[service]
}

// TestStatusJobDone: a job that exited 0 has Job: true, JobState: "done",
// and is not counted as down.
func TestStatusJobDone(t *testing.T) {
	f := jobFixture(t)
	f.engine.containers = []docker.Container{
		container("w1", "portcullis-jobapp", "web", "running"),
		func() docker.Container {
			c := container("s1", "portcullis-jobapp", "setup", "exited")
			c.Status = "Exited (0) 2 minutes ago"
			return c
		}(),
	}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
		"s1": {Running: false, Status: "exited", ExitCode: 0},
	}

	st, err := f.h.Status(context.Background(), "jobapp")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st) != 2 {
		t.Fatalf("status count = %d, want 2", len(st))
	}

	// Find the setup container's status.
	var setupStatus *ContainerStatus
	for i := range st {
		if st[i].Service == "setup" {
			setupStatus = &st[i]
			break
		}
	}
	if setupStatus == nil {
		t.Fatal("setup service not in status")
	}

	// Job field should be true, JobState should be "done".
	if !setupStatus.Job {
		t.Errorf("setup Job = false, want true")
	}
	if setupStatus.JobState != "done" {
		t.Errorf("setup JobState = %q, want %q", setupStatus.JobState, "done")
	}
	if setupStatus.State != "exited" {
		t.Errorf("setup State = %q, want %q", setupStatus.State, "exited")
	}
}

// TestStatusJobFailed: a job that exited non-zero has Job: true, JobState:
// "failed", and makes the instance not fine (flagged in drift).
func TestStatusJobFailed(t *testing.T) {
	f := jobFixture(t)
	f.h.Enable("jobapp")
	web := container("w1", "portcullis-jobapp", "web", "running")
	// C1: Container labels must match what the Hub renders (no incidental exposure drift).
	for k, v := range jobappLabels(t, f, "web") {
		web.Labels[k] = v
	}
	f.engine.containers = []docker.Container{
		web,
		func() docker.Container {
			c := container("s1", "portcullis-jobapp", "setup", "exited")
			c.Status = "Exited (1) 1 minute ago"
			return c
		}(),
	}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
		"s1": {Running: false, Status: "exited", ExitCode: 1},
	}

	st, err := f.h.Status(context.Background(), "jobapp")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	var setupStatus *ContainerStatus
	for i := range st {
		if st[i].Service == "setup" {
			setupStatus = &st[i]
			break
		}
	}
	if setupStatus == nil {
		t.Fatal("setup service not in status")
	}

	if !setupStatus.Job {
		t.Errorf("setup Job = false, want true")
	}
	if setupStatus.JobState != "failed" {
		t.Errorf("setup JobState = %q, want %q", setupStatus.JobState, "failed")
	}

	// C1: Instance should be flagged with drift kind job_failed.
	rep := f.h.Reconcile(context.Background())
	var drift *Drift
	for i := range rep.Items {
		if rep.Items[i].ID == "jobapp" && rep.Items[i].Kind == DriftJobFailed {
			drift = &rep.Items[i]
			break
		}
	}
	if drift == nil {
		t.Fatal("no drift kind job_failed reported for failed job")
	}
	if drift.Kind != DriftJobFailed {
		t.Errorf("drift kind = %v, want %v", drift.Kind, DriftJobFailed)
	}
	if !strings.Contains(drift.Message, "job") || !strings.Contains(drift.Message, "failed") {
		t.Errorf("drift message = %q, should mention job failed", drift.Message)
	}
}

// TestDriftIgnoresFinishedJob: drift never reports an exited-0 job as a
// stopped service; an enabled instance with a done job and all other
// services running has no drift.
func TestDriftIgnoresFinishedJob(t *testing.T) {
	f := jobFixture(t)
	f.h.Enable("jobapp")
	web := container("w1", "portcullis-jobapp", "web", "running")
	// I4: Container labels must match what the Hub renders.
	for k, v := range jobappLabels(t, f, "web") {
		web.Labels[k] = v
	}
	f.engine.containers = []docker.Container{
		web,
		func() docker.Container {
			c := container("s1", "portcullis-jobapp", "setup", "exited")
			c.Status = "Exited (0) 5 minutes ago"
			return c
		}(),
	}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
		"s1": {Running: false, Status: "exited", ExitCode: 0},
	}

	rep := f.h.Reconcile(context.Background())
	// I4: The key assertion is that a done job counts as running, so NO
	// drift should be reported for jobapp (contract: "Drift never reports
	// an exited job as a stopped service").
	for _, d := range rep.Items {
		if d.ID == "jobapp" {
			t.Errorf("unexpected drift for jobapp with done job: kind=%v, message=%q, running=%d/%d", d.Kind, d.Message, d.Running, d.Total)
		}
	}
}

// TestHealthyStepJobDone: the healthy step is job-aware (I3): a done job
// (exited 0) is ready, a failed job ends early, an exited-0 non-job is not ready.
func TestHealthyStepJobDone(t *testing.T) {
	f := jobFixture(t)
	t1 := f.h.Template("jobapp")
	if t1 == nil {
		t.Fatal("template jobapp not found")
	}
	services := f.h.renderedServices(context.Background(), t1)

	// Case 1: Done job (exited 0) is ready.
	f.engine.containers = []docker.Container{
		container("w1", "portcullis-jobapp", "web", "running"),
		func() docker.Container {
			c := container("s1", "portcullis-jobapp", "setup", "exited")
			c.Status = "Exited (0) 1 minute ago"
			return c
		}(),
	}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running", Health: "healthy"},
		"s1": {Running: false, Status: "exited", ExitCode: 0},
	}
	n, m, others, failedJobs, err := f.h.countContainers(context.Background(), t1, services)
	if err != nil {
		t.Fatalf("countContainers (done job): %v", err)
	}
	if m != 2 {
		t.Errorf("done job: m = %d, want 2", m)
	}
	if n != 2 {
		t.Errorf("done job: n = %d, want 2 (both ready)", n)
	}
	if len(others) > 0 {
		t.Errorf("done job: others = %v, want none", others)
	}
	if len(failedJobs) > 0 {
		t.Errorf("done job: failedJobs = %v, want none", failedJobs)
	}

	// Case 2: Failed job (exited 1) is not ready and reported in failedJobs.
	f.engine.containers = []docker.Container{
		container("w2", "portcullis-jobapp", "web", "running"),
		func() docker.Container {
			c := container("s2", "portcullis-jobapp", "setup", "exited")
			c.Status = "Exited (1) 1 minute ago"
			return c
		}(),
	}
	f.engine.states = map[string]docker.State{
		"w2": {Running: true, Status: "running", Health: "healthy"},
		"s2": {Running: false, Status: "exited", ExitCode: 1},
	}
	n, m, others, failedJobs, err = f.h.countContainers(context.Background(), t1, services)
	if err != nil {
		t.Fatalf("countContainers (failed job): %v", err)
	}
	if n != 1 {
		t.Errorf("failed job: n = %d, want 1 (only web ready)", n)
	}
	if len(failedJobs) != 1 || failedJobs[0] != "setup" {
		t.Errorf("failed job: failedJobs = %v, want [setup]", failedJobs)
	}
	if !contains(others, "setup") {
		t.Errorf("failed job: others = %v, should contain setup", others)
	}

	// Case 3: Missing job (no container) is not ready; wait doesn't end early.
	f.engine.containers = []docker.Container{
		container("w3", "portcullis-jobapp", "web", "running"),
		// setup job has no container
	}
	f.engine.states = map[string]docker.State{
		"w3": {Running: true, Status: "running", Health: "healthy"},
	}
	n, m, others, failedJobs, err = f.h.countContainers(context.Background(), t1, services)
	if err != nil {
		t.Fatalf("countContainers (missing job): %v", err)
	}
	if m != 1 {
		t.Errorf("missing job: m = %d, want 1 (only web exists)", m)
	}
	if n != 1 {
		t.Errorf("missing job: n = %d, want 1 (only web ready)", n)
	}
	if len(failedJobs) > 0 {
		t.Errorf("missing job: failedJobs = %v, want none (no container to report)", failedJobs)
	}
}

// TestJobNeverRan: a job with no container (never ran) is reported as
// drift kind job_missing (C2).
func TestJobNeverRan(t *testing.T) {
	f := jobFixture(t)
	f.h.Enable("jobapp")
	// Only web container exists; setup job never ran.
	web := container("w1", "portcullis-jobapp", "web", "running")
	for k, v := range jobappLabels(t, f, "web") {
		web.Labels[k] = v
	}
	f.engine.containers = []docker.Container{
		web,
	}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
	}

	st, err := f.h.Status(context.Background(), "jobapp")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// web's container, then a missing row for the job that never ran
	// (§11.9: state missing, job_state missing, no name).
	if len(st) != 2 || st[0].Service != "web" {
		t.Fatalf("status = %+v, want web then setup (missing)", st)
	}
	if m := st[1]; m.Service != "setup" || m.Name != "" || m.State != StateMissing || m.Status != "no container" || !m.Job || m.JobState != StateMissing {
		t.Errorf("missing job row = %+v", m)
	}

	// C2: Missing job drift should be reported.
	rep := f.h.Reconcile(context.Background())
	var drift *Drift
	for i := range rep.Items {
		if rep.Items[i].ID == "jobapp" && rep.Items[i].Kind == DriftJobMissing {
			drift = &rep.Items[i]
			break
		}
	}
	if drift == nil {
		t.Fatal("no drift kind job_missing reported when job never ran")
	}
	if drift.Kind != DriftJobMissing {
		t.Errorf("drift kind = %v, want %v", drift.Kind, DriftJobMissing)
	}
	if !strings.Contains(drift.Message, "setup") || !strings.Contains(drift.Message, "never ran") {
		t.Errorf("drift message = %q, should mention setup never ran", drift.Message)
	}
}

const profiledJobManifest = `name: Profiled Job App
auth:
  method: forward-auth
  group_access: true
access_group: users_profiledapp
ai:
  unsupported: true
urls:
  - url: https://profiledapp.{{DOMAIN}}
    group: users_profiledapp
jobs: [setup]
settings:
  options:
    - key: mode
      label: Mode
      type: enum
      scope: instance
      setup: true
      options:
        - {value: normal, label: Normal}
        - {value: extended, label: Extended}
      default: normal
      profiles:
        normal: []
        extended: [extended]
`
const profiledJobCompose = `services:
  web:
    image: example.org/web:1.0
    environment:
      MODE: ${MODE:-normal}
    labels:
      traefik.http.routers.profiledapp.rule: Host(` + "`profiledapp.${PORTCULLIS_DOMAIN:-portcullis.local}`" + `)
      traefik.http.routers.profiledapp.entrypoints: websecure
  setup:
    image: example.org/setup:1.0
    profiles: [extended]
`

// TestProfiledJobMissing: a job in a profile the setup choices leave off
// (mode normal, the default) with no container does not trigger
// job_missing drift (§11.9, §13.18; TestProfiledJobFollowsChoice: an
// active one does).
func TestProfiledJobMissing(t *testing.T) {
	// Create a template with a profiled job.
	f := newFixture(t)
	writeFile(t, f.src+"/profiledapp/manifest.yaml", profiledJobManifest)
	writeFile(t, f.src+"/profiledapp/compose.yml", profiledJobCompose)
	f.h.Discover()
	f.h.Enable("profiledapp")

	// Only web container exists; setup job has profiles and never ran.
	web := container("w1", "portcullis-profiledapp", "web", "running")
	// Get correct labels (no exposure drift).
	tmpl := f.h.Template("profiledapp")
	if tmpl == nil {
		t.Fatal("profiledapp template not found after Discover")
	}
	f.h.mu.RLock()
	want, err := f.h.desiredRouteLabelsLocked(tmpl)
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want["web"] {
		web.Labels[k] = v
	}
	f.engine.containers = []docker.Container{web}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
	}

	// No job_missing drift should be reported (profiled job skipped).
	rep := f.h.Reconcile(context.Background())
	for _, d := range rep.Items {
		if d.ID == "profiledapp" && d.Kind == DriftJobMissing {
			t.Errorf("unexpected job_missing drift for profiled job: %+v", d)
		}
	}
}

// TestJobDead: a dead job counts as failed (fail closed).
func TestJobDead(t *testing.T) {
	f := jobFixture(t)
	f.h.Enable("jobapp")
	web := container("w1", "portcullis-jobapp", "web", "running")
	for k, v := range jobappLabels(t, f, "web") {
		web.Labels[k] = v
	}
	setup := container("s1", "portcullis-jobapp", "setup", "dead")
	setup.Status = "Dead"
	f.engine.containers = []docker.Container{web, setup}
	f.engine.states = map[string]docker.State{
		"w1": {Running: true, Status: "running"},
		"s1": {Running: false, Status: "dead", ExitCode: 0},
	}

	// Dead job → job_failed drift.
	rep := f.h.Reconcile(context.Background())
	var drift *Drift
	for i := range rep.Items {
		if rep.Items[i].ID == "jobapp" && rep.Items[i].Kind == DriftJobFailed {
			drift = &rep.Items[i]
			break
		}
	}
	if drift == nil {
		t.Fatal("no job_failed drift when job is dead")
	}
	if !strings.Contains(drift.Message, "setup") || !strings.Contains(drift.Message, "failed") {
		t.Errorf("drift message = %q, should mention job setup failed", drift.Message)
	}
}
