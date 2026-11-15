package hub

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// Source sync (sources.go): start-up sync, fail-safe pulls, revert of a
// version that breaks an enabled instance, status file.

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

const brokenManifest = "name: [unclosed\n"

type syncFixture struct {
	upstream, clone, project, data string
	runner                         *fakeRunner
	engine                         *fakeEngine
}

// newSyncFixture: an upstream repo with grafana (manifest m), the Hub's
// clone of it as source "local", grafana enabled in state.yaml.
func newSyncFixture(t *testing.T, m string) *syncFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	f := &syncFixture{upstream: filepath.Join(root, "upstream"), project: filepath.Join(root, "project"), data: filepath.Join(root, "data"),
		runner: newFakeRunner(), engine: &fakeEngine{logs: map[string]string{}}}
	f.clone = filepath.Join(f.data, "repos", "local")
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=x\n")
	writeFile(t, filepath.Join(f.upstream, "grafana", "manifest.yaml"), m)
	writeFile(t, filepath.Join(f.upstream, "grafana", "compose.yml"), grafanaCompose)
	git(t, f.upstream, "init", "-q", "-b", "main")
	git(t, f.upstream, "add", ".")
	git(t, f.upstream, "commit", "-qm", "one")
	os.MkdirAll(filepath.Dir(f.clone), 0755)
	git(t, root, "clone", "-q", "--", f.upstream, f.clone)
	st := state.New()
	st.Sources = []state.Source{{Name: "local", URL: f.upstream, Path: f.clone}}
	st.SetEnabled("grafana", true)
	if err := st.Save(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *syncFixture) commit(t *testing.T, manifest string) string {
	t.Helper()
	writeFile(t, filepath.Join(f.upstream, "grafana", "manifest.yaml"), manifest)
	git(t, f.upstream, "commit", "-qam", "next")
	return git(t, f.upstream, "rev-parse", "HEAD")
}

func (f *syncFixture) start(t *testing.T, atStart bool) *Hub {
	t.Helper()
	h, err := newTestHub(Config{ProjectDir: f.project, DataDir: f.data, Domain: "example.org", SyncSourcesAtStart: atStart}, f.runner, f.engine, &fakeIdP{})
	if err != nil {
		t.Fatal(err)
	}
	h.Init()
	t.Cleanup(h.Wait)
	return h
}

func readSyncFile(t *testing.T, h *Hub) SourceSyncStatus {
	t.Helper()
	b, err := os.ReadFile(h.sourceSyncPath())
	if err != nil {
		t.Fatal(err)
	}
	var st SourceSyncStatus
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The upgrade case: the clone is a version this Hub rejects, upstream has
// moved on. The start-up sync pulls it before the first policy write.
func TestStartupSyncRefreshesStaleTemplates(t *testing.T) {
	f := newSyncFixture(t, brokenManifest)
	want := f.commit(t, grafanaManifest)
	h := f.start(t, true)
	if h.Template("grafana") == nil {
		t.Fatal("grafana has no template after the start-up sync")
	}
	if got := git(t, f.clone, "rev-parse", "HEAD"); got != want {
		t.Errorf("clone at %s, want %s", got, want)
	}
	st := readSyncFile(t, h)
	if st.Trigger != SyncStartup || st.Running || !st.OK || len(st.Sources) != 1 || !st.Sources[0].Updated || st.Sources[0].After != want || len(st.MissingTemplates) != 0 {
		t.Errorf("status = %+v", st)
	}
	if st.StartedUnix == 0 || st.FinishedUnix < st.StartedUnix {
		t.Errorf("times = %d..%d", st.StartedUnix, st.FinishedUnix)
	}
	if mem := h.SourceSync(); mem == nil || mem.FinishedUnix != st.FinishedUnix {
		t.Errorf("in-memory status = %+v", mem)
	}
	// The policy file the Hub wrote serves grafana (no deny).
	pol, err := os.ReadFile(h.policyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pol), "grafana.example.org") || strings.Contains(string(pol), policy.DenyGroup) {
		t.Errorf("policy:\n%s", pol)
	}
}

// Off: the clone stays as it is (and the stale template stays missing).
func TestStartupSyncOff(t *testing.T) {
	f := newSyncFixture(t, brokenManifest)
	f.commit(t, grafanaManifest)
	h := f.start(t, false)
	if h.Template("grafana") != nil {
		t.Fatal("synced although SyncSourcesAtStart is off")
	}
	if h.SourceSync() != nil {
		t.Error("a status without a sync")
	}
}

// A failed fetch keeps the checkout: the last good copy keeps serving.
func TestSyncFetchFailureKeepsCheckout(t *testing.T) {
	f := newSyncFixture(t, grafanaManifest)
	before := git(t, f.clone, "rev-parse", "HEAD")
	h := f.start(t, false)
	if err := os.RemoveAll(f.upstream); err != nil {
		t.Fatal(err)
	}
	err := h.SyncSources()
	if err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("SyncSources() = %v, want a failure naming the source", err)
	}
	if got := git(t, f.clone, "rev-parse", "HEAD"); got != before {
		t.Errorf("clone moved to %s", got)
	}
	if h.Template("grafana") == nil {
		t.Error("grafana lost its template after a failed fetch")
	}
	st := h.SourceSync()
	if st.OK || st.Sources[0].OK || st.Sources[0].Updated || !strings.Contains(st.Sources[0].Error, "previous version is kept") || st.Trigger != SyncAPI {
		t.Errorf("status = %+v", st)
	}
	if strings.Contains(st.Sources[0].Error, f.upstream) {
		t.Errorf("status error carries git output: %q", st.Sources[0].Error)
	}
}

// A new version without a valid template for an enabled instance is
// reverted; the previous one keeps serving it.
func TestSyncRevertsVersionBreakingEnabledApp(t *testing.T) {
	f := newSyncFixture(t, grafanaManifest)
	before := git(t, f.clone, "rev-parse", "HEAD")
	h := f.start(t, false)
	bad := f.commit(t, brokenManifest)
	st := h.SyncSourcesAs(SyncSignal)
	if got := git(t, f.clone, "rev-parse", "HEAD"); got != before {
		t.Errorf("clone at %s, want the previous %s", got, before)
	}
	if h.Template("grafana") == nil {
		t.Error("grafana lost its template")
	}
	r := st.Sources[0]
	if st.OK || !r.RolledBack || r.Updated || r.After != before || len(r.RolledBackFor) != 1 || r.RolledBackFor[0] != "grafana" || !strings.Contains(r.Error, bad[:12]) {
		t.Errorf("status = %+v", st)
	}
	if len(st.MissingTemplates) != 0 {
		t.Errorf("missing = %v", st.MissingTemplates)
	}
	// Fixed upstream: the next sync takes it.
	good := f.commit(t, grafanaManifest+"# fixed\n")
	if st := h.SyncSourcesAs(SyncSignal); !st.OK || !st.Sources[0].Updated || st.Sources[0].After != good {
		t.Errorf("after the fix: %+v", st)
	}
}

// An enabled instance whose template is still missing after the sync is
// reported and stays denied (fail closed).
func TestSyncReportsMissingTemplates(t *testing.T) {
	f := newSyncFixture(t, brokenManifest)
	h := f.start(t, true)
	st := readSyncFile(t, h)
	if !st.OK || len(st.MissingTemplates) != 1 || st.MissingTemplates[0] != "grafana" {
		t.Errorf("status = %+v", st)
	}
	if h.Template("grafana") != nil {
		t.Error("grafana has a template")
	}
}
