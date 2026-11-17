package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
)

// TestRtForStates: the primary's instances use the primary runtime; a
// worker's only while the server is ready; every other state (and an
// unknown server) is refused with its 409, also through rtOf.
func TestRtForStates(t *testing.T) {
	f := newFixture(t)
	h := f.h
	worker := &runtimetest.Fake{}
	if rt, err := h.rtFor("grafana"); err != nil || rt != h.rt {
		t.Fatalf("primary: %v %v", rt, err)
	}
	h.noteInstanceServer("immich", "nas")
	if _, err := h.rtFor("immich"); err == nil || errStatus(err) != 409 || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("unknown server: %v", err)
	}
	// Revoked last: a revoked entry is terminal (review B-M1).
	for _, c := range []struct{ state, want string }{
		{ServerOffline, "server NAS is offline"},
		{ServerEnrolling, "server NAS isn't ready yet"},
		{"", "server NAS is offline"},
		{ServerRevoked, "server NAS is revoked"},
	} {
		state, want := c.state, c.want
		h.setServer("nas", &serverRT{Name: "NAS", State: state, RT: worker})
		_, err := h.rtFor("immich")
		if err == nil || errStatus(err) != 409 || err.Error() != want {
			t.Errorf("%q: %v", state, err)
		}
		// rtOf: every call refused the same way, nothing reaches the worker.
		if err := h.rtOf("immich").Down(context.Background(), runtime.Project{Name: "portcullis-immich"}); err == nil || err.Error() != want {
			t.Errorf("%q rtOf: %v", state, err)
		}
		if _, ok := h.runtimes()["nas"]; ok {
			t.Errorf("%q: listed in runtimes()", state)
		}
	}
	if len(worker.Calls()) != 0 {
		t.Errorf("a server that isn't ready got calls: %v", worker.Calls())
	}
	if h.setServer("nas", &serverRT{Name: "NAS", State: ServerReady, RT: worker}) {
		t.Error("a revoked entry was replaced")
	}
	h.setServer("nas", nil) // removed: a new entry may follow
	h.setServer("nas", &serverRT{Name: "NAS", State: ServerReady, RT: worker})
	if rt, err := h.rtFor("immich"); err != nil || unwrapRT(rt) != worker {
		t.Errorf("ready: %v %v", rt, err)
	}
	if rts := h.runtimes(); rts["nas"] != worker || rts["primary"] != h.rt {
		t.Errorf("runtimes %v", rts)
	}
	// The index follows state.
	h.mu.Lock()
	in := h.st.Instances["grafana"]
	in.Server = "nas"
	h.st.Instances["grafana"] = in
	h.noteServersLocked()
	h.mu.Unlock()
	if h.serverOf("grafana") != "nas" || h.serverOf("immich") != "" {
		t.Errorf("index: grafana %q immich %q", h.serverOf("grafana"), h.serverOf("immich"))
	}
}

// TestAgentArchiveEntriesChecked (Review Focus 5): a volume archive a
// runtime (a worker's agent) streams is checked entry by entry with the
// Hub's archive rules before anything is kept: a device, a "..", an
// absolute name are refused and nothing escapes the staging file.
func TestAgentArchiveEntriesChecked(t *testing.T) {
	f := newFixture(t)
	h := f.h
	fake := &runtimetest.Fake{Contents: map[string][]byte{}}
	h.setServer("nas", &serverRT{Name: "NAS", State: ServerReady, RT: fake})
	h.noteInstanceServer("immich", "nas")
	dir := t.TempDir()
	for name, hdr := range map[string]*tar.Header{
		"device":   {Name: "data/dev", Typeflag: tar.TypeChar, Mode: 0o600},
		"dot-dot":  {Name: "data/../../etc/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		"absolute": {Name: "/etc/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		"outside":  {Name: "other/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
		tw.WriteHeader(hdr)
		if hdr.Size > 0 {
			tw.Write([]byte("x"))
		}
		tw.Close()
		fake.Contents["vol"] = buf.Bytes()
		dst := filepath.Join(dir, name+".tar")
		if _, err := h.copyVolumeOut(context.Background(), "immich", "vol", dst, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat("/etc/x"); err == nil && name != "absolute" {
			t.Errorf("%s: wrote /etc/x", name)
		}
	}
	// A clean archive goes through the worker's runtime.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: "data/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	tw.Write([]byte("hi"))
	tw.Close()
	fake.Contents["vol"] = buf.Bytes()
	if _, err := h.copyVolumeOut(context.Background(), "immich", "vol", filepath.Join(dir, "ok.tar"), nil); err != nil {
		t.Errorf("clean archive: %v", err)
	}
	var called bool
	for _, c := range fake.Calls() {
		called = called || strings.HasPrefix(c, "volume-out")
	}
	if !called {
		t.Errorf("the worker's runtime wasn't used: %v", fake.Calls())
	}
	_ = errors.New
}

// TestDockerPathUnchanged: an instance on the primary goes to the
// primary's runtime exactly as before (the rest of the suite covers the
// calls and their order).
func TestDockerPathUnchanged(t *testing.T) {
	f := newFixture(t)
	if f.h.rtOf("grafana") != f.h.rt || f.h.rtOf("") != f.h.rt {
		t.Fatal("a primary instance doesn't use the primary runtime")
	}
	if len(f.h.runtimes()) != 1 {
		t.Errorf("runtimes without servers: %v", f.h.runtimes())
	}
}

// TestReconcileTrustsNoWorkerClaim (commit review): units a worker lists
// count only for instances placed on that server; a unit claiming an
// instance of the primary or of another worker is dropped, and nothing
// is asked of another runtime about it.
func TestReconcileTrustsNoWorkerClaim(t *testing.T) {
	f := newFixture(t)
	h := f.h
	liar := &runtimetest.Fake{Units: []runtime.Unit{
		{ID: "c-primary", Project: "portcullis-grafana", Instance: "grafana", Service: "web", State: "exited"},
		{ID: "c-other", Project: "portcullis-photos", Instance: "photos", Service: "web", State: "exited"},
		{ID: "c-mismatch", Project: "portcullis-immich", Instance: "photos", Service: "web", State: "exited"},
		{ID: "c-own", Project: "portcullis-immich", Instance: "immich", Service: "web", State: "running"},
	}}
	other := &runtimetest.Fake{}
	h.setServer("nas", &serverRT{Name: "NAS", State: ServerReady, RT: liar})
	h.setServer("pi", &serverRT{Name: "Pi", State: ServerReady, RT: other})
	h.noteInstanceServer("immich", "nas")
	h.noteInstanceServer("photos", "pi")
	h.Reconcile(context.Background())
	for _, c := range other.Calls() {
		if !strings.HasPrefix(c, "list") {
			t.Errorf("the other worker was asked: %s", c)
		}
	}
	for _, c := range liar.Calls() {
		if strings.Contains(c, "c-primary") || strings.Contains(c, "c-other") || strings.Contains(c, "c-mismatch") {
			t.Errorf("a dropped unit got a follow-up: %s", c)
		}
	}
}
