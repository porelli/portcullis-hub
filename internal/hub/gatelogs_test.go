package hub

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/gatelogs"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// fileSource serves the opened log's day files under dir as group-gate's
// replicas would (gatelogs.Source): every line, keep and the window
// applied; err (an *gatelogs.Incomplete) returned with them.
type fileSource struct {
	dir string
	err error
}

func (s fileSource) Read(_ context.Context, from, to time.Time, keep func([]byte) bool) ([]byte, error) {
	var out bytes.Buffer
	ents, _ := os.ReadDir(filepath.Join(s.dir, signinhistory.OpenedDirName))
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(s.dir, signinhistory.OpenedDirName, e.Name()))
		for _, l := range bytes.Split(b, []byte("\n")) {
			if len(l) > 0 && (keep == nil || keep(l)) {
				out.Write(l)
				out.WriteByte('\n')
			}
		}
	}
	return out.Bytes(), s.err
}

// TestImpersonationAppsHTTPIncomplete: over group-gate's replicas the
// apps are the files' ones; a replica that can't be read marks the list
// incomplete (signinhistory.MoreApps), as an unreadable file does.
func TestImpersonationAppsHTTPIncomplete(t *testing.T) {
	hf := newHistoryFixture(t)
	h := hf.f.h
	started := histNow.Add(-40 * time.Minute)
	ended := started.Add(12 * time.Minute)
	h.imp.now = func() time.Time { return histNow }
	writeSignInClients(t, h, map[string]string{signinhistory.ForwardAuthClient: "Gateway"})
	hf.openedAct(t, started.Add(time.Minute), "alice", "gitea.example.org", "Gitea", "root")
	hf.openedAct(t, started.Add(2*time.Minute), "alice", "files.example.org", "Files", "root")
	hf.openedAct(t, ended.Add(time.Minute), "alice", "late.example.org", "Late", "root")
	a := &impApps{h: h, kc: &impEventsKC{}, sleep: func(context.Context, time.Duration) bool { return true }}
	rec := state.Impersonation{ID: appsImpID, Admin: "root", Target: "alice", Started: started, Until: started.Add(30 * time.Minute),
		Ended: ended, How: ImpStopped}
	fromFiles, _ := a.run(context.Background(), rec)
	want := []signinhistory.OpenedApp{{Name: "Gitea"}, {Name: "Files"}}
	if !reflect.DeepEqual(fromFiles, want) {
		t.Fatalf("files: %+v", fromFiles)
	}
	dir := h.cfg.GroupGateDataDir
	h.cfg.GroupGateDataDir = ""
	h.cfg.GateLogs = &GateLogSources{Opened: fileSource{dir: dir}}
	if got, _ := a.run(context.Background(), rec); !reflect.DeepEqual(got, fromFiles) {
		t.Errorf("http: %+v, want the files' %+v", got, fromFiles)
	}
	h.cfg.GateLogs.Opened = fileSource{dir: dir, err: &gatelogs.Incomplete{Service: "group-gate", Unread: []string{"group-gate-1"}, Listed: 2}}
	got, _ := a.run(context.Background(), rec)
	if !reflect.DeepEqual(got, append(want, signinhistory.OpenedApp{Name: signinhistory.MoreApps})) {
		t.Errorf("a replica down: %+v", got)
	}
}

// TestSignInHistoryHTTPIncomplete: the opened log from the replicas is
// shown; a replica that can't be read names "opened" unknown (shown all
// the same), and nothing is pruned on the Hub's side.
func TestSignInHistoryHTTPIncomplete(t *testing.T) {
	hf := newHistoryFixture(t)
	h := hf.f.h
	hf.openedAct(t, histNow.Add(-time.Hour), "alice", "gitea.example.org", "Gitea", "")
	dir := h.cfg.GroupGateDataDir
	h.cfg.GroupGateDataDir = ""
	h.cfg.GateLogs = &GateLogSources{Opened: fileSource{dir: dir}}
	p, err := h.SignInHistory(context.Background(), "alice", "", 50)
	if err != nil || len(p.Entries) != 1 || p.Entries[0].App != "Gitea" || len(p.Unknown) != 0 {
		t.Fatalf("page = %+v, %v", p, err)
	}
	h.cfg.GateLogs.Opened = fileSource{dir: dir, err: &gatelogs.Incomplete{Service: "group-gate", Unread: []string{"group-gate-0"}, Listed: 2}}
	p, err = h.SignInHistory(context.Background(), "alice", "", 50)
	if err != nil || len(p.Entries) != 1 || !reflect.DeepEqual(p.Unknown, []string{HistoryOpened}) {
		t.Errorf("incomplete page = %+v, %v", p, err)
	}
	h.history.mu.Lock()
	h.history.prune = nil
	h.history.mu.Unlock()
	h.pruneSignInHistory() // no directory: nothing to prune, no panic
}

// statusSource is wg's port (gatelogs.StatusSource).
type statusSource struct {
	b   []byte
	err error
}

func (s statusSource) Status(context.Context) ([]byte, error) { return s.b, s.err }

func TestWGStatusFromHTTP(t *testing.T) {
	v := newVPNFixture(t, nil)
	v.writeStatus(t, true)
	fromFile, err := v.h.wgStatus()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(v.status)
	v.h.cfg.VPNStatusFile = ""
	v.h.cfg.GateLogs = &GateLogSources{WGStatus: statusSource{b: b}}
	if !v.h.vpnStatusOn() {
		t.Error("vpn status off with a wg port")
	}
	got, err := v.h.wgStatus()
	if err != nil || !reflect.DeepEqual(got, fromFile) {
		t.Errorf("http status = %+v, %v; want %+v", got, err, fromFile)
	}
	if !v.h.wgUp() {
		t.Error("wg not up from its port")
	}
	v.h.cfg.GateLogs.WGStatus = statusSource{err: errors.New("wg: no replica is running")}
	if _, err := v.h.wgStatus(); err == nil || v.h.wgUp() {
		t.Errorf("wg down read as up: %v", err)
	}
}

// TestAccessLogFromReplicas: mcp-gate's replicas' lines, merged, read as
// the file's; one replica down shows the other's; none = the 503.
func TestAccessLogFromReplicas(t *testing.T) {
	a := newInstAIFixture(t, nil)
	var even, odd []string
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			even = append(even, accessLine("alice", i))
		} else {
			odd = append(odd, accessLine("bob", i))
		}
	}
	all := make([]string, 0, 20)
	for i := 0; i < 10; i++ {
		all = append(all, even[i], odd[i])
	}
	writeAccessLog(t, a, all, "")
	want, err := a.h.AccessLog(nil, 50)
	if err != nil || len(want) != 20 {
		t.Fatalf("file: %d %v", len(want), err)
	}
	var mu sync.Mutex
	down := map[string]bool{}
	isDown := func(n string) bool { mu.Lock(); defer mu.Unlock(); return down[n] }
	setDown := func(n string) { mu.Lock(); down[n] = true; mu.Unlock() }
	serve := func(name string, ls []string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isDown(name) {
				http.Error(w, "busy", 503)
				return
			}
			start := 0
			if c := r.URL.Query().Get("cursor"); c != "" {
				start, _ = strconv.Atoi(strings.TrimPrefix(c, "c"))
			}
			w.Header().Set("X-Portcullis-Next", "c"+strconv.Itoa(len(ls)))
			w.Header().Set("X-Portcullis-Truncated", "false")
			for _, l := range ls[min(start, len(ls)):] {
				w.Write([]byte(l + "\n"))
			}
		}))
		t.Cleanup(srv.Close)
		return srv.Listener.Addr().String()
	}
	addrs := map[string]string{"10.0.0.1": serve("mcp-gate-0", even), "10.0.0.2": serve("mcp-gate-1", odd)}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, ad string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(ad)
		return (&net.Dialer{}).DialContext(ctx, network, addrs[h])
	}}
	r := gatelogs.Replicas{Service: "mcp-gate", Port: gatelogs.MCPGatePort, Client: &http.Client{Transport: tr},
		Lister: func(context.Context) ([]gatelogs.Replica, error) {
			return []gatelogs.Replica{{Name: "mcp-gate-0", Addr: "10.0.0.1"}, {Name: "mcp-gate-1", Addr: "10.0.0.2"}}, nil
		}}
	a.h.cfg.MCPGateDataDir = ""
	a.h.cfg.GateLogs = &GateLogSources{Access: &gatelogs.Tail{R: r}}
	got, err := a.h.AccessLog(nil, 50)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("replicas: %d lines (%v), want the file's %d", len(got), err, len(want))
	}
	// One down: the other's lines (and what was read of it before).
	a.h.cfg.GateLogs = &GateLogSources{Access: &gatelogs.Tail{R: r}}
	setDown("mcp-gate-1")
	got, err = a.h.AccessLog(func(l AccessLine) bool { return l.User == "alice" }, 50)
	if err != nil || len(got) != 10 {
		t.Errorf("one down: %d %v", len(got), err)
	}
	setDown("mcp-gate-0")
	if _, err := a.h.AccessLog(nil, 50); !errors.Is(err, errAccessLog) {
		t.Errorf("none readable: %v", err)
	}
}
