package agent_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	wagent "github.com/portcullis/hub/internal/agent"
	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/runtime"
	agentrt "github.com/portcullis/hub/internal/runtime/agent"
	"github.com/portcullis/hub/internal/workertest"
)

// client is a hub.control mTLS client of w.
func client(w *workertest.Worker) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(w.CA.Cert)
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{w.Control},
		ServerName: w.ID + ".node.portcullis.internal"}}}
}

var param = regexp.MustCompile(`\{[a-z]+\}`)

// TestAgentServesEveryRoute (final review B3, structural guard): every
// route of agentapi.Routes and ExtraRoutes reaches a handler of the
// ready agent — none answers the catch-all 404 "not found". POST
// /v1/leave (Remove server) is served, wipes the identity and ends.
func TestAgentServesEveryRoute(t *testing.T) {
	w := workertest.NewWorker(t, workertest.Opts{})
	c := client(w)
	var routes []agentapi.Route
	for _, rs := range agentapi.Routes {
		routes = append(routes, rs...)
	}
	for name, r := range agentapi.ExtraRoutes {
		if name != "Leave" {
			routes = append(routes, r)
		}
	}
	routes = append(routes, agentapi.ExtraRoutes["Leave"]) // last: it wipes the identity
	for _, r := range routes {
		p := param.ReplaceAllString(r.Path, "app")
		req, _ := http.NewRequest(r.Method, w.Server.URL+p, strings.NewReader("{}"))
		resp, err := c.Do(req)
		if err != nil {
			// A stream (events) that answered and holds: served.
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound && bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(agentapi.ErrorBody("not found"))) {
			t.Errorf("%s isn't served (the catch-all 404)", r.Pattern())
		}
		if r.Pattern() == agentapi.ExtraRoutes["Leave"].Pattern() {
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("leave: %d %s", resp.StatusCode, b)
			}
			if _, err := os.Stat(filepath.Join(w.DataDir, "identity")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the identity is still there: %v", err)
			}
			select {
			case <-w.Agent.Left():
			default:
				t.Error("the agent didn't signal it left")
			}
		}
	}
}

// TestUnknownExecIs404 (B6): an exec id this agent process didn't start
// (or lost at a restart) is 404, the Hub's "not running".
func TestUnknownExecIs404(t *testing.T) {
	w := workertest.NewWorker(t, workertest.Opts{})
	b, _ := w.Backend(nil)
	if _, err := b.ExecRunning(context.Background(), "never-started"); !docker.IsNotFound(err) {
		t.Errorf("%v (want a not-found)", err)
	}
}

// put pushes a bundle of id (compose, env) through the real backend:
// the agent's status and message (204 = taken).
func put(t *testing.T, w *workertest.Worker, id, composeYAML, env string, adopt bool) (int, string) {
	t.Helper()
	files := fstest.MapFS{"compose.yml": {Data: []byte(composeYAML), Mode: 0o644}}
	if env != "" {
		files["env"] = &fstest.MapFile{Data: []byte(env), Mode: 0o600}
	}
	m := agentapi.BundleManifest{Instance: id, Template: id, Volumes: map[string]string{"data": "portcullis-" + id + "_data"}, Files: map[string]agentapi.FileEntry{}, AdoptVolumes: adopt}
	for n, f := range files {
		s := sha256.Sum256(f.Data)
		m.Files[n] = agentapi.FileEntry{SHA256: hex.EncodeToString(s[:]), Mode: uint32(f.Mode), Size: int64(len(f.Data))}
	}
	b, _ := w.Backend(nil)
	err := b.PushBundle(context.Background(), id, files, m)
	if err == nil {
		return http.StatusNoContent, ""
	}
	var ae *agentrt.Error
	if !errors.As(err, &ae) {
		t.Fatalf("push: %v", err)
	}
	return ae.Status, ae.Msg
}

const volCompose = "services:\n  web:\n    image: x:1@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111" + "\n    volumes: [\"data:/data\"]\nvolumes:\n  data: {}\n"

// TestHiddenVolumesRefused (M1, the agent's backstop): a first bundle of
// an id the agent never held is 409 while volumes labelled with its
// project exist, unless the Hub marks it AdoptVolumes.
func TestHiddenVolumesRefused(t *testing.T) {
	w := workertest.NewWorker(t, workertest.Opts{})
	w.Engine.Lock()
	w.Engine.Volumes["portcullis-app_data"] = runtime.Volume{Name: "portcullis-app_data", Labels: map[string]string{docker.LabelProject: "portcullis-app", docker.LabelVolume: "data"}}
	w.Engine.Unlock()
	if code, msg := put(t, w, "app", volCompose, "", false); code != http.StatusConflict || !strings.Contains(msg, "earlier app") {
		t.Errorf("hidden volumes: %d %s", code, msg)
	}
	if code, msg := put(t, w, "app", volCompose, "", true); code != http.StatusNoContent {
		t.Errorf("adopted: %d %s", code, msg)
	}
	// No volume of it: a first bundle is fine.
	if code, msg := put(t, w, "other", volCompose, "", false); code != http.StatusNoContent {
		t.Errorf("clean: %d %s", code, msg)
	}
}

// TestBundleErrorsRedactEnvBeforeClip (L3): a compose error quoting an
// env value is redacted before the agent clips its message: no 6
// characters of the secret reach the Hub.
func TestBundleErrorsRedactEnvBeforeClip(t *testing.T) {
	secret := strings.Repeat("x", 170) + "S3cr3tValue-9f8e7d6c5b4a3210"
	w := workertest.NewWorker(t, workertest.Opts{})
	w.API.SetConfigForTest(func(ctx context.Context, p compose.Project) ([]byte, error) {
		return nil, errors.New("services.web.image: invalid reference format: " + secret)
	})
	code, msg := put(t, w, "app", volCompose, "TOKEN="+secret+"\n", false)
	if code != http.StatusBadRequest {
		t.Fatalf("%d %s", code, msg)
	}
	for i := 0; i+6 <= len("S3cr3tValue-9f8e7d6c5b4a3210"); i++ {
		if part := "S3cr3tValue-9f8e7d6c5b4a3210"[i : i+6]; strings.Contains(msg, part) {
			t.Fatalf("the answer carries %q: %s", part, msg)
		}
	}
	if !strings.Contains(msg, "***") {
		t.Errorf("not redacted: %s", msg)
	}
}

var _ = wagent.Version
