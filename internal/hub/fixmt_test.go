package hub

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
)

// Fix round after T12/T13 (review-merge-t12-t13.md).

// workerRoot: nas reports its engine data root at root and folder roots
// roots (its facts refreshed).
func workerRoot(t *testing.T, p *placedFixture, root string, roots ...string) {
	t.Helper()
	p.w.mu.Lock()
	p.w.info.BindRoots = roots
	p.w.mu.Unlock()
	p.w.Lock()
	p.w.InfoVal = runtime.Info{ForbiddenRoots: []string{root}}
	p.w.Unlock()
	if _, err := p.h.refreshServerFacts(context.Background(), "nas"); err != nil {
		t.Fatal(err)
	}
}

// TestDockerRootTargetServer (M1): a worker instance's binds and path
// values are judged against the worker's engine root, never the
// primary's; a primary instance's against the primary's.
func TestDockerRootTargetServer(t *testing.T) {
	p := newPlacedFixture(t)
	workerRoot(t, p, "/srv/docker", "/srv", "/var")
	priRoot, err := p.h.rt.Info(context.Background())
	if err != nil || len(priRoot.ForbiddenRoots) == 0 {
		t.Fatalf("primary root %+v %v", priRoot, err)
	}
	pr := priRoot.ForbiddenRoots[0]
	bind := func(id, src string) {
		writeFile(t, filepath.Join(p.src, id, "manifest.yaml"), "name: B\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\n")
		writeFile(t, filepath.Join(p.src, id, "compose.yml"), "services:\n  web:\n    image: plain:1@sha256:3333333333333333333333333333333333333333333333333333333333333333\n    volumes:\n      - "+src+":/x\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers."+id+".rule: Host(`${PORTCULLIS_HOST_"+strings.ToUpper(id)+":-"+id+".portcullis.local}`)\n      traefik.http.routers."+id+".middlewares: portcullis-auth@docker,portcullis-groups@docker\n      traefik.http.services."+id+".loadbalancer.server.port: \"8080\"\n")
	}
	bind("nearworker", "/srv/docker/volumes")
	bind("nearprimary", filepath.ToSlash(filepath.Join(pr, "volumes")))
	p.h.Discover()
	for _, id := range []string{"nearworker", "nearprimary"} {
		if err := p.create(t, id, "nas"); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if err := p.h.checkSecretsMounts(context.Background(), p.h.Template("nearworker")); errStatus(err) != 400 {
		t.Errorf("a bind at the worker's root: %v", err)
	}
	if err := p.h.checkSecretsMounts(context.Background(), p.h.Template("nearprimary")); err != nil {
		t.Errorf("a bind near only the primary's root, on the worker: %v", err)
	}
	// Values: judged against the server named (a create's target).
	if err := p.h.dockerRootRule(context.Background(), "nas", "/srv/docker/x"); errStatus(err) != 400 {
		t.Errorf("worker value at its root: %v", err)
	}
	if err := p.h.dockerRootRule(context.Background(), "nas", pr+"/x"); err != nil {
		t.Errorf("worker value near the primary's root: %v", err)
	}
	if err := p.h.dockerRootRule(context.Background(), "", pr+"/x"); errStatus(err) != 400 {
		t.Errorf("primary value at the primary's root: %v", err)
	}
}

// TestRebindPerServer (L2, L3): a tunnel address is refused whatever
// the Local networks say; a port whose server changed since the preview,
// or whose server is gone, is refused (never the default list).
func TestRebindPerServer(t *testing.T) {
	f, _ := rebindFixture(t)
	ctx := context.Background()
	if _, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "10.214.0.5"}); statusOf(err) != 400 {
		t.Errorf("a link address: %v", err)
	}
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	// The instance is now recorded on a server the Hub doesn't know.
	f.h.mu.Lock()
	in := f.h.st.Instances["samba"]
	in.Server = "gone"
	f.h.st.Instances["samba"] = in
	f.h.mu.Unlock()
	if _, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}); err == nil {
		t.Error("previewed against a gone server")
	}
	if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, directory.Human("admin")); err == nil {
		t.Error("applied against a gone server")
	}
	if _, _, err := f.h.rebindAddress(ctx, "gone", "192.168.1.10"); statusOf(err) != 409 {
		t.Errorf("a gone server's address check: %v", err)
	}
}

// TestForgetRechecksUnderLock (L5): an instance no longer orphaned once
// the lock is held is not forgotten.
func TestForgetRechecksUnderLock(t *testing.T) {
	p := newPlacedFixture(t)
	placedEnabled(t, p, "plainapp")
	p.h.mu.Lock()
	in := p.h.st.Instances["plainapp"]
	in.State = state.InstanceOrphaned
	p.h.st.Instances["plainapp"] = in
	p.h.mu.Unlock()
	p.h.testHookForget = func(id string) {
		// A restore onto nas finished meanwhile.
		p.h.mu.Lock()
		in := p.h.st.Instances[id]
		in.State = ""
		p.h.st.Instances[id] = in
		p.h.mu.Unlock()
	}
	_, err := p.h.StartForget("plainapp", "plainapp", admin)
	if errStatus(err) != 409 {
		t.Fatalf("forget: %v", err)
	}
	if in := p.instance("plainapp"); in.Template == "" || in.State == state.InstanceDeleting {
		t.Errorf("forgotten: %+v", in)
	}
}

// TestServerDetailOneSnapshot (L6): concurrent settings and reads under
// -race.
func TestServerDetailOneSnapshot(t *testing.T) {
	p := newPlacedFixture(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			nets := []string{"192.168.1.0/24"}
			if i%2 == 0 {
				nets = []string{"10.1.0.0/16", "10.2.0.0/16"}
			}
			p.h.SetServerSettings(context.Background(), admin, "nas", ServerSettings{LocalNetworks: &nets})
		}
	}()
	for i := 0; i < 50; i++ {
		if _, err := p.h.ServerDetailOf(context.Background(), "nas"); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

// TestFolderServerNeverChanges (I3): an update naming another server is
// 409, the path unchanged or not.
func TestFolderServerNeverChanges(t *testing.T) {
	p := newPlacedFixture(t)
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	d.add("/mnt/media", "ext4")
	p.w.mu.Lock()
	p.w.disk = d
	p.w.mu.Unlock()
	workerRoot(t, p, "/var/lib/docker", "/mnt")
	if _, _, err := p.h.CreateFolder(context.Background(), FolderInput{ID: "media", Name: "Media", Path: "/mnt/media", Server: "nas"}, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := p.h.UpdateFolder(context.Background(), "media", FolderInput{Name: "Media 2", Server: "other"}, admin); errStatus(err) != 409 {
		t.Errorf("same path, other server: %v", err)
	}
	if fo, _ := storedFolder(p.fixture, "media"); fo.Server != "nas" || fo.Name != "Media" {
		t.Errorf("stored %+v", fo)
	}
}

// TestWorkerTextUntrusted (I2): a worker's reason and version reach the
// views and the doctor as one clipped line without control characters.
func TestWorkerTextUntrusted(t *testing.T) {
	if got := untrusted("bad\nline\x1b[31m more", 300); got != "bad line [31m more" {
		t.Errorf("%q", got)
	}
	long := untrusted(strings.Repeat("é", 400), 100)
	if !strings.HasSuffix(long, "…") || len(long) > 104 || !utf8.ValidString(long) {
		t.Errorf("clip %q", long)
	}
	p := newPlacedFixture(t)
	p.h.srvMu.Lock()
	p.h.pollOf("nas").reason = "tls: bad\ncertificate\x00"
	p.h.srvMu.Unlock()
	for _, v := range p.h.Servers(context.Background()) {
		if v.ID == "nas" && v.Error != "tls: bad certificate" {
			t.Errorf("view error %q", v.Error)
		}
	}
}
