package kube

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/archive"
	"github.com/portcullis/hub/internal/volcopy"
)

// helperCluster: created helper pods run at once; execs of `hub volcopy`
// run the real volcopy against dir (the pod's /vol).
func helperCluster(t *testing.T, dir string) *cluster {
	c := newCluster(t)
	c.typed.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, k8sruntime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
		p.Status.Phase = corev1.PodRunning
		c.typed.Tracker().Create(a.GetResource(), p, ns)
		return true, p, nil
	})
	return c
}

type volExecer struct {
	dir   string
	calls [][]string
	fail  error
}

func (v *volExecer) Exec(ctx context.Context, ns, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	v.calls = append(v.calls, cmd)
	if v.fail != nil {
		return v.fail
	}
	if len(cmd) == 4 && cmd[1] == "volcopy" {
		if cmd[2] == "out" {
			return volcopy.Out(v.dir, stdout)
		}
		return volcopy.In(v.dir, stdin)
	}
	return nil
}

func helperPods(c *cluster) []corev1.Pod {
	l, _ := c.typed.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
	return l.Items
}

// TestHelperSpecMinimal: the helper pod per mode — the Hub's image, `hub
// helper idle`, the helper label, no network label, no token, a read-only
// root, exactly the mode's capabilities, the volume at /vol.
func TestHelperSpecMinimal(t *testing.T) {
	b := newCluster(t).backend(t)
	vol := b.helperPod(HelperVolume, "app", "app--data", true, nil)
	fix := b.helperPod(HelperFixer, "", "", false, &runtime.FixerSpec{Image: hubImage, User: "0:0", CapAdd: []string{"DAC_READ_SEARCH"},
		Binds: []runtime.BindMount{{Source: "/srv/photos", Target: "/root", ReadOnly: true}}, Scratch: []string{"/out"}, Memory: 64 << 20})
	for _, c := range []struct {
		p    *corev1.Pod
		kind string
		inst string
		caps []string
	}{{vol, HelperVolume, "app", []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}}, {fix, HelperFixer, FixerInstance, []string{"DAC_READ_SEARCH"}}} {
		p := c.p
		if !strings.HasPrefix(p.Name, "hub-helper-") || len(p.Name) != len("hub-helper-")+8 {
			t.Errorf("name %s", p.Name)
		}
		if p.Labels[LabelHelper] != c.kind || p.Labels[LabelInstance] != c.inst || len(p.Labels) != 2 {
			t.Errorf("%s labels %v", c.kind, p.Labels)
		}
		if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken || p.Spec.ServiceAccountName != "" {
			t.Errorf("%s: token", c.kind)
		}
		ct := p.Spec.Containers[0]
		if ct.Image != hubImage || strings.Join(ct.Command, " ") != "/usr/local/bin/hub helper idle" {
			t.Errorf("%s: %s %v", c.kind, ct.Image, ct.Command)
		}
		sc := ct.SecurityContext
		var add []string
		for _, a := range sc.Capabilities.Add {
			add = append(add, string(a))
		}
		if !slices.Equal(add, c.caps) || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || !*sc.ReadOnlyRootFilesystem || *sc.AllowPrivilegeEscalation {
			t.Errorf("%s security %+v", c.kind, sc)
		}
	}
	if m := vol.Spec.Containers[0].VolumeMounts; len(m) != 1 || m[0].MountPath != "/vol" || !m[0].ReadOnly || vol.Spec.Volumes[0].PersistentVolumeClaim.ClaimName != "app--data" {
		t.Errorf("volume helper mounts %+v", m)
	}
	if v := fix.Spec.Volumes; len(v) != 2 || v[0].HostPath == nil || v[0].HostPath.Path != "/srv/photos" || *v[0].HostPath.Type != corev1.HostPathDirectory || v[1].EmptyDir == nil {
		t.Errorf("fixer volumes %+v", v)
	}
	// Golden of the volume helper (the random suffix blanked).
	vol.Name = "hub-helper-xxxxxxxx"
	got, _ := json.MarshalIndent(vol.Spec, "", "  ")
	want, err := os.ReadFile("testdata/helper-volume.json")
	if err != nil || string(want) != string(got)+"\n" {
		if *update {
			os.WriteFile("testdata/helper-volume.json", append(got, '\n'), 0o644)
			return
		}
		t.Errorf("volume helper spec differs (-update):\n%s", got)
	}
}

// TestHelperRemovedOnFailure: a failing copy still deletes the helper.
func TestHelperRemovedOnFailure(t *testing.T) {
	c := helperCluster(t, "")
	b := c.backend(t)
	ex := &volExecer{dir: t.TempDir(), fail: errors.New("stream broke")}
	b.cfg.Exec = ex
	if err := b.VolumeIn(context.Background(), "app", "app--data", "/data", strings.NewReader("")); err == nil {
		t.Fatal("no error")
	}
	if p := helperPods(c); len(p) != 0 {
		t.Errorf("helpers left: %d", len(p))
	}
	rc, err := b.VolumeOut(context.Background(), "app", "app--data", "/data")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, rc)
	rc.Close()
	if p := helperPods(c); len(p) != 0 {
		t.Errorf("helpers left after out: %d", len(p))
	}
}

func TestHelperSweepAtStart(t *testing.T) {
	c := newCluster(t)
	ctx := context.Background()
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "hub-helper-aaaaaaaa", Namespace: ns, Labels: map[string]string{LabelHelper: HelperVolume, LabelInstance: "a"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "hub-helper-bbbbbbbb", Namespace: ns, Labels: map[string]string{LabelHelper: HelperFixer, LabelInstance: FixerInstance}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "a--web-1", Namespace: ns, Labels: map[string]string{LabelInstance: "a"}}},
	} {
		c.typed.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{})
	}
	if err := c.backend(t).SweepHelpers(ctx); err != nil {
		t.Fatal(err)
	}
	left := helperPods(c)
	if len(left) != 1 || left[0].Name != "a--web-1" {
		t.Errorf("left %v", left)
	}
	// RemoveHelper refuses a non-helper pod.
	if err := c.backend(t).RemoveHelper(ctx, "a--web-1/web"); err == nil {
		t.Error("removed an app pod")
	}
}

// canonical is a volume archive as the Hub keeps it in a backup
// (archive.Normalize at /data), as comparable entries (no mtimes).
func canonical(t *testing.T, r io.Reader) []string {
	var out bytes.Buffer
	if err := archive.Normalize(r, &out, "/data", nil); err != nil {
		t.Fatal(err)
	}
	var es []string
	tr := tar.NewReader(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return es
		}
		b, _ := io.ReadAll(tr)
		es = append(es, strings.Join([]string{h.Name, string(h.Typeflag), h.Linkname, string(rune(h.Mode)), string(b)}, "|"))
	}
}

// dockerArchive is the Engine's archive of a directory mounted at /data
// ("data/", "data/…", like GET /containers/{id}/archive).
func dockerArchive(t *testing.T, dir string) []byte {
	var raw bytes.Buffer
	if err := volcopy.Out(dir, &raw); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	tr, tw := tar.NewReader(&raw), tar.NewWriter(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		h.Name = "data/" + strings.TrimPrefix(strings.TrimPrefix(h.Name, "./"), "/")
		if h.Name == "data/" || h.Name == "data/." {
			h.Name = "data/"
		}
		tw.WriteHeader(h)
		io.Copy(tw, tr)
	}
	tw.Close()
	return out.Bytes()
}

// TestInstanceBackupFormatUnchanged: a volume copied out through a kube
// helper gives the same canonical archive (the backup's inner tar) as
// the Engine's archive of the same volume, and restores to the same
// content.
func TestInstanceBackupFormatUnchanged(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "conf"), 0o750)
	os.WriteFile(filepath.Join(dir, "conf", "echo.conf"), []byte("listen 8080;\n"), 0o640)
	os.WriteFile(filepath.Join(dir, "state.db"), []byte("db"), 0o600)
	os.Symlink("conf/echo.conf", filepath.Join(dir, "current"))
	c := helperCluster(t, dir)
	b := c.backend(t)
	b.cfg.Exec = &volExecer{dir: dir}
	rc, err := b.VolumeOut(context.Background(), "echo", "echo--data", "/data")
	if err != nil {
		t.Fatal(err)
	}
	kube := canonical(t, rc)
	rc.Close()
	docker := canonical(t, bytes.NewReader(dockerArchive(t, dir)))
	if !slices.Equal(kube, docker) {
		t.Errorf("kube %q\ndocker %q", kube, docker)
	}
	// Restore through a helper: the same content.
	dst := t.TempDir()
	b.cfg.Exec = &volExecer{dir: dst}
	var canon bytes.Buffer
	archive.Normalize(bytes.NewReader(dockerArchive(t, dir)), &canon, "/data", nil)
	if err := b.VolumeIn(context.Background(), "echo", "echo--data", "/data", &canon); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "conf", "echo.conf")); string(got) != "listen 8080;\n" {
		t.Errorf("restored %q", got)
	}
}

// RunFixer: the fixer runs by exec in a fixer helper of the Hub's own
// image only; its report is the stdout.
func TestRunFixerByExec(t *testing.T) {
	c := helperCluster(t, "")
	b := c.backend(t)
	ex := &volExecer{}
	b.cfg.Exec = ex
	res, err := b.RunFixer(context.Background(), runtime.FixerSpec{Image: hubImage, Cmd: []string{"/usr/local/bin/hub", "folderfix", "check"}, User: "0:0", Label: "folder:x", Pids: 8, Memory: 1 << 26, Timeout: 1 << 40}, nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if len(ex.calls) != 1 || strings.Join(ex.calls[0], " ") != "/usr/local/bin/hub folderfix check" {
		t.Errorf("calls %v", ex.calls)
	}
	if _, err := b.RunFixer(context.Background(), runtime.FixerSpec{Image: "docker.io/library/alpine@sha256:" + strings.Repeat("0", 64), Cmd: []string{"/bin/sh"}}, nil); err == nil {
		t.Error("ran another image")
	}
	if len(helperPods(c)) != 0 {
		t.Error("fixer helper left")
	}
}
