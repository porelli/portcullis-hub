package kube

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/portcullis/hub/internal/runtime"
)

// Helper pods (contract §6 "On Kubernetes"): the Hub's own image
// (HUB_SELF_IMAGE) running `hub helper idle`, one PVC or hostPath, no
// network label (the namespace's deny-all), no token, a read-only root;
// the Hub execs `hub volcopy out|in /vol` or `hub folderfix …` in it.
const (
	// HelperVolume / HelperFixer are portcullis.io/helper's values.
	HelperVolume = "volume"
	HelperFixer  = "fixer"
	// FixerInstance is a fixer helper's instance label (it serves a
	// shared folder, not an instance; no instance id starts with
	// "portcullis").
	FixerInstance = "portcullis-fixer"
	// helperMount is where a volume helper mounts its PVC: never an
	// image path (the Podman domains_data lesson).
	helperMount = "/vol"
	// helperReady bounds the wait for a helper pod to run.
	helperReady = 2 * time.Minute
)

// volumeCaps are a volume copy helper's capabilities (root: it writes
// every owner and mode of the archive).
var volumeCaps = []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FOWNER"}

func randSuffix() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// helperPod is a helper's spec: kind volume (instance's PVC claim at
// /vol, read-only for reads) or fixer (spec's binds and scratch).
func (b *Backend) helperPod(kind, instance string, claim string, readOnly bool, fs *runtime.FixerSpec) *corev1.Pod {
	t, f, root := true, false, int64(0)
	sc := &corev1.SecurityContext{RunAsUser: &root, RunAsGroup: &root, RunAsNonRoot: &f, AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &t,
		Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
	c := corev1.Container{Name: "helper", Image: b.cfg.HubImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"/usr/local/bin/hub", "helper", "idle"}, SecurityContext: sc,
		Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: mustQuantity("256Mi")}, Requests: corev1.ResourceList{corev1.ResourceMemory: mustQuantity("256Mi")}}}
	var vols []corev1.Volume
	switch kind {
	case HelperVolume:
		sc.Capabilities.Add = volumeCaps
		vols = append(vols, corev1.Volume{Name: "vol", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim, ReadOnly: readOnly}}})
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "vol", MountPath: helperMount, ReadOnly: readOnly})
	case HelperFixer:
		instance = FixerInstance
		if u, g, err := numericUser(fs.User); err == nil {
			sc.RunAsUser = &u
			if g != nil {
				sc.RunAsGroup = g
			}
		}
		for _, cp := range fs.CapAdd {
			sc.Capabilities.Add = append(sc.Capabilities.Add, corev1.Capability(cp))
		}
		dir := corev1.HostPathDirectory
		for i, bm := range fs.Binds {
			n := fmt.Sprintf("bind-%d", i)
			vols = append(vols, corev1.Volume{Name: n, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: bm.Source, Type: &dir}}})
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: n, MountPath: bm.Target, ReadOnly: bm.ReadOnly})
		}
		for i, s := range fs.Scratch {
			n := fmt.Sprintf("scratch-%d", i)
			vols = append(vols, corev1.Volume{Name: n, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: n, MountPath: s})
		}
		if fs.Memory > 0 {
			q := *resourceQuantity(fs.Memory)
			c.Resources = corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q}, Requests: corev1.ResourceList{corev1.ResourceMemory: q}}
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hub-helper-" + randSuffix(), Namespace: b.cfg.Namespace,
			Labels: map[string]string{LabelHelper: kind, LabelInstance: instance}},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &f,
			EnableServiceLinks:           &f,
			RestartPolicy:                corev1.RestartPolicyNever,
			Containers:                   []corev1.Container{c},
			Volumes:                      vols,
			SecurityContext:              &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		},
	}
}

// startHelper creates p and waits until it runs; the returned stop
// deletes it (always: a background context, also after a failure).
func (b *Backend) startHelper(ctx context.Context, p *corev1.Pod) (stop func(), err error) {
	pods := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace)
	if _, err := pods.Create(ctx, p, metav1.CreateOptions{FieldManager: FieldManager}); err != nil {
		return nil, fmt.Errorf("helper pod: %w", err)
	}
	stop = func() {
		if err := pods.Delete(context.Background(), p.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			log.Printf("kube: removing helper pod %s: %v", p.Name, err)
		}
	}
	deadline := b.cfg.Clock().Add(helperReady)
	for {
		cur, err := pods.Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			stop()
			return nil, fmt.Errorf("helper pod %s: %w", p.Name, err)
		}
		if cur.Status.Phase == corev1.PodRunning {
			return stop, nil
		}
		if cur.Status.Phase == corev1.PodFailed || cur.Status.Phase == corev1.PodSucceeded {
			stop()
			return nil, fmt.Errorf("helper pod %s ended (%s)", p.Name, cur.Status.Phase)
		}
		if !b.cfg.Clock().Before(deadline) {
			stop()
			return nil, fmt.Errorf("helper pod %s didn't start within %s", p.Name, helperReady)
		}
		if err := b.cfg.Sleep(ctx, b.cfg.Poll); err != nil {
			stop()
			return nil, err
		}
	}
}

// pipeReader is the stdout of an exec streamed to the caller; Close
// ends the exec and removes the helper.
type pipeReader struct {
	*io.PipeReader
	done func()
}

func (r *pipeReader) Close() error {
	err := r.PipeReader.Close()
	r.done()
	return err
}

// VolumeOut streams PVC volume of instance as a tar ("./…" entries:
// archive.Normalize reads them) from a read-only volume helper; closing
// the stream ends the exec and deletes the helper.
func (b *Backend) VolumeOut(ctx context.Context, instance, volume, _ string) (io.ReadCloser, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	p := b.helperPod(HelperVolume, instance, volume, true, nil)
	stop, err := b.startHelper(ctx, p)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	ectx, cancel := context.WithCancel(ctx)
	go func() {
		errb := &limited{max: 4 << 10}
		err := b.cfg.Exec.Exec(ectx, b.cfg.Namespace, p.Name, "helper", []string{"/usr/local/bin/hub", "volcopy", "out", helperMount}, nil, pw, errb)
		if err != nil {
			err = fmt.Errorf("volume copy out: %w%s", err, stderrTail(errb))
		}
		pw.CloseWithError(err)
	}()
	return &pipeReader{PipeReader: pr, done: func() { cancel(); stop() }}, nil
}

// VolumeIn extracts r (a canonical archive) into PVC volume through a
// writable volume helper (exec stdin).
func (b *Backend) VolumeIn(ctx context.Context, instance, volume, _ string, r io.Reader) error {
	if err := b.gate(); err != nil {
		return err
	}
	p := b.helperPod(HelperVolume, instance, volume, false, nil)
	stop, err := b.startHelper(ctx, p)
	if err != nil {
		return err
	}
	defer stop()
	errb := &limited{max: 4 << 10}
	if err := b.cfg.Exec.Exec(ctx, b.cfg.Namespace, p.Name, "helper", []string{"/usr/local/bin/hub", "volcopy", "in", helperMount}, r, io.Discard, errb); err != nil {
		return fmt.Errorf("restoring volume %s: %w%s", volume, err, stderrTail(errb))
	}
	return nil
}

func stderrTail(l *limited) string {
	if s := strings.TrimSpace(l.buf.String()); s != "" {
		return ": " + s
	}
	return ""
}

// RemoveHelper deletes a leftover helper pod (List with Filter.Helper;
// the unit id's pod part).
func (b *Backend) RemoveHelper(ctx context.Context, id string) error {
	if err := b.gate(); err != nil {
		return err
	}
	pod, _, _ := strings.Cut(id, "/")
	p, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if _, ok := p.Labels[LabelHelper]; !ok {
		return fmt.Errorf("pod %s is not a helper: not removing it", pod)
	}
	return b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Delete(ctx, pod, metav1.DeleteOptions{})
}

// SweepHelpers deletes every helper pod (Hub start).
func (b *Backend) SweepHelpers(ctx context.Context) error {
	l, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelHelper})
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range l.Items {
		if err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// tail keeps the last max bytes written.
type tail struct {
	buf     []byte
	max     int
	clipped bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.clipped = true
	}
	return len(p), nil
}

// RunFixer runs the shared-folder fixer: a fixer helper (the spec's
// binds, scratch dirs, user and caps), In extracted at InPath, the
// command exec'd (stdout's last MaxRunStdout bytes, stderr's first
// MaxRunStderr), OutPath streamed to out after a 0 exit; the helper is
// always deleted. A non-zero exit is not an error (ExitCode).
func (b *Backend) RunFixer(ctx context.Context, s runtime.FixerSpec, out func(tar io.Reader) error) (*runtime.RunResult, error) {
	if err := b.gate(); err != nil {
		return nil, err
	}
	if s.Image != b.cfg.HubImage {
		return nil, fmt.Errorf("fixer image %q is not the Hub's own (%s)", s.Image, b.cfg.HubImage)
	}
	if len(s.Cmd) == 0 || !path.IsAbs(s.Cmd[0]) {
		return nil, errors.New("helper argv must start with an absolute path")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	p := b.helperPod(HelperFixer, "", "", false, &s)
	stop, err := b.startHelper(ctx, p)
	if err != nil {
		return nil, err
	}
	defer stop()
	ex := func(cmd []string, in io.Reader, so, se io.Writer) error {
		return b.cfg.Exec.Exec(ctx, b.cfg.Namespace, p.Name, "helper", cmd, in, so, se)
	}
	if s.In != nil {
		errb := &limited{max: 4 << 10}
		if err := ex([]string{"/usr/local/bin/hub", "volcopy", "in", s.InPath}, s.In, io.Discard, errb); err != nil {
			return nil, fmt.Errorf("fixer input: %w%s", err, stderrTail(errb))
		}
	}
	so := &tail{max: runtime.MaxRunStdout}
	se := &limited{max: runtime.MaxRunStderr}
	err = ex(s.Cmd, nil, so, se)
	res := &runtime.RunResult{ExitCode: exitCode(err), Stdout: so.buf, Stderr: se.buf.Bytes(), StdoutClipped: so.clipped, StderrClipped: se.truncated}
	if ctx.Err() != nil {
		return res, fmt.Errorf("fixer: %w", ctx.Err())
	}
	if res.ExitCode < 0 {
		return res, fmt.Errorf("fixer: %w", err)
	}
	if res.ExitCode == 0 && s.OutPath != "" && out != nil {
		pr, pw := io.Pipe()
		go func() {
			pw.CloseWithError(ex([]string{"/usr/local/bin/hub", "volcopy", "out", s.OutPath}, nil, pw, io.Discard))
		}()
		err := out(pr)
		pr.Close()
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func mustQuantity(s string) resource.Quantity { return resource.MustParse(s) }

func resourceQuantity(n int64) *resource.Quantity { return resource.NewQuantity(n, resource.BinarySI) }
