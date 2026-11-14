package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/exec"

	"github.com/portcullis/hub/internal/runtime"
)

// maxExecOutput bounds captured exec output (as on Docker).
const maxExecOutput = 4 << 20

// RemoteExec is the Execer over pods/exec (create only: the WebSocket
// executor, falling back to SPDY; Task 0 Q3).
type RemoteExec struct {
	Client kubernetes.Interface
	Config *rest.Config
}

func (r RemoteExec) Exec(ctx context.Context, ns, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := r.Client.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: container, Command: cmd, Stdin: stdin != nil, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	ws, err := remotecommand.NewWebSocketExecutor(r.Config, http.MethodGet, req.URL().String())
	if err != nil {
		return err
	}
	spdy, err := remotecommand.NewSPDYExecutor(r.Config, http.MethodPost, req.URL())
	if err != nil {
		return err
	}
	ex, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool { return httpstreamUpgradeFailure(err) })
	if err != nil {
		return err
	}
	return ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

// httpstreamUpgradeFailure: fall back to SPDY only when the WebSocket
// upgrade itself failed.
func httpstreamUpgradeFailure(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "upgrade") || strings.Contains(err.Error(), "websocket"))
}

// limited keeps the first max bytes written.
type limited struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room < len(p) {
		if room > 0 {
			l.buf.Write(p[:room])
		}
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

// exitCode is err's exit status (0 = none; -1 = unknown).
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ce exec.CodeExitError
	if errors.As(err, &ce) {
		return ce.Code
	}
	var ee exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus()
	}
	return -1
}

func (b *Backend) exec(ctx context.Context, id string, in runtime.ExecInput, stdout, stderr io.Writer) (code int, timedOut bool, err error) {
	if err := b.gate(); err != nil {
		return -1, false, err
	}
	pod, c, err := splitID(id)
	if err != nil {
		return -1, false, err
	}
	if in.User != "" {
		return -1, false, fmt.Errorf("exec as user %s: Kubernetes exec runs as the container's user", in.User)
	}
	if b.cfg.Exec == nil {
		return -1, false, errors.New("kube: no exec transport")
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdin io.Reader
	if !in.NoStdin {
		stdin = bytes.NewReader(in.Stdin)
	}
	err = b.cfg.Exec.Exec(ectx, b.cfg.Namespace, pod, c, in.Cmd, stdin, stdout, stderr)
	if ectx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		return -1, true, nil
	}
	code = exitCode(err)
	if code > 0 {
		return code, false, nil
	}
	if err != nil {
		return -1, false, err
	}
	return 0, false, nil
}

// Exec runs in.Cmd in the unit (stdout and stderr together, capped).
func (b *Backend) Exec(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecResult, error) {
	out := &limited{max: maxExecOutput}
	code, to, err := b.exec(ctx, id, in, out, out)
	if err != nil {
		return nil, err
	}
	return &runtime.ExecResult{Output: out.buf.Bytes(), ExitCode: code, TimedOut: to, Truncated: out.truncated}, nil
}

// ExecSplit runs in.Cmd with stdout and stderr apart.
func (b *Backend) ExecSplit(ctx context.Context, id string, in runtime.ExecInput) (*runtime.ExecSplitResult, error) {
	so, se := &limited{max: runtime.MaxRunStdout}, &limited{max: runtime.MaxRunStderr}
	code, to, err := b.exec(ctx, id, in, so, se)
	if err != nil {
		return nil, err
	}
	return &runtime.ExecSplitResult{Stdout: so.buf.Bytes(), Stderr: se.buf.Bytes(), StdoutTruncated: so.truncated, StderrTruncated: se.truncated, ExitCode: code, TimedOut: to}, nil
}

// ExecRunning: a Kubernetes exec ends with its stream (never still
// running after a timeout).
func (b *Backend) ExecRunning(context.Context, string) (bool, error) { return false, b.gate() }

// Signal sends sig to the unit's main process by exec (kill -s <SIG> 1).
// With no kill in the image the service's pod is restarted through its
// Deployment's pod template (never a pod patch) and ErrReloadDegraded
// returned.
func (b *Backend) Signal(ctx context.Context, id, sig string) error {
	if sig == "" {
		return errors.New("signal: no signal")
	}
	var out bytes.Buffer
	_, _, err := b.exec(ctx, id, runtime.ExecInput{Cmd: []string{"kill", "-s", strings.TrimPrefix(strings.ToUpper(sig), "SIG"), "1"}, Timeout: 30 * time.Second, NoStdin: true}, &out, &out)
	if err == nil && !strings.Contains(out.String(), "executable file not found") {
		return nil
	}
	if err != nil && !strings.Contains(err.Error(), "executable file not found") && !strings.Contains(out.String(), "executable file not found") {
		return err
	}
	pod, _, _ := splitID(id)
	if rerr := b.restartPodOwner(ctx, pod, b.cfg.Clock().UTC().Format(time.RFC3339Nano)); rerr != nil {
		return fmt.Errorf("no kill in the image, and restarting the pod failed: %w", rerr)
	}
	return ErrReloadDegraded
}

// restartPodOwner restarts pod's Deployment by its pod template
// annotation portcullis.io/rev (the Recreate strategy replaces the pod).
func (b *Backend) restartPodOwner(ctx context.Context, pod, rev string) error {
	p, err := b.cfg.Client.CoreV1().Pods(b.cfg.Namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return err
	}
	inst, svc := p.Labels[LabelInstance], p.Labels[LabelService]
	if inst == "" || svc == "" {
		return fmt.Errorf("pod %s is no instance's", pod)
	}
	return b.restartDeployment(ctx, inst, ObjectName(inst, svc), rev)
}

func (b *Backend) restartDeployment(ctx context.Context, instance, name, rev string) error {
	d, err := b.cfg.Client.AppsV1().Deployments(b.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if d.Labels[LabelInstance] != instance {
		return fmt.Errorf("deployment %s isn't instance %s's", name, instance)
	}
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{%q:%q}}}}}`, AnnotationRev, rev)
	_, err = b.cfg.Client.AppsV1().Deployments(b.cfg.Namespace).Patch(ctx, name, mergePatch, []byte(patch), metav1.PatchOptions{FieldManager: FieldManager})
	return err
}
